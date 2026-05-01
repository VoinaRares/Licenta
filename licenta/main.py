import asyncio
import logging
import os
import time

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlmodel import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from licenta.api import auth, encrypt
from licenta.services.database_service import engine, test_connection, create_db_and_tables
from licenta.services.log_service import write_api_log
from licenta.services.shamir_storage_service import ShamirStorageService

logger = logging.getLogger(__name__)

_ACTION_MAP = {
    ("POST", "/auth/user"): "create_user",
    ("POST", "/encrypt/handshake"): "handshake",
    ("POST", "/encrypt/store"): "store",
    ("POST", "/encrypt/rotate"): "rotate",
}

_SKIP_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon.ico")


def _resolve_action(method: str, path: str) -> str:
    key = (method, path)
    if key in _ACTION_MAP:
        return _ACTION_MAP[key]
    if method == "GET" and path.startswith("/encrypt/retrieve/"):
        return "retrieve"
    return path


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(_SKIP_PREFIXES):
            return await call_next(request)
        start = time.monotonic()
        status_code = 500
        error_details = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as exc:
            error_details = str(exc)
            raise
        finally:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            user_id = getattr(request.state, "user_id", None)
            client_ip = request.client.host if request.client else "unknown"
            action = _resolve_action(request.method, request.url.path)
            try:
                with Session(engine) as log_session:
                    write_api_log(
                        session=log_session,
                        entry_point=request.url.path,
                        client_ip=client_ip,
                        action=action,
                        status_code=status_code,
                        method=request.method,
                        user_id=user_id,
                        duration_ms=duration_ms,
                        error_details=error_details,
                    )
            except Exception:
                logger.exception("Failed to write API request log")


async def _rotation_loop(interval_seconds: int):
    """Background loop that periodically rotates all ciphertext keys."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            with Session(engine) as session:
                service = ShamirStorageService(session=session)
                results = await service.rotate_all_objects()
                logger.info("Key rotation run complete: %s", results)
        except Exception:
            logger.exception("Periodic key rotation failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    test_connection()
    create_db_and_tables()
    interval_seconds = int(os.getenv("KEY_ROTATION_INTERVAL_SECONDS", "86400"))

    rotation_task = asyncio.create_task(_rotation_loop(interval_seconds))
    try:
        yield
    finally:
        rotation_task.cancel()


app = FastAPI(lifespan=lifespan)
app.add_middleware(RequestLoggingMiddleware)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])