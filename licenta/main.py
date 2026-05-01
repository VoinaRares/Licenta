import logging
import os
import time

import httpx
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from licenta.api import auth, encrypt
from licenta.services.database_service import engine, test_connection, create_db_and_tables
from licenta.services.log_service import write_api_log
from licenta.services import http_client

logger = logging.getLogger(__name__)

_SKIP_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon.ico")


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
            route = request.scope.get("route")
            action = getattr(route, "path", request.url.path)
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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    test_connection()
    create_db_and_tables()
    client = httpx.AsyncClient()
    http_client.set_client(client)
    try:
        yield
    finally:
        await http_client.close()


app = FastAPI(lifespan=lifespan)

_allowed_origins = [o for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])
