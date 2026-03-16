import asyncio
import logging
import os

from fastapi import FastAPI
from licenta.api import encrypt
from licenta.api import auth
from licenta.services.database_service import engine, test_connection, create_db_and_tables
from licenta.services.shamir_storage_service import ShamirStorageService
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)



async def _rotation_loop(interval_seconds: int):
    """Background loop that periodically rotates all ciphertext keys."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            from sqlmodel import Session

            with Session(engine) as session:
                service = ShamirStorageService(session=session)
                results = service.rotate_all_objects()
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

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["encrypt"])