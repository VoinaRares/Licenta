"""Standalone key-rotation worker. Run separately from the FastAPI process:
    python -m licenta.rotation_worker
"""
import asyncio
import logging
import os

import httpx
from dotenv import load_dotenv
from sqlmodel import Session

from licenta.services import http_client
from licenta.services.database_service import engine, test_connection
from licenta.services.shamir_storage_service import ShamirStorageService

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


async def rotation_loop(interval_seconds: int) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            with Session(engine) as session:
                service = ShamirStorageService(session=session)
                results = await service.rotate_all_objects()
                logger.info("Key rotation run complete: %s", results)
        except Exception:
            logger.exception("Periodic key rotation failed")


async def main() -> None:
    test_connection()
    interval_seconds = max(60, int(os.getenv("KEY_ROTATION_INTERVAL_SECONDS", "86400")))
    logger.info("Starting rotation worker, interval=%ds", interval_seconds)
    client = httpx.AsyncClient()
    http_client.set_client(client)
    try:
        await rotation_loop(interval_seconds)
    finally:
        await http_client.close()


if __name__ == "__main__":
    asyncio.run(main())
