import asyncio
import json
import logging
import time
from typing import Callable, Optional

import httpx
from sqlmodel import Session

from licenta.services import http_client
from licenta.services.database_service import engine
from licenta.services.log_service import write_node_log

logger = logging.getLogger(__name__)


class NodeClient:
    def __init__(
        self,
        devices: list[dict],
        threshold: int,
        signer: Callable[[dict], str],
        verifier: Callable[[dict, str, int], bool],
    ):
        self.devices = devices
        self.threshold = threshold
        self._signer = signer
        self._verifier = verifier

    async def send_shares(
        self,
        shares: list[tuple[int, int]],
        object_id: int,
        user_id: Optional[int] = None,
    ) -> int:
        """Fan out share storage to all nodes concurrently via asyncio.gather."""
        async def send_one(index: int, device: dict) -> bool:
            x, y = shares[index]
            node_id = device["node_id"]
            payload = {
                "node_id": node_id,
                "object_id": object_id,
                "share_id": index,
                "x": x,
                "y": str(y),
            }
            return await self._execute_store_share(device, payload, "store_share", user_id)

        results = await asyncio.gather(
            *[send_one(i, d) for i, d in enumerate(self.devices) if i < len(shares)],
            return_exceptions=True,
        )
        return sum(1 for r in results if r is True)

    async def restore_shares(
        self,
        old_shares: list[tuple[int, int]],
        object_id: int,
        user_id: Optional[int] = None,
    ) -> int:
        """Re-send old shares back to nodes after a failed rotation, concurrently."""
        old_shares_by_x = {x: y for x, y in old_shares}

        async def restore_one(device_index: int, device: dict) -> bool:
            x = device_index + 1
            if x not in old_shares_by_x:
                return False
            y = old_shares_by_x[x]
            node_id = device["node_id"]
            payload = {
                "node_id": node_id,
                "object_id": object_id,
                "share_id": device_index,
                "x": x,
                "y": str(y),
            }
            return await self._execute_store_share(device, payload, "restore_share", user_id)

        results = await asyncio.gather(
            *[restore_one(i, d) for i, d in enumerate(self.devices)],
            return_exceptions=True,
        )
        return sum(1 for r in results if r is True)

    async def retrieve_shares(
        self,
        object_id: int,
        needs_verification: bool,
        user_id: Optional[int] = None,
    ) -> list[tuple[int, int]]:
        """Fan out share retrieval; cancel stragglers once threshold shares arrive."""
        client = http_client.get()

        async def fetch_one(device: dict) -> tuple[int, int] | None:
            device_url = device["url"]
            node_id = device["node_id"]
            start = time.monotonic()
            status_code = 0
            error_details = None
            result: tuple[int, int] | None = None

            try:
                response = await client.get(
                    f"{device_url}/retrieve_share",
                    params={
                        "object_id": object_id,
                        "needs_verification": needs_verification,
                    },
                    timeout=5.0,
                )
                status_code = response.status_code
                if response.status_code == 200:
                    result = self._parse_signed_share(response.json(), node_id)
            except httpx.HTTPError as e:
                error_details = str(e)
                logger.warning("Failed retrieving share from %s: %s", device_url, e)
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.warning("Malformed response from node %s: %s", node_id, e)

            duration_ms = round((time.monotonic() - start) * 1000, 2)
            self._write_request_log(
                node_id, "retrieve_share", "GET", status_code, user_id, duration_ms, error_details
            )
            return result

        tasks = {asyncio.ensure_future(fetch_one(d)): d for d in self.devices}
        retrieved_shares: list[tuple[int, int]] = []
        pending = set(tasks.keys())

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    share = task.result()
                    if share is not None:
                        retrieved_shares.append(share)
                except Exception as e:
                    logger.warning("Share fetch task raised: %s", e)

            if len(retrieved_shares) >= self.threshold:
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                break

        return retrieved_shares


    async def _execute_store_share(
        self,
        device: dict,
        payload: dict,
        action: str,
        user_id: Optional[int],
    ) -> bool:
        """Sign a share payload, POST it to /store_share, log the outcome."""
        signature = self._signer(payload)
        client = http_client.get()
        node_id = device["node_id"]
        start = time.monotonic()
        status_code = 0
        error_details = None
        success = False
        try:
            response = await client.post(
                f"{device['url']}/store_share",
                json={"payload": payload, "signature": signature},
                timeout=5.0,
            )
            status_code = response.status_code
            response.raise_for_status()
            success = True
            logger.debug("Completed %s on node %s (object %s)", action, node_id, payload.get("object_id"))
        except httpx.HTTPStatusError as e:
            error_details = str(e)
            logger.warning("Failed %s on %s: %s", action, device["url"], e)
        except httpx.HTTPError as e:
            error_details = str(e)
            logger.warning("Failed %s on %s: %s", action, device["url"], e)

        duration_ms = round((time.monotonic() - start) * 1000, 2)
        self._write_request_log(node_id, action, "POST", status_code, user_id, duration_ms, error_details)
        return success

    def _parse_signed_share(
        self, signed_data: dict, node_id: int
    ) -> tuple[int, int] | None:
        """Verify the node signature and extract the (x, y) share from a response."""
        payload = signed_data.get("payload")
        signature = signed_data.get("signature")
        if not (payload and signature):
            logger.warning("Missing payload or signature from node %s", node_id)
            return None
        if not self._verifier(payload, signature, node_id):
            logger.warning("Signature verification failed for node %s", node_id)
            return None
        x = payload.get("x")
        y = payload.get("y")
        if x is None or y is None:
            logger.warning("Missing x or y in payload from node %s", node_id)
            return None
        return (int(x), int(y))

    def _write_request_log(
        self,
        node_id: int,
        action: str,
        method: str,
        status_code: int,
        user_id: Optional[int],
        duration_ms: float,
        error_details: Optional[str],
    ) -> None:
        try:
            with Session(engine) as log_session:
                write_node_log(
                    session=log_session,
                    node_id=node_id,
                    action=action,
                    method=method,
                    status_code=status_code,
                    user_id=user_id,
                    duration_ms=duration_ms,
                    error_details=error_details,
                )
        except Exception:
            logger.exception("Failed to write node request log for node %s", node_id)
