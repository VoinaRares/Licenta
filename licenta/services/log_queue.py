"""
Async fire-and-forget log queue.

Enqueue log entries from the hot path; a background drainer flushes them to
Postgres without blocking request handling.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

logger = logging.getLogger(__name__)

_queue: asyncio.Queue = asyncio.Queue()


@dataclass
class _NodeLogEntry:
    kind: Literal["node"] = field(default="node", init=False)
    node_id: int = 0
    action: str = ""
    method: str = ""
    status_code: int = 0
    user_id: Optional[int] = None
    duration_ms: Optional[float] = None
    error_details: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class _APILogEntry:
    kind: Literal["api"] = field(default="api", init=False)
    entry_point: str = ""
    client_ip: str = ""
    action: str = ""
    status_code: int = 0
    method: str = ""
    user_id: Optional[int] = None
    duration_ms: Optional[float] = None
    error_details: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def enqueue_node_log(
    *,
    node_id: int,
    action: str,
    method: str,
    status_code: int,
    user_id: Optional[int] = None,
    duration_ms: Optional[float] = None,
    error_details: Optional[str] = None,
) -> None:
    try:
        _queue.put_nowait(_NodeLogEntry(
            node_id=node_id,
            action=action,
            method=method,
            status_code=status_code,
            user_id=user_id,
            duration_ms=duration_ms,
            error_details=error_details,
        ))
    except asyncio.QueueFull:
        logger.warning("Log queue full — dropping node log for node %s", node_id)


def enqueue_api_log(
    *,
    entry_point: str,
    client_ip: str,
    action: str,
    status_code: int,
    method: str,
    user_id: Optional[int] = None,
    duration_ms: Optional[float] = None,
    error_details: Optional[str] = None,
) -> None:
    try:
        _queue.put_nowait(_APILogEntry(
            entry_point=entry_point,
            client_ip=client_ip,
            action=action,
            status_code=status_code,
            method=method,
            user_id=user_id,
            duration_ms=duration_ms,
            error_details=error_details,
        ))
    except asyncio.QueueFull:
        logger.warning("Log queue full — dropping API log for %s", entry_point)


async def drain_forever() -> None:
    """Background task: pull entries from the queue and write them to Postgres."""
    from sqlmodel import Session
    from licenta.services.database_service import engine
    from licenta.services.log_service import write_api_log, write_node_log

    while True:
        entry = await _queue.get()
        try:
            with Session(engine) as session:
                if isinstance(entry, _NodeLogEntry):
                    write_node_log(
                        session=session,
                        node_id=entry.node_id,
                        action=entry.action,
                        method=entry.method,
                        status_code=entry.status_code,
                        user_id=entry.user_id,
                        duration_ms=entry.duration_ms,
                        error_details=entry.error_details,
                    )
                else:
                    write_api_log(
                        session=session,
                        entry_point=entry.entry_point,
                        client_ip=entry.client_ip,
                        action=entry.action,
                        status_code=entry.status_code,
                        method=entry.method,
                        user_id=entry.user_id,
                        duration_ms=entry.duration_ms,
                        error_details=entry.error_details,
                    )
        except Exception:
            logger.exception("Failed to flush log entry")
        finally:
            _queue.task_done()
