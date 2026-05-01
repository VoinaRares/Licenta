import logging
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session

from licenta.models.API_request_log import APIRequestLog
from licenta.models.node_request_log import NodeRequestLog

logger = logging.getLogger(__name__)


def write_api_log(
    session: Session,
    entry_point: str,
    client_ip: str,
    action: str,
    status_code: int,
    method: str,
    user_id: Optional[int] = None,
    duration_ms: Optional[float] = None,
    error_details: Optional[str] = None,
) -> None:
    log = APIRequestLog(
        entry_point=entry_point,
        client_ip=client_ip,
        action=action,
        status_code=status_code,
        method=method,
        user_id=user_id,
        duration_ms=duration_ms,
        error_details=error_details,
        timestamp=datetime.now(timezone.utc),
    )
    session.add(log)
    session.commit()


def write_node_log(
    session: Session,
    node_id: int,
    action: str,
    method: str,
    status_code: int,
    user_id: Optional[int] = None,
    duration_ms: Optional[float] = None,
    error_details: Optional[str] = None,
) -> None:
    log = NodeRequestLog(
        node_id=node_id,
        action=action,
        method=method,
        status_code=status_code,
        user_id=user_id,
        duration_ms=duration_ms,
        error_details=error_details,
        timestamp=datetime.now(timezone.utc),
    )
    session.add(log)
    session.commit()
