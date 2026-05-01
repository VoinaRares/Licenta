from sqlmodel import Field, SQLModel
from typing import Optional
from datetime import datetime, timezone


class NodeRequestLog(SQLModel, table=True):
    __tablename__ = "node_request_logs"

    id: int | None = Field(default=None, primary_key=True)
    node_id: int = Field(foreign_key="public_keys.node_id")
    user_id: Optional[int] = Field(default=None, foreign_key="users.id")
    action: str
    method: str
    status_code: int
    duration_ms: Optional[float] = None
    error_details: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))