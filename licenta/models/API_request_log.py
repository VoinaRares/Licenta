from sqlmodel import Field, SQLModel
from typing import Optional
import datetime
from datetime import timezone


class APIRequestLog(SQLModel, table=True):
    __tablename__="api_request_log"
    
    id: int | None = Field(default=None, primary_key=True)
    entry_point: str
    client_ip: str
    action: str
    status_code: int
    method: str
    user_id: int = Field(foreign_key="users.id")  
    duration_ms: Optional[str] = None
    error_details: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    