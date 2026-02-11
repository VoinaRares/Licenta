from sqlmodel import SQLModel, Field
from datetime import datetime, timezone

class User(SQLModel, table=True):
    __tablename__ = "users"
    id: int | None = Field(default=None, primary_key=True)
    api_key_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))