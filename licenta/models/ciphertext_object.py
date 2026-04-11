from typing import Annotated
from sqlmodel import Field, Session, SQLModel

class CipherText(SQLModel, table=True):
    __tablename__="cipher_texts"
    
    id : int | None = Field(default=None, primary_key=True)
    cipherText: str
    user_id: int = Field(foreign_key="users.id")
    needs_verification: bool = Field(default=False)
    key_version: int = Field(default=1)
    is_rotating: bool = Field(default=False)
