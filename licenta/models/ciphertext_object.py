from typing import Annotated
from sqlmodel import Field, Session, SQLModel

class CipherTextObject(SQLModel, table=True):
    id : int | None = Field(default=None, primary_key=True)
    cipherText: str
