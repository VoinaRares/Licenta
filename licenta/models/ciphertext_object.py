from typing import Annotated
from sqlmodel import Field, Session, SQLModel

class CipherText(SQLModel, table=True):
    __tablename__="cipher_texts"
    
    id : int | None = Field(default=None, primary_key=True)
    cipherText: str
