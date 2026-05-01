from sqlmodel import Field, SQLModel


class PublicKey(SQLModel, table=True):
    __tablename__ = "public_keys"
    
    key_id: int | None = Field(default=None, primary_key=True)
    key: str
    node_id: int = Field(unique=True)
    