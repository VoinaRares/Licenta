from pydantic import BaseModel

class RetrieveInput(BaseModel):
    session_id: str
    object_id: str