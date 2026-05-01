from pydantic import BaseModel

class RetrieveInput(BaseModel):
    object_id: str