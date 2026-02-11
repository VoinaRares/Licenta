from pydantic import BaseModel

class CreateUserOutput(BaseModel):
    api_key: str
    user_id: int