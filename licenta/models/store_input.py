from pydantic import BaseModel

class StoreInput(BaseModel):
    session_id: str
    client_ciphertext_b64: str
    