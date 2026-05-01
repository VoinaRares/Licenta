from pydantic import BaseModel

class StoreInput(BaseModel):
    client_ciphertext_b64: str
    needs_verification: bool = False
