from pydantic import BaseModel

class RetrieveOutput(BaseModel):
    client_ciphertext_b64: str