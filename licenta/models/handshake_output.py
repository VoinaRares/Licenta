from pydantic import BaseModel

class HandshakeOutput(BaseModel):
    server_pubkey_b64: str