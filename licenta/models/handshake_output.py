from pydantic import BaseModel

class HandshakeOutput(BaseModel):
    session_id: str
    server_pubkey_b64: str