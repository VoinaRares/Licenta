from fastapi import FastAPI
from pydantic import BaseModel
import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from datetime import datetime

app = FastAPI()

STORAGE_DIR = "shares"
UNLOCK_TOKEN_PATH = "unlock.token"

os.makedirs(STORAGE_DIR, exist_ok=True)

class SignedShareInput(BaseModel):
    payload: dict
    signature: str

with open("server_public_key.pem", "rb") as f:
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

with open("admin_public_key.pem", "rb") as f:
    ADMIN_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

with open("private_key.pem", "rb") as f:
    NODE_PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

def canonicalize_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()

def verify_signature(payload: dict, signature_b64: str) -> bool:
    signature = base64.b64decode(signature_b64)
    try:
        SERVER_PUBLIC_KEY.verify(
            signature,
            canonicalize_payload(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def sign_payload(payload: dict, private_key_path: str = "private_key.pem") -> str:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    message = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()

def is_unlocked() -> bool:

    if not os.path.exists(UNLOCK_TOKEN_PATH):
        return False

    try:
        with open(UNLOCK_TOKEN_PATH, "r") as f:
            token_wrapper = json.load(f)

        token_payload = token_wrapper["payload"]
        token_signature = token_wrapper["signature"]

        signature = base64.b64decode(token_signature)

        ADMIN_PUBLIC_KEY.verify(
            signature,
            canonicalize_payload(token_payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        expiry = datetime.fromisoformat(token_payload["expiry"])

        if datetime.utcnow() > expiry:
            return False

        return token_payload.get("unlock", False)

    except Exception:
        return False

@app.post("/store_share")
def store_share(inp: SignedShareInput):
    if not verify_signature(inp.payload, inp.signature):
        return {"status": "invalid_signature"}, 400

    object_id = inp.payload['object_id']
    path = os.path.join(STORAGE_DIR, f"share_{object_id}.json")

    with open(path, "w") as f:
        json.dump(inp.payload, f)

    return {"status": "stored"}

@app.get("/retrieve_share")
def retrieve_share(object_id: int):

    if not is_unlocked():
        return {"error": "Node locked"}, 403

    path = os.path.join(STORAGE_DIR, f"share_{object_id}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)

        signature = sign_payload(data, "private_key.pem")

        return {
            "payload": data,
            "signature": signature
        }

    return {"error": "Share not found"}

@app.get("/health")
def health():
    return {"status": "ok"}
