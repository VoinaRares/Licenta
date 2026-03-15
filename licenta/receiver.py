from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from datetime import datetime, timezone
from typing import Optional

app = FastAPI()

STORAGE_DIR = "shares"
UNLOCK_TOKEN_PATH = "unlock.token"
OBJECT_UNLOCK_DIR = "object_unlock_tokens"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(OBJECT_UNLOCK_DIR, exist_ok=True)

NODE_ID = os.environ.get("NODE_ID", "default-node")

class SignedShareInput(BaseModel):
    payload: dict
    signature: str

class SignedTokenInput(BaseModel):
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

def verify_admin_signature(payload: dict, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        ADMIN_PUBLIC_KEY.verify(
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

def verify_server_signature(payload: dict, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
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

def sign_payload(payload: dict) -> str:
    message = canonicalize_payload(payload)
    signature = NODE_PRIVATE_KEY.sign(
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

        payload = token_wrapper["payload"]
        signature = token_wrapper["signature"]

        if not verify_admin_signature(payload, signature):
            return False

        expiry = datetime.fromisoformat(payload["expiry"]).replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expiry:
            return False

        return payload.get("unlock", False)

    except Exception:
        return False

def is_object_unlocked(object_id: int) -> bool:
    token_path = os.path.join(OBJECT_UNLOCK_DIR, f"object_{object_id}.token")

    if not os.path.exists(token_path):
        return False

    try:
        with open(token_path, "r") as f:
            token_wrapper = json.load(f)

        payload = token_wrapper["payload"]
        signature = token_wrapper["signature"]

        if not verify_admin_signature(payload, signature):
            return False

        if payload.get("object_id") != object_id:
            return False

        expiry = datetime.fromisoformat(payload["expiry"]).replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expiry:
            return False

        if not payload.get("release", False):
            return False

        os.remove(token_path)

        return True

    except Exception:
        return False


@app.post("/store_share")
def store_share(inp: SignedShareInput):
    if not verify_server_signature(inp.payload, inp.signature):
        raise HTTPException(status_code=400, detail="Invalid signature")

    object_id = inp.payload['object_id']
    path = os.path.join(STORAGE_DIR, f"share_{object_id}.json")

    with open(path, "w") as f:
        json.dump(inp.payload, f)

    return {"status": "stored"}

@app.post("/upload_object_token")
def upload_object_token(token: SignedTokenInput):
    payload = token.payload
    signature = token.signature

    if not verify_admin_signature(payload, signature):
        raise HTTPException(status_code=400, detail="Invalid admin signature")

    object_id = payload.get("object_id")
    if object_id is None:
        raise HTTPException(status_code=400, detail="Missing object_id")

    token_path = os.path.join(OBJECT_UNLOCK_DIR, f"object_{object_id}.token")

    with open(token_path, "w") as f:
        json.dump({
            "payload": payload,
            "signature": signature
        }, f)

    return {"status": "object token stored"}

@app.get("/retrieve_share")
def retrieve_share(object_id: int, needs_verification: Optional[bool] = False):

    if not is_unlocked():
        raise HTTPException(status_code=403, detail="Node locked")

    if needs_verification:
        if not is_object_unlocked(object_id):
            raise HTTPException(status_code=403, detail="Object not authorized")

    path = os.path.join(STORAGE_DIR, f"share_{object_id}.json")

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Share not found")

    with open(path, "r") as f:
        data = json.load(f)

    signature = sign_payload(data)

    return {
        "payload": data,
        "signature": signature
    }

@app.get("/health")
def health():
    return {"status": "ok"}