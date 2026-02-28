import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

with open("admin_private_key.pem", "rb") as f:
    ADMIN_PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

payload = {
    "unlock": True,
    "expiry": "2026-02-20T12:00:00"
}

message = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()

signature = ADMIN_PRIVATE_KEY.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

token = {
    "payload": payload,
    "signature": base64.b64encode(signature).decode()
}

with open("unlock.token", "w") as f:
    json.dump(token, f)

print("unlock.token generated")
