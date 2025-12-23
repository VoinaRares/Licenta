# client.py (FINAL WORKING VERSION)

import base64, requests, os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://127.0.0.1:8000/encrypt"

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

# 1) Generate client keypair
client_priv = x25519.X25519PrivateKey.generate()
client_pub = client_priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("Sending handshake...")
resp = requests.post(f"{SERVER}/handshake", json={
    "client_pubkey_b64": b64(client_pub)
})
resp.raise_for_status()

data = resp.json()
session_id = data["session_id"]
server_pub_b64 = data["server_pubkey_b64"]
print("Session ID:", session_id)

# derive session key
server_pub = x25519.X25519PublicKey.from_public_bytes(ub64(server_pub_b64))
shared = client_priv.exchange(server_pub)

session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session-transport-key"
).derive(shared)

print("Session key:", session_key.hex())

# 2) Encrypt inner layer
plaintext = b"Hello, this is a secret message!"
aes = AESGCM(session_key)
inner_nonce = os.urandom(12)
inner_ct = aes.encrypt(inner_nonce, plaintext, b"")

print("Storing object...")

upload = requests.post(f"{SERVER}/store", json={
    "session_id": session_id,
    "client_ciphertext_b64": b64(inner_ct),
    "client_nonce_b64": b64(inner_nonce),
    "aad": "file=test",
    "object_id": "obj-test-001"
})
upload.raise_for_status()
udata = upload.json()
print("Store response:", udata)

object_id = udata["object_id"]

# # 3) Retrieve object
# print("Retrieving…")
# ret = requests.get(f"{SERVER}/retrieve/{object_id}?session_id={session_id}")
# ret.raise_for_status()
# r = ret.json()
# print("Retrieve response:", r)

# wrapped_ct = ub64(r["ciphertext_b64"])
# wrapped_nonce = ub64(r["nonce_b64"])

# aes2 = AESGCM(session_key)
# inner_recovered = aes2.decrypt(wrapped_nonce, wrapped_ct, b"")

# assert inner_recovered == inner_ct
# print("Inner ciphertext matches ✔")

# # decrypt final plaintext
# final_plaintext = aes.decrypt(inner_nonce, inner_ct, b"")
# print("Final plaintext:", final_plaintext.decode())
