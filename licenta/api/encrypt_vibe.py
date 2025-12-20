import base64, os, time, uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sslib import shamir, randomness

router = APIRouter()

# -----------------------------------------------------------------------------------
# In-memory storage
# -----------------------------------------------------------------------------------
SESSIONS = {}        # session_id → { session_key: bytes, server_priv: X25519PrivateKey }
OBJECTS = {}         # object_id → { outer_cipher_b64, outer_nonce_b64, aad, shares, prime_mod }

NODE_COUNT = 5
THRESHOLD = 3

# -----------------------------------------------------------------------------------
# MODELS
# -----------------------------------------------------------------------------------

class HandshakeInput(BaseModel):
    client_pubkey_b64: str

class HandshakeOutput(BaseModel):
    session_id: str
    server_pubkey_b64: str

class StoreInput(BaseModel):
    session_id: str
    client_ciphertext_b64: str
    object_id: str | None = None

class StoreOutput(BaseModel):
    object_id: str
    shares: dict

class RetrieveOutput(BaseModel):
    object_id: str
    ciphertext_b64: str
    nonce_b64: str
    aad: str

# -----------------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------------

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

def share_to_dict(share) -> dict:
    """
    Convert a shamir share to a serializable dict.
    Assumes that share is in the form of (index, value) and that value is bytes.
    """
    # For shares in the form (index, value), where value is expected to be bytes
    idx = share[0]
    val = share[1]
    
    # Convert the value (bytes) to base64 using the base64 module
    return {"index": idx, "value": base64.b64encode(val).decode('utf-8')}


# -----------------------------------------------------------------------------------
# HANDSHAKE
# -----------------------------------------------------------------------------------

@router.post("/handshake", response_model=HandshakeOutput)
def handshake(inp: HandshakeInput):
    client_pub_bytes = ub64(inp.client_pubkey_b64)
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)

    server_priv = x25519.X25519PrivateKey.generate()
    server_pub = server_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    shared = server_priv.exchange(client_pub)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-transport-key"
    ).derive(shared)

    session_id = str(uuid.uuid4())
    SESSIONS[session_id] = {
        "session_key": session_key,
        "server_priv": server_priv,
        "timestamp": time.time()
    }

    return HandshakeOutput(
        session_id=session_id,
        server_pubkey_b64=b64(server_pub)
    )

# -----------------------------------------------------------------------------------
# STORE
# -----------------------------------------------------------------------------------

@router.post("/store", response_model=StoreOutput)
def store(inp: StoreInput):
    if inp.session_id not in SESSIONS:
        raise HTTPException(400, "Invalid session")


    inner_cipher = ub64(inp.client_ciphertext_b64)

    # generate storage key (random 256-bit)
    storage_key = os.urandom(32)

    # Outer encryption
    aes = AESGCM(storage_key)
    outer_nonce = os.urandom(12)
    outer_cipher = aes.encrypt(outer_nonce, inner_cipher, inp.aad.encode())

    # Split the storage key into shares
    shares = shamir.split_secret(
        secret_bytes=storage_key,
        required_shares=THRESHOLD,
        distributed_shares=NODE_COUNT,
        randomness_source=randomness.UrandomReader()
    )

    # Store shares for later reconstruction
    shares_dict = {}
    shares_b64 = {}
    i = 0
    
    # Iterate over all shares and prepare for storage
    for share in shares["shares"]:
        shares_dict[i] = share  # Store raw shares for reconstruction
        
        # Convert share to dict and base64 encode the value
        share_info = share_to_dict(share)
        
        # If the share value is bytes, it is converted to base64
        shares_b64[str(i)] = share_info.get("value", b64(share) if isinstance(share, bytes) else str(share))
        i += 1

    # Store object with shares
    object_id = inp.object_id or f"obj-{uuid.uuid4()}"
    OBJECTS[object_id] = {
        "outer_cipher_b64": b64(outer_cipher),
        "outer_nonce_b64": b64(outer_nonce),
        "aad": inp.aad,
        "shares": shares_dict,  # Store raw shares for reconstruction
        "prime_mod": base64.b64encode(shares["prime_mod"]).decode()
    }

    return StoreOutput(
        object_id=object_id,
        shares=shares_b64  # Return base64-encoded shares in response
    )

# -----------------------------------------------------------------------------------
# RETRIEVE
# -----------------------------------------------------------------------------------

@router.get("/retrieve/{object_id}", response_model=RetrieveOutput)
def retrieve(object_id: str, session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(400, "Invalid session")

    if object_id not in OBJECTS:
        raise HTTPException(404, "Object not found")

    obj = OBJECTS[object_id]

    # Pick threshold shares
    all_shares = obj["shares"]
    picked_indices = list(all_shares.keys())[:THRESHOLD]
    picked = [all_shares[i] for i in picked_indices]

    # Convert stored tuples to "idx-base64" strings
    picked_str = [
        f"{idx}-{base64.b64encode(val).decode()}"
        for idx, val in picked
    ]

    # Build structure for sslib
    shamir_payload = {
        "required_shares": THRESHOLD,
        "prime_mod": obj["prime_mod"],
        "shares": picked_str
    }

    # Reconstruct using sslib API
    reconstructed_key = shamir.recover_secret(shamir.from_base64(shamir_payload))

    aes_outer = AESGCM(reconstructed_key)
    outer_nonce = ub64(obj["outer_nonce_b64"])
    outer_cipher = ub64(obj["outer_cipher_b64"])
    inner_cipher = aes_outer.decrypt(outer_nonce, outer_cipher, obj["aad"].encode())

    # Wrap for session transport
    aes_sess = AESGCM(SESSIONS[session_id]["session_key"])
    wrap_nonce = os.urandom(12)
    wrap_ct = aes_sess.encrypt(wrap_nonce, inner_cipher, b"")

    return RetrieveOutput(
        object_id=object_id,
        ciphertext_b64=b64(wrap_ct),
        nonce_b64=b64(wrap_nonce),
        aad=obj["aad"]
    )
