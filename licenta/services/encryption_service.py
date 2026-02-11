import uuid
import base64
from licenta.models.handshake_output import HandshakeOutput
from licenta.models.handshake_input import HandshakeInput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from licenta.services.storage_service import StorageServiceInterface


SESSION_KEYS = {}

def handshake(inp: HandshakeInput) -> HandshakeOutput:
    client_pubkey_bytes = base64.b64decode(inp.client_pubkey_b64)
    client_pubkey = x25519.X25519PublicKey.from_public_bytes(client_pubkey_bytes)

    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    shared_secret = server_private_key.exchange(client_pubkey)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake session key",
    ).derive(shared_secret)

    session_id = str(uuid.uuid4())

    SESSION_KEYS[session_id] = session_key

    server_pubkey_bytes = server_public_key.public_bytes(
        Encoding.Raw,
        PublicFormat.Raw
    )

    return HandshakeOutput(
        session_id=session_id,
        server_pubkey_b64=base64.b64encode(server_pubkey_bytes).decode()
    )


def store(inp: StoreInput, storage_service: StorageServiceInterface, user_id: int) -> StoreOutput:
    return storage_service.store(inp, user_id)

def retrieve(inp: RetrieveInput, storage_service: StorageServiceInterface, user_id: int) -> RetrieveOutput:
    return storage_service.retrieve(inp, user_id)

