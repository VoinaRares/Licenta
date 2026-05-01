import base64
from licenta.models.handshake_output import HandshakeOutput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from licenta.services.storage_service_interface import StorageServiceInterface


def handshake() -> HandshakeOutput:
    server_private_key = x25519.X25519PrivateKey.generate()
    server_pubkey_bytes = server_private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw
    )
    return HandshakeOutput(
        server_pubkey_b64=base64.b64encode(server_pubkey_bytes).decode()
    )


async def store(inp: StoreInput, storage_service: StorageServiceInterface, user_id: int) -> StoreOutput:
    return await storage_service.store(inp, user_id)

async def retrieve(inp: RetrieveInput, storage_service: StorageServiceInterface, user_id: int) -> RetrieveOutput:
    return await storage_service.retrieve(inp, user_id)

