import base64
import json
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from sqlmodel import Session, select

from licenta.models.public_key import PublicKey

logger = logging.getLogger(__name__)


def canonicalize_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_payload(payload: dict) -> str:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        canonicalize_payload(payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify_node_signature(
    payload: dict, signature_b64: str, node_id: int, session: Session
) -> bool:
    try:
        statement = select(PublicKey).where(PublicKey.node_id == node_id)
        public_key_obj = session.exec(statement).first()

        if not public_key_obj:
            logger.warning("No public key found in database for node %s", node_id)
            return False

        public_key = serialization.load_pem_public_key(public_key_obj.key.encode())
        signature = base64.b64decode(signature_b64)
        message = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        logger.error("Signature verification failed for node %s: %s", node_id, e)
        return False
