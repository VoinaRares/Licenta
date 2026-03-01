from licenta.services.storage_service import StorageServiceInterface
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.models.ciphertext_object import CipherText
from licenta.models.public_key import PublicKey

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from sqlmodel import Session, select

import requests
import json
import secrets
import base64
from typing import List, Tuple
from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from itertools import combinations
import logging

logger = logging.getLogger(__name__)


class ShamirStorageService(StorageServiceInterface):

    def __init__(self, session: Session, num_shares: int = 5, threshold: int = 3):
        self.devices = [
            {"node_id": 1, "url": "http://localhost:8080/101"},
            {"node_id": 2, "url": "http://localhost:8080/102"},
            {"node_id": 3, "url": "http://localhost:8080/103"},
            {"node_id": 4, "url": "http://localhost:8080/104"},
            {"node_id": 5, "url": "http://localhost:8080/105"}
        ]

        self.num_shares = num_shares
        self.threshold = threshold
        self.session = session
        self.PRIME_FIELD = 2**521 - 1

    def store(self, inp: StoreInput, user_id: int) -> StoreOutput:
        master_secret = secrets.token_bytes(32)

        fernet_key_raw = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)

        fernet_key = base64.urlsafe_b64encode(fernet_key_raw)
        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(inp.client_ciphertext_b64.encode())

        obj = CipherText(cipherText=ciphertext.decode(), user_id=user_id, needs_verifcation=inp.needs_verification)
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)

        secret_int = int.from_bytes(master_secret, "big")
        shares = self._create_shares(secret=secret_int)

        self._send_shares_to_devices(shares, obj.id)

        return StoreOutput(object_id=str(obj.id))

    def retrieve(self, inp: RetrieveInput, user_id: int) -> RetrieveOutput:
        obj_id = int(inp.object_id)
        obj = self.session.get(CipherText, obj_id)

        if obj is None:
            raise ValueError("Object not found")

        if obj.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden"
            )

        shares = self._retrieve_shares_from_devices(object_id=obj_id, needs_verification=obj.needs_verifcation)

        if len(shares) < self.threshold:
            raise ValueError("Not enough shares")

        secret_int = self._byzantine_consensus(shares)
        master_secret = secret_int.to_bytes(32, "big")

        fernet_key_raw = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)

        fernet_key = base64.urlsafe_b64encode(fernet_key_raw)
        fernet = Fernet(fernet_key)

        plaintext = fernet.decrypt(obj.cipherText.encode())

        return RetrieveOutput(client_ciphertext_b64=plaintext.decode())

    def _send_shares_to_devices(self, shares: List[Tuple[int, int]], object_id: int):
        for index, device in enumerate(self.devices):
            if index >= len(shares):
                break

            x, y = shares[index]
            node_id = device["node_id"]

            payload = {
                "node_id": node_id,
                "object_id": object_id,
                "share_id": index,
                "x": x,
                "y": str(y)
            }

            signature = self._sign_payload(payload)

            signed_payload = {
                "payload": payload,
                "signature": signature
            }

            try:
                response = requests.post(
                    f"{device['url']}/store_share",
                    json=signed_payload,
                    timeout=5
                )
                response.raise_for_status()
                print("Sending to node:", node_id)
                print(payload)
                print(signature)
                print(response.status_code)
                print(response.text)

            except requests.RequestException as e:
                print(f"Failed storing share on {device['url']}: {e}")

    def _verify_node_signature(self, payload: dict, signature_b64: str, node_id: int) -> bool:
        try:
            # Retrieve node's public key from database
            statement = select(PublicKey).where(PublicKey.node_id == node_id)
            public_key_obj = self.session.exec(statement).first()
            
            if not public_key_obj:
                logger.warning(f"No public key found in database for node {node_id}")
                return False
            
            public_key = serialization.load_pem_public_key(public_key_obj.key.encode())
            signature = base64.b64decode(signature_b64)
            message = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()

            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed for node {node_id}: {e}")
            return False

    def _retrieve_shares_from_devices(self, object_id: int, needs_verification: bool) -> List[Tuple[int, int]]:
        retrieved_shares = []

        for device in self.devices:
            device_url = device["url"]
            node_id = device["node_id"]

            try:
                response = requests.get(
                    f"{device_url}/retrieve_share",
                    params={'object_id': object_id, 'needs_verification': needs_verification},
                )

                if response.status_code != 200:
                    continue

                signed_data = response.json()

                payload = signed_data.get("payload")
                signature = signed_data.get("signature")

                if not payload or not signature:
                    continue

                print("Trying node", node_id, "response:", signed_data)
                if not self._verify_node_signature(payload, signature, node_id):
                    print("Node signature verification failed for node", node_id)
                    continue
                
                retrieved_shares.append(
                    (int(payload['x']), int(payload['y']))
                )
            except requests.exceptions.RequestException:
                pass

        return retrieved_shares

    def _canonicalize_payload(self, payload: dict) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()

    def _sign_payload(self, payload: dict) -> str:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        signature = private_key.sign(
            self._canonicalize_payload(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    def _generate_coefficients(self, secret: int) -> list[int]:
        return [secret] + [secrets.randbelow(self.PRIME_FIELD) for _ in range(self.threshold - 1)]

    def _create_shares(self, secret: int) -> List[Tuple[int, int]]:
        coeffs = self._generate_coefficients(secret)
        shares = []

        for x in range(1, self.num_shares + 1):
            y = sum(
                coeff * pow(x, power, self.PRIME_FIELD)
                for power, coeff in enumerate(coeffs)
            ) % self.PRIME_FIELD

            shares.append((x, y))

        return shares

    def _reconstruct_secret(self, shares: list[tuple[int, int]]) -> int:
        secret = 0

        for i, (xi, yi) in enumerate(shares):
            numerator = 1
            denominator = 1

            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-xj)) % self.PRIME_FIELD
                    denominator = (denominator * (xi - xj)) % self.PRIME_FIELD

            lagrange_coeff = numerator * pow(denominator, -1, self.PRIME_FIELD)
            secret = (secret + yi * lagrange_coeff) % self.PRIME_FIELD

        return secret

    def _byzantine_consensus(self, shares: list[tuple[int, int]]) -> int:
        secret_count: dict[int, int] = {}

        for comb in combinations(shares, self.threshold):
            secret = self._reconstruct_secret(list(comb))
            secret_count[secret] = secret_count.get(secret, 0) + 1

        if not secret_count:
            raise ValueError("No valid secrets reconstructed")

        return max(secret_count, key=secret_count.get)
