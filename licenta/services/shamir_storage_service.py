from licenta.services.storage_service import StorageServiceInterface
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.models.ciphertext_object import CipherText
from licenta.models.public_key import PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlmodel import Session, select
import requests
import secrets
import base64
from typing import List, Tuple
from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from itertools import combinations

class ShamirStorageService(StorageServiceInterface):
    """
    Storage service implementing Shamir's Secret Sharing scheme
    """
    def __init__(self, session: Session ,num_shares: int = 5, threshold: int = 3):
        self.devices = [
            {"node_id": 1,"url": "http://localhost:8080/101"},
            {"node_id": 2,"url": "http://localhost:8080/102"},
            {"node_id": 3,"url": "http://localhost:8080/103"},
            {"node_id": 4,"url": "http://localhost:8080/104"},
            {"node_id": 5,"url": "http://localhost:8080/105"}
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

        obj = CipherText(cipherText=ciphertext.decode(), user_id=user_id)
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
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: user has no access to this object")

        shares = self._retrieve_shares_from_devices(obj_id)

        if len(shares) < self.threshold:
            raise ValueError(f"Not enough shares: got {len(shares)}, need {self.threshold}")

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

    
    # Helper methods
    
    def _generate_coefficients(self, secret: int )-> list[int]:
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

    
    def _send_shares_to_devices(self, shares: List[Tuple[int, int]], object_id: int):
        """
        Send one share per device (up to number of devices). The payload includes the object id.
        """
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

            print(payload)
            try:
                response = requests.post(
                    f"{device['url']}/store_share",
                    json=payload,
                    timeout=5
                )
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to store share on {device['url']}: {e}")
    
    def _retrieve_shares_from_devices(self, object_id: int) -> List[Tuple[int, int]]:
        """Simulate retrieving shares from devices by object_id."""
        retrieved_shares = []
        for device in self.devices:
            device_url = device["url"]
            try:
                response = requests.get(f"{device_url}/retrieve_share", params={'object_id': object_id})
                if response.status_code == 200:
                    share_data = response.json()
                    retrieved_shares.append((int(share_data['x']), int(share_data['y'])))
            except requests.exceptions.RequestException as e:
                print(f"Error retrieving from {device_url}: {e}")
        return retrieved_shares
    
    def _reconstruct_secret(self, shares: list[tuple[int, int]]) -> int:
        """
        Reconstruct the secret from the shares using Lagrange interpolation.
        """
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


    def _byzantine_consensus(self, shares: list[tuple[int, int]] ) -> int:
        """
        Does a Byzantine consensus on the shares to filter out any potentially corrupted shares.
        Tries all combinations of shares of size threshold. Reconstructs the secret for each combination.
        Returns the most common secret among the combinations. 
        """
        secret_count: dict[int, int] = {}
        for comb in combinations(shares, self.threshold):
            secret = self._reconstruct_secret(list(comb))
            secret_count[secret] = secret_count.get(secret, 0) + 1
            
        if secret_count:
            most_common_secret = max(secret_count, key=secret_count.get)
            return most_common_secret
        if not secret_count:
            raise ValueError("No valid secrets reconstructed from shares")
        
    def _get_key_id_for_node(self, node_id: int) -> int:
        statement = select(PublicKey.key_id).where(PublicKey.node_id == node_id)
        return self.session.exec(statement).one()
