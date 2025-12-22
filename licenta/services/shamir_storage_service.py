from licenta.services.storage_service import StorageServiceInterface
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.models.ciphertext_object import CipherTextObject
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlmodel import Session
import random
import requests
import secrets
from typing import List, Tuple
from cryptography.fernet import Fernet

class ShamirStorageService(StorageServiceInterface):
    """
    Storage service implementing Shamir's Secret Sharing scheme
    """
    def __init__(self, session: Session ,num_shares: int = 5, threshold: int = 3):
        self.devices = ["http://device1link", "http://device2link"]
        self.num_shares = num_shares
        self.threshold = threshold
        self.session = session
        self.PRIME_FIELD = 2**521 - 1
    
    def store(self, inp: StoreInput) -> StoreOutput:
        # 1. Generate master secret
        master_secret = secrets.token_bytes(32)

        # 2. Derive Fernet key
        fernet_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)

        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(inp.client_ciphertext_b64.encode())

        # 3. Store ciphertext in DB
        obj = CipherTextObject(cipherText=ciphertext.decode())
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)

        # 4. Split master secret
        secret_int = int.from_bytes(master_secret, "big")
        shares = self.__create_shares(secret=secret_int)

        # 5. Send shares to devices
        self.__send_shares_to_devices(shares, obj.id)

        return StoreOutput(object_id=str(obj.id))
            
        
        
    def retrieve(self, inp: RetrieveInput) -> RetrieveOutput:
        shares = self._retrieve_shares_from_devices(inp)

        if len(shares) < self.threshold:
            return RetrieveOutput(error="Not enough shares")

        secret_int = self._reconstruct_secret(shares)
        master_secret = secret_int.to_bytes(32, "big")

        fernet_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)

        return RetrieveOutput(encryption_key=fernet_key)

    
    # Helper methods
    
    def _generate_coefficients(self, secret: int )-> list[int]:
        return [secret] + [secrets.randbelow(self.PRIME_FIELD) for _ in range(self.threshold - 1)]
    
    
    def _create_shares(self, secret: int):
        coeffs = self._generate_coefficients(secret)
        shares = []

        for x in range(1, self.num_shares + 1):
            y = sum(
                coeff * pow(x, power, self.PRIME_FIELD)
                for power, coeff in enumerate(coeffs)
            ) % self.PRIME_FIELD
            shares.append((x, y))

        return shares

    
    def _send_shares_to_devices(self, encryption_key: bytes):
        secret = int.from_bytes(encryption_key, byteorder='big')
        shares = self._create_shares(secret)

        for index, device_url in enumerate(self.devices):
            x, y = shares[index]

            payload = {
                "share_id": index,
                "x": x,
                "y": str(y)
            }

            try:
                response = requests.post(
                    f"{device_url}/store_share",
                    json=payload,
                    timeout=5
                )
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to store share on {device_url}: {e}")
    
    def _retrieve_shares_from_devices(self, inp: RetrieveInput) -> List[Tuple[int, int]]:
        """Simulate retrieving shares from devices."""
        retrieved_shares = []
        for device_url in self.devices:
            try:
                # Simulate retrieving shares by making HTTP requests
                response = requests.get(device_url, params={'share_id': inp.share_id})
                if response.status_code == 200:
                    share_data = response.json()
                    retrieved_shares.append((share_data['share_id'], share_data['share_value']))
            except requests.exceptions.RequestException as e:
                print(f"Error retrieving from {device_url}: {e}")
        return retrieved_shares
    
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
