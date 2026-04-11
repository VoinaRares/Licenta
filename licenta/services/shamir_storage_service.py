from licenta.services.storage_service_interface import StorageServiceInterface
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

import httpx
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

    async def store(self, inp: StoreInput, user_id: int) -> StoreOutput:
        master_secret = secrets.token_bytes(32)

        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(inp.client_ciphertext_b64.encode())

        obj = CipherText(cipherText=ciphertext.decode(), user_id=user_id, needs_verification=inp.needs_verification)
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)

        secret_int = int.from_bytes(master_secret, "big")
        shares = self._create_shares(secret=secret_int)

        success_count = await self._send_shares_to_devices(shares, obj.id)
        if success_count < self.threshold:
            self.session.delete(obj)
            self.session.commit()
            raise ValueError(f"Failed to distribute shares to enough nodes (success={success_count}, threshold={self.threshold})")

        return StoreOutput(object_id=str(obj.id))

    async def rotate_all_objects(self) -> dict:
        """Rotate keys for every CipherText object in the database."""
        statement = select(CipherText)
        objects = self.session.exec(statement).all()

        # Extract the needed fields while all objects are still loaded in the
        # session. After the first rotate_key_for_object commit, SQLAlchemy
        # expires every object in the identity map, and accessing obj.user_id
        # on a subsequent iteration would trigger a lazy reload per object.
        object_pairs = [(obj.id, obj.user_id) for obj in objects]

        results = {"rotated": [], "failed": []}
        for obj_id, user_id in object_pairs:
            try:
                await self.rotate_key_for_object(obj_id, user_id)
                results["rotated"].append(obj_id)
            except Exception as e:
                logger.warning("Key rotation failed for object %s: %s", obj_id, e)
                results["failed"].append({"object_id": obj_id, "error": str(e)})

        if results["failed"]:
            logger.error(
                "Key rotation run completed with %d failure(s): %s",
                len(results["failed"]),
                results["failed"],
            )

        return results

    async def retrieve(self, inp: RetrieveInput, user_id: int) -> RetrieveOutput:
        try:
            obj_id = int(inp.object_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid object_id '{inp.object_id}': must be a numeric integer."
            )
        obj = self.session.get(CipherText, obj_id)

        if obj is None:
            raise ValueError("Object not found")

        if obj.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden"
            )

        if obj.is_rotating:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="This object is currently undergoing key rotation. Please try again shortly."
            )

        # Save the key version before the async node requests. If a rotation
        # completes while we are waiting for node responses, the version will
        # change and we will detect the inconsistency below.
        version_before = obj.key_version

        shares = await self._retrieve_shares_from_devices(object_id=obj_id, needs_verification=obj.needs_verification)

        # Re-read the object from the database so that cipherText and key_version
        # reflect any rotation that may have committed during the await above.
        self.session.refresh(obj)

        if obj.is_rotating:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="This object is currently undergoing key rotation. Please try again shortly."
            )

        if obj.key_version != version_before:
            # A rotation completed while node responses were in flight. The shares
            # collected may be a mix of old and new, making decryption unreliable.
            # The client should retry; the next attempt will see a consistent state.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Key rotation completed during retrieval. Please retry the request."
            )

        if len(shares) < self.threshold:
            raise ValueError("Not enough shares")

        secret_int = self._byzantine_consensus(shares)
        master_secret = secret_int.to_bytes(32, "big")

        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)

        plaintext = fernet.decrypt(obj.cipherText.encode())

        return RetrieveOutput(client_ciphertext_b64=plaintext.decode())

    def _derive_fernet_key(self, master_secret: bytes) -> bytes:
        fernet_key_raw = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)

        return base64.urlsafe_b64encode(fernet_key_raw)

    def _encrypt_plaintext(self, plaintext_b64: str, master_secret: bytes) -> str:
        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        return fernet.encrypt(plaintext_b64.encode()).decode()

    async def rotate_key_for_object(self, object_id: int, user_id: int) -> bool:
        """Rotate the encryption key for a single CipherText object.

        Uses SELECT FOR UPDATE to atomically acquire the is_rotating lock,
        preventing TOCTOU races between concurrent rotation attempts.
        Caches old shares before distribution; if new share distribution fails,
        restores old shares to nodes before clearing the lock.
        Bypasses needs_verification when retrieving shares internally (system operation).
        """
        # SELECT FOR UPDATE acquires a row-level lock before the check-and-set.
        # Any concurrent caller that reaches this point will block until we commit,
        # then read is_rotating=True and raise immediately — eliminating the TOCTOU
        # window that existed with a plain session.get() + separate UPDATE.
        statement = select(CipherText).where(CipherText.id == object_id).with_for_update()
        obj = self.session.exec(statement).first()

        if obj is None:
            raise ValueError("Object not found")

        if obj.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden"
            )

        if obj.is_rotating:
            raise ValueError(f"Key rotation already in progress for object {object_id}. Please try again shortly.")

        obj.is_rotating = True
        self.session.add(obj)
        self.session.commit()
        # Row lock released on commit; is_rotating=True is now visible to all readers.

        try:
            # Retrieve shares bypassing needs_verification: this is an internal
            # system operation authorised by the server's own RSA signature, not
            # a user-initiated access, so the user-level unlock layer does not apply.
            old_shares = await self._retrieve_shares_from_devices(object_id=object_id, needs_verification=False)

            if len(old_shares) < self.threshold:
                raise ValueError(
                    f"Not enough shares to rotate key for object {object_id} "
                    f"(got {len(old_shares)}, need {self.threshold})"
                )

            secret_int = self._byzantine_consensus(old_shares)
            master_secret = secret_int.to_bytes(32, "big")

            fernet_key = self._derive_fernet_key(master_secret)
            fernet = Fernet(fernet_key)
            # Accessing obj.cipherText after the earlier commit causes SQLAlchemy
            # to lazily refresh the object from the database, which is correct.
            plaintext_b64 = fernet.decrypt(obj.cipherText.encode()).decode()

            new_master_secret = secrets.token_bytes(32)
            new_ciphertext = self._encrypt_plaintext(plaintext_b64, new_master_secret)

            new_secret_int = int.from_bytes(new_master_secret, "big")
            new_shares = self._create_shares(secret=new_secret_int)

            # Require ALL nodes to accept new shares to prevent stale shares
            # from corrupting future Byzantine consensus votes.
            success_count = await self._send_shares_to_devices(new_shares, object_id)

            if success_count < self.num_shares:
                # Some nodes were overwritten with new shares before the failure.
                # Restore the cached old shares so that the node state stays
                # consistent with the old ciphertext that remains in the database.
                restore_count = await self._restore_old_shares(old_shares, object_id)
                logger.error(
                    "Key rotation aborted for object %s: %d/%d nodes accepted new shares. "
                    "Restored %d/%d old shares.",
                    object_id, success_count, self.num_shares,
                    restore_count, len(old_shares),
                )
                raise ValueError(
                    f"Key rotation aborted for object {object_id}: only {success_count}/{self.num_shares} "
                    f"nodes accepted the new shares. No database changes committed."
                )

            obj.cipherText = new_ciphertext
            obj.key_version = (obj.key_version or 1) + 1
            obj.is_rotating = False
            self.session.add(obj)
            self.session.commit()

        except Exception:
            # Rollback any dirty session state, then clear the rotation lock.
            self.session.rollback()
            obj = self.session.get(CipherText, object_id)
            if obj is not None:
                obj.is_rotating = False
                self.session.add(obj)
                self.session.commit()
            raise

        # Refresh is intentionally outside the try block: a failure here means
        # the rotation already committed successfully, so it must not be reported
        # as a rotation failure by the exception handler above.
        self.session.refresh(obj)
        return True

    async def rotate_keys_for_user(self, user_id: int) -> dict:
        """Rotate the key for all CipherText objects belonging to the given user."""
        statement = select(CipherText).where(CipherText.user_id == user_id)
        objects = self.session.exec(statement).all()

        results = {"rotated": [], "failed": []}
        for obj in objects:
            try:
                await self.rotate_key_for_object(obj.id, user_id)
                results["rotated"].append(obj.id)
            except Exception as e:
                logger.warning("Key rotation failed for object %s: %s", obj.id, e)
                results["failed"].append({"object_id": obj.id, "error": str(e)})

        return results

    async def _send_shares_to_devices(self, shares: List[Tuple[int, int]], object_id: int) -> int:
        """Send each share to its corresponding device.

        Returns the number of devices that successfully stored the share.
        shares[i] is sent to devices[i]; x values are assumed to be 1-indexed
        and match the device order produced by _create_shares.
        """
        success_count = 0

        async with httpx.AsyncClient() as client:
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
                    response = await client.post(
                        f"{device['url']}/store_share",
                        json=signed_payload,
                        timeout=5.0
                    )
                    response.raise_for_status()

                    success_count += 1
                    logger.debug("Stored share on node %s: %s", node_id, payload)

                except httpx.HTTPError as e:
                    logger.warning("Failed storing share on %s: %s", device["url"], e)

        return success_count

    async def _restore_old_shares(self, old_shares: List[Tuple[int, int]], object_id: int) -> int:
        """Re-send old shares back to their original nodes after a failed rotation.

        Maps each share to its node by x value (x=1 → devices[0], x=2 → devices[1], …),
        correctly handling gaps where a node was unreachable during the original retrieval.
        Returns the number of nodes that accepted the restored share.
        """
        old_shares_by_x = {x: y for x, y in old_shares}
        success_count = 0

        async with httpx.AsyncClient() as client:
            for device_index, device in enumerate(self.devices):
                x = device_index + 1  # x values are 1-indexed, matching _create_shares output
                if x not in old_shares_by_x:
                    # This node was unreachable during the original retrieval;
                    # it still holds its original share, so nothing to restore.
                    continue

                y = old_shares_by_x[x]
                node_id = device["node_id"]

                payload = {
                    "node_id": node_id,
                    "object_id": object_id,
                    "share_id": device_index,
                    "x": x,
                    "y": str(y)
                }

                signature = self._sign_payload(payload)

                try:
                    response = await client.post(
                        f"{device['url']}/store_share",
                        json={"payload": payload, "signature": signature},
                        timeout=5.0
                    )
                    response.raise_for_status()
                    success_count += 1
                    logger.debug("Restored old share to node %s for object %s", node_id, object_id)

                except httpx.HTTPError as e:
                    logger.warning("Failed restoring old share to %s: %s", device["url"], e)

        return success_count

    def _verify_node_signature(self, payload: dict, signature_b64: str, node_id: int) -> bool:
        try:
            statement = select(PublicKey).where(PublicKey.node_id == node_id)
            public_key_obj = self.session.exec(statement).first()

            if not public_key_obj:
                logger.warning("No public key found in database for node %s", node_id)
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
            logger.error("Signature verification failed for node %s: %s", node_id, e)
            return False

    async def _retrieve_shares_from_devices(self, object_id: int, needs_verification: bool) -> List[Tuple[int, int]]:
        retrieved_shares = []

        async with httpx.AsyncClient() as client:
            for device in self.devices:
                device_url = device["url"]
                node_id = device["node_id"]

                # Separate the HTTP transport error from response-parsing errors so
                # that a misbehaving node returning malformed data does not silently
                # abort the entire loop via an unhandled exception.
                try:
                    response = await client.get(
                        f"{device_url}/retrieve_share",
                        params={"object_id": object_id, "needs_verification": needs_verification},
                        timeout=5.0
                    )
                except httpx.HTTPError as e:
                    logger.warning("Failed retrieving share from %s: %s", device_url, e)
                    continue

                if response.status_code != 200:
                    continue

                try:
                    signed_data = response.json()
                    payload = signed_data.get("payload")
                    signature = signed_data.get("signature")

                    if not payload or not signature:
                        continue

                    if not self._verify_node_signature(payload, signature, node_id):
                        logger.warning("Node signature verification failed for node %s", node_id)
                        continue

                    retrieved_shares.append(
                        (int(payload['x']), int(payload['y']))
                    )

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning("Malformed response from node %s: %s", node_id, e)

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
