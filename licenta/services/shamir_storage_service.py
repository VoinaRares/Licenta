import base64
import logging
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlmodel import Session, select

from licenta.models.ciphertext_object import CipherText
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.services.database_service import engine
from licenta.services.node_client import NodeClient
from licenta.services.node_signing import sign_payload, verify_node_signature
from licenta.services.shamir_math import (
    PRIME_FIELD,
    byzantine_consensus,
    create_shares,
)
from licenta.services.storage_service_interface import StorageServiceInterface

logger = logging.getLogger(__name__)


class ShamirStorageService(StorageServiceInterface):

    def __init__(self, session: Session, num_shares: int = 5, threshold: int = 3):
        self.devices = [
            {"node_id": 1, "url": "http://localhost:8080/101"},
            {"node_id": 2, "url": "http://localhost:8080/102"},
            {"node_id": 3, "url": "http://localhost:8080/103"},
            {"node_id": 4, "url": "http://localhost:8080/104"},
            {"node_id": 5, "url": "http://localhost:8080/105"},
        ]
        self.num_shares = num_shares
        self.threshold = threshold
        self.session = session
        self.PRIME_FIELD = PRIME_FIELD

        self.node_client = NodeClient(
            devices=self.devices,
            threshold=threshold,
            signer=sign_payload,
            verifier=lambda payload, sig, node_id: verify_node_signature(
                payload, sig, node_id, session
            ),
        )

    async def store(self, inp: StoreInput, user_id: int) -> StoreOutput:
        master_secret = secrets.token_bytes(32)

        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        ciphertext: bytes = fernet.encrypt(inp.client_ciphertext_b64.encode())

        obj = CipherText(
            ciphertext=ciphertext,
            user_id=user_id,
            needs_verification=inp.needs_verification,
        )
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)
        assert obj.id is not None

        secret_int = int.from_bytes(master_secret, "big")
        shares = create_shares(secret_int, self.num_shares, self.threshold)

        success_count = await self.node_client.send_shares(shares, obj.id, user_id=user_id)
        if success_count < self.threshold:
            self.session.delete(obj)
            self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"Failed to distribute shares to enough nodes "
                    f"(success={success_count}, threshold={self.threshold})"
                ),
            )

        return StoreOutput(object_id=str(obj.id))

    async def retrieve(self, inp: RetrieveInput, user_id: int) -> RetrieveOutput:
        obj_id = inp.object_id  # Already int from Pydantic
        obj = self.session.get(CipherText, obj_id)

        if obj is None or obj.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Object not found",
            )

        if obj.is_rotating:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="This object is currently undergoing key rotation. Please try again shortly.",
            )

        version_before = obj.key_version

        shares = await self.node_client.retrieve_shares(
            object_id=obj_id,
            needs_verification=obj.needs_verification,
            user_id=user_id,
        )

        self.session.refresh(obj)

        if obj.is_rotating:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="This object is currently undergoing key rotation. Please try again shortly.",
            )

        if obj.key_version != version_before:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Key rotation completed during retrieval. Please retry the request.",
            )

        if len(shares) < self.threshold:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Not enough shares available to reconstruct the secret.",
            )

        try:
            secret_int = byzantine_consensus(shares, self.threshold)
            master_secret = secret_int.to_bytes(32, "big")
        except OverflowError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Share reconstruction failed: reconstructed value too large. Shares may be corrupted.",
            )

        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        plaintext = fernet.decrypt(obj.ciphertext)  # bytes directly — no .encode()
        return RetrieveOutput(client_ciphertext_b64=plaintext.decode())

    async def rotate_all_objects(self) -> dict:
        """Rotate keys for every CipherText object in the database."""
        statement = select(CipherText)
        objects = self.session.exec(statement).all()

        object_pairs: list[tuple[int, int]] = []
        for obj in objects:
            assert obj.id is not None
            object_pairs.append((obj.id, obj.user_id))

        results: dict = {"rotated": [], "failed": []}
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

    async def rotate_key_for_object(self, object_id: int, user_id: int) -> bool:
        """Rotate the encryption key for a single CipherText object.

        Uses a Postgres advisory lock to prevent concurrent rotation across
        multiple processes, plus SELECT FOR UPDATE to prevent races within a
        single process. The is_rotating flag remains visible to read paths
        during the rotation.
        """
        with engine.connect() as lock_conn:
            acquired = lock_conn.execute(
                text("SELECT pg_try_advisory_lock(:id)"), {"id": object_id}
            ).scalar()
            lock_conn.commit()

            if not acquired:
                raise ValueError(
                    f"Key rotation already in progress for object {object_id}. "
                    "Please try again shortly."
                )

            try:
                obj = self._load_rotation_target(object_id, user_id)

                obj.is_rotating = True
                self.session.add(obj)
                self.session.commit()

                try:
                    new_ciphertext, new_version = await self._perform_key_rotation(
                        obj, object_id, user_id
                    )
                    obj.ciphertext = new_ciphertext
                    obj.key_version = new_version
                    obj.is_rotating = False
                    self.session.add(obj)
                    self.session.commit()
                except Exception:
                    self._reset_rotating_flag(object_id)
                    raise

            finally:
                try:
                    lock_conn.execute(
                        text("SELECT pg_advisory_unlock(:id)"), {"id": object_id}
                    )
                    lock_conn.commit()
                except Exception:
                    logger.exception(
                        "Failed to release advisory lock for object %s", object_id
                    )

        self.session.refresh(obj)
        return True

    async def rotate_keys_for_user(self, user_id: int) -> dict:
        """Rotate the key for all CipherText objects belonging to the given user."""
        statement = select(CipherText).where(CipherText.user_id == user_id)
        objects = self.session.exec(statement).all()

        results: dict = {"rotated": [], "failed": []}
        for obj in objects:
            assert obj.id is not None
            try:
                await self.rotate_key_for_object(obj.id, user_id)
                results["rotated"].append(obj.id)
            except Exception as e:
                logger.warning("Key rotation failed for object %s: %s", obj.id, e)
                results["failed"].append({"object_id": obj.id, "error": str(e)})

        return results

    def _load_rotation_target(self, object_id: int, user_id: int) -> CipherText:
        """SELECT FOR UPDATE the target object and validate it is eligible for rotation."""
        statement = (
            select(CipherText)
            .where(CipherText.id == object_id)
            .with_for_update()
        )
        obj = self.session.exec(statement).first()
        if obj is None or obj.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Object not found",
            )
        if obj.is_rotating:
            raise ValueError(
                f"Key rotation already in progress for object {object_id}. "
                "Please try again shortly."
            )
        return obj

    async def _perform_key_rotation(
        self, obj: CipherText, object_id: int, user_id: int
    ) -> tuple[bytes, int]:
        """Retrieve shares, re-key the ciphertext, push new shares to all nodes.

        Returns (new_ciphertext, new_key_version) on success, raises on failure.
        """
        old_shares = await self.node_client.retrieve_shares(
            object_id=object_id,
            needs_verification=False,
            user_id=user_id,
        )

        if len(old_shares) < self.threshold:
            raise ValueError(
                f"Not enough shares to rotate key for object {object_id} "
                f"(got {len(old_shares)}, need {self.threshold})"
            )

        try:
            secret_int = byzantine_consensus(old_shares, self.threshold)
            master_secret = secret_int.to_bytes(32, "big")
        except OverflowError:
            raise ValueError(
                f"Share reconstruction failed for object {object_id}: "
                "reconstructed value too large."
            )

        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        plaintext_b64 = fernet.decrypt(obj.ciphertext).decode()

        new_master_secret = secrets.token_bytes(32)
        new_ciphertext = self._encrypt_plaintext(plaintext_b64, new_master_secret)

        new_secret_int = int.from_bytes(new_master_secret, "big")
        new_shares = create_shares(new_secret_int, self.num_shares, self.threshold)

        success_count = await self.node_client.send_shares(
            new_shares, object_id, user_id=user_id
        )

        if success_count < self.num_shares:
            restore_count = await self.node_client.restore_shares(
                old_shares, object_id, user_id=user_id
            )
            logger.error(
                "Key rotation aborted for object %s: %d/%d nodes accepted new shares. "
                "Restored %d/%d old shares.",
                object_id,
                success_count,
                self.num_shares,
                restore_count,
                len(old_shares),
            )
            raise ValueError(
                f"Key rotation aborted for object {object_id}: only "
                f"{success_count}/{self.num_shares} nodes accepted the new shares."
            )

        return new_ciphertext, (obj.key_version or 1) + 1

    def _reset_rotating_flag(self, object_id: int) -> None:
        """Roll back the session and clear is_rotating on the stored object."""
        self.session.rollback()
        fresh = self.session.get(CipherText, object_id)
        if fresh is not None:
            fresh.is_rotating = False
            self.session.add(fresh)
            self.session.commit()
            
    def _derive_fernet_key(self, master_secret: bytes) -> bytes:
        fernet_key_raw = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fernet key",
        ).derive(master_secret)
        return base64.urlsafe_b64encode(fernet_key_raw)

    def _encrypt_plaintext(self, plaintext_b64: str, master_secret: bytes) -> bytes:
        fernet_key = self._derive_fernet_key(master_secret)
        fernet = Fernet(fernet_key)
        return fernet.encrypt(plaintext_b64.encode())
