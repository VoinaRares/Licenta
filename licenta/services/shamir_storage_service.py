import asyncio
import base64
import json
import logging
import secrets
import time
from collections import Counter
from itertools import combinations
from typing import Optional

import httpx
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlmodel import Session, select

from licenta.models.ciphertext_object import CipherText
from licenta.models.public_key import PublicKey
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.services import http_client
from licenta.services.database_service import engine
from licenta.services.log_service import write_node_log
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
        self.PRIME_FIELD = 2**521 - 1

    # -------------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------------

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
        shares = self._create_shares(secret=secret_int)

        success_count = await self._send_shares_to_devices(shares, obj.id, user_id=user_id)
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

        shares = await self._retrieve_shares_from_devices(
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
            secret_int = self._byzantine_consensus(shares)
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

                obj.is_rotating = True
                self.session.add(obj)
                self.session.commit()

                try:
                    old_shares = await self._retrieve_shares_from_devices(
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
                        secret_int = self._byzantine_consensus(old_shares)
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
                    new_shares = self._create_shares(secret=new_secret_int)

                    success_count = await self._send_shares_to_devices(
                        new_shares, object_id, user_id=user_id
                    )

                    if success_count < self.num_shares:
                        restore_count = await self._restore_old_shares(
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

                    obj.ciphertext = new_ciphertext
                    obj.key_version = (obj.key_version or 1) + 1
                    obj.is_rotating = False
                    self.session.add(obj)
                    self.session.commit()

                except Exception:
                    self.session.rollback()
                    fresh = self.session.get(CipherText, object_id)
                    if fresh is not None:
                        fresh.is_rotating = False
                        self.session.add(fresh)
                        self.session.commit()
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

    # -------------------------------------------------------------------------
    # Node communication
    # -------------------------------------------------------------------------

    async def _send_shares_to_devices(
        self,
        shares: list[tuple[int, int]],
        object_id: int,
        user_id: Optional[int] = None,
    ) -> int:
        """Fan out share storage to all nodes concurrently via asyncio.gather."""
        client = http_client.get()

        async def send_one(index: int, device: dict) -> bool:
            x, y = shares[index]
            node_id = device["node_id"]
            payload = {
                "node_id": node_id,
                "object_id": object_id,
                "share_id": index,
                "x": x,
                "y": str(y),
            }
            signature = self._sign_payload(payload)
            start = time.monotonic()
            status_code = 0
            error_details = None
            success = False
            try:
                response = await client.post(
                    f"{device['url']}/store_share",
                    json={"payload": payload, "signature": signature},
                    timeout=5.0,
                )
                status_code = response.status_code
                response.raise_for_status()
                success = True
                logger.debug("Stored share on node %s: %s", node_id, payload)
            except httpx.HTTPStatusError as e:
                error_details = str(e)
                logger.warning("Failed storing share on %s: %s", device["url"], e)
            except httpx.HTTPError as e:
                error_details = str(e)
                logger.warning("Failed storing share on %s: %s", device["url"], e)

            duration_ms = round((time.monotonic() - start) * 1000, 2)
            try:
                with Session(engine) as log_session:
                    write_node_log(
                        session=log_session,
                        node_id=node_id,
                        action="store_share",
                        method="POST",
                        status_code=status_code,
                        user_id=user_id,
                        duration_ms=duration_ms,
                        error_details=error_details,
                    )
            except Exception:
                logger.exception("Failed to write node request log for node %s", node_id)

            return success

        results = await asyncio.gather(
            *[send_one(i, d) for i, d in enumerate(self.devices) if i < len(shares)],
            return_exceptions=True,
        )
        return sum(1 for r in results if r is True)

    async def _restore_old_shares(
        self,
        old_shares: list[tuple[int, int]],
        object_id: int,
        user_id: Optional[int] = None,
    ) -> int:
        """Re-send old shares back to nodes after a failed rotation, concurrently."""
        old_shares_by_x = {x: y for x, y in old_shares}
        client = http_client.get()

        async def restore_one(device_index: int, device: dict) -> bool:
            x = device_index + 1
            if x not in old_shares_by_x:
                return False
            y = old_shares_by_x[x]
            node_id = device["node_id"]
            payload = {
                "node_id": node_id,
                "object_id": object_id,
                "share_id": device_index,
                "x": x,
                "y": str(y),
            }
            signature = self._sign_payload(payload)
            start = time.monotonic()
            status_code = 0
            error_details = None
            success = False
            try:
                response = await client.post(
                    f"{device['url']}/store_share",
                    json={"payload": payload, "signature": signature},
                    timeout=5.0,
                )
                status_code = response.status_code
                response.raise_for_status()
                success = True
                logger.debug(
                    "Restored old share to node %s for object %s", node_id, object_id
                )
            except httpx.HTTPStatusError as e:
                error_details = str(e)
                logger.warning("Failed restoring old share to %s: %s", device["url"], e)
            except httpx.HTTPError as e:
                error_details = str(e)
                logger.warning("Failed restoring old share to %s: %s", device["url"], e)

            duration_ms = round((time.monotonic() - start) * 1000, 2)
            try:
                with Session(engine) as log_session:
                    write_node_log(
                        session=log_session,
                        node_id=node_id,
                        action="restore_share",
                        method="POST",
                        status_code=status_code,
                        user_id=user_id,
                        duration_ms=duration_ms,
                        error_details=error_details,
                    )
            except Exception:
                logger.exception("Failed to write node request log for node %s", node_id)

            return success

        results = await asyncio.gather(
            *[restore_one(i, d) for i, d in enumerate(self.devices)],
            return_exceptions=True,
        )
        return sum(1 for r in results if r is True)

    async def _retrieve_shares_from_devices(
        self,
        object_id: int,
        needs_verification: bool,
        user_id: Optional[int] = None,
    ) -> list[tuple[int, int]]:
        """Fan out share retrieval; cancel stragglers once threshold shares arrive."""
        client = http_client.get()

        async def fetch_one(device: dict) -> tuple[int, int] | None:
            device_url = device["url"]
            node_id = device["node_id"]
            start = time.monotonic()
            status_code = 0
            error_details = None
            result: tuple[int, int] | None = None

            try:
                response = await client.get(
                    f"{device_url}/retrieve_share",
                    params={
                        "object_id": object_id,
                        "needs_verification": needs_verification,
                    },
                    timeout=5.0,
                )
                status_code = response.status_code
                if response.status_code == 200:
                    signed_data = response.json()
                    payload = signed_data.get("payload")
                    signature = signed_data.get("signature")
                    if payload and signature:
                        if self._verify_node_signature(payload, signature, node_id):
                            x = payload.get("x")
                            y = payload.get("y")
                            if x is None or y is None:
                                logger.warning(
                                    "Missing x or y in payload from node %s", node_id
                                )
                            else:
                                result = (int(x), int(y))
                        else:
                            logger.warning(
                                "Signature verification failed for node %s", node_id
                            )
                    else:
                        logger.warning(
                            "Missing payload or signature from node %s", node_id
                        )
            except httpx.HTTPError as e:
                error_details = str(e)
                logger.warning("Failed retrieving share from %s: %s", device_url, e)
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.warning("Malformed response from node %s: %s", node_id, e)

            duration_ms = round((time.monotonic() - start) * 1000, 2)
            try:
                with Session(engine) as log_session:
                    write_node_log(
                        session=log_session,
                        node_id=node_id,
                        action="retrieve_share",
                        method="GET",
                        status_code=status_code,
                        user_id=user_id,
                        duration_ms=duration_ms,
                        error_details=error_details,
                    )
            except Exception:
                logger.exception("Failed to write node request log for node %s", node_id)

            return result

        tasks = {asyncio.ensure_future(fetch_one(d)): d for d in self.devices}
        retrieved_shares: list[tuple[int, int]] = []
        pending = set(tasks.keys())

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    share = task.result()
                    if share is not None:
                        retrieved_shares.append(share)
                except Exception as e:
                    logger.warning("Share fetch task raised: %s", e)

            if len(retrieved_shares) >= self.threshold:
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                break

        return retrieved_shares

    # -------------------------------------------------------------------------
    # Cryptography helpers
    # -------------------------------------------------------------------------

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

    def _verify_node_signature(
        self, payload: dict, signature_b64: str, node_id: int
    ) -> bool:
        try:
            statement = select(PublicKey).where(PublicKey.node_id == node_id)
            public_key_obj = self.session.exec(statement).first()

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

    def _canonicalize_payload(self, payload: dict) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def _sign_payload(self, payload: dict) -> str:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            self._canonicalize_payload(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    def _generate_coefficients(self, secret: int) -> list[int]:
        return [secret] + [
            secrets.randbelow(self.PRIME_FIELD) for _ in range(self.threshold - 1)
        ]

    def _create_shares(self, secret: int) -> list[tuple[int, int]]:
        coeffs = self._generate_coefficients(secret)
        shares = []
        for x in range(1, self.num_shares + 1):
            y = (
                sum(
                    coeff * pow(x, power, self.PRIME_FIELD)
                    for power, coeff in enumerate(coeffs)
                )
                % self.PRIME_FIELD
            )
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
        secret_count = Counter(
            self._reconstruct_secret(list(comb))
            for comb in combinations(shares, self.threshold)
        )
        if not secret_count:
            raise ValueError("No valid secrets reconstructed")
        return secret_count.most_common(1)[0][0]
