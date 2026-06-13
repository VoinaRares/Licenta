import secrets
from threading import Lock

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cachetools import TTLCache
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlmodel import Session, select

from licenta.models.create_user_output import CreateUserOutput
from licenta.models.user import User
from licenta.services.database_service import get_session

router = APIRouter()
_ph = PasswordHasher()

# Verified users cached for 5 minutes to avoid Argon2 on every request.
_user_cache: TTLCache = TTLCache(maxsize=1024, ttl=300)
_cache_lock = Lock()


@router.post("/user")
def create_user(session: Session = Depends(get_session)):
    raw_api_key = secrets.token_urlsafe(32)
    key_prefix = raw_api_key[:8]
    api_key_hash = _ph.hash(raw_api_key)

    user = User(api_key_hash=api_key_hash, key_prefix=key_prefix)
    session.add(user)
    session.commit()
    session.refresh(user)

    return CreateUserOutput(api_key=raw_api_key, user_id=user.id)


def get_current_user(
    request: Request,
    api_key: str = Header(..., alias="X-API-Key"),
    session: Session = Depends(get_session),
) -> User:
    with _cache_lock:
        cached = _user_cache.get(api_key)
    if cached is not None:
        request.state.user_id = cached.id
        return cached

    key_prefix = api_key[:8]
    statement = select(User).where(User.key_prefix == key_prefix)
    candidates = session.exec(statement).all()

    for user in candidates:
        try:
            _ph.verify(user.api_key_hash, api_key)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            continue

        if _ph.check_needs_rehash(user.api_key_hash):
            user.api_key_hash = _ph.hash(api_key)
            session.add(user)
            session.commit()

        with _cache_lock:
            _user_cache[api_key] = user

        request.state.user_id = user.id
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )
