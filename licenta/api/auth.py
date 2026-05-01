import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlmodel import Session, select

from licenta.models.create_user_output import CreateUserOutput
from licenta.models.user import User
from licenta.services.database_service import get_session

router = APIRouter()
_ph = PasswordHasher()


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

        request.state.user_id = user.id
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )
