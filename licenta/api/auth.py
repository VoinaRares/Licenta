from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlmodel import Session, select
from licenta.services.database_service import get_session
from licenta.models.create_user_output import CreateUserOutput
from licenta.models.user import User
import secrets, hashlib

router = APIRouter()

@router.post("/user")
def create_user(session: Session = Depends(get_session)):
    raw_api_key = secrets.token_urlsafe(32)
    api_key_hash = _hash_api_key(raw_api_key)
    
    user = User(api_key_hash=api_key_hash)
    session.add(user)
    session.commit()
    session.refresh(user)
    
    return CreateUserOutput(api_key=raw_api_key, user_id=user.id)


def get_current_user(api_key: str = Header(..., alias="X-API-Key"), session: Session = Depends(get_session))-> User:
    api_key_hash = _hash_api_key(api_key=api_key)
    statement = select(User).where(User.api_key_hash == api_key_hash)
    session_user = session.exec(statement).first()
    if session_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return session_user

def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()\

