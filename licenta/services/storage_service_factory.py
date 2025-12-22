from fastapi import Depends
from sqlmodel import Session
from licenta.main import get_session
from licenta.services.storage_service import StorageServiceInterface
from licenta.services.shamir_storage_service import ShamirStorageService

def get_storage_service(
    session: Session = Depends(get_session),
) -> StorageServiceInterface:
    #Needs additional parameters for additional services if implemented
    return ShamirStorageService(session)
