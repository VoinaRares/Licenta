from fastapi import Depends
from sqlmodel import Session
from licenta.services.storage_service_interface import StorageServiceInterface
from licenta.services.shamir_storage_service import ShamirStorageService
from licenta.services.database_service import get_session

def get_storage_service(
    session: Session = Depends(get_session),
) -> StorageServiceInterface:
    return ShamirStorageService(session)
