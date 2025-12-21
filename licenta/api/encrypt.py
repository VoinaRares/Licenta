from fastapi import APIRouter
from licenta.models.handshake_output import HandshakeOutput
from licenta.models.handshake_input import HandshakeInput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.services import encryption_service
from licenta.services.storage_service import StorageServiceInterface
from licenta.services.shamir_storage_service import ShamirStorageService
router = APIRouter()

storage_service: StorageServiceInterface = ShamirStorageService()

@router.post("/handshake", response_model=HandshakeOutput)
def handshake(inp: HandshakeInput):
    return encryption_service.handshake(inp)

@router.post("/store", response_model=StoreOutput)
def store(inp: StoreInput):
    return encryption_service.store(inp, storage_service)

@router.get("/retrieve/{object_id}", response_model=RetrieveOutput)
def retrieve(object_id: str, session_id: str):
    inp = RetrieveInput(session_id=session_id, object_id=object_id)
    return encryption_service.retrieve(inp)