from fastapi import APIRouter, Depends
from licenta.api.auth import get_current_user
from licenta.models.user import User
from licenta.models.handshake_output import HandshakeOutput
from licenta.models.handshake_input import HandshakeInput
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput
from licenta.services import encryption_service
from licenta.services.storage_service_interface import StorageServiceInterface
from licenta.services.storage_service_factory import get_storage_service

router = APIRouter(
    dependencies=[Depends(get_current_user)]
)


@router.post("/handshake", response_model=HandshakeOutput)
def handshake(inp: HandshakeInput):
    return encryption_service.handshake(inp)

@router.post("/store", response_model=StoreOutput)
async def store(inp: StoreInput, storage_service: StorageServiceInterface = Depends(get_storage_service), current_user: User = Depends(get_current_user)):
    return await encryption_service.store(inp, storage_service, current_user.id)

@router.get("/retrieve/{object_id}", response_model=RetrieveOutput)
async def retrieve(object_id: str, session_id: str, storage_service: StorageServiceInterface = Depends(get_storage_service), current_user: User = Depends(get_current_user)):
    inp = RetrieveInput(session_id=session_id, object_id=object_id)
    return await encryption_service.retrieve(inp, storage_service, current_user.id)


@router.post("/rotate")
async def rotate_keys(storage_service: StorageServiceInterface = Depends(get_storage_service), current_user: User = Depends(get_current_user)):
    return await storage_service.rotate_keys_for_user(current_user.id)
