from fastapi import APIRouter
from licenta.models import HandshakeInput, HandshakeOutput, StoreInput, StoreOutput, RetrieveInput, RetrieveOutput
from licenta.services import encryption_service
router = APIRouter()



@router.post("/handshake", response_model=HandshakeOutput)
def handshake(inp: HandshakeInput):
    return encryption_service.handshake(inp)

@router.post("/store", response_model=StoreOutput)
def store(inp: StoreInput):
    return encryption_service.store(inp)

@router.get("/retrieve/{object_id}", response_model=RetrieveOutput)
def retrieve(object_id: str, session_id: str):
    inp = RetrieveInput(session_id=session_id, object_id=object_id)
    return encryption_service.retrieve(inp)