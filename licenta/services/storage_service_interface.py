from abc import ABC, abstractmethod
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput

class StorageServiceInterface(ABC):

    @abstractmethod
    async def store(self, inp: StoreInput, user_id: int) -> StoreOutput:
        pass

    @abstractmethod
    async def retrieve(self, inp: RetrieveInput, user_id: int) -> RetrieveOutput:
        pass

    @abstractmethod
    async def rotate_keys_for_user(self, user_id: int) -> dict:
        pass
