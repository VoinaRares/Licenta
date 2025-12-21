from abc import ABC, abstractmethod
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput

class StorageServiceInterface(ABC):
    
    @abstractmethod
    def store(self, inp: StoreInput) -> StoreOutput:
        pass
    
    @abstractmethod
    def retrieve(self, inp: RetrieveInput) -> RetrieveOutput:
        pass

    