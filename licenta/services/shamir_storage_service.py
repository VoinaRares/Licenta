from licenta.services.storage_service import StorageServiceInterface
from licenta.models.store_input import StoreInput
from licenta.models.store_output import StoreOutput
from licenta.models.retrieve_input import RetrieveInput
from licenta.models.retrieve_output import RetrieveOutput

class ShamirStorageService(StorageServiceInterface):
    """
    Storage service implementing Shamir's Secret Sharing scheme
    """
    devices = [] #List for devices
    
    
    def __init__(self):
        pass
    
    def store(self, inp: StoreInput) -> StoreOutput:
        """
        Stores data using Shamir's Secret Sharing scheme
        """
        pass
    
    def retrieve(self, inp: RetrieveInput) -> RetrieveOutput:
        """
        Retrieves and reconstructs data using Shamir's Secret Sharing scheme
        """
        pass
    
    # Helper mehotds
    
    def __test(self):
        pass