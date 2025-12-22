from licenta.services.shamir_storage_service import ShamirStorageService


def test_create_shares():
    service = ShamirStorageService(session=None, num_shares=5, threshold=3)
    secret = 123456789
    shares = service._create_shares(secret)
    assert len(shares) == 5
    x_values = set(x for x, y in shares)
    assert len(x_values) == 5
    print("Shares created:", shares)
    
def test_reconstruct_secret():
    service = ShamirStorageService(session=None, num_shares=5, threshold=3)
    secret = 987654321
    shares = service._create_shares(secret)
    selected_shares = shares[:3]
    reconstructed_secret = service._reconstruct_secret(selected_shares)
    assert reconstructed_secret == secret
    print ("Reconstructed secret:", reconstructed_secret)
    
    
def test_reconstruct_secret_insufficient_shares():
    service = ShamirStorageService(session=None, num_shares=5, threshold=3)
    secret = 555555555
    shares = service._create_shares(secret)
    selected_shares = shares[:2]
    reconstructed_secret = service._reconstruct_secret(selected_shares)
    assert reconstructed_secret != secret
    print ("Reconstructed secret with insufficient shares:", reconstructed_secret)
    
    
test_create_shares()
test_reconstruct_secret()
test_reconstruct_secret_insufficient_shares()
print("All tests passed.")