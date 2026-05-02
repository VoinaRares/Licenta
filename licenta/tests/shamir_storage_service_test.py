from licenta.services.shamir_math import create_shares, reconstruct_secret


def test_create_shares():
    secret = 123456789
    shares = create_shares(secret, num_shares=5, threshold=3)
    assert len(shares) == 5
    x_values = set(x for x, y in shares)
    assert len(x_values) == 5
    print("Shares created:", shares)

def test_reconstruct_secret():
    secret = 987654321
    shares = create_shares(secret, num_shares=5, threshold=3)
    selected_shares = shares[:3]
    reconstructed_secret = reconstruct_secret(selected_shares)
    assert reconstructed_secret == secret
    print ("Reconstructed secret:", reconstructed_secret)


def test_reconstruct_secret_insufficient_shares():
    secret = 555555555
    shares = create_shares(secret, num_shares=5, threshold=3)
    selected_shares = shares[:2]
    reconstructed_secret = reconstruct_secret(selected_shares)
    assert reconstructed_secret != secret
    print ("Reconstructed secret with insufficient shares:", reconstructed_secret)

test_create_shares()
test_reconstruct_secret()
test_reconstruct_secret_insufficient_shares()
print("All tests passed.")
