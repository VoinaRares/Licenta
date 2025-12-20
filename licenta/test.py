from sslib import shamir, randomness
import base64 as b64


k_threshold = 3
n = 5
secret = "This is a secret"


shares = shamir.split_secret(secret.encode('ascii'), required_shares=k_threshold, distributed_shares=n, randomness_source=randomness.UrandomReader())

print(shares)
print(f"Required share number: {shares["required_shares"]}")
for i in range(n):
    print(f"Share {shares['shares'][i][0]}: {shares['shares'][i][1].hex()}")
print(f"Prime modulus: {int(shares["prime_mod"].hex(), 16)}")

shares_dict = {}
shares_b64 = {}
    
for i in range(n):
    share = shares['shares'][i]
    shares_dict[share[0]] = share  # Store raw shares for reconstruction
    shares_b64[str(share[0])] = b64.b64encode(share[1]).decode('ascii')
    
    

    
