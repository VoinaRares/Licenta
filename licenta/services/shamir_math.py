import secrets
from collections import Counter
from itertools import combinations

PRIME_FIELD = 2**521 - 1


def generate_coefficients(secret: int, threshold: int, prime: int = PRIME_FIELD) -> list[int]:
    return [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]


def create_shares(
    secret: int,
    num_shares: int,
    threshold: int,
    prime: int = PRIME_FIELD,
) -> list[tuple[int, int]]:
    coeffs = generate_coefficients(secret, threshold, prime)
    shares = []
    for x in range(1, num_shares + 1):
        y = (
            sum(
                coeff * pow(x, power, prime)
                for power, coeff in enumerate(coeffs)
            )
            % prime
        )
        shares.append((x, y))
    return shares


def reconstruct_secret(
    shares: list[tuple[int, int]], prime: int = PRIME_FIELD
) -> int:
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (-xj)) % prime
                denominator = (denominator * (xi - xj)) % prime
        lagrange_coeff = numerator * pow(denominator, -1, prime)
        secret = (secret + yi * lagrange_coeff) % prime
    return secret


def byzantine_consensus(
    shares: list[tuple[int, int]],
    threshold: int,
    prime: int = PRIME_FIELD,
) -> int:
    secret_count = Counter(
        reconstruct_secret(list(comb), prime)
        for comb in combinations(shares, threshold)
    )
    if not secret_count:
        raise ValueError("No valid secrets reconstructed")
    return secret_count.most_common(1)[0][0]
