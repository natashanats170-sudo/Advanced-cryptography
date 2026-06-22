def is_prime(n):
    """Simple primality check."""
    if n < 2: return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0: return False
    return True

def diffie_hellman(p, g, a, b):
    """
    Perform Diffie-Hellman key exchange.
    p = prime modulus, g = generator,
    a = Alice private key, b = Bob private key.
    """
    if not is_prime(p):
        raise ValueError(f"{p} is not prime.")

    # Public keys
    A = pow(g, a, p)   # g^a mod p  (pow() uses fast modular exponentiation)
    B = pow(g, b, p)   # g^b mod p

    # Shared secrets
    alice_secret = pow(B, a, p)   # B^a mod p
    bob_secret   = pow(A, b, p)   # A^b mod p

    print(f"\n=== Diffie-Hellman Key Exchange ===")
    print(f"Public prime (p)   : {p}")
    print(f"Generator (g)      : {g}")
    print(f"Alice private key  : {a}")
    print(f"Bob   private key  : {b}")
    print(f"Alice public key   : {A}")
    print(f"Bob   public key   : {B}")
    print(f"Alice shared secret: {alice_secret}")
    print(f"Bob   shared secret: {bob_secret}")
    print(f"Keys match         : {alice_secret == bob_secret}")
    return alice_secret

# Example from lecture
diffie_hellman(p=23, g=5, a=6, b=15)

# Stronger real-world parameters
diffie_hellman(p=2357, g=2, a=1234, b=5678)
