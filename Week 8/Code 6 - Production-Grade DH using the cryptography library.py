from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Generate DH parameters (large prime p and generator g)
# key_size=512 is for demo only; use 2048+ in production
parameters = dh.generate_parameters(generator=2, key_size=512)

# Alice generates her key pair
alice_private_key = parameters.generate_private_key()
alice_public_key  = alice_private_key.public_key()

# Bob generates his key pair
bob_private_key = parameters.generate_private_key()
bob_public_key  = bob_private_key.public_key()

# Alice computes shared key using Bob's public key
alice_shared = alice_private_key.exchange(bob_public_key)

# Bob computes shared key using Alice's public key
bob_shared = bob_private_key.exchange(alice_public_key)

# Derive a usable AES key from the shared secret using HKDF
def derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dh key exchange"
    ).derive(shared_secret)

alice_key = derive_key(alice_shared)
bob_key   = derive_key(bob_shared)

print(f"Alice key : {alice_key.hex()}")
print(f"Bob   key : {bob_key.hex()}")
print(f"Keys match: {alice_key == bob_key}")
