from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate 2048-bit key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key  = private_key.public_key()

# Save private key to PEM file
with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

# Encrypt a message
message    = b"Hello RSA"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Decrypt
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(plaintext)  # b"Hello RSA"
