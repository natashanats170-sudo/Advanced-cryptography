from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Generate 2048-bit RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Save private key
with open("private.key", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

# Build a CSR
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "maureen.example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Maureen Wanjiku"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "KE"),
    ]))
    .sign(private_key, hashes.SHA256())
)

# Save CSR
with open("request.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

print("Private key saved to private.key")
print("CSR saved to request.csr")
