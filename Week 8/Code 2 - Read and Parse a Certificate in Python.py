from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime

def inspect_certificate(pem_path: str):
    """Load a PEM certificate and print key fields."""
    with open(pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    print("=== Certificate Details ===")
    print(f"Subject   : {cert.subject.rfc4514_string()}")
    print(f"Issuer    : {cert.issuer.rfc4514_string()}")
    print(f"Serial No : {cert.serial_number}")
    print(f"Valid From: {cert.not_valid_before_utc}")
    print(f"Expires   : {cert.not_valid_after_utc}")
    print(f"Algorithm : {cert.signature_algorithm_oid.dotted_string}")

    # Check if expired
    now = datetime.datetime.now(datetime.timezone.utc)
    if now > cert.not_valid_after_utc:
        print("STATUS    : *** EXPIRED ***")
    else:
        days_left = (cert.not_valid_after_utc - now).days
        print(f"STATUS    : Valid ({days_left} days remaining)")

inspect_certificate("certificate.pem")
