from cryptography.fernet import Fernet

def encrypt_file(filepath, key):
    f = Fernet(key)
    with open(filepath, "rb") as fh:
        data = fh.read()
    encrypted = f.encrypt(data)
    with open(filepath + ".enc", "wb") as fh:
        fh.write(encrypted)
    print(f"Encrypted: {filepath} -> {filepath}.enc")

encrypt_file("secret.txt", key)
