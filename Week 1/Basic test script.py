from cryptography.fernet import Fernet

key = Fernet.generate_key()
f   = Fernet(key)

token = f.encrypt(b"Encryption successful: ciphertext generated")
print(token)
print(f.decrypt(token))
