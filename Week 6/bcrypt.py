import bcrypt

password = b"MyP@ssword123"

# Hash with auto-generated salt, 10 rounds
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=10))
print("Hash:", hashed)

# Verify
if bcrypt.checkpw(password, hashed):
    print("Password verified!")
else:
    print("Invalid password.")
