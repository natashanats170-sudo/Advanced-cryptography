# Public values (shared openly)
p = 23   # prime modulus
g = 5    # generator

# Private keys (kept secret)
alice_private = 6
bob_private   = 15

# Step 3: Compute public keys
alice_public = (g ** alice_private) % p   # 5^6 mod 23 = 8
bob_public   = (g ** bob_private)   % p   # 5^15 mod 23 = 19

# Step 5: Compute shared secrets (should be equal)
alice_secret = (bob_public   ** alice_private) % p   # 19^6 mod 23
bob_secret   = (alice_public ** bob_private)   % p   # 8^15 mod 23

print(f"Alice Public Key : {alice_public}")    # 8
print(f"Bob   Public Key : {bob_public}")      # 19
print(f"Alice Secret     : {alice_secret}")    # 2
print(f"Bob   Secret     : {bob_secret}")      # 2
print(f"Keys match       : {alice_secret == bob_secret}")
