def rc4(key, plaintext):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    cipher = []
    for byte in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        cipher.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(cipher)

key = [ord(c) for c in "SECRET"]
msg = b"SECURE_MESSAGE"
enc = rc4(key, msg)
dec = rc4(key, enc)
print("Decrypted:", dec)
