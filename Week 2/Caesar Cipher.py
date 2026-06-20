def encrypt(text, shift=3):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            result += chr((ord(ch) - 65 + shift) % 26 + 65)
        else:
            result += ch
    return result

print(encrypt("HELLO"))  # -> KHOOR
