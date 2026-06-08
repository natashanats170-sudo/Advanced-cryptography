"""
classical_ciphers.py
Implements multiple classical ciphers with security analysis.
"""

import string
from collections import Counter
import itertools

class CaesarCipher:
    """Caesar cipher - shift each letter by a fixed amount"""
    
    def __init__(self, shift=3):
        self.shift = shift % 26
    
    def encrypt(self, text):
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) - 65 + self.shift) % 26 + 65))
            elif char.islower():
                result.append(chr((ord(char) - 97 + self.shift) % 26 + 97))
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text):
        # Decryption is just encryption with negative shift
        return CaesarCipher(-self.shift).encrypt(text)
    
    @staticmethod
    def brute_force(ciphertext):
        """Try all 25 possible shifts"""
        results = []
        for shift in range(1, 26):
            decrypted = CaesarCipher(shift).decrypt(ciphertext)
            results.append((shift, decrypted))
        return results


class VigenereCipher:
    """Vigenere cipher - uses a keyword to determine shifts"""
    
    def __init__(self, keyword):
        self.keyword = keyword.lower()
        self.key_length = len(keyword)
    
    def _shift_char(self, char, shift, encrypt=True):
        if not char.isalpha():
            return char
        shift_amount = shift if encrypt else -shift
        base = 65 if char.isupper() else 97
        return chr((ord(char) - base + shift_amount) % 26 + base)
    
    def encrypt(self, text):
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(self.keyword[key_index % self.key_length]) - 97
                result.append(self._shift_char(char, shift, encrypt=True))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text):
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(self.keyword[key_index % self.key_length]) - 97
                result.append(self._shift_char(char, shift, encrypt=False))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)


def frequency_analysis(text):
    """Perform frequency analysis on ciphertext for security evaluation"""
    letters_only = [char.lower() for char in text if char.isalpha()]
    freq = Counter(letters_only)
    total = len(letters_only)
    
    print("\nFrequency Analysis:")
    print("-" * 40)
    for letter in string.ascii_lowercase:
        count = freq.get(letter, 0)
        percentage = (count / total) * 100 if total > 0 else 0
        bar = '█' * int(percentage / 2)
        print(f"{letter}: {percentage:5.1f}% {bar}")


def security_evaluation(cipher_name, key_space_size, weaknesses):
    """Provide security evaluation for a cipher"""
    print(f"\n{'='*50}")
    print(f"SECURITY EVALUATION: {cipher_name}")
    print(f"{'='*50}")
    print(f"Key space size: {key_space_size} possible keys")
    
    if key_space_size < 2**40:
        print("⚠ WARNING: Key space too small for modern security")
    
    print("\nWeaknesses:")
    for weakness in weaknesses:
        print(f"  • {weakness}")
    
    if key_space_size >= 2**128:
        print("\n✓ Key space meets modern security requirements")


def main():
    print("CLASSICAL CIPHER DEMONSTRATION")
    print("=" * 60)
    
    # Caesar Cipher
    print("\n1. CAESAR CIPHER")
    plaintext = "The quick brown fox jumps over the lazy dog"
    caesar = CaesarCipher(shift=5)
    ciphertext = caesar.encrypt(plaintext)
    decrypted = caesar.decrypt(ciphertext)
    
    print(f"Original: {plaintext}")
    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    
    # Show brute force attack
    print("\nBrute forcing Caesar cipher:")
    for shift, result in CaesarCipher.brute_force(ciphertext)[:3]:
        print(f"  Shift {shift:2d}: {result[:50]}...")
    
    security_evaluation(
        "Caesar Cipher",
        key_space_size=25,
        weaknesses=[
            "Only 25 possible keys (trivial brute force)",
            "Preserves letter frequencies",
            "No diffusion - each letter maps independently",
            "Vulnerable to frequency analysis"
        ]
    )
    
    # Vigenere Cipher
    print("\n\n2. VIGENERE CIPHER")
    vigenere = VigenereCipher(keyword="crypto")
    ciphertext_vig = vigenere.encrypt(plaintext)
    decrypted_vig = vigenere.decrypt(ciphertext_vig)
    
    print(f"Original: {plaintext}")
    print(f"Encrypted: {ciphertext_vig}")
    print(f"Decrypted: {decrypted_vig}")
    
    # Perform frequency analysis on Vigenere ciphertext
    frequency_analysis(ciphertext_vig)
    
    security_evaluation(
        "Vigenere Cipher",
        key_space_size=26**5,  # Assuming 5-letter keyword
        weaknesses=[
            "Kasiski examination can reveal key length",
            "Frequency analysis still possible once key length is known",
            "Key repetition creates patterns",
            "Vulnerable to known-plaintext attacks"
        ]
    )
    
    # Comparison with modern requirements
    print("\n" + "="*50)
    print("MODERN SECURITY REQUIREMENTS")
    print("="*50)
    print("Minimum key size for symmetric ciphers: 128 bits")
    print("Recommended: AES-256 (256-bit keys)")
    print("\nClassical ciphers are for educational purposes only.")
    print("Do NOT use them for actual security.")


if __name__ == "__main__":
    main()
