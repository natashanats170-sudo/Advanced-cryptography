"""
stream_cipher.py
Implements stream cipher systems with various keystream generators.
"""

import hashlib
import secrets
import time
from typing import List, Tuple

class LFSR:
    """Linear Feedback Shift Register for pseudorandom bit generation"""
    
    def __init__(self, seed: int, taps: List[int], length: int):
        """
        seed: initial state
        taps: bit positions that feed into XOR
        length: number of bits in register
        """
        self.state = seed & ((1 << length) - 1)
        self.taps = taps
        self.length = length
        self.mask = (1 << length) - 1
    
    def next_bit(self) -> int:
        """Generate next pseudorandom bit"""
        # Compute feedback bit (XOR of tap positions)
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        
        # Shift register and insert feedback at highest bit
        self.state = ((self.state << 1) | feedback) & self.mask
        return feedback
    
    def next_byte(self) -> int:
        """Generate a full byte (8 bits)"""
        byte = 0
        for i in range(8):
            byte = (byte << 1) | self.next_bit()
        return byte
    
    def generate_keystream(self, length: int) -> bytes:
        """Generate keystream of specified length in bytes"""
        return bytes([self.next_byte() for _ in range(length)])


class ChaCha20Simulator:
    """
    Simplified ChaCha20-like stream cipher (educational version)
    Actual ChaCha20 uses quarter rounds and block permutations
    """
    
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        self.key = key
        self.nonce = nonce
        self.counter = counter
        self.block_size = 64
    
    def _hash_block(self, block_input: bytes) -> bytes:
        """Simplified block transformation using SHA256"""
        return hashlib.sha256(block_input).digest()[:self.block_size]
    
    def _generate_block(self, block_counter: int) -> bytes:
        """Generate one keystream block"""
        # Construct block input (simplified version)
        block_input = (
            self.key + 
            self.nonce + 
            block_counter.to_bytes(8, 'little')
        )
        return self._hash_block(block_input)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """XOR plaintext with keystream"""
        ciphertext = bytearray()
        block_counter = self.counter
        
        for i in range(0, len(plaintext), self.block_size):
            keystream = self._generate_block(block_counter)
            chunk = plaintext[i:i+self.block_size]
            # XOR with keystream
            encrypted_chunk = bytes(
                chunk[j] ^ keystream[j] for j in range(len(chunk))
            )
            ciphertext.extend(encrypted_chunk)
            block_counter += 1
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decryption is identical to encryption for stream ciphers"""
        return self.encrypt(ciphertext)


class StreamCipherAnalyzer:
    """Tools for analyzing stream cipher randomness"""
    
    @staticmethod
    def byte_frequency(data: bytes) -> dict:
        """Analyze frequency of each byte value"""
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        return freq
    
    @staticmethod
    def chi_square_test(data: bytes) -> float:
        """Chi-square test for randomness"""
        freq = StreamCipherAnalyzer.byte_frequency(data)
        expected = len(data) / 256
        chi2 = sum((count - expected)**2 / expected for count in freq.values())
        return chi2
    
    @staticmethod
    def runs_test(bits: List[int]) -> Tuple[int, float]:
        """
        Test for runs (consecutive identical bits)
        Returns (number_of_runs, p_value)
        """
        if len(bits) < 2:
            return 1, 1.0
        
        runs = 1
        for i in range(1, len(bits)):
            if bits[i] != bits[i-1]:
                runs += 1
        
        # Expected runs for random sequence
        n = len(bits)
        expected_runs = (2 * n - 1) / 3
        
        # Simplified p-value
        variance = (16 * n - 29) / 90
        if variance > 0:
            z_score = abs(runs - expected_runs) / (variance ** 0.5)
            p_value = 2 * (1 - min(0.9999, z_score / 10))  # Simplified
        else:
            p_value = 1.0
        
        return runs, p_value
    
    @staticmethod
    def print_analysis(data: bytes, name: str):
        """Print comprehensive randomness analysis"""
        print(f"\nAnalysis: {name}")
        print("-" * 50)
        print(f"Total bytes: {len(data)}")
        print(f"Total bits: {len(data) * 8}")
        
        # Convert to bits for runs test
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        
        runs, p_value = StreamCipherAnalyzer.runs_test(bits)
        print(f"Runs test: {runs} runs (p-value ≈ {p_value:.4f})")
        
        chi2 = StreamCipherAnalyzer.chi_square_test(data)
        print(f"Chi-square statistic: {chi2:.2f}")
        
        if chi2 < 300 and p_value > 0.01:
            print("✓ Passes basic randomness tests")
        else:
            print("⚠ May have non-random patterns")


def main():
    print("STREAM CIPHER AND KEYSTREAM GENERATION")
    print("=" * 60)
    
    # 1. LFSR Demonstration
    print("\n1. LFSR Keystream Generation")
    print("-" * 40)
    
    # 16-bit LFSR with taps at positions 16,14,13,11 (maximal length)
    lfsr = LFSR(seed=0xACE1, taps=[15, 13, 12, 10], length=16)
    
    print("Generating 32 bytes of LFSR keystream:")
    keystream = lfsr.generate_keystream(32)
    print(f"Keystream (hex): {keystream.hex()}")
    
    # Test encryption with LFSR
    plaintext = b"Secret message for stream cipher test!"
    lfsr2 = LFSR(seed=0xACE1, taps=[15, 13, 12, 10], length=16)
    keystream2 = lfsr2.generate_keystream(len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream2))
    
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Decryption (same as encryption for stream ciphers)
    lfsr3 = LFSR(seed=0xACE1, taps=[15, 13, 12, 10], length=16)
    keystream3 = lfsr3.generate_keystream(len(ciphertext))
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream3))
    print(f"Decrypted: {decrypted}")
    
    # 2. ChaCha20-like Simulator
    print("\n\n2. ChaCha20-like Stream Cipher")
    print("-" * 40)
    
    key = secrets.token_bytes(32)  # 256-bit key
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    
    cipher = ChaCha20Simulator(key, nonce)
    plaintext = b"This is a longer test message for the stream cipher. " * 5
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Key (hex): {key.hex()[:32]}...")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Plaintext length: {len(plaintext)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Verify decryption
    cipher2 = ChaCha20Simulator(key, nonce)
    decrypted = cipher2.decrypt(ciphertext)
    
    if decrypted == plaintext:
        print("✓ Encryption/decryption successful")
    else:
        print("✗ Verification failed")
    
    # 3. Randomness Testing
    print("\n\n3. KEYSTREAM RANDOMNESS ANALYSIS")
    print("=" * 50)
    
    # Generate keystreams from different sources
    lfsr_keystream = LFSR(seed=0x1234, taps=[15, 13, 12, 10], length=16).generate_keystream(1000)
    crypto_keystream = secrets.token_bytes(1000)
    
    # Analyze LFSR output
    StreamCipherAnalyzer.print_analysis(lfsr_keystream, "LFSR Keystream")
    
    # Analyze cryptographically secure keystream
    StreamCipherAnalyzer.print_analysis(crypto_keystream, "Cryptographically Secure Keystream")
    
    # 4. Security Discussion
    print("\n" + "="*60)
    print("STREAM CIPHER SECURITY CONSIDERATIONS")
    print("="*60)
    print("""
    Advantages:
    • Very fast in software
    • No padding required
    • Error propagation limited to single bits
    
    Critical Requirements:
    • NEVER reuse key+nonce pair
    • Must use cryptographically secure PRNG
    • Proper key management essential
    
    Modern Stream Ciphers:
    • ChaCha20 (recommended)
    • AES-CTR mode
    • Salsa20
    
    WARNING: Do not implement your own stream cipher in production!
    """)
    
    print("\nKey Reuse Attack Demonstration:")
    key_reuse_key = b"fixedkey123"
    nonce = b"nonce12345"
    
    cipher = ChaCha20Simulator(key_reuse_key, nonce)
    msg1 = b"Secret message one"
    msg2 = b"Confidential data two"
    
    c1 = cipher.encrypt(msg1)
    cipher2 = ChaCha20Simulator(key_reuse_key, nonce)
    c2 = cipher2.encrypt(msg2)
    
    # Attacker XORs the two ciphertexts
    xor_result = bytes(c1[i] ^ c2[i] for i in range(min(len(c1), len(c2))))
    print(f"XOR of two ciphertexts (reveals msg1 XOR msg2): {xor_result.hex()[:64]}...")
    print("This shows why key+nonce reuse is catastrophic!")


if __name__ == "__main__":
    main()
