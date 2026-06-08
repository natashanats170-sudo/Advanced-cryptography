"""
aes_file_encryption.py
Comprehensive file encryption using AES in multiple modes.
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time
import json

class AESFileEncryptor:
    """Complete file encryption solution using AES"""
    
    def __init__(self, password: str = None, key: bytes = None):
        """
        Initialize with either password (will derive key) or direct key
        """
        if key:
            self.key = key
            self.key_derived = False
        elif password:
            self.key = None
            self.password = password
            self.key_derived = True
        else:
            raise ValueError("Either password or key must be provided")
        
        self.backend = default_backend()
    
    def _derive_key(self, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive AES-256 key from password using PBKDF2"""
        kdf = PBKDF2(
            algorithm=hashlib.sha256,
            length=32,  # 256 bits
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(self.password.encode('utf-8'))
    
    def _encrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-CBC mode"""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def _decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-CBC mode"""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()
    
    def _encrypt_gcm(self, data: bytes) -> tuple:
        """Encrypt using AES-GCM (authenticated encryption)"""
        iv = os.urandom(12)  # 96-bit IV recommended for GCM
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, iv, encryptor.tag
    
    def _decrypt_gcm(self, ciphertext: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-GCM"""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_file_cbc(self, input_file: str, output_file: str = None) -> dict:
        """
        Encrypt a file using AES-CBC mode
        Returns metadata dictionary
        """
        if output_file is None:
            output_file = input_file + ".enc"
        
        # Generate random IV and salt if key is password-derived
        iv = os.urandom(16)
        
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Derive key if needed
        if self.key_derived:
            salt = os.urandom(16)
            self.key = self._derive_key(salt)
        else:
            salt = None
        
        # Encrypt
        start_time = time.time()
        ciphertext = self._encrypt_cbc(plaintext, iv)
        encryption_time = time.time() - start_time
        
        # Write encrypted file with metadata header
        metadata = {
            'mode': 'CBC',
            'iv': base64.b64encode(iv).decode('ascii'),
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext),
            'encryption_time': encryption_time
        }
        
        if salt:
            metadata['salt'] = base64.b64encode(salt).decode('ascii')
            metadata['pbkdf2_iterations'] = 100000
        
        # Write metadata first (as JSON), then ciphertext
        with open(output_file, 'wb') as f:
            # Write metadata length prefix (4 bytes)
            metadata_json = json.dumps(metadata).encode('utf-8')
            f.write(len(metadata_json).to_bytes(4, 'big'))
            f.write(metadata_json)
            f.write(ciphertext)
        
        return metadata
    
    def decrypt_file_cbc(self, input_file: str, output_file: str = None) -> dict:
        """Decrypt a file encrypted with AES-CBC mode"""
        if output_file is None:
            output_file = input_file.replace('.enc', '.dec')
        
        with open(input_file, 'rb') as f:
            # Read metadata
            meta_len = int.from_bytes(f.read(4), 'big')
            metadata_json = f.read(meta_len)
            metadata = json.loads(metadata_json.decode('utf-8'))
            ciphertext = f.read()
        
        iv = base64.b64decode(metadata['iv'])
        
        # Derive key if needed
        if 'salt' in metadata:
            salt = base64.b64decode(metadata['salt'])
            self.key = self._derive_key(salt, metadata.get('pbkdf2_iterations', 100000))
        
        # Decrypt
        plaintext = self._decrypt_cbc(ciphertext, iv)
        
        # Verify size
        if len(plaintext) != metadata['original_size']:
            print(f"Warning: Size mismatch (expected {metadata['original_size']}, got {len(plaintext)})")
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        return metadata
    
    def encrypt_file_gcm(self, input_file: str, output_file: str = None) -> dict:
        """Encrypt a file using AES-GCM (authenticated encryption)"""
        if output_file is None:
            output_file = input_file + ".gcm_enc"
        
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Derive key if needed
        if self.key_derived:
            salt = os.urandom(16)
            self.key = self._derive_key(salt)
        else:
            salt = None
        
        # Encrypt
        start_time = time.time()
        ciphertext, iv, tag = self._encrypt_gcm(plaintext)
        encryption_time = time.time() - start_time
        
        metadata = {
            'mode': 'GCM',
            'iv': base64.b64encode(iv).decode('ascii'),
            'tag': base64.b64encode(tag).decode('ascii'),
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext),
            'encryption_time': encryption_time
        }
        
        if salt:
            metadata['salt'] = base64.b64encode(salt).decode('ascii')
            metadata['pbkdf2_iterations'] = 100000
        
        with open(output_file, 'wb') as f:
            metadata_json = json.dumps(metadata).encode('utf-8')
            f.write(len(metadata_json).to_bytes(4, 'big'))
            f.write(metadata_json)
            f.write(ciphertext)
        
        return metadata
    
    def decrypt_file_gcm(self, input_file: str, output_file: str = None) -> dict:
        """Decrypt a file encrypted with AES-GCM mode"""
        if output_file is None:
            output_file = input_file.replace('.gcm_enc', '.dec')
        
        with open(input_file, 'rb') as f:
            meta_len = int.from_bytes(f.read(4), 'big')
            metadata_json = f.read(meta_len)
            metadata = json.loads(metadata_json.decode('utf-8'))
            ciphertext = f.read()
        
        iv = base64.b64decode(metadata['iv'])
        tag = base64.b64decode(metadata['tag'])
        
        if 'salt' in metadata:
            salt = base64.b64decode(metadata['salt'])
            self.key = self._derive_key(salt, metadata.get('pbkdf2_iterations', 100000))
        
        plaintext = self._decrypt_gcm(ciphertext, iv, tag)
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        return metadata


def create_test_file(filename: str, size_mb: int = 1):
    """Create a test file with random data"""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_mb * 1024 * 1024))
    print(f"Created test file: {filename} ({size_mb} MB)")


def main():
    print("AES FILE ENCRYPTION DEMONSTRATION")
    print("=" * 60)
    
    # Create test file
    test_file = "test_plaintext.txt"
    with open(test_file, 'w') as f:
        f.write("This is a secret message.\n" * 1000)
        f.write("Confidential data that needs protection.\n" * 1000)
    print(f"Created test file: {test_file}")
    
    # 1. Password-based encryption with CBC mode
    print("\n1. AES-CBC with Password Derivation")
    print("-" * 40)
    
    password = "MySecurePassword123!"
    encryptor = AESFileEncryptor(password=password)
    
    # Encrypt
    metadata = encryptor.encrypt_file_cbc(test_file, "encrypted_cbc.bin")
    print(f"Encryption metadata: {json.dumps(metadata, indent=2)}")
    
    # Decrypt
    encryptor2 = AESFileEncryptor(password=password)
    encryptor2.decrypt_file_cbc("encrypted_cbc.bin", "decrypted_cbc.txt")
    
    # Verify
    with open(test_file, 'rb') as f1, open("decrypted_cbc.txt", 'rb') as f2:
        if f1.read() == f2.read():
            print("✓ CBC encryption/decryption verified")
        else:
            print("✗ Verification failed")
    
    # 2. AES-GCM (Authenticated Encryption)
    print("\n2. AES-GCM (Authenticated Encryption)")
    print("-" * 40)
    
    encryptor_gcm = AESFileEncryptor(password=password)
    metadata_gcm = encryptor_gcm.encrypt_file_gcm(test_file, "encrypted_gcm.bin")
    print(f"GCM metadata: {json.dumps(metadata_gcm, indent=2)}")
    
    # Tamper detection demonstration
    print("\nTamper detection test:")
    with open("encrypted_gcm.bin", 'rb') as f:
        data = bytearray(f.read())
    
    # Corrupt one byte
    if len(data) > 100:
        data[100] ^= 0xFF
        with open("corrupted.bin", 'wb') as f:
            f.write(data)
        
        try:
            encryptor_gcm2 = AESFileEncryptor(password=password)
            encryptor_gcm2.decrypt_file_gcm("corrupted.bin", "corrupted_dec.txt")
            print("⚠ GCM did NOT detect corruption (unexpected)")
        except Exception as e:
            print(f"✓ GCM detected tampering: {str(e)[:60]}...")
    
    # 3. Performance comparison
    print("\n3. Performance Comparison")
    print("-" * 40)
    
    # Create larger test file
    large_file = "large_test.bin"
    create_test_file(large_file, 5)  # 5 MB
    
    # Test with raw key (no PBKDF2 overhead)
    raw_key = os.urandom(32)
    encryptor_raw = AESFileEncryptor(key=raw_key)
    
    import time
    start = time.time()
    encryptor_raw.encrypt_file_cbc(large_file, "large_encrypted.bin")
    cbc_time = time.time() - start
    
    start = time.time()
    encryptor_raw.encrypt_file_gcm(large_file, "large_encrypted_gcm.bin")
    gcm_time = time.time() - start
    
    print(f"CBC encryption time: {cbc_time:.2f} seconds")
    print(f"GCM encryption time: {gcm_time:.2f} seconds")
    
    # 4. Security best practices
    print("\n" + "="*60)
    print("AES SECURITY BEST PRACTICES")
    print("="*60)
    print("""
    ✓ Use AES-256 (256-bit keys)
    ✓ Use GCM mode for authenticated encryption
    ✓ Use random IVs (12 bytes for GCM, 16 for CBC)
    ✓ Use PBKDF2 with high iterations (100,000+) for passwords
    ✓ Store IV, salt, and tag with ciphertext
    ✗ Never reuse IV with same key
    ✗ Never use ECB mode
    ✗ Never roll your own crypto
    """)
    
    # Cleanup
    for f in [test_file, "encrypted_cbc.bin", "decrypted_cbc.txt", 
              "encrypted_gcm.bin", "corrupted.bin", large_file,
              "large_encrypted.bin", "large_encrypted_gcm.bin"]:
        if os.path.exists(f):
            os.remove(f)
    print("\nCleanup complete.")


if __name__ == "__main__":
    # Note: Requires cryptography library
    # pip install cryptography
    main()
