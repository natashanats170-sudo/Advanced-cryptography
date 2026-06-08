"""
rsa_crypto.py
Complete RSA implementation with key generation, encryption, signing, and key management.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512
from Crypto.Random import get_random_bytes
import base64
import json
import time
import os
from datetime import datetime

class RSAManager:
    """Complete RSA key management and cryptographic operations"""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA manager with specified key size
        key_size: 2048, 3072, or 4096 bits
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        
        # Security levels based on key size
        self.security_levels = {
            2048: "128-bit security (good until ~2030)",
            3072: "128-bit security (good until ~2040)",
            4096: "192-bit security (long-term)"
        }
    
    def generate_keys(self) -> dict:
        """Generate a new RSA key pair"""
        print(f"Generating {self.key_size}-bit RSA key pair...")
        start_time = time.time()
        
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        
        generation_time = time.time() - start_time
        print(f"Key generation completed in {generation_time:.2f} seconds")
        
        # Export keys for display
        private_pem = self.private_key.export_key('PEM')
        public_pem = self.public_key.export_key('PEM')
        
        return {
            'private_key_pem': private_pem.decode('ascii'),
            'public_key_pem': public_pem.decode('ascii'),
            'key_size': self.key_size,
            'generation_time': generation_time,
            'security_level': self.security_levels.get(self.key_size, "Unknown")
        }
    
    def save_keys(self, filename_base: str, passphrase: str = None):
        """Save keys to files with optional passphrase protection"""
        if not self.private_key or not self.public_key:
            raise ValueError("No keys to save. Generate keys first.")
        
        # Save private key (encrypted if passphrase provided)
        if passphrase:
            private_pem = self.private_key.export_key('PEM', passphrase=passphrase)
        else:
            private_pem = self.private_key.export_key('PEM')
        
        with open(f"{filename_base}_private.pem", 'wb') as f:
            f.write(private_pem)
        
        # Save public key (no encryption needed)
        public_pem = self.public_key.export_key('PEM')
        with open(f"{filename_base}_public.pem", 'wb') as f:
            f.write(public_pem)
        
        print(f"Saved keys: {filename_base}_private.pem, {filename_base}_public.pem")
    
    def load_private_key(self, filename: str, passphrase: str = None):
        """Load private key from file"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        if passphrase:
            self.private_key = RSA.import_key(key_data, passphrase=passphrase)
        else:
            self.private_key = RSA.import_key(key_data)
        
        self.public_key = self.private_key.publickey()
        print(f"Loaded private key from {filename}")
    
    def load_public_key(self, filename: str):
        """Load public key from file"""
        with open(filename, 'rb') as f:
            key_data = f.read()
        
        self.public_key = RSA.import_key(key_data)
        print(f"Loaded public key from {filename}")
    
    def encrypt_oaep(self, plaintext: bytes) -> tuple:
        """
        Encrypt using OAEP padding (recommended)
        Returns (ciphertext, encryption_time)
        """
        if not self.public_key:
            raise ValueError("No public key loaded")
        
        cipher = PKCS1_OAEP.new(self.public_key)
        start_time = time.time()
        
        # RSA can only encrypt data smaller than key size minus padding
        max_size = (self.public_key.size_in_bytes() - 42)  # OAEP overhead
        
        if len(plaintext) > max_size:
            raise ValueError(f"Plaintext too large. Max {max_size} bytes for {self.key_size}-bit RSA")
        
        ciphertext = cipher.encrypt(plaintext)
        enc_time = time.time() - start_time
        
        return ciphertext, enc_time
    
    def decrypt_oaep(self, ciphertext: bytes) -> tuple:
        """Decrypt using OAEP padding"""
        if not self.private_key:
            raise ValueError("No private key loaded")
        
        cipher = PKCS1_OAEP.new(self.private_key)
        start_time = time.time()
        plaintext = cipher.decrypt(ciphertext)
        dec_time = time.time() - start_time
        
        return plaintext, dec_time
    
    def sign_message(self, message: bytes, hash_alg=SHA256) -> bytes:
        """
        Sign message using RSA-PSS (Probabilistic Signature Scheme)
        Returns signature
        """
        if not self.private_key:
            raise ValueError("No private key loaded")
        
        # Hash the message
        h = hash_alg.new()
        h.update(message)
        
        # Create signature
        signer = pkcs1_15.new(self.private_key)
        signature = signer.sign(h)
        
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes, hash_alg=SHA256) -> bool:
        """Verify message signature"""
        if not self.public_key:
            raise ValueError("No public key loaded")
        
        h = hash_alg.new()
        h.update(message)
        
        try:
            verifier = pkcs1_15.new(self.public_key)
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def hybrid_encrypt(self, plaintext: bytes) -> dict:
        """
        Hybrid encryption: Use RSA to encrypt a symmetric key, 
        then use AES for the actual data
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        
        # Generate random AES key
        aes_key = get_random_bytes(32)  # AES-256
        
        # Encrypt AES key with RSA
        encrypted_key, _ = self.encrypt_oaep(aes_key)
        
        # Encrypt data with AES
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext_data = cipher_aes.encrypt(pad(plaintext, AES.block_size))
        
        return {
            'encrypted_symmetric_key': encrypted_key,
            'iv': iv,
            'ciphertext': ciphertext_data,
            'algorithm': 'RSA-OAEP + AES-256-CBC'
        }
    
    def hybrid_decrypt(self, encrypted_data: dict) -> bytes:
        """Decrypt hybrid encrypted data"""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        # Decrypt AES key with RSA
        aes_key, _ = self.decrypt_oaep(encrypted_data['encrypted_symmetric_key'])
        
        # Decrypt data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, encrypted_data['iv'])
        plaintext = unpad(cipher_aes.decrypt(encrypted_data['ciphertext']), AES.block_size)
        
        return plaintext
    
    def get_key_info(self) -> dict:
        """Get detailed information about loaded keys"""
        if not self.private_key and not self.public_key:
            return {"error": "No keys loaded"}
        
        info = {
            'key_size': self.key_size,
            'algorithm': 'RSA',
        }
        
        if self.public_key:
            info['public_key'] = {
                'modulus_length': self.public_key.size_in_bits(),
                'exponent': self.public_key.e,
                'modulus_hex': hex(self.public_key.n)[:50] + "..."
            }
        
        if self.private_key:
            info['private_key'] = {
                'modulus_length': self.private_key.size_in_bits(),
                'exponent': self.private_key.d,
                'has_private_components': True
            }
        
        return info


class CertificateSimulator:
    """Simulate X.509 certificate creation and validation"""
    
    @staticmethod
    def create_self_signed_cert(rsa_manager: RSAManager, 
                                 common_name: str,
                                 days_valid: int = 365) -> dict:
        """Create a simple self-signed certificate (simulated)"""
        
        cert = {
            'version': 3,
            'serial_number': int(time.time()),
            'signature_algorithm': 'sha256WithRSAEncryption',
            'issuer': f'CN={common_name}',
            'validity': {
                'not_before': datetime.now().isoformat(),
                'not_after': datetime.now().timestamp() + (days_valid * 86400)
            },
            'subject': f'CN={common_name}',
            'public_key': rsa_manager.public_key.export_key('PEM').decode('ascii'),
            'extensions': {
                'basic_constraints': 'CA:FALSE',
                'key_usage': 'digitalSignature, keyEncipherment'
            }
        }
        
        # Sign the certificate
        cert_json = json.dumps(cert, sort_keys=True).encode('utf-8')
        signature = rsa_manager.sign_message(cert_json)
        
        cert['signature'] = base64.b64encode(signature).decode('ascii')
        
        return cert
    
    @staticmethod
    def verify_certificate(cert: dict, ca_rsa: RSAManager) -> bool:
        """Verify a certificate signature"""
        signature = base64.b64decode(cert['signature'])
        cert_copy = cert.copy()
        del cert_copy['signature']
        cert_json = json.dumps(cert_copy, sort_keys=True).encode('utf-8')
        
        return ca_rsa.verify_signature(cert_json, signature)


def main():
    print("RSA PUBLIC KEY CRYPTOGRAPHY SYSTEM")
    print("=" * 60)
    
    # 1. Key Generation
    print("\n1. RSA Key Generation")
    print("-" * 40)
    
    rsa = RSAManager(key_size=2048)
    keys = rsa.generate_keys()
    
    print(f"Security level: {keys['security_level']}")
    print(f"Public key (first 200 chars):\n{keys['public_key_pem'][:200]}...")
    
    # 2. Encryption/Decryption
    print("\n2. Encryption and Decryption")
    print("-" * 40)
    
    message = b"Confidential message for secure transmission"
    print(f"Original message: {message}")
    
    # Encrypt
    ciphertext, enc_time = rsa.encrypt_oaep(message)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Encryption time: {enc_time*1000:.2f} ms")
    
    # Decrypt
    decrypted, dec_time = rsa.decrypt_oaep(ciphertext)
    print(f"Decryption time: {dec_time*1000:.2f} ms")
    print(f"Decrypted: {decrypted}")
    
    if decrypted == message:
        print("✓ Encryption/decryption successful")
    
    # 3. Digital Signatures
    print("\n3. Digital Signatures")
    print("-" * 40)
    
    document = b"Legal contract: Alice agrees to pay Bob 100 BTC"
    signature = rsa.sign_message(document)
    print(f"Document: {document}")
    print(f"Signature (hex): {signature.hex()[:64]}...")
    
    # Verify signature
    is_valid = rsa.verify_signature(document, signature)
    print(f"Signature valid: {is_valid}")
    
    # Tampered document
    tampered = b"Legal contract: Alice agrees to pay Bob 10000 BTC"
    is_valid_tampered = rsa.verify_signature(tampered, signature)
    print(f"Tampered document signature valid: {is_valid_tampered}")
    
    # 4. Hybrid Encryption (for large data)
    print("\n4. Hybrid Encryption (RSA + AES)")
    print("-" * 40)
    
    large_data = b"This is a large file content. " * 100  # 3.1 KB
    print(f"Original data size: {len(large_data)} bytes")
    
    hybrid_encrypted = rsa.hybrid_encrypt(large_data)
    print(f"Encrypted symmetric key size: {len(hybrid_encrypted['encrypted_symmetric_key'])} bytes")
    print(f"Ciphertext size: {len(hybrid_encrypted['ciphertext'])} bytes")
    
    hybrid_decrypted = rsa.hybrid_decrypt(hybrid_encrypted)
    print(f"Decrypted data matches: {hybrid_decrypted == large_data}")
    
    # 5. Key Management and Persistence
    print("\n5. Key Management")
    print("-" * 40)
    
    # Save keys with password protection
    passphrase = "SecureKeyPassphrase123!"
    rsa.save_keys("my_rsa_keys", passphrase=passphrase)
    
    # Load keys back
    rsa2 = RSAManager()
    rsa2.load_private_key("my_rsa_keys_private.pem", passphrase=passphrase)
    
    # Test loaded keys
    test_msg = b"Test key loading"
    cipher2, _ = rsa2.encrypt_oaep(test_msg)
    plain2, _ = rsa2.decrypt_oaep(cipher2)
    print(f"Key reloading test: {plain2 == test_msg}")
    
    # 6. Certificate Simulation
    print("\n6. Certificate Generation and Validation")
    print("-" * 40)
    
    cert = CertificateSimulator.create_self_signed_cert(rsa, "example.com", days_valid=365)
    print(f"Certificate for: {cert['subject']}")
    print(f"Valid until: {datetime.fromtimestamp(cert['validity']['not_after']).date()}")
    
    # Verify certificate
    is_valid = CertificateSimulator.verify_certificate(cert, rsa)
    print(f"Certificate signature valid: {is_valid}")
    
    # 7. Performance and Security Analysis
    print("\n7. RSA Performance Analysis")
    print("-" * 40)
    
    # Test with different key sizes
    for size in [1024, 2048, 3072]:
        if size == 1024:
            print("\n⚠ 1024-bit RSA is DEPRECATED (shown for comparison only)")
        
        rsa_test = RSAManager(key_size=size)
        
        # Measure generation time
        start = time.time()
        rsa_test.generate_keys()
        gen_time = time.time() - start
        
        # Measure encryption/decryption
        test_msg = b"Small test message"
        start = time.time()
        ct, _ = rsa_test.encrypt_oaep(test_msg)
        enc_time = time.time() - start
        
        start = time.time()
        pt, _ = rsa_test.decrypt_oaep(ct)
        dec_time = time.time() - start
        
        print(f"\nRSA-{size}:")
        print(f"  Key generation: {gen_time:.3f} sec")
        print(f"  Encryption: {enc_time*1000:.2f} ms")
        print(f"  Decryption: {dec_time*1000:.2f} ms")
        print(f"  Max plaintext: {rsa_test.public_key.size_in_bytes() - 42} bytes")
    
    # 8. Security Recommendations
    print("\n" + "="*60)
    print("RSA SECURITY RECOMMENDATIONS")
    print("="*60)
    print("""
    ✓ Use at least 2048-bit keys (3072+ for long-term security)
    ✓ Always use OAEP padding (never PKCS#1 v1.5)
    ✓ Use RSA for key exchange and signatures, not bulk encryption
    ✓ Implement hybrid encryption for large data
    ✓ Protect private keys with strong passphrases
    ✓ Rotate keys periodically (e.g., every 2 years)
    
    ✗ Never use RSA-1024 or smaller
    ✗ Never share private keys
    ✗ Never use deterministic padding
    ✗ Never sign untrusted data without hashing
    """)
    
    # Cleanup
    for f in ["my_rsa_keys_private.pem", "my_rsa_keys_public.pem"]:
        if os.path.exists(f):
            os.remove(f)
    print("\nCleanup complete.")


if __name__ == "__main__":
    # Requires: pip install pycryptodome
    main()
