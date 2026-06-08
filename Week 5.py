"""
password_hashing.py
Secure password storage using modern hashing algorithms.
"""

import hashlib
import secrets
import time
import json
import re
from typing import Tuple, Dict
from dataclasses import dataclass
from collections import defaultdict

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("Warning: bcrypt not installed. Install with: pip install bcrypt")

try:
    import argon2
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("Warning: argon2-cffi not installed. Install with: pip install argon2-cffi")


@dataclass
class HashResult:
    """Store hash results with metadata"""
    hash_value: str
    algorithm: str
    salt: str
    time_ms: float
    cost_factors: Dict


class SecurePasswordHasher:
    """
    Comprehensive password hashing with multiple algorithms
    Implements best practices for secure password storage
    """
    
    def __init__(self):
        self.user_database = {}
        
        # Recommended cost factors (adjust based on hardware)
        self.costs = {
            'pbkdf2': {
                'iterations': 100000,
                'dklen': 32
            },
            'bcrypt': {
                'rounds': 12  # 2^12 iterations
            },
            'argon2': {
                'time_cost': 3,
                'memory_cost': 65536,  # 64 MB
                'parallelism': 4
            }
        }
    
    def hash_pbkdf2(self, password: str, salt: bytes = None) -> HashResult:
        """
        Hash password using PBKDF2 with SHA256
        NIST recommended for password storage
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        start_time = time.perf_counter()
        
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.costs['pbkdf2']['iterations'],
            dklen=self.costs['pbkdf2']['dklen']
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return HashResult(
            hash_value=hash_value.hex(),
            algorithm='PBKDF2-SHA256',
            salt=salt.hex(),
            time_ms=elapsed_ms,
            cost_factors={'iterations': self.costs['pbkdf2']['iterations']}
        )
    
    def hash_bcrypt(self, password: str) -> HashResult:
        """Hash password using bcrypt"""
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt not installed")
        
        start_time = time.perf_counter()
        
        # bcrypt includes salt in the output
        hash_bytes = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=self.costs['bcrypt']['rounds'])
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return HashResult(
            hash_value=hash_bytes.decode('utf-8'),
            algorithm='bcrypt',
            salt='embedded',
            time_ms=elapsed_ms,
            cost_factors={'rounds': self.costs['bcrypt']['rounds']}
        )
    
    def hash_argon2(self, password: str) -> HashResult:
        """Hash password using Argon2id (winner of Password Hashing Competition)"""
        if not ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi not installed")
        
        ph = PasswordHasher(
            time_cost=self.costs['argon2']['time_cost'],
            memory_cost=self.costs['argon2']['memory_cost'],
            parallelism=self.costs['argon2']['parallelism']
        )
        
        start_time = time.perf_counter()
        hash_value = ph.hash(password)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # Argon2 hash contains all parameters
        return HashResult(
            hash_value=hash_value,
            algorithm='Argon2id',
            salt='embedded',
            time_ms=elapsed_ms,
            cost_factors={
                'time_cost': self.costs['argon2']['time_cost'],
                'memory_cost': self.costs['argon2']['memory_cost'],
                'parallelism': self.costs['argon2']['parallelism']
            }
        )
    
    def verify_pbkdf2(self, password: str, stored_hash: str, salt_hex: str) -> bool:
        """Verify PBKDF2 password"""
        new_hash = self.hash_pbkdf2(password, bytes.fromhex(salt_hex))
        return new_hash.hash_value == stored_hash
    
    def verify_bcrypt(self, password: str, stored_hash: str) -> bool:
        """Verify bcrypt password"""
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt not installed")
        
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except ValueError:
            return False
    
    def verify_argon2(self, password: str, stored_hash: str) -> bool:
        """Verify Argon2 password"""
        if not ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi not installed")
        
        ph = PasswordHasher()
        try:
            ph.verify(stored_hash, password)
            return True
        except argon2.exceptions.VerificationError:
            return False
    
    def create_user(self, username: str, password: str, algorithm: str = 'argon2') -> Dict:
        """Create a new user with hashed password"""
        if username in self.user_database:
            raise ValueError(f"User {username} already exists")
        
        if algorithm == 'pbkdf2':
            result = self.hash_pbkdf2(password)
        elif algorithm == 'bcrypt':
            result = self.hash_bcrypt(password)
        elif algorithm == 'argon2':
            result = self.hash_argon2(password)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        self.user_database[username] = {
            'hash': result.hash_value,
            'algorithm': result.algorithm,
            'salt': result.salt if algorithm == 'pbkdf2' else None,
            'cost_factors': result.cost_factors,
            'created_at': time.time()
        }
        
        return self.user_database[username]
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate a user"""
        if username not in self.user_database:
            return False, "User not found"
        
        user_data = self.user_database[username]
        
        if user_data['algorithm'] == 'PBKDF2-SHA256':
            valid = self.verify_pbkdf2(password, user_data['hash'], user_data['salt'])
        elif user_data['algorithm'] == 'bcrypt':
            valid = self.verify_bcrypt(password, user_data['hash'])
        elif user_data['algorithm'] == 'Argon2id':
            valid = self.verify_argon2(password, user_data['hash'])
        else:
            return False, "Unknown algorithm"
        
        if valid:
            return True, "Authentication successful"
        else:
            return False, "Invalid password"
    
    def benchmark_algorithms(self, password: str = "TestPassword123!", iterations: int = 5):
        """Benchmark different hashing algorithms"""
        results = {}
        
        print(f"\nBenchmarking (average of {iterations} iterations):")
        print("-" * 60)
        
        # PBKDF2
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.hash_pbkdf2(password)
            times.append((time.perf_counter() - start) * 1000)
        results['PBKDF2'] = sum(times) / len(times)
        
        # bcrypt
        if BCRYPT_AVAILABLE:
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                self.hash_bcrypt(password)
                times.append((time.perf_counter() - start) * 1000)
            results['bcrypt'] = sum(times) / len(times)
        
        # Argon2
        if ARGON2_AVAILABLE:
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                self.hash_argon2(password)
                times.append((time.perf_counter() - start) * 1000)
            results['Argon2id'] = sum(times) / len(times)
        
        for algo, time_ms in results.items():
            print(f"{algo:12s}: {time_ms:6.2f} ms")
        
        return results


class PasswordPolicy:
    """Enforce password complexity requirements"""
    
    def __init__(self):
        self.policies = {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_special': True,
            'max_identical_chars': 3,
            'disallow_common_passwords': True,
            'min_entropy_bits': 40
        }
        
        # Common weak passwords (truncated list)
        self.common_passwords = {
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', 'dragon', 'master', 'password123'
        }
    
    def check_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of password"""
        from collections import Counter
        import math
        
        length = len(password)
        if length == 0:
            return 0.0
        
        freq = Counter(password)
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy * length
    
    def evaluate(self, password: str) -> Tuple[bool, list]:
        """
        Evaluate password against policies
        Returns (is_valid, list_of_issues)
        """
        issues = []
        
        # Length check
        if len(password) < self.policies['min_length']:
            issues.append(f"Minimum length {self.policies['min_length']} characters")
        
        # Character requirements
        if self.policies['require_uppercase'] and not any(c.isupper() for c in password):
            issues.append("At least one uppercase letter")
        
        if self.policies['require_lowercase'] and not any(c.islower() for c in password):
            issues.append("At least one lowercase letter")
        
        if self.policies['require_digits'] and not any(c.isdigit() for c in password):
            issues.append("At least one digit")
        
        if self.policies['require_special']:
            special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
            if not any(c in special_chars for c in password):
                issues.append("At least one special character")
        
        # Check for repeated characters
        max_same = 1
        current_count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                current_count += 1
                max_same = max(max_same, current_count)
            else:
                current_count = 1
        
        if max_same > self.policies['max_identical_chars']:
            issues.append(f"No more than {self.policies['max_identical_chars']} identical characters in a row")
        
        # Check common passwords
        if self.policies['disallow_common_passwords']:
            if password.lower() in self.common_passwords:
                issues.append("Password is too common")
        
        # Check entropy
        entropy = self.check_entropy(password)
        if entropy < self.policies['min_entropy_bits']:
            issues.append(f"Password entropy too low ({entropy:.1f} bits, need {self.policies['min_entropy_bits']})")
        
        return len(issues) == 0, issues, entropy


def main():
    print("SECURE PASSWORD HASHING AND AUTHENTICATION")
    print("=" * 60)
    
    # Initialize password hasher
    hasher = SecurePasswordHasher()
    
    # 1. Password Hashing Demonstration
    print("\n1. Password Hashing Algorithms")
    print("-" * 40)
    
    password = "MySecurePassword123!"
    
    # Hash with different algorithms
    pbkdf2_result = hasher.hash_pbkdf2(password)
    print(f"PBKDF2: {pbkdf2_result.hash_value[:64]}... ({pbkdf2_result.time_ms:.2f} ms)")
    
    if BCRYPT_AVAILABLE:
        bcrypt_result = hasher.hash_bcrypt(password)
        print(f"bcrypt: {bcrypt_result.hash_value[:64]}... ({bcrypt_result.time_ms:.2f} ms)")
    
    if ARGON2_AVAILABLE:
        argon2_result = hasher.hash_argon2(password)
        print(f"Argon2id: {argon2_result.hash_value[:64]}... ({argon2_result.time_ms:.2f} ms)")
    
    # 2. User Registration and Authentication
    print("\n2. User Authentication System")
    print("-" * 40)
    
    # Create users with different algorithms
    hasher.create_user("alice", "AlicePassword123!", algorithm="pbkdf2")
    if BCRYPT_AVAILABLE:
        hasher.create_user("bob", "BobSecure456@", algorithm="bcrypt")
    if ARGON2_AVAILABLE:
        hasher.create_user("carol", "CarolSecret789#", algorithm="argon2")
    
    # Authenticate users
    print("\nAuthentication tests:")
    success, msg = hasher.authenticate("alice", "AlicePassword123!")
    print(f"  Alice (correct): {msg}")
    
    success, msg = hasher.authenticate("alice", "WrongPassword")
    print(f"  Alice (wrong): {msg}")
    
    if BCRYPT_AVAILABLE:
        success, msg = hasher.authenticate("bob", "BobSecure456@")
        print(f"  Bob (correct): {msg}")
    
    # 3. Password Policy Enforcement
    print("\n3. Password Complexity Policy")
    print("-" * 40)
    
    policy = PasswordPolicy()
    
    test_passwords = [
        "weak",
        "Password123",
        "StrongP@ssw0rd2024!",
        "aaaaaaaaaaaa",
        "CommonPassword123"
    ]
    
    for pwd in test_passwords:
        is_valid, issues, entropy = policy.evaluate(pwd)
        status = "✓" if is_valid else "✗"
        print(f"\n{status} Password: {pwd}")
        print(f"   Entropy: {entropy:.1f} bits")
        if issues:
            print(f"   Issues: {', '.join(issues[:3])}")
            if len(issues) > 3:
                print(f"   ... and {len(issues)-3} more")
    
    # 4. Benchmark Performance
    print("\n4. Performance Benchmark")
    print("-" * 40)
    hasher.benchmark_algorithms(iterations=3)
    
    # 5. Salt and Rainbow Table Protection
    print("\n5. Salt Demonstration")
    print("-" * 40)
    
    same_password = "CommonPassword"
    hash1 = hasher.hash_pbkdf2(same_password)
    hash2 = hasher.hash_pbkdf2(same_password)
    
    print(f"Same password, different salts:")
    print(f"  Hash 1: {hash1.hash_value[:32]}...")
    print(f"  Hash 2: {hash2.hash_value[:32]}...")
    print(f"  Hashes identical? {hash1.hash_value == hash2.hash_value}")
    print(f"  This prevents rainbow table attacks!")
    
    # 6. Security Best Practices
    print("\n" + "="*60)
    print("PASSWORD SECURITY BEST PRACTICES")
    print("="*60)
    print("""
    DO's:
    ✓ Use Argon2id as first choice, then bcrypt, then PBKDF2
    ✓ Use unique random salts for each password
    ✓ Use high cost factors (adjust based on hardware)
    ✓ Enforce strong password policies
    ✓ Implement rate limiting on authentication attempts
    
    DON'Ts:
    ✗ Never store passwords in plain text
    ✗ Never use MD5 or SHA1 for passwords
    ✗ Never implement your own hashing algorithm
    ✗ Never use unsalted hashes
    ✗ Never log or display passwords
    """)
    
    # Bonus: Time-based comparison
    print("\n6. Time-Memory Tradeoff")
    print("-" * 40)
    
    print("Modern hashing algorithms are intentionally slow.")
    print("This makes brute-force attacks expensive for attackers,")
    print("while being acceptable for legitimate authentication (under 1 second).")
    print("\nFor production systems, adjust cost factors so that")
    print("hashing takes ~200-500ms on your target hardware.")


if __name__ == "__main__":
    main()
