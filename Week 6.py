"""
password_hashing_comparison.py
Comprehensive comparison of bcrypt vs SHA-256 for password security
Demonstrates salting, key stretching, and resistance to attacks
"""

import hashlib
import bcrypt
import time
import os
import secrets
import string
from collections import defaultdict
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
import numpy as np

class PasswordSecurityDemo:
    """
    Demonstrates password security differences between bcrypt and SHA-256
    Shows why modern authentication systems use bcrypt/Argon2 instead of plain SHA
    """
    
    def __init__(self):
        self.rainbow_tables = {}  # Simulated rainbow table
        self.breached_passwords = set()
        
    # ==================== SHA-256 (INSECURE for passwords) ====================
    
    def hash_sha256_unsalted(self, password: str) -> str:
        """Hash password with SHA-256 - NO SALT (VULNERABLE)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def hash_sha256_salted(self, password: str, salt: bytes = None) -> Tuple[str, bytes]:
        """Hash password with SHA-256 - WITH SALT (better but still fast)"""
        if salt is None:
            salt = os.urandom(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1)
        return hash_obj.hex(), salt
    
    def hash_sha256_stretched(self, password: str, salt: bytes = None, iterations: int = 100000) -> Tuple[str, bytes]:
        """Hash with SHA-256 using key stretching (PBKDF2)"""
        if salt is None:
            salt = os.urandom(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return hash_obj.hex(), salt
    
    # ==================== bcrypt (SECURE for passwords) ====================
    
    def hash_bcrypt(self, password: str, rounds: int = 12) -> str:
        """
        Hash password with bcrypt
        - Automatically includes salt
        - Key stretching (2^rounds iterations)
        - Adaptive (can increase rounds as hardware improves)
        """
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def verify_bcrypt(self, password: str, hashed: str) -> bool:
        """Verify password against bcrypt hash"""
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    # ==================== Attack Simulations ====================
    
    def build_rainbow_table(self, common_passwords: List[str], algorithm: str = 'sha256'):
        """
        Build a simulated rainbow table for common passwords
        This shows how attackers pre-compute hashes
        """
        rainbow = {}
        for password in common_passwords:
            if algorithm == 'sha256':
                rainbow[password] = self.hash_sha256_unsalted(password)
            elif algorithm == 'bcrypt':
                # Note: Building rainbow table for bcrypt is impractical due to salt
                rainbow[password] = "[HASH WITH SALT - CAN'T PRECOMPUTE]"
        return rainbow
    
    def brute_force_demo(self, target_hash: str, algorithm: str, max_attempts: int = 100000):
        """
        Simulate brute force attack on password hash
        Shows how computational cost affects attack feasibility
        """
        print(f"\n{'='*60}")
        print(f"BRUTE FORCE ATTACK SIMULATION - {algorithm.upper()}")
        print(f"{'='*60}")
        
        # Simulated password space (4-character lowercase only for demo)
        chars = string.ascii_lowercase
        attempts = 0
        start_time = time.time()
        found = False
        
        # Try all combinations of increasing length
        for length in range(1, 5):
            for combo in self._generate_combinations(chars, length):
                attempts += 1
                test_pwd = ''.join(combo)
                
                if algorithm == 'sha256_unsalted':
                    test_hash = self.hash_sha256_unsalted(test_pwd)
                elif algorithm == 'sha256_salted':
                    # Extract salt from target (simplified)
                    test_hash, _ = self.hash_sha256_salted(test_pwd, b'salt')
                elif algorithm == 'bcrypt':
                    test_hash = self.hash_bcrypt(test_pwd)
                else:
                    continue
                
                if test_hash == target_hash:
                    found = True
                    break
                
                if attempts >= max_attempts:
                    break
            
            if found or attempts >= max_attempts:
                break
        
        elapsed = time.time() - start_time
        
        if found:
            print(f"✓ Password found in {attempts} attempts ({elapsed:.2f} seconds)")
        else:
            print(f"✗ Password NOT found after {attempts} attempts ({elapsed:.2f} seconds)")
        
        return found, attempts, elapsed
    
    def _generate_combinations(self, chars, length):
        """Generate all combinations of given length"""
        if length == 1:
            for c in chars:
                yield [c]
        else:
            for c in chars:
                for rest in self._generate_combinations(chars, length - 1):
                    yield [c] + rest
    
    def rainbow_table_attack(self, target_hash: str, rainbow_table: Dict) -> bool:
        """
        Simulate rainbow table attack
        Shows how pre-computed tables allow instant hash reversal
        """
        for password, hash_value in rainbow_table.items():
            if hash_value == target_hash:
                return True, password
        return False, None
    
    # ==================== Performance Testing ====================
    
    def performance_test(self, password: str, iterations: int = 10) -> Dict:
        """
        Measure hashing speed for different algorithms
        Slower is better for password hashing!
        """
        results = {}
        
        # SHA-256 unsalted (VERY FAST - BAD for passwords)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.hash_sha256_unsalted(password)
            times.append((time.perf_counter() - start) * 1000)
        results['SHA-256 (unsalted)'] = {
            'avg_ms': sum(times) / len(times),
            'hashes_per_second': 1000 / (sum(times) / len(times))
        }
        
        # SHA-256 with salt (still fast)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.hash_sha256_salted(password)
            times.append((time.perf_counter() - start) * 1000)
        results['SHA-256 (salted)'] = {
            'avg_ms': sum(times) / len(times),
            'hashes_per_second': 1000 / (sum(times) / len(times))
        }
        
        # SHA-256 with stretching (PBKDF2 - 100k iterations)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.hash_sha256_stretched(password, iterations=100000)
            times.append((time.perf_counter() - start) * 1000)
        results['SHA-256 (stretched, 100k)'] = {
            'avg_ms': sum(times) / len(times),
            'hashes_per_second': 1000 / (sum(times) / len(times))
        }
        
        # bcrypt (rounds=12)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.hash_bcrypt(password, rounds=12)
            times.append((time.perf_counter() - start) * 1000)
        results['bcrypt (rounds=12)'] = {
            'avg_ms': sum(times) / len(times),
            'hashes_per_second': 1000 / (sum(times) / len(times))
        }
        
        # bcrypt (rounds=14) - slower but more secure
        times = []
        for _ in range(min(iterations, 5)):  # Fewer iterations for slower hash
            start = time.perf_counter()
            self.hash_bcrypt(password, rounds=14)
            times.append((time.perf_counter() - start) * 1000)
        results['bcrypt (rounds=14)'] = {
            'avg_ms': sum(times) / len(times) if times else 0,
            'hashes_per_second': 1000 / (sum(times) / len(times)) if times else 0
        }
        
        return results
    
    # ==================== Salt Demonstration ====================
    
    def salt_demonstration(self, password: str):
        """Show how salting makes identical passwords hash differently"""
        print(f"\n{'='*60}")
        print("SALT DEMONSTRATION - Same Password, Different Hashes")
        print(f"{'='*60}")
        print(f"Password: '{password}'\n")
        
        # SHA-256 without salt
        hash1 = self.hash_sha256_unsalted(password)
        hash2 = self.hash_sha256_unsalted(password)
        print(f"SHA-256 (no salt):")
        print(f"  Attempt 1: {hash1}")
        print(f"  Attempt 2: {hash2}")
        print(f"  Identical? ✓ YES - Rainbow table vulnerable!\n")
        
        # SHA-256 with salt
        hash1, salt1 = self.hash_sha256_salted(password)
        hash2, salt2 = self.hash_sha256_salted(password)
        print(f"SHA-256 (with salt):")
        print(f"  Salt 1: {salt1.hex()}")
        print(f"  Hash 1: {hash1[:32]}...")
        print(f"  Salt 2: {salt2.hex()}")
        print(f"  Hash 2: {hash2[:32]}...")
        print(f"  Identical? ✗ NO - Rainbow table ineffective!\n")
        
        # bcrypt (includes salt automatically)
        bcrypt_hash1 = self.hash_bcrypt(password)
        bcrypt_hash2 = self.hash_bcrypt(password)
        print(f"bcrypt (salt embedded):")
        print(f"  Hash 1: {bcrypt_hash1[:40]}...")
        print(f"  Hash 2: {bcrypt_hash2[:40]}...")
        print(f"  Identical? ✗ NO - Salt + stretching!")
    
    # ==================== Cost Factor Demonstration ====================
    
    def cost_factor_demo(self, password: str):
        """Demonstrate how bcrypt cost factor affects performance and security"""
        print(f"\n{'='*60}")
        print("COST FACTOR DEMONSTRATION (bcrypt)")
        print(f"{'='*60}")
        
        for rounds in [8, 10, 12, 14]:
            if rounds > 12:
                print(f"\nTesting rounds={rounds} (this will be slower)...")
            
            start = time.perf_counter()
            hash_value = self.hash_bcrypt(password, rounds=rounds)
            elapsed = time.perf_counter() - start
            
            # Time to crack estimate (simplified)
            hashes_per_second = 1 / elapsed
            annual_cracks = hashes_per_second * 86400 * 365
            years_to_crack_billion = 1_000_000_000 / annual_cracks
            
            print(f"\nRounds = {rounds:2d} (2^{rounds} = {2**rounds:,} iterations):")
            print(f"  Hashing time: {elapsed*1000:.2f} ms")
            print(f"  Hashes/second: {hashes_per_second:.1f}")
            print(f"  Time to crack 1B passwords: {years_to_crack_billion:.1f} years (at this speed)")
    
    # ==================== Authentication System Demo ====================
    
    class AuthSystem:
        """Complete authentication system using bcrypt"""
        
        def __init__(self):
            self.users = {}
            self.login_attempts = defaultdict(int)
            self.lockout_time = 300  # 5 minutes
            self.max_attempts = 5
        
        def register(self, username: str, password: str, hasher) -> bool:
            """Register a new user with bcrypt hashed password"""
            if username in self.users:
                print(f"✗ Username '{username}' already exists")
                return False
            
            # Hash password with bcrypt
            hashed = hasher.hash_bcrypt(password)
            
            self.users[username] = {
                'hash': hashed,
                'created_at': time.time(),
                'last_login': None
            }
            
            print(f"✓ User '{username}' registered successfully")
            print(f"  Password hash: {hashed[:40]}...")
            return True
        
        def login(self, username: str, password: str, hasher) -> Tuple[bool, str]:
            """Authenticate user with rate limiting"""
            
            # Check lockout
            if username in self.login_attempts:
                attempts, lockout_until = self.login_attempts[username]
                if lockout_until > time.time():
                    remaining = int(lockout_until - time.time())
                    return False, f"Account locked. Try again in {remaining} seconds"
            
            if username not in self.users:
                return False, "Invalid username or password"
            
            # Verify password using bcrypt
            stored_hash = self.users[username]['hash']
            if hasher.verify_bcrypt(password, stored_hash):
                self.users[username]['last_login'] = time.time()
                self.login_attempts[username] = (0, 0)  # Reset attempts
                return True, "Login successful"
            else:
                # Increment failed attempts
                attempts, _ = self.login_attempts.get(username, (0, 0))
                attempts += 1
                remaining = self.max_attempts - attempts
                if attempts >= self.max_attempts:
                    lockout_until = time.time() + self.lockout_time
                    self.login_attempts[username] = (attempts, lockout_until)
                    return False, f"Too many failed attempts. Account locked for {self.lockout_time} seconds"
                else:
                    self.login_attempts[username] = (attempts, 0)
                    return False, f"Invalid password. {remaining} attempts remaining"
        
        def get_user_stats(self, username: str) -> Dict:
            """Get user statistics"""
            if username not in self.users:
                return {}
            user = self.users[username]
            return {
                'username': username,
                'created': time.ctime(user['created_at']),
                'last_login': time.ctime(user['last_login']) if user['last_login'] else 'Never',
                'hash_prefix': user['hash'][:30] + '...'
            }
    
    # ==================== Rainbow Table Attack Demo ====================
    
    def rainbow_table_demo(self, common_passwords: List[str]):
        """Demonstrate why salting defeats rainbow tables"""
        print(f"\n{'='*60}")
        print("RAINBOW TABLE ATTACK DEMONSTRATION")
        print(f"{'='*60}")
        
        # Build rainbow table for unsalted SHA-256
        print("\n1. Building rainbow table for unsalted SHA-256...")
        rainbow_unsalted = {}
        for pwd in common_passwords:
            rainbow_unsalted[pwd] = self.hash_sha256_unsalted(pwd)
        
        print(f"   Rainbow table built with {len(rainbow_unsalted)} entries")
        print(f"   Example entry: '{common_passwords[0]}' -> {rainbow_unsalted[common_passwords[0]][:32]}...")
        
        # Hash a password with unsalted SHA-256
        test_password = common_passwords[2]
        target_hash = self.hash_sha256_unsalted(test_password)
        
        print(f"\n2. Attacking unsalted SHA-256 hash:")
        print(f"   Target hash: {target_hash[:32]}...")
        
        # Rainbow table lookup (instant)
        found, cracked = self.rainbow_table_attack(target_hash, rainbow_unsalted)
        if found:
            print(f"   ✓ CRACKED! Password is '{cracked}'")
            print(f"   ⚠ Attack time: microseconds (instant)")
        else:
            print(f"   ✗ Not found in rainbow table")
        
        # Try with salted SHA-256
        print(f"\n3. Attacking salted SHA-256:")
        salted_hash, salt = self.hash_sha256_salted(test_password)
        print(f"   Salt: {salt.hex()}")
        print(f"   Hash: {salted_hash[:32]}...")
        
        # Rainbow table lookup (fails because of salt)
        found, _ = self.rainbow_table_attack(salted_hash, rainbow_unsalted)
        if not found:
            print(f"   ✗ Rainbow table attack FAILED!")
            print(f"   ✓ Salt makes pre-computed tables useless")
        
        # Try with bcrypt
        print(f"\n4. Attacking bcrypt hash:")
        bcrypt_hash = self.hash_bcrypt(test_password)
        print(f"   Hash: {bcrypt_hash[:40]}...")
        print(f"   ✗ Rainbow table attack impossible")
        print(f"   ✓ bcrypt includes salt AND is intentionally slow")
    
    # ==================== Visualization ====================
    
    def visualize_performance(self, results: Dict):
        """Create visualization of hashing performance"""
        try:
            algorithms = list(results.keys())
            times = [results[algo]['avg_ms'] for algo in algorithms]
            
            plt.figure(figsize=(12, 6))
            bars = plt.bar(algorithms, times, color=['red', 'orange', 'yellow', 'green', 'blue'])
            plt.ylabel('Time (milliseconds)')
            plt.title('Password Hashing Speed Comparison\n(Slower = More Secure Against Brute Force)')
            plt.xticks(rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, time_ms in zip(bars, times):
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{time_ms:.2f}ms',
                        ha='center', va='bottom')
            
            # Add annotation
            plt.text(0.5, -0.3, 
                    "Note: SHA-256 is extremely fast (bad for passwords)\nbcrypt is slow (good for passwords)",
                    transform=plt.gca().transAxes,
                    ha='center', fontsize=10, style='italic')
            
            plt.tight_layout()
            plt.show()
        except Exception as e:
            print(f"Could not create visualization: {e}")
            print("(Matplotlib not installed - install with: pip install matplotlib)")

def main():
    """Main demonstration"""
    print("=" * 80)
    print("PASSWORD SECURITY: bcrypt vs SHA-256")
    print("Understanding Salt, Key Stretching, and Attack Resistance")
    print("=" * 80)
    
    demo = PasswordSecurityDemo()
    
    # 1. SALT DEMONSTRATION
    print("\n" + "="*80)
    print("SECTION 1: Why Salting is Critical")
    print("="*80)
    demo.salt_demonstration("MySecret123")
    
    # 2. RAINBOW TABLE ATTACK DEMO
    print("\n" + "="*80)
    print("SECTION 2: Rainbow Table Attack Demonstration")
    print("="*80)
    common_passwords = ["password123", "qwerty", "admin", "letmein", "welcome"]
    demo.rainbow_table_demo(common_passwords)
    
    # 3. PERFORMANCE COMPARISON
    print("\n" + "="*80)
    print("SECTION 3: Performance Comparison (Speed = Weakness)")
    print("="*80)
    results = demo.performance_test("TestPassword123", iterations=5)
    
    print("\nHashing Speed Results (lower is WORSE for security):")
    print("-" * 60)
    for algo, data in results.items():
        print(f"{algo:30s}: {data['avg_ms']:8.2f} ms ({data['hashes_per_second']:10,.0f} hashes/second)")
    
    print("\n⚡ SHA-256: MILLIONS of hashes/second - Attacker can brute force rapidly")
    print("✓ bcrypt: Hundreds of hashes/second - Attacker needs decades")
    
    # 4. COST FACTOR DEMONSTRATION
    print("\n" + "="*80)
    print("SECTION 4: bcrypt Cost Factor (Adaptive Security)")
    print("="*80)
    demo.cost_factor_demo("TestPassword")
    
    # 5. COMPLETE AUTHENTICATION SYSTEM
    print("\n" + "="*80)
    print("SECTION 5: Production-Ready Authentication System")
    print("="*80)
    
    auth = demo.AuthSystem()
    
    # Register users
    print("\nUser Registration:")
    print("-" * 40)
    auth.register("alice", "AliceSecurePassword123!", demo)
    auth.register("bob", "BobStrongPassword456@", demo)
    
    # Attempt registration with existing username
    auth.register("alice", "AnotherPassword", demo)
    
    # Login attempts
    print("\nLogin Attempts:")
    print("-" * 40)
    
    # Successful login
    success, msg = auth.login("alice", "AliceSecurePassword123!", demo)
    print(f"Alice (correct password): {msg}")
    
    # Failed login
    success, msg = auth.login("alice", "WrongPassword", demo)
    print(f"Alice (wrong password): {msg}")
    
    # Multiple failed attempts (lockout simulation)
    print("\nSimulating brute force protection (multiple failures):")
    for i in range(4):
        success, msg = auth.login("bob", f"wrong_{i}", demo)
        print(f"  Attempt {i+1}: {msg}")
    
    # User stats
    print("\nUser Statistics:")
    print("-" * 40)
    for username in ["alice", "bob"]:
        stats = auth.get_user_stats(username)
        if stats:
            print(f"{stats['username']}:")
            print(f"  Created: {stats['created']}")
            print(f"  Last login: {stats['last_login']}")
            print(f"  Hash prefix: {stats['hash_prefix']}")
    
    # 6. SECURITY COMPARISON SUMMARY
    print("\n" + "="*80)
    print("SECTION 6: Security Comparison Summary")
    print("="*80)
    
    comparison = {
        "Feature": ["Salt", "Key Stretching", "Adaptive Cost", "Brute Force Resistance", "Rainbow Table Resistance", "GPU Resistant", "Timing Safe"],
        "SHA-256 (unsalted)": ["✗", "✗", "✗", "✗ (extremely weak)", "✗", "✗", "✓"],
        "SHA-256 (salted)": ["✓", "✗", "✗", "✗ (still too fast)", "✓", "✗", "✓"],
        "SHA-256 (PBKDF2)": ["✓", "✓", "✗ (fixed iterations)", "⚠ (better but fast)", "✓", "✗", "✓"],
        "bcrypt": ["✓", "✓", "✓", "✓", "✓", "✓", "✓"]
    }
    
    print("\n{:<25} {:<25} {:<25} {:<25}".format(
        comparison["Feature"][0],
        "SHA-256 (unsalted)",
        "SHA-256 (salted)",
        "bcrypt"
    ))
    print("-" * 100)
    
    for i in range(1, len(comparison["Feature"])):
        print("{:<25} {:<25} {:<25} {:<25}".format(
            comparison["Feature"][i],
            comparison["SHA-256 (unsalted)"][i] if i < len(comparison["SHA-256 (unsalted)"]) else "N/A",
            comparison["SHA-256 (salted)"][i] if i < len(comparison["SHA-256 (salted)"]) else "N/A",
            comparison["bcrypt"][i] if i < len(comparison["bcrypt"]) else "N/A"
        ))
    
    # 7. BEST PRACTICES
    print("\n" + "="*80)
    print("SECURITY BEST PRACTICES - What We Learned")
    print("="*80)
    
    best_practices = """
    ✓ ALWAYS use bcrypt, Argon2id, or PBKDF2 for passwords
    ✓ NEVER use plain SHA-256, MD5, or unsalted hashes
    ✓ ALWAYS use a unique salt for each password
    ✓ Use key stretching (many iterations) to slow down hashing
    ✓ Implement account lockout after failed attempts
    ✓ Use adaptive cost factors (increase as hardware improves)
    ✓ Store ONLY the hash, never the plaintext password
    ✓ Use HTTPS for all authentication traffic
    
    ⚠ Even with bcrypt, enforce strong password policies
    ⚠ Monitor for breached passwords (use haveibeenpwned API)
    ⚠ Implement MFA for additional security layer
    """
    print(best_practices)
    
    # 8. REAL-WORLD ATTACK SCENARIO
    print("\n" + "="*80)
    print("REAL-WORLD ATTACK SCENARIO: Database Breach")
    print("="*80)
    
    print("""
    Scenario: A website's password database is stolen.
    
    If passwords were stored with:
    
    ❌ PLAIN TEXT:    Attacker instantly sees all passwords
    ❌ MD5/SHA-256:   Attacker cracks billions of passwords/hour with GPUs
    ❌ SHA-256+salt:   Slightly better but still vulnerable to GPU cracking
    ✓ bcrypt:         Attacker cracks only ~100 passwords/second
                      With cost factor 12, cracking 1M passwords would take:
                      ~10,000 seconds per password = ~115 days for ONE password!
                      For 1M passwords: 115 million days (impossible!)
    
    This is why bcrypt and similar algorithms are industry standard.
    """)
    
    # Optional: Visualization
    try:
        demo.visualize_performance(results)
    except:
        pass  # Skip if matplotlib not available
    
    print("\n" + "="*80)
    print("CONCLUSION")
    print("="*80)
    print("""
    Through practical exercises, we have demonstrated:
    
    1. Salt prevents rainbow table attacks by making identical passwords hash uniquely
    2. Key stretching (iterations) slows down brute force attempts significantly
    3. bcrypt's adaptive cost factor allows security to increase with hardware improvements
    4. Fast hashing algorithms (SHA-256) are DANGEROUS for passwords
    5. Production systems MUST implement rate limiting and account lockout
    
    The bcrypt authentication system built here represents industry best practices
    for secure password storage and verification.
    """)
    
    print("\nDemo complete! Remember: NEVER store plaintext passwords!")

if __name__ == "__main__":
    main()
