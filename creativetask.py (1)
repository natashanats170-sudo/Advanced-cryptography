import math

def analyze_password(password: str) -> dict:
    """
    Returns entropy (bits), pool size, and a strength label.
    """
    length = len(password)
    pool   = 0

    has_lower  = any(c.islower()     for c in password)
    has_upper  = any(c.isupper()     for c in password)
    has_digit  = any(c.isdigit()     for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower:  pool += 26
    if has_upper:  pool += 26
    if has_digit:  pool += 10
    if has_symbol: pool += 33

    if pool == 0 or length == 0:
        return {"entropy": 0, "pool": 0, "verdict": "Empty – no password entered."}

    entropy = length * math.log2(pool)

    if entropy < 28:
        verdict = "Very Weak – trivially guessable."
    elif entropy < 36:
        verdict = "Weak – easily guessable."
    elif entropy < 60:
        verdict = "Moderate – some resistance, but improvable."
    elif entropy < 128:
        verdict = "Strong – resistant to brute force."
    else:
        verdict = "Very Strong – excellent resistance."

    return {
        "length":  length,
        "pool":    pool,
        "entropy": round(entropy, 2),
        "verdict": verdict,
    }


# ── Demo ──────────────────────────────────────────────────────────────────
test_passwords = ["abc", "password", "P@ssw0rd", "Tr0ub4dor&3", "X9#mK@2pLq!vR7$e"]

for pwd in test_passwords:
    result = analyze_password(pwd)
    print(f"Password : {pwd}")
    print(f"  Pool   : {result['pool']} chars")
    print(f"  Entropy: {result['entropy']} bits")
    print(f"  Verdict: {result['verdict']}")
    print()
