============================================
  PASSWORD STRENGTH ANALYZER
  Cybersecurity Portfolio Tool
  Author: Shyaka Imena Cedric
  GitHub: github.com/YOUR_USERNAME
  Description: Analyzes password strength using
               multiple security criteria:
               - Entropy calculation
               - Pattern detection (keyboard walks,
                 common substitutions, dates)
               - Dictionary/common password check
               - Estimated crack time
               - Actionable improvement tips
==============================================
"""

import re
import math
import hashlib
import argparse
import getpass
from typing import Tuple


# ──────────────────────────────────────────
# COMMON PASSWORDS (top 50 subset for demo)
# In production: load from rockyou.txt or similar
# ──────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "dragon",
    "master", "hello", "shadow", "sunshine", "princess",
    "welcome", "login", "solo", "starwars", "football",
    "iloveyou", "passw0rd", "superman", "batman", "trustno1",
    "access", "mustang", "michael", "jessica", "123456789",
    "696969", "password1", "test", "root", "toor",
    "qwerty123", "mypassword", "pass", "secret", "admin123",
    "changeme", "default", "system", "123qwe", "pass123",
    "rwanda2024", "kigali123", "rwanda123", "africa123", "12345678"
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qweasd", "asdzxc",
    "123456", "234567", "345678", "456789", "567890",
    "qwertyuiop", "asdfghjkl", "zxcvbnm"
]

# Substitution map (leet speak)
LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '@': 'a',
    '$': 's', '!': 'i', '+': 't'
})


# ──────────────────────────────────────────
# ENTROPY CALCULATOR
# ──────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password): charset_size += 32
    if not charset_size:
        charset_size = 26

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


# ──────────────────────────────────────────
# CRACK TIME ESTIMATOR
# ──────────────────────────────────────────
def estimate_crack_time(entropy: float) -> str:
    """Estimate time to crack based on entropy (offline, 10B guesses/sec)."""
    guesses = 2 ** entropy
    guesses_per_second = 10_000_000_000  # 10 billion (GPU cracking)
    seconds = guesses / guesses_per_second

    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 2592000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000:
        return f"{int(seconds // 2592000)} months"
    elif seconds < 3153600000:
        return f"{int(seconds // 31536000)} years"
    else:
        return "centuries"


# ──────────────────────────────────────────
# WEAKNESS DETECTORS
# ──────────────────────────────────────────
def check_common_password(password: str) -> Tuple[bool, str]:
    lower = password.lower()
    deeted = lower.translate(LEET_MAP)  # check leet speak too
    if lower in COMMON_PASSWORDS or deeted in COMMON_PASSWORDS:
        return True, "Password is in the common passwords list (will be cracked instantly)"
    return False, ""


def check_keyboard_walk(password: str) -> Tuple[bool, str]:
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            return True, f"Contains keyboard pattern: '{walk}'"
    return False, ""


def check_repeated_chars(password: str) -> Tuple[bool, str]:
    if re.search(r'(.)\1{2,}', password):
        return True, "Contains 3+ repeated characters (e.g. 'aaa', '111')"
    return False, ""


def check_date_pattern(password: str) -> Tuple[bool, str]:
    if re.search(r'(19|20)\d{2}', password):
        return True, "Contains a year (e.g. 2024) — easily guessed"
    if re.search(r'\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2,4}\b', password):
        return True, "Contains what looks like a date"
    return False, ""


def check_length(password: str) -> Tuple[bool, str]:
    if len(password) < 8:
        return True, f"Too short: {len(password)} chars (minimum: 8, recommended: 12+)"
    return False, ""


# ──────────────────────────────────────────
# SCORING ENGINE
# ──────────────────────────────────────────
def score_password(password: str):
    score = 0
    tips = []
    warnings = []

    # Length scoring
    length = len(password)
    if length >= 20: score += 30
    elif length >= 16: score += 25
    elif length >= 12: score += 20
    elif length >= 8: score += 10
    else:
        score -= 20
        tips.append("🔧 Make it at least 12 characters long")

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', password))

    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 10

    if not has_upper: tips.append("🔧 Add uppercase letters (A-Z)")
    if not has_lower: tips.append("🔧 Add lowercase letters (a-z)")
    if not has_digit: tips.append("🔧 Add numbers (0-9)")
    if not has_special: tips.append("🔧 Add special characters (!@#$%...)")

    # Weakness checks
    checks = [
        check_common_password(password),
        check_keyboard_walk(password),
        check_repeated_chars(password),
        check_date_pattern(password),
        check_length(password),
    ]

    for failed, msg in checks:
        if failed:
            score -= 20
            warnings.append(f"⚠️  {msg}")

    # Entropy bonus
    entropy = calculate_entropy(password)
    if entropy > 60: score += 20
    elif entropy > 40: score += 10

    # Cap score
    score = max(0, min(score, 100))

    return score, entropy, tips, warnings


# ──────────────────────────────────────────
# STRENGTH LABEL
# ──────────────────────────────────────────
def get_strength_label(score: int) -> Tuple[str, str]:
    if score >= 80:
        return "💪 STRONG", "✅"
    elif score >= 60:
        return "🟡 MODERATE", "⚠️ "
    elif score >= 40:
        return "🟠 WEAK", "❌"
    else:
        return "🔴 VERY WEAK", "🚨"


# ──────────────────────────────────────────
# STRENGTH BAR
# ──────────────────────────────────────────
def render_bar(score: int) -> str:
    filled = score // 5
    empty = 20 - filled
    colors = {
        "strong": "█",
        "bar": "█",
        "empty": "░"
    }
    bar = colors["bar"] * filled + colors["empty"] * empty
    return f"[{bar}] {score}/100"


# ──────────────────────────────────────────
# SIMULATE HIBP CHECK (SHA-1 prefix method)
# In production: call https://api.pwnedpasswords.com/range/{prefix}
# ──────────────────────────────────────────
def simulate_breach_check(password: str) -> str:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    # Simulated — in real project, call the API
    return f"SHA-1 prefix: {prefix}... (in production: check HaveIBeenPwned API)"


# ──────────────────────────────────────────
# MAIN ANALYZER
# ──────────────────────────────────────────
def analyze(password: str, show_breach: bool = False):
    score, entropy, tips, warnings = score_password(password)
    label, icon = get_strength_label(score)
    crack_time = estimate_crack_time(entropy)

    print("\n" + "═" * 58)
    print("  CEDRIC'S PASSWORD STRENGTH ANALYZER")
    print("═" * 58)

    # Masked preview
    masked = password[:2] + "*" * (len(password) - 4) + password[-2:] if len(password) > 4 else "****"
    print(f"  Password  : {masked}")
    print(f"  Length    : {len(password)} characters")
    print(f"  Entropy   : {entropy} bits")
    print(f"  Crack time: ~{crack_time} (offline GPU attack)")
    print()
    print(f"  Strength  : {label}")
    print(f"  Score     : {render_bar(score)}")

    if warnings:
        print(f"\n{'─'*58}")
        print("  WARNINGS")
        print(f"{'─'*58}")
        for w in warnings:
            print(f"  {w}")

    if tips:
        print(f"\n{'─'*58}")
        print("  IMPROVEMENTS")
        print(f"{'─'*58}")
        for t in tips:
            print(f"  {t}")

    if show_breach:
        print(f"\n{'─'*58}")
        print("  BREACH CHECK (HaveIBeenPwned simulation)")
        print(f"{'─'*58}")
        print(f"  {simulate_breach_check(password)}")

    print("\n" + "═" * 58 + "\n")


# ──────────────────────────────────────────
# CLI
# ──────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cedric's Password Strength Analyzer")
    parser.add_argument("-p", "--password", help="Password to analyze (use --hidden for secure input)")
    parser.add_argument("--hidden", action="store_true", help="Enter password securely (hidden input)")
    parser.add_argument("--breach", action="store_true", help="Simulate HaveIBeenPwned breach check")
    parser.add_argument("--batch", help="Analyze multiple passwords from a file (one per line)")
    args = parser.parse_args()

    if args.batch:
        try:
            with open(args.batch) as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"\n[*] Batch analyzing {len(passwords)} passwords...")
            for pwd in passwords:
                analyze(pwd, args.breach)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.batch}")

    elif args.hidden:
        pwd = getpass.getpass("Enter password (hidden): ")
        analyze(pwd, args.breach)

    elif args.password:
        analyze(args.password, args.breach)

    else:
        # Interactive demo
        print("\n  Password Strength Analyzer - Interactive Mode")
        print("  Type 'quit' to exit\n")
        while True:
            pwd = getpass.getpass("  Enter password: ")
            if pwd.lower() == "quit":
                break
            analyze(pwd, True)
