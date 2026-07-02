import re
import math
import secrets
import string
from typing import Dict, List, Set

MIN_LENGTH_STRONG = 12
SUGGESTION_LENGTH = 16
COMMON_PASSWORDS_FILE = "common_passwords.txt"
SYMBOLS = r"""!@#$%^&*()-_=+[]{}|;:,.<>?/`~"\'"""

ENTROPY_THRESHOLDS = {
    "Weak": 0,
    "Medium": 40,
    "Strong": 60,
    "Very Strong": 80
}

DEFAULT_GUESSES_PER_SEC = 1e9

def check_length(password: str) -> int:
    return len(password)


def check_upper(password: str) -> int:
    return len(re.findall(r"[A-Z]", password))


def check_lower(password: str) -> int:
    return len(re.findall(r"[a-z]", password))


def check_digits(password: str) -> int:
    return len(re.findall(r"\d", password))


def check_symbols(password: str) -> int:
    pattern = "[" + re.escape(SYMBOLS) + "]"
    return len(re.findall(pattern, password))

def load_common_passwords(path: str = COMMON_PASSWORDS_FILE) -> Set[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()
    except Exception:
        return set()

  def calculate_entropy(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(rf"[{re.escape(SYMBOLS)}]", password):
        pool += len(SYMBOLS)

    if pool <= 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

def estimate_crack_time(entropy: float, guesses_per_sec: float = DEFAULT_GUESSES_PER_SEC) -> str:
    if entropy <= 0:
        return "instant"
    seconds = (2 ** entropy) / guesses_per_sec

    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    return f"{seconds / 31536000:.2f} years"

def strength_from_entropy(entropy: float) -> str:
    if entropy < ENTROPY_THRESHOLDS["Medium"]:
        return "Weak"
    if entropy < ENTROPY_THRESHOLDS["Strong"]:
        return "Medium"
    if entropy < ENTROPY_THRESHOLDS["Very Strong"]:
        return "Strong"
    return "Very Strong"

def normalize_score(score: int, max_score: int) -> float:
    if max_score <= 0:
        return 0.0
    return round((score / max_score) * 100, 1)

def suggest_password(length: int = SUGGESTION_LENGTH) -> str:
    if length < 8:
        length = 8

    alphabet = string.ascii_letters + string.digits + SYMBOLS
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SYMBOLS)
    ]
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    pwd_list = required + remaining
    secrets.SystemRandom().shuffle(pwd_list)
    return "".join(pwd_list)

def is_pwned_placeholder(password: str) -> bool:
    return False

def analyze(password: str, common_path: str = COMMON_PASSWORDS_FILE) -> Dict:
    if password is None:
        password = ""

    length = check_length(password)
    upp = check_upper(password)
    low = check_lower(password)
    digs = check_digits(password)
    syms = check_symbols(password)

    common = load_common_passwords(common_path)

    tips: List[str] = []
    suggestions: List[str] = []

    score = 0
    max_score = 10

    if length >= 20:
        score += 4
    elif length >= 16:
        score += 3
    elif length >= MIN_LENGTH_STRONG:
        score += 2
    elif length >= 8:
        score += 1
    else:
        tips.append(f"Use at least {MIN_LENGTH_STRONG} characters for strong passwords.")

    if upp:
        score += 1
    else:
        tips.append("Add uppercase letters.")

    if low:
        score += 1
    else:
        tips.append("Add lowercase letters.")

    if digs:
        score += 1
    else:
        tips.append("Add numbers.")

    if syms:
        score += 1
    else:
        tips.append("Add symbols or punctuation characters.")

    lowered = password.lower()
    if lowered and lowered in common:
        tips.append("This password is found in common password lists.")
        score = max(0, score - 4)
    else:
        score += 1

    if is_pwned_placeholder(password):
        tips.append("This password appears in known breaches.")
        score = max(0, score - 2)
    else:
        score += 1

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    entropy_strength = strength_from_entropy(entropy)
    score_percent = normalize_score(score, max_score)

    if score_percent < 30:
        final_strength = "Weak"
    else:
        levels = ["Weak", "Medium", "Strong", "Very Strong"]
        idx = levels.index(entropy_strength)
        if score_percent >= 80 and idx < len(levels) - 1:
            idx += 1
        final_strength = levels[idx]

    if final_strength in ("Weak", "Medium"):
        for _ in range(3):
            suggestions.append(suggest_password())

    if length >= MIN_LENGTH_STRONG and upp and low and digs and syms and lowered not in common:
        tips = [] 
    return {
        "length": length,
        "has_upper": bool(upp),
        "has_lower": bool(low),
        "has_digits": bool(digs),
        "has_symbols": bool(syms),
        "entropy": entropy,
        "score": score,
        "score_percent": score_percent,
        "strength": final_strength,
        "entropy_strength": entropy_strength,
        "crack_time": crack_time,
        "tips": tips,
        "suggestions": suggestions
    }

if __name__ == "__main__":
    test_passwords = [
        "password",
        "P@ssw0rd123",
        "correcthorsebatterystaple",
        "Tr0ub4dor&3",
        suggest_password(12)
    ]
    for p in test_passwords:
        res = analyze(p)
        print(f"\nPassword: {p}")
        print(f"Length: {res['length']}, Entropy: {res['entropy']} bits")
        print(f"Strength: {res['strength']} ({res['entropy_strength']})")
        print(f"Score: {res['score']} / 10 ({res['score_percent']}%)")
        print(f"Crack Time: {res['crack_time']}")
        if res["tips"]:
            print("Tips:")
            for t in res["tips"]:
                print(f"- {t}")
        if res["suggestions"]:
            print("Suggestions:")
            for s in res["suggestions"]:
                print(f"- {s}")
