import re
import math
import string
import hashlib
import time
import json
import secrets
import random
from flask import Flask, render_template, request, jsonify, session
from collections import Counter
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ─────────────────────────────────────────────────────────────────────
#  Common password list (top 200 most used — kept minimal for speed)
# ─────────────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "iloveyou", "admin", "letmein", "monkey", "1234567",
    "sunshine", "master", "dragon", "123123", "welcome", "shadow",
    "superman", "michael", "football", "baseball", "solo", "princess",
    "passw0rd", "trustno1", "12345678", "1234567890", "hello", "charlie",
    "donald", "password123", "qwerty123", "1q2w3e4r", "google", "test",
    "0987654321", "zxcvbnm", "jordan23", "hunter2", "asdfgh", "1234",
    "12345", "pass", "login", "guest", "root", "toor", "alpine",
    "changeme", "secret", "password!", "pa$$word", "qwertyuiop",
}

# Keyboard patterns (rows/columns)
KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()"
]
KEYBOARD_COLS = ["qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik,", "ol.", "p;/"]

# Common sequential patterns
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789",
             "zyxwvutsrqponmlkjihgfedcba", "9876543210"]


# ─────────────────────────────────────────────────────────────────────
#  Core analysis functions
# ─────────────────────────────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """Shannon entropy in bits."""
    if not password:
        return 0.0
    freq = Counter(password)
    length = len(password)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy * length, 2)


def get_charset_size(password: str) -> int:
    """Returns the total character-set pool size used."""
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>/?`~]', password):
        pool += 33
    if re.search(r'[\s]', password):
        pool += 1
    return pool


def estimate_crack_time(password: str) -> dict:
    """Brute-force crack time at different speeds (seconds)."""
    pool = get_charset_size(password)
    length = len(password)
    if pool == 0 or length == 0:
        return {}

    combinations = pool ** length
    speeds = {
        "Online (1k/s)":        1_000,
        "Online (10k/s)":       10_000,
        "Offline (1M/s)":       1_000_000,
        "GPU cluster (1B/s)":   1_000_000_000,
        "Supercomputer (1T/s)": 1_000_000_000_000,
    }

    results = {}
    for label, speed in speeds.items():
        seconds = combinations / speed
        results[label] = _humanize_time(seconds)
    return results


def _humanize_time(seconds: float) -> str:
    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years/1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years/1_000_000:.1f} million years"
    return f"{years/1_000_000_000:.1f} billion years"


def detect_patterns(password: str) -> list:
    """Finds weak patterns inside the password."""
    issues = []
    low = password.lower()

    # Repeated characters (e.g., aaaa)
    if re.search(r'(.)\1{2,}', password):
        issues.append("Repeated characters detected (e.g., 'aaa')")

    # Sequential letters / digits
    for seq in SEQUENCES:
        for n in range(3, len(seq) + 1):
            sub = seq[:n]
            if sub in low and len(sub) >= 3:
                issues.append(f"Sequential pattern detected: '{sub}'")
                break

    # Keyboard rows
    for row in KEYBOARD_ROWS:
        for n in range(4, len(row) + 1):
            chunk = row[:n]
            if chunk in low and len(chunk) >= 4:
                issues.append(f"Keyboard row pattern detected: '{chunk}'")
                break

    # Leet-speak substitution check
    leet_map = {'@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '$': 's'}
    decoded = low
    for k, v in leet_map.items():
        decoded = decoded.replace(k, v)
    if decoded in COMMON_PASSWORDS:
        issues.append("Leet-speak substitution of a common password detected")

    # All-same character class
    if password.isdigit():
        issues.append("Password is entirely numeric")
    if password.isalpha():
        issues.append("Password is entirely alphabetic (no numbers/symbols)")

    # Year pattern
    if re.search(r'(19|20)\d{2}', password):
        issues.append("Year pattern detected (e.g., 2023)")

    # Common suffixes
    if re.search(r'(123|!|@|#|1|2|3|!)$', password):
        issues.append("Common weak suffix detected (e.g., '123', '!')")

    return list(dict.fromkeys(issues))  # de-duplicate


def check_character_diversity(password: str) -> dict:
    """Breaks down character types present."""
    return {
        "uppercase": len(re.findall(r'[A-Z]', password)),
        "lowercase": len(re.findall(r'[a-z]', password)),
        "digits":    len(re.findall(r'\d', password)),
        "symbols":   len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>/?`~]', password)),
        "spaces":    len(re.findall(r'\s', password)),
    }


def calculate_score(password: str) -> dict:
    """
    Returns a 0-100 score and strength label.
    Weighted across: length, diversity, entropy, patterns, commonness.
    """
    if not password:
        return {"score": 0, "label": "Empty", "color": "#555"}

    score = 0

    # -- Length points (max 30) --
    length = len(password)
    if length >= 20:   score += 30
    elif length >= 16: score += 25
    elif length >= 12: score += 20
    elif length >= 10: score += 14
    elif length >= 8:  score += 8
    elif length >= 6:  score += 4

    # -- Character diversity (max 25) --
    diversity = check_character_diversity(password)
    has_types = sum(1 for v in [diversity["uppercase"], diversity["lowercase"],
                                 diversity["digits"], diversity["symbols"]] if v > 0)
    score += has_types * 6  # max 24 if all 4 types present

    # -- Entropy (max 25) --
    entropy = calculate_entropy(password)
    if entropy >= 60:   score += 25
    elif entropy >= 40: score += 18
    elif entropy >= 25: score += 12
    elif entropy >= 15: score += 6

    # -- Pattern penalties (max -30) --
    patterns = detect_patterns(password)
    score -= len(patterns) * 7

    # -- Common password penalty --
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)

    score = max(0, min(100, score))

    if score >= 85:
        label, color = "Very Strong", "#00e5b0"
    elif score >= 65:
        label, color = "Strong",      "#4ade80"
    elif score >= 45:
        label, color = "Moderate",    "#facc15"
    elif score >= 25:
        label, color = "Weak",        "#fb923c"
    else:
        label, color = "Very Weak",   "#f87171"

    return {"score": score, "label": label, "color": color}


def sha1_prefix(password: str) -> str:
    """Returns the first 5 hex chars of the SHA-1 hash (for HIBP k-anonymity)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[:5]


def get_suggestions(password: str, score_data: dict, patterns: list, diversity: dict) -> list:
    """Generates tailored improvement suggestions."""
    tips = []
    length = len(password)

    if length < 12:
        tips.append("Increase length to at least 12 characters — length is the single biggest factor.")
    if length < 16:
        tips.append("Consider using a passphrase (4+ random words) for both length and memorability.")
    if diversity["uppercase"] == 0:
        tips.append("Add uppercase letters to increase character variety.")
    if diversity["lowercase"] == 0:
        tips.append("Mix in some lowercase letters.")
    if diversity["digits"] == 0:
        tips.append("Include at least one number.")
    if diversity["symbols"] == 0:
        tips.append("Add special symbols like !, @, #, $, % to significantly boost strength.")
    if password.lower() in COMMON_PASSWORDS:
        tips.append("This is one of the most commonly used passwords — never use it!")
    for p in patterns[:3]:
        tips.append(f"Pattern issue: {p} — avoid predictable sequences.")
    if score_data["score"] >= 65 and not tips:
        tips.append("Your password looks good! For maximum security, use a password manager.")
    if score_data["score"] >= 85:
        tips.append("Excellent password! Store it safely in a password manager.")
    return tips


def generate_strong_password(length: int = 16, style: str = "mixed") -> str:
    """Generate a cryptographically strong password."""
    if style == "passphrase":
        wordlist = [
            "apple", "brave", "cloud", "delta", "eagle", "frost", "grace",
            "haven", "ivory", "joker", "karma", "lunar", "magic", "noble",
            "ocean", "pixel", "quest", "river", "solar", "tiger", "ultra",
            "vivid", "water", "xenon", "yacht", "zebra", "amber", "blaze",
            "coral", "dusk",  "ember", "flare", "gleam", "haze",  "iris",
            "jewel", "knack", "lemon", "mango", "nova",  "onyx",  "pearl",
            "quill", "raven", "storm", "topaz", "unity", "viper", "willow",
        ]
        words = [secrets.choice(wordlist) for _ in range(4)]
        separator = secrets.choice(["-", "_", ".", "!", "#"])
        num = secrets.randbelow(999)
        return f"{separator.join(words)}{separator}{num}"

    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    pw = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    pw += [secrets.choice(chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def analyze_password(password: str) -> dict:
    """Master function — returns full analysis report."""
    score_data  = calculate_score(password)
    diversity   = check_character_diversity(password)
    patterns    = detect_patterns(password)
    entropy     = calculate_entropy(password)
    charset     = get_charset_size(password)
    crack_times = estimate_crack_time(password)
    suggestions = get_suggestions(password, score_data, patterns, diversity)
    sha1_pre    = sha1_prefix(password)
    is_common   = password.lower() in COMMON_PASSWORDS

    combinations = charset ** len(password) if charset > 0 else 0

    return {
        "length":        len(password),
        "score":         score_data["score"],
        "label":         score_data["label"],
        "color":         score_data["color"],
        "entropy":       entropy,
        "charset_size":  charset,
        "combinations":  f"{combinations:.2e}" if combinations > 0 else "0",
        "diversity":     diversity,
        "patterns":      patterns,
        "crack_times":   crack_times,
        "suggestions":   suggestions,
        "is_common":     is_common,
        "sha1_prefix":   sha1_pre,
        "hibp_note":     "Use sha1_prefix to check haveibeenpwned.com/range/ API (k-anonymity safe)",
        "timestamp":     datetime.now().strftime("%H:%M:%S"),
    }


# ─────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    password = data.get("password", "")
    if len(password) > 500:
        return jsonify({"error": "Password too long (max 500 chars)"}), 400
    result = analyze_password(password)
    return jsonify(result)


@app.route("/generate", methods=["POST"])
def generate():
    data   = request.get_json()
    length = int(data.get("length", 16))
    style  = data.get("style", "mixed")
    length = max(8, min(64, length))
    pw = generate_strong_password(length, style)
    return jsonify({"password": pw, "analysis": analyze_password(pw)})


@app.route("/history", methods=["POST"])
def save_history():
    data = request.get_json()
    if "history" not in session:
        session["history"] = []
    entry = {
        "sha1_prefix": data.get("sha1_prefix"),
        "score":       data.get("score"),
        "label":       data.get("label"),
        "length":      data.get("length"),
        "time":        datetime.now().strftime("%H:%M:%S"),
    }
    session["history"] = (session["history"] + [entry])[-10:]
    session.modified = True
    return jsonify({"history": session["history"]})


@app.route("/history", methods=["GET"])
def get_history():
    return jsonify({"history": session.get("history", [])})


@app.route("/history", methods=["DELETE"])
def clear_history():
    session.pop("history", None)
    session.modified = True
    return jsonify({"status": "cleared"})


@app.route("/compare", methods=["POST"])
def compare():
    data = request.get_json()
    passwords = data.get("passwords", [])[:5]
    results = [analyze_password(p) for p in passwords]
    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
