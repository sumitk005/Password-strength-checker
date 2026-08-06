"""
Password Strength Checker - Backend (Flask)
=============================================
A production-quality Flask backend that powers a real-time password
strength analysis and secure password generation tool.

No database is used. No external/paid APIs are used.
Everything runs 100% locally using pure Python logic.

Author : Final Year CS Project
Module : app.py (Main Flask Application)
"""

import re
import math
import secrets
import string
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# -------------------------------------------------------------------
# STATIC DATA SETS USED FOR ANALYSIS
# -------------------------------------------------------------------

# A curated list of the most common / breached passwords.
# In a real product this could be loaded from a much larger wordlist
# (e.g. rockyou.txt), but a curated in-memory set keeps this project
# fully self-contained with no external files or downloads required.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "111111",
    "1234567", "sunshine", "qwerty", "iloveyou", "admin", "welcome",
    "monkey", "login", "abc123", "starwars", "123123", "dragon",
    "passw0rd", "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "letmein", "football", "shadow", "superman", "666666",
    "photoshop", "1234567890", "maggie", "password1", "password123",
    "welcome123", "changeme", "root", "toor", "user", "test", "guest",
    "administrator", "default", "000000", "1q2w3e4r", "zaq1zaq1",
    "qwertyuiop", "asdfghjkl", "iloveyou1", "princess", "flower",
    "hottie", "loveme", "baseball", "soccer", "basketball", "michael",
    "ashley", "jennifer", "hunter", "buster", "harley", "ranger",
}

# Common keyboard-walk patterns (rows / diagonals on a QWERTY layout)
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl", "zxcv",
    "zxcvbn", "zxcvbnm", "qazwsx", "wsxedc", "1qaz2wsx", "qweasd",
    "poiuy", "lkjhg", "mnbvc", "1q2w3e", "1q2w3e4r",
]

# Common sequential runs (numeric and alphabetic)
SEQUENTIAL_PATTERNS = [
    "0123456789", "1234567890", "abcdefghijklmnopqrstuvwxyz",
]


# -------------------------------------------------------------------
# CORE ANALYSIS FUNCTIONS
# -------------------------------------------------------------------

def has_sequential_pattern(password, run_length=4):
    """
    Detects sequential runs such as '1234', 'abcd', or reversed
    sequences such as '4321', 'dcba' of at least `run_length`
    characters, checked against numeric and alphabetic sequences.
    """
    pwd_lower = password.lower()

    for seq in SEQUENTIAL_PATTERNS:
        seq_rev = seq[::-1]
        for i in range(len(seq) - run_length + 1):
            chunk = seq[i:i + run_length]
            chunk_rev = seq_rev[i:i + run_length]
            if chunk in pwd_lower or chunk_rev in pwd_lower:
                return True
    return False


def has_keyboard_pattern(password, run_length=4):
    """
    Detects keyboard-walk patterns like 'qwerty', 'asdf', 'zxcv'
    (including their reverses) of at least `run_length` characters.
    """
    pwd_lower = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        pattern_rev = pattern[::-1]
        for i in range(len(pattern) - run_length + 1):
            chunk = pattern[i:i + run_length]
            chunk_rev = pattern_rev[i:i + run_length]
            if chunk in pwd_lower or chunk_rev in pwd_lower:
                return True
    return False


def has_repeated_characters(password, threshold=3):
    """
    Detects `threshold` or more of the exact same character
    appearing consecutively, e.g. 'aaa', '111'.
    """
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count >= threshold:
                return True
        else:
            count = 1
    return False


def is_common_password(password):
    """Checks the password (case-insensitively) against the common list."""
    return password.lower() in COMMON_PASSWORDS


def calculate_character_pool(password):
    """
    Determines the size of the character pool used in the password.
    This pool size is required to calculate entropy correctly.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approximate count of common special characters
    return pool


def calculate_entropy(password):
    """
    Calculates Shannon-style password entropy in bits using the
    standard formula:

        entropy = length * log2(pool_size)

    A higher entropy means a password is harder to brute-force.
    """
    pool_size = calculate_character_pool(password)
    if pool_size == 0 or len(password) == 0:
        return 0.0
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy_bits):
    """
    Estimates the time required for an offline brute-force attack to
    crack a password of the given entropy, assuming a modern attacker
    capable of ~10 billion (1e10) guesses per second.

    Returns a tuple: (human_readable_string, seconds_float)
    """
    guesses_per_second = 1e10
    total_combinations = 2 ** entropy_bits
    # On average an attacker finds the password after searching half
    # the keyspace.
    seconds = (total_combinations / 2) / guesses_per_second

    if seconds < 1:
        return "Instantly", seconds
    if seconds < 60:
        return f"{seconds:.0f} Seconds", seconds
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f} Minutes", seconds
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.0f} Hours", seconds
    days = hours / 24
    if days < 30:
        return f"{days:.0f} Days", seconds
    months = days / 30
    if months < 12:
        return f"{months:.0f} Months", seconds
    years = days / 365
    if years < 100:
        return f"{years:.0f} Years", seconds
    if years < 1_000_000:
        return f"{years:,.0f} Years", seconds
    return "Millions of Years", seconds


def analyze_password(password):
    """
    Runs the full password analysis pipeline and returns a
    dictionary containing every metric the frontend needs to render
    the strength meter, suggestions, entropy, and crack time.
    """
    result = {
        "length": len(password),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_number": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "is_common": is_common_password(password),
        "has_sequential": has_sequential_pattern(password),
        "has_keyboard_pattern": has_keyboard_pattern(password),
        "has_repeated": has_repeated_characters(password),
    }

    # ---------------- SCORING SYSTEM (0 - 100) ----------------
    score = 0
    feedback = []

    # 1) Length scoring (up to 30 points)
    length = result["length"]
    if length == 0:
        score = 0
    else:
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 24
        elif length >= 8:
            score += 16
        elif length >= 6:
            score += 8
        else:
            score += 2
            feedback.append("Increase the password length (minimum 8+ characters recommended).")

    # 2) Character diversity (up to 40 points, 10 each)
    diversity_count = 0
    if result["has_upper"]:
        score += 10
        diversity_count += 1
    else:
        feedback.append("Add uppercase letters (A-Z).")

    if result["has_lower"]:
        score += 10
        diversity_count += 1
    else:
        feedback.append("Add lowercase letters (a-z).")

    if result["has_number"]:
        score += 10
        diversity_count += 1
    else:
        feedback.append("Add numbers (0-9).")

    if result["has_special"]:
        score += 10
        diversity_count += 1
    else:
        feedback.append("Add special symbols (e.g. ! @ # $ %).")

    # 3) Entropy bonus (up to 20 points)
    entropy = calculate_entropy(password)
    entropy_score = min(20, round((entropy / 100) * 20))
    score += entropy_score

    # 4) Penalties for weaknesses
    if result["is_common"]:
        score = min(score, 5)  # common passwords are always critically weak
        feedback.insert(0, "This is one of the most commonly used passwords in the world. Avoid it completely.")

    if result["has_sequential"]:
        score -= 15
        feedback.append("Avoid sequential patterns such as '1234' or 'abcd'.")

    if result["has_keyboard_pattern"]:
        score -= 15
        feedback.append("Avoid keyboard patterns such as 'qwerty' or 'asdf'.")

    if result["has_repeated"]:
        score -= 10
        feedback.append("Avoid repeating the same character multiple times in a row.")

    if diversity_count <= 1:
        feedback.append("Avoid using only one type of character — mix letters, numbers, and symbols.")

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    # ---------------- STRENGTH LABEL ----------------
    if length == 0:
        label = "Very Weak"
    elif score < 20:
        label = "Very Weak"
    elif score < 40:
        label = "Weak"
    elif score < 60:
        label = "Medium"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    # ---------------- CRACK TIME & ENTROPY ----------------
    crack_time_str, crack_time_seconds = estimate_crack_time(entropy)
    security_percentage = min(100, round((entropy / 80) * 100))  # 80 bits ~ excellent

    if entropy < 28:
        complexity_rating = "Very Poor"
    elif entropy < 36:
        complexity_rating = "Weak"
    elif entropy < 60:
        complexity_rating = "Reasonable"
    elif entropy < 128:
        complexity_rating = "Strong"
    else:
        complexity_rating = "Very Strong"

    if not feedback:
        feedback.append("Excellent! Your password follows all recommended security practices.")

    return {
        "score": score,
        "strength_label": label,
        "entropy": entropy,
        "security_percentage": security_percentage,
        "complexity_rating": complexity_rating,
        "crack_time": crack_time_str,
        "feedback": feedback,
        "details": result,
    }


def generate_password(length=16, use_upper=True, use_lower=True,
                       use_numbers=True, use_symbols=True):
    """
    Generates a cryptographically secure random password using
    Python's `secrets` module (CSPRNG - safe for security purposes,
    unlike the standard `random` module).

    Guarantees at least one character from every selected category.
    """
    length = max(4, min(64, int(length)))

    pools = []
    guaranteed_chars = []

    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed_chars.append(secrets.choice(string.ascii_lowercase))
    if use_numbers:
        pools.append(string.digits)
        guaranteed_chars.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}?"
        pools.append(symbols)
        guaranteed_chars.append(secrets.choice(symbols))

    # Fallback: if the user somehow deselects everything, default to
    # lowercase letters so the function never fails.
    if not pools:
        pools = [string.ascii_lowercase]
        guaranteed_chars = [secrets.choice(string.ascii_lowercase)]

    combined_pool = "".join(pools)
    remaining_length = max(0, length - len(guaranteed_chars))
    random_chars = [secrets.choice(combined_pool) for _ in range(remaining_length)]

    password_chars = guaranteed_chars + random_chars
    # Shuffle securely so guaranteed characters aren't always at the start.
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


# -------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------

@app.route("/")
def index():
    """Renders the main single-page application."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Accepts JSON: { "password": "..." }
    Returns a full analysis (score, strength label, entropy,
    crack time, feedback, etc.) as JSON.
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str):
        return jsonify({"error": "Invalid input type."}), 400

    # Basic input validation / safety limit
    if len(password) > 128:
        return jsonify({"error": "Password too long (max 128 characters)."}), 400

    result = analyze_password(password)
    return jsonify(result), 200


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """
    Accepts JSON:
        {
            "length": 16,
            "uppercase": true,
            "lowercase": true,
            "numbers": true,
            "symbols": true
        }
    Returns a generated secure password and its analysis.
    """
    data = request.get_json(silent=True) or {}

    try:
        length = int(data.get("length", 16))
    except (ValueError, TypeError):
        return jsonify({"error": "Length must be a number."}), 400

    if length < 4 or length > 64:
        return jsonify({"error": "Length must be between 4 and 64."}), 400

    use_upper = bool(data.get("uppercase", True))
    use_lower = bool(data.get("lowercase", True))
    use_numbers = bool(data.get("numbers", True))
    use_symbols = bool(data.get("symbols", True))

    if not any([use_upper, use_lower, use_numbers, use_symbols]):
        return jsonify({"error": "Select at least one character type."}), 400

    password = generate_password(length, use_upper, use_lower, use_numbers, use_symbols)
    analysis = analyze_password(password)

    return jsonify({
        "password": password,
        "analysis": analysis,
    }), 200


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "Route not found."}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
