import math
import re

def load_common_passwords(file_path="common_passwords.txt"):
    try:
        with open(file_path, "r") as file:
            return set(p.strip().lower() for p in file)
    except FileNotFoundError:
        return set()

def check_password_strength(password, common_passwords):
    suggestions = []
    score = 0

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Make your password at least 12 characters long.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add at least one number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Add at least one special character.")

    if password.lower() in common_passwords:
        score = 0
        suggestions.append("Avoid using common passwords.")

    charset_size = 0
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"\d", password): charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset_size += 32

    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

    if score >= 5 and entropy >= 60:
        verdict = "Very Strong"
    elif score >= 4 and entropy >= 50:
        verdict = "Strong"
    elif score >= 3 and entropy >= 40:
        verdict = "Moderate"
    else:
        verdict = "Weak"

    return {
        "password": password,
        "score": score,
        "entropy_bits": round(entropy, 2),
        "verdict": verdict,
        "suggestions": suggestions
    }

def main():
    common_passwords = load_common_passwords()
    print("🔐 Password Strength Checker 🔐\n")
    password = input("Enter a password to check: ")
    result = check_password_strength(password, common_passwords)

    print(f"\nPassword: {result['password']}")
    print(f"Score: {result['score']} / 6")
    print(f"Entropy: {result['entropy_bits']} bits")
    print(f"Strength: {result['verdict']}")

    if result["suggestions"]:
        print("\nSuggestions to improve:")
        for s in result["suggestions"]:
            print(f" - {s}")

if __name__ == "__main__":
    main()
