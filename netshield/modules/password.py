import secrets
import string

from netshield.base import BaseModule
from netshield.theme import ask, say

SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def score_password(password):
    """Return (score out of 5, list of improvement hints)."""
    checks = [
        (len(password) >= 8, "Use at least 8 characters"),
        (any(c.isupper() for c in password), "Add an upper case letter"),
        (any(c.islower() for c in password), "Add a lower case letter"),
        (any(c.isdigit() for c in password), "Add a digit"),
        (any(not c.isalnum() for c in password), "Add a symbol"),
    ]
    score = sum(1 for passed, _ in checks if passed)
    hints = [hint for passed, hint in checks if not passed]
    return score, hints


def generate_password(length=16):
    """Cryptographically secure password with at least one of each class."""
    if length < 8:
        raise ValueError("length must be at least 8")
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, SYMBOLS]
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class PasswordCheckerModule(BaseModule):
    name = "Check Password Strength"
    description = "Score a password and get hints to improve it"

    def run(self):
        password = ask("Enter a password:")
        score, hints = score_password(password)
        say("info", f"\nScore: {score}/5")
        if score == 5:
            say("ok", "Status: Strong Password")
        elif score >= 3:
            say("warn", "Status: Medium Password")
        else:
            say("error", "Status: Weak Password")
        if hints:
            say("dim", "\nSuggestions:")
            for hint in hints:
                say("warn", f"  - {hint}")


class PasswordGeneratorModule(BaseModule):
    name = "Generate Password"
    description = "Create a secure random password"

    def run(self):
        text = ask("Length (default 16):")
        try:
            length = int(text) if text else 16
            password = generate_password(length)
        except ValueError as error:
            say("error", f"[!] {error}")
            return
        say("ok", f"\n[+] Generated Password: {password}\n")
