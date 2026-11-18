import hashlib
from pathlib import Path

from netshield.base import BaseModule
from netshield.theme import ask, say

ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
# hex length -> algorithm, used to guess what kind of hash was supplied
LENGTH_TO_ALGORITHM = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "passwords.txt"


def hash_text(text, algorithm):
    return hashlib.new(algorithm, text.encode()).hexdigest()


def detect_algorithm(hash_value):
    return LENGTH_TO_ALGORITHM.get(len(hash_value))


def crack_hash(target_hash, wordlist_path, algorithm=None):
    """Dictionary attack. Streams the wordlist line by line.

    Returns (password or None, attempts). Raises FileNotFoundError.
    """
    target = target_hash.strip().lower()
    algorithm = algorithm or detect_algorithm(target)
    if algorithm is None:
        raise ValueError("unsupported hash length (md5/sha1/sha256/sha512 only)")
    attempts = 0
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            word = line.strip()
            if not word:
                continue
            attempts += 1
            if hash_text(word, algorithm) == target:
                return word, attempts
    return None, attempts


class HashModule(BaseModule):
    name = "Hash Text"
    description = "MD5, SHA-1, SHA-256 and SHA-512 of any text"

    def run(self):
        text = ask("Enter text to hash:")
        say("ok", f"\n[+] Original: {text}")
        for algorithm in ALGORITHMS:
            say("ok", f"[+] {algorithm.upper():<7}: {hash_text(text, algorithm)}")


class HashCrackerModule(BaseModule):
    name = "Hash Cracker"
    description = "Dictionary attack on MD5/SHA-1/SHA-256/SHA-512 (only for hashes you own)"

    def run(self):
        target = ask("Enter target hash:").lower()
        if not target:
            say("error", "[-] Hash input cannot be empty.")
            return
        algorithm = detect_algorithm(target)
        if algorithm is None:
            say("error", "[-] Unrecognised hash length (expected md5, sha1, sha256 or sha512).")
            return
        path = ask(f"Wordlist path (Enter for {DEFAULT_WORDLIST.name}):") or str(DEFAULT_WORDLIST)
        say("info", f"[+] Detected {algorithm.upper()}, attacking with {path}...")
        try:
            word, attempts = crack_hash(target, path, algorithm)
        except FileNotFoundError:
            say("error", f"[ERROR] Wordlist not found: {path}")
            return
        if word is None:
            say("error", f"[FAILED] Not found after {attempts} attempts.")
        else:
            say("ok", f"[SUCCESS] Password: {word}  ({attempts} attempts)")
