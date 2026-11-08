"""Cryptographically random, independent 10-word staff credentials."""
from pathlib import Path
import secrets
from argon2 import PasswordHasher, exceptions
from cryptography.fernet import Fernet

WORDS = tuple(Path(__file__).with_name("words.txt").read_text(encoding="utf-8").splitlines())
if len(WORDS) != 1024 or len(set(WORDS)) != 1024:
    raise RuntimeError("Word list must contain 1,024 unique words")

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def generate_phrase() -> str:
    # 10 * log2(1024) = 100 bits, chosen with OS-backed randomness.
    return " ".join(secrets.choice(WORDS) for _ in range(10))


def normalise_phrase(s: str) -> str:
    return " ".join(s.lower().split())


def hash_phrase(s: str) -> str:
    return HASHER.hash(normalise_phrase(s))


def verify_phrase(hash_value: str, candidate: str) -> bool:
    candidate = normalise_phrase(candidate)
    if len(candidate.split()) != 10 or len(candidate) > 160:
        return False
    try:
        return HASHER.verify(hash_value, candidate)
    except (exceptions.VerifyMismatchError, exceptions.VerificationError, exceptions.InvalidHashError):
        return False


def new_fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


def build_fernet(key: str) -> Fernet:
    return Fernet(key.encode("ascii"))
