import hashlib
import bcrypt
from argon2 import PasswordHasher


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hash(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def argon2_hash(password: str) -> str:
    ph = PasswordHasher()
    return ph.hash(password)