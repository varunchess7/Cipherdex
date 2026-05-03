import base64
import binascii
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def export_private_key(private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_public_key(pem_data: str):
    return serialization.load_pem_public_key(pem_data.encode("utf-8"))


def _load_private_key(pem_data: str, password: Optional[bytes] = None):
    return serialization.load_pem_private_key(pem_data.encode("utf-8"), password=password)


def rsa_encrypt(public_key_pem: str, plaintext: str) -> str:
    public_key = _load_public_key(public_key_pem)
    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(private_key_pem: str, ciphertext_b64: str, password: Optional[bytes] = None) -> str:
    private_key = _load_private_key(private_key_pem, password)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def _parse_aes_key(key: str) -> bytes:
    if not key:
        raise ValueError("AES requires a base64 or hex-encoded key")

    try:
        key_bytes = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        try:
            key_bytes = bytes.fromhex(key)
        except ValueError:
            raise ValueError("AES key must be base64 or hex encoded")

    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    return key_bytes


def aes_encrypt(key: str, plaintext: str) -> str:
    key_bytes = _parse_aes_key(key)
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def aes_decrypt(key: str, ciphertext_b64: str) -> str:
    key_bytes = _parse_aes_key(key)
    try:
        data = base64.b64decode(ciphertext_b64)
    except (binascii.Error, ValueError):
        raise ValueError("AES ciphertext must be base64 encoded")

    if len(data) < 13:
        raise ValueError("AES ciphertext is invalid or too short")

    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key_bytes)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")
