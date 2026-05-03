import base64
import pytest

from cipherdex.ciphers import (
    affine_cipher,
    atbash_cipher,
    caesar_cipher,
    playfair_cipher,
    rail_fence_cipher,
    rot13_cipher,
    vigenere_cipher,
)
from cipherdex.moderncrypto import (
    aes_decrypt,
    aes_encrypt,
    export_private_key,
    export_public_key,
    generate_rsa_private_key,
    rsa_decrypt,
    rsa_encrypt,
)


def test_caesar_cipher_encrypts_and_decrypts():
    assert caesar_cipher("Abc xyz!", 3) == "Def abc!"
    assert caesar_cipher("Def abc!", -3) == "Abc xyz!"


def test_rot13_cipher_is_self_decrypting():
    encrypted = rot13_cipher("hello")

    assert encrypted == "uryyb"
    assert rot13_cipher(encrypted) == "hello"


def test_atbash_cipher_is_self_decrypting():
    encrypted = atbash_cipher("Abc xyz!")

    assert encrypted == "Zyx cba!"
    assert atbash_cipher(encrypted) == "Abc xyz!"


def test_vigenere_cipher_encrypts_and_decrypts():
    encrypted = vigenere_cipher("ATTACKATDAWN", "LEMON")

    assert encrypted == "LXFOPVEFRNHR"
    assert vigenere_cipher(encrypted, "LEMON", decrypt=True) == "ATTACKATDAWN"


def test_vigenere_cipher_requires_letter_key():
    with pytest.raises(ValueError, match="letter key"):
        vigenere_cipher("hello", "123")


def test_affine_cipher_encrypts_and_decrypts():
    encrypted = affine_cipher("hello", 5, 8)

    assert encrypted == "rclla"
    assert affine_cipher(encrypted, 5, 8, decrypt=True) == "hello"


def test_affine_cipher_rejects_invalid_a_key():
    with pytest.raises(ValueError, match="coprime"):
        affine_cipher("hello", 2, 8)


def test_playfair_cipher_encrypts_and_decrypts():
    encrypted = playfair_cipher("hide the gold", "playfair example")

    assert encrypted == "bmodzbxdnage"
    assert playfair_cipher(encrypted, "playfair example", decrypt=True) == "hidethegoldx"


def test_rail_fence_cipher_encrypts_and_decrypts():
    encrypted = rail_fence_cipher("WEAREDISCOVEREDFLEEATONCE", 3)

    assert encrypted == "WECRLTEERDSOEEFEAOCAIVDEN"
    assert rail_fence_cipher(encrypted, 3, decrypt=True) == "WEAREDISCOVEREDFLEEATONCE"


def test_aes_encrypts_and_decrypts():
    key = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
    encrypted = aes_encrypt(key, "hello world")

    assert encrypted != "hello world"
    assert aes_decrypt(key, encrypted) == "hello world"


def test_rsa_encrypts_and_decrypts():
    private_key = generate_rsa_private_key()
    private_pem = export_private_key(private_key).decode("utf-8")
    public_pem = export_public_key(private_key.public_key()).decode("utf-8")

    encrypted = rsa_encrypt(public_pem, "hello world")
    assert encrypted != "hello world"
    assert rsa_decrypt(private_pem, encrypted) == "hello world"
