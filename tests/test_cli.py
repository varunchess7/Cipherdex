import base64
from pathlib import Path

from typer.testing import CliRunner

from cipherdex.main import app
from cipherdex.moderncrypto import export_private_key, export_public_key, generate_rsa_private_key


runner = CliRunner()


def test_encrypt_caesar_command():
    result = runner.invoke(app, ["encrypt", "--algo", "caesar", "--key", "3", "abc"])

    assert result.exit_code == 0
    assert "Encrypted: def" in result.output


def test_decrypt_caesar_command():
    result = runner.invoke(app, ["decrypt", "--algo", "caesar", "--key", "3", "def"])

    assert result.exit_code == 0
    assert "Decrypted: abc" in result.output


def test_encrypt_decrypt_aes_command():
    key = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
    result_encrypt = runner.invoke(app, ["encrypt", "--algo", "aes", "--key", key, "hello"])

    assert result_encrypt.exit_code == 0
    assert "Encrypted:" in result_encrypt.output
    ciphertext = result_encrypt.output.strip().split("Encrypted: ", 1)[1]

    result_decrypt = runner.invoke(app, ["decrypt", "--algo", "aes", "--key", key, ciphertext])
    assert result_decrypt.exit_code == 0
    assert "Decrypted: hello" in result_decrypt.output


def test_encrypt_decrypt_aes_pbkdf2_command():
    password = "testpassword"
    result_encrypt = runner.invoke(app, ["encrypt", "--algo", "aes-password", "--password", password, "hello"])

    assert result_encrypt.exit_code == 0
    assert "Encrypted:" in result_encrypt.output
    ciphertext = result_encrypt.output.strip().split("Encrypted: ", 1)[1]

    result_decrypt = runner.invoke(app, ["decrypt", "--algo", "aes-password", "--password", password, ciphertext])
    assert result_decrypt.exit_code == 0
    assert "Decrypted: hello" in result_decrypt.output


def test_encrypt_decrypt_rsa_command(tmp_path):
    private_key = generate_rsa_private_key()
    private_pem = export_private_key(private_key).decode("utf-8")
    public_pem = export_public_key(private_key.public_key()).decode("utf-8")

    pub_path = tmp_path / "pub.pem"
    priv_path = tmp_path / "priv.pem"
    pub_path.write_text(public_pem, encoding="utf-8")
    priv_path.write_text(private_pem, encoding="utf-8")

    result_encrypt = runner.invoke(app, ["encrypt", "--algo", "rsa", "--pub-key-file", str(pub_path), "hello"])
    assert result_encrypt.exit_code == 0
    ciphertext = result_encrypt.output.strip().split("Encrypted: ", 1)[1]

    result_decrypt = runner.invoke(app, ["decrypt", "--algo", "rsa", "--private-key-file", str(priv_path), ciphertext])
    assert result_decrypt.exit_code == 0
    assert "Decrypted: hello" in result_decrypt.output


def test_affine_command_rejects_bad_key():
    result = runner.invoke(
        app,
        ["encrypt", "--algo", "affine", "--key", "2", "--key2", "8", "hello"],
    )

    assert result.exit_code == 0
    assert "Affine --key must be coprime with 26" in result.output


def test_encrypt_file_creates_default_encrypted_file():
    input_file = Path("test_message.txt")
    output_file = input_file.with_name("Encrypted test_message.txt")
    input_file.write_text("abc", encoding="utf-8")

    try:
        result = runner.invoke(
            app,
            ["encrypt", "--algo", "caesar", "--key", "3", "--file", str(input_file)],
        )

        assert result.exit_code == 0
        assert output_file.read_text(encoding="utf-8") == "def"
    finally:
        input_file.unlink(missing_ok=True)
        output_file.unlink(missing_ok=True)


def test_analyze_shows_index_of_coincidence():
    result = runner.invoke(app, ["analyze", "hello world"])

    assert result.exit_code == 0
    assert "Letter Frequency" in result.output
    assert "Index of Coincidence" in result.output


def test_analyze_file_shows_index_of_coincidence():
    input_file = Path("test_analyze_message.txt")
    input_file.write_text("hello world", encoding="utf-8")

    try:
        result = runner.invoke(app, ["analyze", "--file", str(input_file)])

        assert result.exit_code == 0
        assert "Letter Frequency" in result.output
        assert "Index of Coincidence" in result.output
    finally:
        input_file.unlink(missing_ok=True)


def test_detect_shows_cipher_detection():
    result = runner.invoke(app, ["detect", "khoor zruog"])

    assert result.exit_code == 0
    assert "Cipher Detection" in result.output
    assert "Signals" in result.output


def test_detect_file_shows_cipher_detection():
    input_file = Path("test_detect_message.txt")
    input_file.write_text("khoor zruog", encoding="utf-8")

    try:
        result = runner.invoke(app, ["detect", "--file", str(input_file)])

        assert result.exit_code == 0
        assert "Cipher Detection" in result.output
        assert "Signals" in result.output
    finally:
        input_file.unlink(missing_ok=True)


def test_generate_aes_key():
    result = runner.invoke(app, ["generate-key", "--algo", "aes"])

    assert result.exit_code == 0
    assert "AES Key (base64):" in result.output


def test_generate_rsa_key(tmp_path):
    result = runner.invoke(app, ["generate-key", "--algo", "rsa", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "RSA Keys Generated:" in result.output
    assert (tmp_path / "priv.pem").exists()
    assert (tmp_path / "pub.pem").exists()


def test_hash_sha256():
    result = runner.invoke(app, ["hash", "--algo", "sha256", "hello"])

    assert result.exit_code == 0
    assert "Hash (sha256):" in result.output
    assert "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in result.output


def test_hash_sha512():
    result = runner.invoke(app, ["hash", "--algo", "sha512", "hello"])

    assert result.exit_code == 0
    assert "Hash (sha512):" in result.output


def test_hash_bcrypt():
    result = runner.invoke(app, ["hash", "--algo", "bcrypt", "password"])

    assert result.exit_code == 0
    assert "Hash (bcrypt):" in result.output
    assert result.output.startswith("Hash (bcrypt): $2b$")


def test_hash_argon2():
    result = runner.invoke(app, ["hash", "--algo", "argon2", "password"])

    assert result.exit_code == 0
    assert "Hash (argon2):" in result.output
    assert "$argon2" in result.output
