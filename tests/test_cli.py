from pathlib import Path

from typer.testing import CliRunner

from main import app


runner = CliRunner()


def test_encrypt_caesar_command():
    result = runner.invoke(app, ["encrypt", "--algo", "caesar", "--key", "3", "abc"])

    assert result.exit_code == 0
    assert "Encrypted: def" in result.output


def test_decrypt_caesar_command():
    result = runner.invoke(app, ["decrypt", "--algo", "caesar", "--key", "3", "def"])

    assert result.exit_code == 0
    assert "Decrypted: abc" in result.output


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
