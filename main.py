from pathlib import Path
from typing import Optional

import typer
from rich import print
from ciphers import caesar_cipher, atbash_cipher, rot13_cipher, vigenere_cipher, affine_cipher, playfair_cipher, rail_fence_cipher
from analyze_ciphers import cipherinfo
from collections import Counter

app = typer.Typer()

CIPHERS = {
    "caesar": {
        "needs_key": True,
        "encrypt": lambda text, key: caesar_cipher(text, int(key)),
        "decrypt": lambda text, key: caesar_cipher(text, -int(key)),
    },
    "rot13": {
        "needs_key": False,
        "encrypt": lambda text, key: rot13_cipher(text),
        "decrypt": lambda text, key: rot13_cipher(text),
    },
    "atbash": {
        "needs_key": False,
        "encrypt": lambda text, key: atbash_cipher(text),
        "decrypt": lambda text, key: atbash_cipher(text),
    },
    "vigenere": {
        "needs_key": True,
        "encrypt": lambda text, key: vigenere_cipher(text, key),
        "decrypt": lambda text, key: vigenere_cipher(text, key, decrypt=True),
    },
    "affine": {
        "needs_key": True,
        "encrypt": lambda text, key, key2: affine_cipher(text, int(key), int(key2)),
        "decrypt": lambda text, key, key2: affine_cipher(text, int(key), int(key2), decrypt=True),
    },
    "playfair": {
        "needs_key": True,
        "encrypt": lambda text, key: playfair_cipher(text, key),
        "decrypt": lambda text, key: playfair_cipher(text, key, decrypt=True),
    },
    "railfence": {
        "needs_key": True,
        "encrypt": lambda text, key: rail_fence_cipher(text, int(key)),
        "decrypt": lambda text, key: rail_fence_cipher(text, int(key), decrypt=True),
    },
}


def run_cipher(algo: str, text: str, key: str, key2: str, mode: str):
    algo = algo.lower()
    cipher = CIPHERS.get(algo)

    if cipher is None:
        print(f"[bold red]Error:[/bold red] Unknown algorithm '{algo}'")
        raise typer.Exit()

    if cipher["needs_key"] and not key:
        print(f"[bold red]Error:[/bold red] {algo.title()} cipher requires --key")
        raise typer.Exit()

    if algo == "affine" and not key2:
        print("[bold red]Error:[/bold red] Affine cipher requires --key and --key2")
        raise typer.Exit()
    
    try:
        if algo == "affine":
            return cipher[mode](text, key, key2)
        else:
            return cipher[mode](text, key) # Caesar, Vigenere, etc. only get 1 key
    
    except ValueError as error:
        print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit()


def get_input_text(text: str, input_file: Optional[Path]):
    if input_file:
        return input_file.read_text(encoding="utf-8")

    if not text:
        print("[bold red]Error:[/bold red] Enter text or use --file")
        raise typer.Exit()

    return text


def show_output(result: str, output_file: Optional[Path], label: str):
    if output_file:
        output_file.write_text(result, encoding="utf-8")
        print(f"[bold green]Saved:[/bold green] {output_file}")
    else:
        print(f"[bold green]{label}:[/bold green] {result}")


def encrypted_file_name(input_file: Path):
    return input_file.with_name(f"Encrypted {input_file.name}")


@app.command()
def list():

    print("[bold cyan]Available ciphers:[/bold cyan]")

    for cipher_name in CIPHERS:
        print(f"- {cipher_name}")

@app.command()
def analyze(algo: str = typer.Argument(..., help="Cipher algorithm (caesar, rot13, atbash, vigenere, affine, playfair, railfence)")):
    info = cipherinfo.get(algo)
    print(f"[bold cyan]{info}[/bold cyan]")

@app.command()
def bruteforce(text: str = typer.Argument(..., help="Text to encrypt")):
    key = 1
    for i in range(25):
        print(f"key={key}", caesar_cipher(text, -key))
        key += 1

@app.command()
def frequency(text):
    freq = Counter(char.lower() for char in text if char.isalpha())
    
    for letter, count in freq.items():
        print(f"{letter}: {count}")


@app.command()
def interactive():
    print("[bold cyan]Cryptic Interactive Mode[/bold cyan]")
    print("Available ciphers:")

    for cipher_name in CIPHERS:
        print(f"- {cipher_name}")

    algo = typer.prompt("Choose cipher").lower()
    if algo not in CIPHERS:
        print(f"[bold red]Error:[/bold red] Unknown algorithm '{algo}'")
        raise typer.Exit()
    
    if algo in ["caesar", "rot13", "atbash"]:
        print("[yellow]Warning: This cipher is not secure[/yellow]")

    mode = typer.prompt("Encrypt or decrypt").lower()
    if mode not in ["encrypt", "decrypt"]:
        print("[bold red]Error:[/bold red] Mode must be encrypt or decrypt")
        raise typer.Exit()

    text = typer.prompt("Enter text")
    key = ""
    key2 = ""

    if CIPHERS[algo]["needs_key"]:
        key = typer.prompt("Enter key")

    if algo == "affine":
        key2 = typer.prompt("Enter second key")

    result = run_cipher(algo, text, key, key2, mode)
    print(f"[bold green]Result:[/bold green] {result}")


# ---------- ENCRYPT COMMAND ----------

@app.command()
def encrypt(
    algo: str = typer.Option(..., help="Cipher algorithm (caesar, rot13, atbash, vigenere, affine, playfair, railfence)"),
    text: str = typer.Argument("", help="Text to encrypt"),
    key: str = typer.Option("", help="Key (required for Caesar, Vigenere, Affine, Playfair, and Rail Fence)"),
    key2: str = typer.Option("", help="Second Key for Affine Cipher"),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read text from a file"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to a file")
):
    """
    Encrypt text using selected cipher.
    """

    text = get_input_text(text, input_file)
    result = run_cipher(algo, text, key, key2, "encrypt")

    if input_file and output_file is None:
        output_file = encrypted_file_name(input_file)

    show_output(result, output_file, "Encrypted")


# ---------- DECRYPT COMMAND (you will add logic later) ----------

@app.command()
def decrypt(
    algo: str = typer.Option(..., help="Cipher algorithm"),
    text: str = typer.Argument("", help="Text to decrypt"),
    key: str = typer.Option("", help="Key (if needed)"),
    key2: str = typer.Option("", help="Second Key for Affine Cipher"),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read text from a file"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save result to a file")
):
    """
    Decrypt text using selected cipher.
    """

    text = get_input_text(text, input_file)
    result = run_cipher(algo, text, key, key2, "decrypt")
    show_output(result, output_file, "Decrypted")


# ---------- ENTRY ----------

if __name__ == "__main__":
    app()
