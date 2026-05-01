import typer
from rich import print
from ciphers import caesar_cipher, atbash_cipher, rot13_cipher, vigenere_cipher, affine_cipher, playfair_cipher, rail_fence_cipher
from analyze_ciphers import cipherinfo

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


@app.command()
def list():

    print("[bold cyan]Available ciphers:[/bold cyan]")

    for cipher_name in CIPHERS:
        print(f"- {cipher_name}")

@app.command()
def analyze(algo: str = typer.Option(..., help="Cipher algorithm (caesar, rot13, atbash, vigenere, affine, playfair, railfence)")):
    info = cipherinfo.get(algo)
    print(f"[bold cyan]{info}[/bold cyan]")

# ---------- ENCRYPT COMMAND ----------

@app.command()
def encrypt(
    algo: str = typer.Option(..., help="Cipher algorithm (caesar, rot13, atbash, vigenere, affine, playfair, railfence)"),
    text: str = typer.Argument(..., help="Text to encrypt"),
    key: str = typer.Option("", help="Key (required for Caesar, Vigenere, Affine, Playfair, and Rail Fence)"),
    key2: str = typer.Option("", help="Second Key for Affine Cipher")
):
    """
    Encrypt text using selected cipher.
    """

    result = run_cipher(algo, text, key, key2, "encrypt")
    print(f"[bold green]Encrypted:[/bold green] {result}")


# ---------- DECRYPT COMMAND (you will add logic later) ----------

@app.command()
def decrypt(
    algo: str = typer.Option(..., help="Cipher algorithm"),
    text: str = typer.Argument(..., help="Text to decrypt"),
    key: str = typer.Option("", help="Key (if needed)"),
    key2: str = typer.Option("", help="Second Key for Affine Cipher")
):
    """
    Decrypt text using selected cipher.
    """

    result = run_cipher(algo, text, key, key2, "decrypt")
    print(f"[bold green]Decrypted:[/bold green] {result}")


# ---------- ENTRY ----------

if __name__ == "__main__":
    app()
