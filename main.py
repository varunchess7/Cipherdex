from pathlib import Path
from typing import Optional

import typer
from rich import print
from rich.table import Table
from ciphers import caesar_cipher, atbash_cipher, rot13_cipher, vigenere_cipher, affine_cipher, playfair_cipher, rail_fence_cipher
from analyze_ciphers import cipherinfo
from collections import Counter

app = typer.Typer(
    help="Encrypt, decrypt, inspect, and analyze text with classic cipher algorithms."
)

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


def index_of_coincidence(freq: Counter, total: int):
    if total < 2:
        return 0

    matches = sum(count * (count - 1) for count in freq.values())
    possible_pairs = total * (total - 1)
    return matches / possible_pairs


def guess_cipher_from_ioc(ioc: float, total: int):
    if total < 20:
        return "Text is very short, so the guess is weak."

    if ioc >= 0.055:
        return (
            "Looks English-like or frequency-preserving. It could be plain English, "
            "Caesar, Atbash, Affine, Rail Fence, or another substitution/transposition cipher."
        )

    if ioc >= 0.045:
        return (
            "Looks somewhat English-like, but not clear. It may be short text, mixed text, "
            "or a cipher that only partly hides letter frequency."
        )

    if ioc >= 0.035:
        return (
            "Looks flatter than normal English. It could be Vigenere, Playfair, "
            "or another cipher that spreads out letter frequencies."
        )

    return "Looks very flat/random. It may be strongly encrypted, random text, or not English."


@app.command()
def list():
    """
    Show all cipher algorithms supported by this tool.
    """

    print("[bold cyan]Available ciphers:[/bold cyan]")

    for cipher_name in CIPHERS:
        print(f"- {cipher_name}")

@app.command()
def info(
    algo: str = typer.Argument(
        ...,
        help="Cipher to explain. Choices: caesar, rot13, atbash, vigenere, affine, playfair, railfence."
    )
):
    """
    Explain what a cipher does and how it works.
    """
    info = cipherinfo.get(algo)
    print(f"[bold cyan]{info}[/bold cyan]")


@app.command()
def bruteforce(
    text: str = typer.Argument(..., help="Caesar-encrypted text to try every possible shift against.")
):
    """
    Try all Caesar cipher shifts from key 1 to key 25.
    """
    key = 1
    for i in range(25):
        print(f"key={key}", caesar_cipher(text, -key))
        key += 1

@app.command()
def analyze(
    text: str = typer.Argument(..., help="Text to analyze for letter frequency and cipher clues.")
):
    """
    Show letter frequency, Index of Coincidence, and a simple cipher guess.
    """
    freq = Counter(char.lower() for char in text if char.isalpha())
    total = sum(freq.values())

    if total == 0:
        print("[bold red]Error:[/bold red] Text must contain at least one letter")
        raise typer.Exit()

    table = Table(title="Letter Frequency")
    table.add_column("Letter", style="cyan", justify="center")
    table.add_column("Bar", justify="left")
    table.add_column("Count", style="green", justify="right")
    table.add_column("Percent", style="yellow", justify="right")

    bar_width = 30

    for letter, count in freq.most_common():
        percent = (count / total) * 100
        bar_length = round((percent / 100) * bar_width)
        bar = "#" * bar_length
        table.add_row(letter, f"[white]{bar}[/white]", str(count), f"{percent:.2f}%")

    print(table)

    ioc = index_of_coincidence(freq, total)
    guess = guess_cipher_from_ioc(ioc, total)

    summary = Table(title="Cipher Guess")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Letters analyzed", str(total))
    summary.add_row("Index of Coincidence", f"{ioc:.4f}")
    summary.add_row("Guess", guess)

    print(summary)


@app.command()
def interactive():
    """
    Start a prompt-based mode for choosing a cipher and entering text.
    """
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
    algo: str = typer.Option(
        ...,
        help="Cipher to use. Choices: caesar, rot13, atbash, vigenere, affine, playfair, railfence."
    ),
    text: str = typer.Argument("", help="Text to encrypt. Optional if --file is used."),
    key: str = typer.Option(
        "",
        help="Main key. Caesar/Rail Fence/Affine use numbers; Vigenere/Playfair use words."
    ),
    key2: str = typer.Option("", help="Second numeric key. Required only for affine."),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read plaintext from a file instead of TEXT."),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save encrypted text to this file. With --file, defaults to 'Encrypted <filename>'."
    )
):
    """
    Encrypt typed text or a file using the selected cipher.
    """

    text = get_input_text(text, input_file)
    result = run_cipher(algo, text, key, key2, "encrypt")

    if input_file and output_file is None:
        output_file = encrypted_file_name(input_file)

    show_output(result, output_file, "Encrypted")


# ---------- DECRYPT COMMAND (you will add logic later) ----------

@app.command()
def decrypt(
    algo: str = typer.Option(
        ...,
        help="Cipher to use. Choices: caesar, rot13, atbash, vigenere, affine, playfair, railfence."
    ),
    text: str = typer.Argument("", help="Text to decrypt. Optional if --file is used."),
    key: str = typer.Option(
        "",
        help="Main key used during encryption. Caesar/Rail Fence/Affine use numbers; Vigenere/Playfair use words."
    ),
    key2: str = typer.Option("", help="Second numeric key. Required only for affine."),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read ciphertext from a file instead of TEXT."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save decrypted text to this file.")
):
    """
    Decrypt typed text or a file using the selected cipher.
    """

    text = get_input_text(text, input_file)
    result = run_cipher(algo, text, key, key2, "decrypt")
    show_output(result, output_file, "Decrypted")


# ---------- ENTRY ----------

if __name__ == "__main__":
    app()
