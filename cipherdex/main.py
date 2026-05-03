from pathlib import Path
from typing import Optional
from math import gcd

import typer
from rich import print
from rich.table import Table
from cipherdex.ciphers import caesar_cipher, atbash_cipher, rot13_cipher, vigenere_cipher, affine_cipher, playfair_cipher, rail_fence_cipher
from cipherdex.analyze_ciphers import cipherinfo
from cipherdex import moderncrypto
from collections import Counter

app = typer.Typer(
    help="Encrypt, decrypt, inspect, and analyze text with classic cipher algorithms.",
    epilog=(
        "**Common command options:** "
        "`encrypt/decrypt --algo TEXT` chooses the cipher. "
        "`--key TEXT` is the main key. "
        "`--key2 TEXT` is for affine. "
        "`--file PATH` reads from a file. "
        "`--output PATH` saves to a file. "
        "`analyze --file PATH` analyzes a file. "
        "`generate-key --algo aes` generates an AES key. "
        "`generate-key --algo rsa` generates RSA key pair. "
        "**Examples:** "
        "`cipherdex encrypt --algo caesar --key 3 \"hello\"`; "
        "`cipherdex encrypt --algo caesar --key 3 --file message.txt`; "
        "`cipherdex analyze --file \"Encrypted message.txt\"`; "
        "`cipherdex decrypt --algo affine --key 5 --key2 8 \"rclla\"`."
    ),
    rich_markup_mode="markdown",
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
    "aes": {
        "needs_key": True,
        "encrypt": lambda text, key: moderncrypto.aes_encrypt(key, text),
        "decrypt": lambda text, key: moderncrypto.aes_decrypt(key, text),
    },
    "rsa": {
        "needs_key": False,
        "encrypt": None,
        "decrypt": None,
    },
}


def run_cipher(
    algo: str,
    text: str,
    key: str,
    key2: str,
    mode: str,
    pub_key_file: Optional[Path] = None,
    private_key_file: Optional[Path] = None,
    key_password: str = "",
):
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

    if algo == "rsa":
        if mode == "encrypt" and not pub_key_file:
            print("[bold red]Error:[/bold red] RSA encryption requires --pub-key-file")
            raise typer.Exit()
        if mode == "decrypt" and not private_key_file:
            print("[bold red]Error:[/bold red] RSA decryption requires --private-key-file")
            raise typer.Exit()

    if algo == "affine":
        validate_affine_keys(key, key2)
    
    try:
        if algo == "rsa":
            if mode == "encrypt":
                public_pem = pub_key_file.read_text(encoding="utf-8")
                return moderncrypto.rsa_encrypt(public_pem, text)
            private_pem = private_key_file.read_text(encoding="utf-8")
            password_bytes = key_password.encode("utf-8") if key_password else None
            return moderncrypto.rsa_decrypt(private_pem, text, password_bytes)

        if algo == "aes":
            return cipher[mode](text, key)

        if algo == "affine":
            return cipher[mode](text, key, key2)
        return cipher[mode](text, key)

    except ValueError as error:
        print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit()


def validate_affine_keys(key: str, key2: str):
    try:
        a = int(key)
        int(key2)
    except ValueError:
        print("[bold red]Error:[/bold red] Affine keys must be numbers")
        raise typer.Exit()

    if gcd(a, 26) != 1:
        print("[bold red]Error:[/bold red] Affine --key must be coprime with 26")
        print("Valid --key values include: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25")
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


def english_score(text: str):
    common_words = [
        "the", "and", "you", "that", "have", "for", "not", "with", "this",
        "hello", "world", "text", "message", "english",
    ]
    lowered = text.lower()
    score = sum(lowered.count(word) for word in common_words) * 10
    score += sum(1 for char in lowered if char in "etaoinshrdlu")
    return score


def detect_cipher(text: str):
    letters = [char.lower() for char in text if char.isalpha()]
    total = len(letters)

    if total == 0:
        print("[bold red]Error:[/bold red] Text must contain at least one letter")
        raise typer.Exit()

    freq = Counter(letters)
    ioc = index_of_coincidence(freq, total)
    unique_letters = len(freq)
    repeated_pairs = sum(
        1
        for index in range(len(letters) - 1)
        if letters[index] == letters[index + 1]
    )

    guesses = []

    if total < 20:
        guesses.append(("Unknown / too short", 35, "Not enough letters for a strong pattern match."))
    elif ioc >= 0.055:
        guesses.append((
            "English text or substitution/transposition cipher",
            70,
            "High IoC means normal English letter frequency is still visible.",
        ))
        guesses.append((
            "Caesar / Atbash / Affine / Rail Fence",
            55,
            "These ciphers often preserve English-like frequency patterns.",
        ))
    elif ioc >= 0.035:
        guesses.append((
            "Vigenere or Playfair",
            60,
            "IoC is flatter than normal English, suggesting frequency is being spread out.",
        ))
    else:
        guesses.append((
            "Random text or stronger encryption",
            65,
            "Very low IoC means letter frequencies are unusually flat.",
        ))

    best_shift = max(range(26), key=lambda shift: english_score(caesar_cipher(text, -shift)))
    best_caesar = caesar_cipher(text, -best_shift)
    caesar_margin = 8 if total < 20 else 20
    if best_shift and english_score(best_caesar) >= english_score(text) + caesar_margin:
        guesses.insert(0, (
            "Caesar cipher",
            75,
            f"Caesar brute-force found readable-looking text with key {best_shift}: {best_caesar[:60]}",
        ))

    if unique_letters <= 5 and total >= 20:
        guesses.append((
            "Limited alphabet / encoded text",
            50,
            "Only a few different letters appear, which is unusual for normal English.",
        ))

    if repeated_pairs == 0 and total >= 40 and ioc < 0.055:
        guesses.append((
            "Playfair",
            45,
            "No repeated adjacent letters can be a clue, but this is weak by itself.",
        ))

    guesses = sorted(guesses, key=lambda guess: guess[1], reverse=True)
    return ioc, total, unique_letters, guesses


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
    text: str = typer.Argument("", help="Text to analyze. Optional if --file is used."),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read text to analyze from a file.")
):
    """
    Analyze typed text or a file for letter frequency, Index of Coincidence, and cipher clues.
    """
    text = get_input_text(text, input_file)
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
def detect(
    text: str = typer.Argument("", help="Text to detect. Optional if --file is used."),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read text to detect from a file.")
):
    """
    Guess which cipher may have produced the text.
    """
    text = get_input_text(text, input_file)
    ioc, total, unique_letters, guesses = detect_cipher(text)

    table = Table(title="Cipher Detection")
    table.add_column("Guess", style="cyan")
    table.add_column("Confidence", style="green", justify="right")
    table.add_column("Reason", style="yellow")

    for name, confidence, reason in guesses:
        table.add_row(name, f"{confidence}%", reason)

    print(table)

    details = Table(title="Signals")
    details.add_column("Metric", style="cyan")
    details.add_column("Value", style="green")
    details.add_row("Letters analyzed", str(total))
    details.add_row("Unique letters", str(unique_letters))
    details.add_row("Index of Coincidence", f"{ioc:.4f}")

    print(details)


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

    pub_key_file = None
    private_key_file = None
    key_password = ""

    if algo == "rsa":
        if mode == "encrypt":
            pub_key_file = Path(typer.prompt("Public key file path"))
        else:
            private_key_file = Path(typer.prompt("Private key file path"))
            key_password = typer.prompt("Private key password (optional)", default="")
    elif CIPHERS[algo]["needs_key"]:
        key = typer.prompt("Enter key")

    if algo == "affine":
        key2 = typer.prompt("Enter second key")

    result = run_cipher(
        algo,
        text,
        key,
        key2,
        mode,
        pub_key_file=pub_key_file,
        private_key_file=private_key_file,
        key_password=key_password,
    )
    print(f"[bold green]Result:[/bold green] {result}")


# ---------- ENCRYPT COMMAND ----------

@app.command()
def encrypt(
    algo: str = typer.Option(
        ...,
        help="Cipher to use. Choices: caesar, rot13, atbash, vigenere, affine, playfair, railfence, aes, rsa."
    ),
    text: str = typer.Argument("", help="Text to encrypt. Optional if --file is used."),
    key: str = typer.Option(
        "",
        help="Main key. Caesar/Rail Fence/Affine use numbers; Vigenere/Playfair use words; AES uses a base64/hex key."
    ),
    key2: str = typer.Option("", help="Second numeric key. Required only for affine."),
    pub_key_file: Optional[Path] = typer.Option(None, "--pub-key-file", help="Public key file for RSA encrypt."),
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
    result = run_cipher(algo, text, key, key2, "encrypt", pub_key_file=pub_key_file)

    if input_file and output_file is None:
        output_file = encrypted_file_name(input_file)

    show_output(result, output_file, "Encrypted")


# ---------- DECRYPT COMMAND (you will add logic later) ----------

@app.command()
def decrypt(
    algo: str = typer.Option(
        ...,
        help="Cipher to use. Choices: caesar, rot13, atbash, vigenere, affine, playfair, railfence, aes, rsa."
    ),
    text: str = typer.Argument("", help="Text to decrypt. Optional if --file is used."),
    key: str = typer.Option(
        "",
        help="Main key used during encryption. Caesar/Rail Fence/Affine use numbers; Vigenere/Playfair use words; AES uses a base64/hex key."
    ),
    key2: str = typer.Option("", help="Second numeric key. Required only for affine."),
    private_key_file: Optional[Path] = typer.Option(None, "--private-key-file", help="Private key file for RSA decrypt."),
    key_password: str = typer.Option("", "--key-password", help="Password for encrypted RSA private key files."),
    input_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read ciphertext from a file instead of TEXT."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save decrypted text to this file.")
):
    """
    Decrypt typed text or a file using the selected cipher.
    """

    text = get_input_text(text, input_file)
    result = run_cipher(
        algo,
        text,
        key,
        key2,
        "decrypt",
        private_key_file=private_key_file,
        key_password=key_password,
    )
    show_output(result, output_file, "Decrypted")


@app.command()
def generate_key(
    algo: str = typer.Option(..., help="Algorithm to generate key for. Choices: aes, rsa."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Directory to save RSA key files. Defaults to current directory."),
    key_password: str = typer.Option("", "--key-password", help="Password to encrypt RSA private key."),
):
    """
    Generate a new key for AES or RSA encryption.
    """

    if algo.lower() == "aes":
        import base64
        import os

        key_bytes = os.urandom(32)  # 256-bit
        key_b64 = base64.b64encode(key_bytes).decode("utf-8")
        print(f"[bold green]AES Key (base64):[/bold green] {key_b64}")
        print("[yellow]Use this with --key for AES encrypt/decrypt.[/yellow]")

    elif algo.lower() == "rsa":
        private_key = moderncrypto.generate_rsa_private_key()
        password_bytes = key_password.encode("utf-8") if key_password else None
        priv_pem = moderncrypto.export_private_key(private_key, password_bytes)
        pub_pem = moderncrypto.export_public_key(private_key.public_key())

        if output_dir is None:
            output_dir = Path.cwd()

        priv_path = output_dir / "priv.pem"
        pub_path = output_dir / "pub.pem"

        priv_path.write_bytes(priv_pem)
        pub_path.write_bytes(pub_pem)

        print(f"[bold green]RSA Keys Generated:[/bold green]")
        print(f"Private key: {priv_path}")
        print(f"Public key: {pub_path}")
        print("[yellow]Use --pub-key-file for encrypt, --private-key-file for decrypt.[/yellow]")

    else:
        print(f"[bold red]Error:[/bold red] Unknown algorithm '{algo}'. Use 'aes' or 'rsa'.")
        raise typer.Exit()


# ---------- ENTRY ----------

if __name__ == "__main__":
    app()
