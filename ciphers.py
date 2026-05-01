alphabet = "abcdefghijklmnopqrstuvwxyz"

# ---------- CIPHERS ----------

def caesar_cipher(text: str, key: int):
    result = ""
    for char in text:
        if char.lower() in alphabet:
            o = alphabet.index(char.lower())
            new_index = (o + key) % 26
            new_char = alphabet[new_index]
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result


def rot13_cipher(text: str):
    return caesar_cipher(text, 13)


def vigenere_cipher(text: str, key: str, decrypt: bool = False):
    clean_key = "".join(char.lower() for char in key if char.lower() in alphabet)
    if not clean_key:
        raise ValueError("Vigenere cipher requires a letter key")

    result = ""
    key_index = 0

    for char in text:
        if char.lower() in alphabet:
            text_index = alphabet.index(char.lower())
            key_shift = alphabet.index(clean_key[key_index % len(clean_key)])

            if decrypt:
                key_shift = -key_shift

            new_index = (text_index + key_shift) % 26
            new_char = alphabet[new_index]
            result += new_char.upper() if char.isupper() else new_char
            key_index += 1
        else:
            result += char

    return result


def atbash_cipher(text: str):
    reversed_alphabet = alphabet[::-1]
    result = ""

    for char in text:
        if char.lower() in alphabet:
            o = alphabet.index(char.lower())
            new_char = reversed_alphabet[o]
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result


def affine_cipher(text: str, a: int, b: int, decrypt: bool = False):
    # helper to check coprime
    def gcd(x, y):
        while y:
            x, y = y, x % y
        return x

    # modular inverse of a mod 26
    def mod_inverse(a, m=26):
        for i in range(m):
            if (a * i) % m == 1:
                return i
        raise ValueError("No modular inverse exists")

    if gcd(a, 26) != 1:
        raise ValueError("Key 'a' must be coprime with 26")

    result = ""

    if decrypt:
        a_inv = mod_inverse(a)

    for char in text:
        if char.lower() in alphabet:
            x = alphabet.index(char.lower())

            if decrypt:
                new_index = (a_inv * (x - b)) % 26
            else:
                new_index = (a * x + b) % 26

            new_char = alphabet[new_index]
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char

    return result


def playfair_cipher(text: str, key: str, decrypt: bool = False):
    playfair_alphabet = "abcdefghiklmnopqrstuvwxyz"  # no j

    clean_key = "".join(
        dict.fromkeys(
            char.lower().replace("j", "i")
            for char in key
            if char.lower() in alphabet
        )
    )
    if not clean_key:
        raise ValueError("Playfair cipher requires a letter key")

    grid_string = clean_key + "".join(c for c in playfair_alphabet if c not in clean_key)
    grid = [list(grid_string[i:i+5]) for i in range(0, 25, 5)]

    def find_pos(char):
        for r in range(5):
            for c in range(5):
                if grid[r][c] == char:
                    return r, c

        raise ValueError(f"Character '{char}' is not in the Playfair grid")

    text = "".join(
        char.lower().replace("j", "i")
        for char in text
        if char.lower() in alphabet
    )
    if not text:
        raise ValueError("Playfair cipher requires text with at least one letter")

    pairs = []
    if decrypt:
        if len(text) % 2 != 0:
            text += "x"
        pairs = [(text[i], text[i + 1]) for i in range(0, len(text), 2)]
    else:
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i + 1] if i + 1 < len(text) else "x"

            if a == b:
                pairs.append((a, "x"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2

    result = ""

    for a, b in pairs:
        r1, c1 = find_pos(a)
        r2, c2 = find_pos(b)

        if r1 == r2:
            shift = -1 if decrypt else 1
            result += grid[r1][(c1 + shift) % 5]
            result += grid[r2][(c2 + shift) % 5]
        elif c1 == c2:
            shift = -1 if decrypt else 1
            result += grid[(r1 + shift) % 5][c1]
            result += grid[(r2 + shift) % 5][c2]
        else:
            result += grid[r1][c2]
            result += grid[r2][c1]

    return result


def rail_fence_cipher(text: str, rails: int, decrypt: bool = False):
    if rails < 2:
        raise ValueError("Rail Fence cipher requires at least 2 rails")

    if rails >= len(text):
        return text

    rail_pattern = []
    rail = 0
    direction = 1

    for _ in text:
        rail_pattern.append(rail)

        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1

        rail += direction

    if not decrypt:
        return "".join(
            char
            for current_rail in range(rails)
            for char, char_rail in zip(text, rail_pattern)
            if char_rail == current_rail
        )

    rail_lengths = [rail_pattern.count(current_rail) for current_rail in range(rails)]
    rail_text = []
    index = 0

    for length in rail_lengths:
        rail_text.append(list(text[index:index + length]))
        index += length

    result = ""
    rail_indexes = [0] * rails

    for current_rail in rail_pattern:
        result += rail_text[current_rail][rail_indexes[current_rail]]
        rail_indexes[current_rail] += 1

    return result
