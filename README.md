#  CipherDex

**CipherDex** is a powerful command-line toolkit for encryption, decryption, and cryptanalysis of classical ciphers.

> Explore, analyze, and break classical ciphers directly from your terminal.

---

##  Installation

```bash
pip install cipherdex
```

---

##  Usage

###  Encrypt text

```bash
cipherdex encrypt --algo caesar "hello world" --key 3
```

###  Decrypt text

```bash
cipherdex decrypt --algo caesar "khoor zruog" --key 3
```

###  AES encrypt/decrypt

```bash
cipherdex encrypt --algo aes --key <BASE64_KEY> "hello world"
cipherdex decrypt --algo aes --key <BASE64_KEY> <BASE64_CIPHERTEXT>
```

###  RSA encrypt/decrypt

```bash
cipherdex encrypt --algo rsa --pub-key-file pub.pem "secret message"
cipherdex decrypt --algo rsa --private-key-file priv.pem <BASE64_CIPHERTEXT>
```

###  Generate key

```bash
cipherdex generate-key --algo aes
cipherdex generate-key --algo rsa
```

###  Analyze text

```bash
cipherdex analyze "khoor zruog"
```

###  Detect cipher

```bash
cipherdex detect "khoor zruog"
```

###  Bruteforce Caesar cipher

```bash
cipherdex bruteforce "khoor"
```

---

##  Features

* Multiple cipher support:

  * Caesar, ROT13, Atbash
  * Vigenère, Affine
  * Playfair, Rail Fence
  * AES-GCM and RSA (modern encryption)
*  Letter frequency analysis
*  Index of Coincidence (IC)
*  Cipher detection heuristics
*  Brute-force attack tools
*  File input/output support
*  Rich CLI output

---

##  Disclaimer

This tool is for **educational purposes only**.
The ciphers implemented are not secure for real-world encryption.

---

##  Author

Varun

---

##  License

MIT License
