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
