# CrackVault 🔓

A multi-mode password cracking tool built in Python with a dark-themed GUI. Developed as part of the **ST5062CEM Programming and Algorithms 2** coursework at Softwarica College / Coventry University.

CrackVault cracks hashes, ZIP files, and PDFs using wordlist, brute-force, and rule-based attacks — all through a clean Tkinter interface. The twist? Every core data structure (HashMap, Queue, Trie) is built from scratch. No `dict`, no `deque`, no shortcuts.

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)
![Tests](https://img.shields.io/badge/Tests-46%20Passed-brightgreen)
![License](https://img.shields.io/badge/License-Educational-orange)

---

## What It Does

- **Hash Cracking** — Wordlist, brute-force, and rule-based attacks across 12 algorithms (MD5, SHA-1, SHA-256, SHA-512, SHA-3 variants, BLAKE2)
- **File Cracking** — Cracks password-protected ZIP and PDF files
- **Hash Generator** — Generates all 12 hash types for any input text
- **Hash Identifier** — Identifies possible algorithms from a hash string based on its length
- **Session History** — Logs every cracking attempt with timestamps, speed, and results
- **Keyword Priority** — Enter keywords related to the target and CrackVault generates 6,626+ mutations, trying them first before the wordlist

---

## Keyword Priority System

This is the main feature that sets CrackVault apart. If you know something about the password (a name, a word, a pattern), enter it as a keyword. The tool will:

1. Generate thousands of mutations — case variants, leet-speak (`a→@, e→3, s→$`), reversed, doubled, suffixed (`123`, `!`, `2025`), prefixed, and multi-keyword combos
2. Deduplicate everything using the custom HashMap
3. Try all mutations **first** before touching the wordlist

**Example:** Password is `defensivespace`. Without keywords, it takes 301 attempts from rockyou.txt. With keywords `defensive space`, it cracks on attempt **#1**. That's a **301x speedup**.

---

## Custom Data Structures

Everything below was implemented from scratch — no built-in Python containers used for these:

| Structure | What It Does | Key Detail |
|-----------|-------------|------------|
| **HashMap** | Key-value storage with O(1) lookup | DJB2 hash function, separate chaining, auto-resize at 75% load |
| **Queue** | FIFO ordering for priority words | Singly linked list with front/rear pointers |
| **Trie** | Prefix tree for keyword storage | Character-by-character traversal, recursive prefix search |

These power everything: algorithm lookups, mutation deduplication, priority ordering, leet-speak mappings, and session logging.

---

## How to Run

### Option 1: Run the .exe (Windows)
Download `CrackVault.exe` from the release, double-click, done. No Python needed.

### Option 2: Run from source
```bash
# Make sure you have Python 3.10+
python crackvault.py
```

For PDF cracking, install pikepdf:
```bash
pip install pikepdf
```

### Run Tests
```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

---

## Supported Hash Algorithms

MD5 · SHA-1 · SHA-224 · SHA-256 · SHA-384 · SHA-512 · SHA3-224 · SHA3-256 · SHA3-384 · SHA3-512 · BLAKE2b · BLAKE2s

---

## Performance

Tested on a standard Windows 11 laptop (CPU only):

| Metric | Value |
|--------|-------|
| MD5 wordlist speed | ~66,000 passwords/sec |
| Keyword priority speedup | 301x (when keywords match) |
| Mutations per keyword set | 6,626+ unique candidates |
| Unit tests | 46/46 passed in 1.59s |

---

## Tech Stack

- **Language:** Python 3.13
- **GUI:** Tkinter (built-in)
- **Hashing:** hashlib (standard library)
- **ZIP Cracking:** zipfile (standard library)
- **PDF Cracking:** pikepdf
- **Brute Force:** itertools
- **Packaging:** PyInstaller
- **Testing:** unittest

---

## Disclaimer

CrackVault is an **educational tool** developed for academic coursework. It is intended for authorised security testing and learning purposes only. Do not use it to crack passwords on systems you do not own or have explicit permission to test. The developer takes no responsibility for any misuse.

---

Developed by Netanix Lab
