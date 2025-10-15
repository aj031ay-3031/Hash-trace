#!/usr/bin/env python3
"""
hash_tool.py
- identify: guess which hash algorithm a string likely uses
- verify: given plaintext and hash, verify if they match (for supported algos)
- pwned: check if plaintext password appears in breaches (HIBP k-Anonymity)

Usage examples:
  python hash_tool.py identify 5d41402abc4b2a76b9719d911017c592
  python hash_tool.py verify hello 5d41402abc4b2a76b9719d911017c592
  python hash_tool.py pwned password123
"""

import sys
import re
import hashlib
import requests
import binascii

# ---------- Hash identification heuristics ----------
HASH_PATTERNS = [
    ("md5", re.compile(r'^[a-fA-F0-9]{32}$')),
    ("sha1", re.compile(r'^[a-fA-F0-9]{40}$')),
    ("sha224", re.compile(r'^[a-fA-F0-9]{56}$')),
    ("sha256", re.compile(r'^[a-fA-F0-9]{64}$')),
    ("sha384", re.compile(r'^[a-fA-F0-9]{96}$')),
    ("sha512", re.compile(r'^[a-fA-F0-9]{128}$')),
    ("bcrypt", re.compile(r'^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$')),  # $2b$12$...
    ("argon2", re.compile(r'^\$argon2(id|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$')),
    ("md5crypt", re.compile(r'^\$1\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22}$')),
    ("phpass", re.compile(r'^\$P\$[./A-Za-z0-9]{31}$')),
    ("ntlm", re.compile(r'^[A-Fa-f0-9]{32}$')),  # collides with md5 but NTLM often uppercase hex
]

def identify_hash(h):
    h = h.strip()
    matches = []
    for name, pat in HASH_PATTERNS:
        if pat.match(h):
            matches.append(name)
    # length heuristics
    length = len(h)
    if not matches:
        matches.append(f"unknown (length {length})")
    return matches

# ---------- Verification ----------
def verify_plain_against_hash(plain, hash_str):
    """Try to verify plaintext against hash_str for common algorithms."""
    h = hash_str.strip()
    candidates = []

    # hex-only (md5/sha1/sha256/sha512)
    if re.fullmatch(r'^[A-Fa-f0-9]+$', h):
        # try standard hex digests
        try:
            if hashlib.md5(plain.encode()).hexdigest().lower() == h.lower():
                candidates.append(("md5", True))
        except Exception:
            pass
        try:
            if hashlib.sha1(plain.encode()).hexdigest().lower() == h.lower():
                candidates.append(("sha1", True))
        except Exception:
            pass
        try:
            if hashlib.sha256(plain.encode()).hexdigest().lower() == h.lower():
                candidates.append(("sha256", True))
        except Exception:
            pass
        try:
            if hashlib.sha512(plain.encode()).hexdigest().lower() == h.lower():
                candidates.append(("sha512", True))
        except Exception:
            pass

    # bcrypt (requires bcrypt lib)
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        try:
            import bcrypt
            ok = bcrypt.checkpw(plain.encode(), h.encode())
            candidates.append(("bcrypt", ok))
        except Exception as e:
            candidates.append(("bcrypt", f"lib bcrypt not installed or error: {e}"))

    # argon2
    if h.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher, exceptions
            ph = PasswordHasher()
            try:
                ph.verify(h, plain)
                candidates.append(("argon2", True))
            except exceptions.VerifyMismatchError:
                candidates.append(("argon2", False))
        except Exception as e:
            candidates.append(("argon2", f"argon2-cffi not installed or error: {e}"))

    # phpass / md5crypt / NTLM etc. — complex to verify without libs
    # We will not attempt to brute force or crack; only simple checks above.

    return candidates

# ---------- HaveIBeenPwned k-Anonymity password check ----------
# API: https://haveibeenpwned.com/API/v3#PwnedPasswords
def check_pwned_password(password):
    """Return count of times password seen in breaches (0 means not found).
       Uses k-Anonymity: send first 5 chars of SHA1 and match suffixes locally.
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HIBP error: status {resp.status_code}")
    lines = resp.text.splitlines()
    for line in lines:
        part, count = line.split(':')
        if part.strip().upper() == suffix:
            return int(count)
    return 0

# ---------- CLI ----------
def print_usage():
    print("Usage:")
    print("  hash_tool.py identify <hash>")
    print("  hash_tool.py verify <plaintext> <hash>")
    print("  hash_tool.py pwned <plaintext_password>")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "identify":
        s = sys.argv[2]
        res = identify_hash(s)
        print("Possible hash types:", ", ".join(res))
    elif cmd == "verify":
        if len(sys.argv) < 4:
            print("verify requires plaintext and hash")
            sys.exit(1)
        plain = sys.argv[2]
        h = sys.argv[3]
        res = verify_plain_against_hash(plain, h)
        if not res:
            print("No matches found or unsupported hash type. (Did you install bcrypt/argon2 libs?)")
        else:
            for algo, val in res:
                print(f"{algo}: {val}")
    elif cmd == "pwned":
        pwd = sys.argv[2]
        try:
            count = check_pwned_password(pwd)
            if count:
                print(f"⚠️ Password found {count} times in breaches. Change it.")
            else:
                print("✅ Password not found in HIBP (best-effort).")
        except Exception as e:
            print("Error checking HIBP:", e)
    else:
        print_usage()
