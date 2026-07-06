#!/usr/bin/env python3
"""Regenerate the encrypted TFL deck gate (tfl.html).

Encrypts the deck (tfl-app/public/deck.html) under a passphrase and splices
the new BLOB into tfl.html. Matches the in-browser WebCrypto decrypt exactly:
PBKDF2-SHA256 (200k iterations) -> AES-256-GCM, all fields base64.

Usage:
    TFL_GATE_PW=... python3 make_tfl_gate.py            # phrase from env
    python3 make_tfl_gate.py                             # prompts (no echo)

The passphrase is NEVER written to disk or printed. After running: review
`git diff tfl.html`, commit, push (GitHub Pages), then verify the live page
decrypts with the phrase and rejects a wrong one.

(Rebuilt 2026-07-05 — the original lived in a session scratchpad and was
lost with it. This copy is committed so that can't happen again.)
"""
import base64
import getpass
import json
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
DECK = os.path.join(HERE, "..", "tfl-app", "public", "deck.html")
GATE = os.path.join(HERE, "tfl.html")
ITER = 200_000


def main():
    pw = os.environ.get("TFL_GATE_PW") or getpass.getpass("Gate passphrase: ")
    if not pw or len(pw) < 12:
        sys.exit("Refusing: passphrase under 12 chars.")

    plaintext = open(DECK, "rb").read()
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    key = kdf.derive(pw.encode())
    ct = AESGCM(key).encrypt(iv, plaintext, None)

    blob = json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
        "iter": ITER,
    })

    gate = open(GATE).read()
    new_gate, n = re.subn(r"const BLOB = \{.*?\};", f"const BLOB = {blob};", gate, count=1, flags=re.S)
    if n != 1:
        sys.exit("Could not find `const BLOB = {...};` in tfl.html — aborting, nothing written.")
    open(GATE, "w").write(new_gate)

    # Round-trip sanity check: decrypt what we just embedded.
    check = AESGCM(key).decrypt(iv, ct, None)
    assert check == plaintext, "round-trip decrypt mismatch"
    print(f"OK: deck ({len(plaintext)} bytes) encrypted -> tfl.html BLOB replaced (iter={ITER}).")
    print("Next: git diff tfl.html, commit, push, verify live (wrong phrase rejected, right phrase renders).")


if __name__ == "__main__":
    main()
