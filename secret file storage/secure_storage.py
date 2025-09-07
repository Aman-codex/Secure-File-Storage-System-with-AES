
"""
secure_storage.py
Simple CLI: encrypt/decrypt files using AES-GCM + PBKDF2 key derivation.

File format (binary):
  [salt (16 bytes)] [nonce (12 bytes)] [ciphertext + tag (rest)]

Usage:
  python secure_storage.py encrypt  myfile.txt
  python secure_storage.py decrypt  myfile.txt.enc
"""
import argparse
import os
import sys
from getpass import getpass
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ---- Parameters (tweakable) ----
SALT_SIZE = 16        # bytes
NONCE_SIZE = 12       # AES-GCM recommended nonce size (bytes)
KEY_LEN = 32          # AES-256
PBKDF2_ITERS = 200000 # cost factor for brute-force resistance

# ---- Utilities ----
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a symmetric key from password + salt using PBKDF2-HMAC-SHA256.
    Returns KEY_LEN bytes.
    """
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("salt must be 16 bytes")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

# ---- Encryption / Decryption ----
def encrypt_file(infile: str, password: str, outfile: str = None) -> str:
    """
    Encrypt an entire input file in memory and save as outfile.
    Format: salt | nonce | ciphertext+tag
    """
    if outfile is None:
        outfile = infile + ".enc"
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    with open(infile, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(outfile, "wb") as f:
        f.write(salt + nonce + ciphertext)

    return outfile

def decrypt_file(encfile: str, password: str, outfile: str = None) -> str:
    """
    Read encrypted file (salt|nonce|ct) and decrypt. Raises ValueError on failure.
    """
    with open(encfile, "rb") as f:
        data = f.read()

    min_len = SALT_SIZE + NONCE_SIZE + 1
    if len(data) < min_len:
        raise ValueError("Encrypted file too short or corrupted.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        # AESGCM will fail on authentication/tag mismatch => wrong password or tampering
        raise ValueError("Decryption failed — wrong password or file tampered.") from e

    if outfile is None:
        if encfile.endswith(".enc"):
            outfile = encfile[:-4]
        else:
            outfile = "decrypted_" + os.path.basename(encfile)

    with open(outfile, "wb") as f:
        f.write(plaintext)

    return outfile

# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(description="Secure file storage (AES-GCM)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("infile", help="Path to input file")
    p_enc.add_argument("-o", "--out", help="Output filename (optional)")

    p_dec = sub.add_parser("decrypt", help="Decrypt an encrypted file")
    p_dec.add_argument("infile", help="Path to encrypted file")
    p_dec.add_argument("-o", "--out", help="Output filename (optional)")

    args = parser.parse_args()

    try:
        if args.cmd == "encrypt":
            if not os.path.isfile(args.infile):
                print("Input file not found:", args.infile)
                sys.exit(1)
            pw = getpass("Enter new password: ")
            pw2 = getpass("Confirm password: ")
            if pw != pw2:
                print("Passwords do not match.")
                sys.exit(1)
            out = encrypt_file(args.infile, pw, args.out)
            print("Encrypted ->", out)

        elif args.cmd == "decrypt":
            if not os.path.isfile(args.infile):
                print("Input file not found:", args.infile)
                sys.exit(1)
            pw = getpass("Enter password: ")
            out = decrypt_file(args.infile, pw, args.out)
            print("Decrypted ->", out)

    except ValueError as ve:
        print("ERROR:", ve)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(3)

if __name__ == "__main__":
    main()
