
"""
secure_storage_stream.py
Chunked/streaming encryption for large files using AES-GCM per chunk.

File format:
  MAGIC (4 bytes) = b'SFS2'
  salt (16)
  base_nonce_part (4)
  chunk_size (uint32, 4 bytes, big-endian)
  then repeated:
    chunk_ct_len (uint32, 4 bytes)  # length of ciphertext+tag
    chunk_ct (chunk_ct_len bytes)

Advantages:
 - constant memory usage
 - each chunk authenticated (if any chunk tampered, decrypt fails)
"""
import argparse
import os
import sys
import struct
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

MAGIC = b"SFS2"
SALT_SIZE = 16
BASE_NONCE_SIZE = 4    # we'll append an 8-byte counter to make 12 bytes nonce
KEY_LEN = 32
PBKDF2_ITERS = 200000
DEFAULT_CHUNK = 64 * 1024  # 64 KiB

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITERS, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_stream(infile: str, password: str, outfile: str = None, chunk_size: int = DEFAULT_CHUNK):
    if outfile is None:
        outfile = infile + ".enc"
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    base = os.urandom(BASE_NONCE_SIZE)

    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        # header
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(base)
        fout.write(struct.pack(">I", chunk_size))

        counter = 0
        aesgcm = AESGCM(key)
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            # construct 12-byte nonce = base (4) + counter (8)
            nonce = base + counter.to_bytes(8, "big")
            ct = aesgcm.encrypt(nonce, chunk, associated_data=None)
            # write length + ciphertext
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            counter += 1
    return outfile

def decrypt_stream(encfile: str, password: str, outfile: str = None):
    if outfile is None:
        if encfile.endswith(".enc"):
            outfile = encfile[:-4]
        else:
            outfile = "decrypted_" + os.path.basename(encfile)

    with open(encfile, "rb") as fin, open(outfile, "wb") as fout:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError("Unrecognized format.")

        salt = fin.read(SALT_SIZE)
        base = fin.read(BASE_NONCE_SIZE)
        chunk_size_data = fin.read(4)
        chunk_size = struct.unpack(">I", chunk_size_data)[0]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        counter = 0
        while True:
            len_data = fin.read(4)
            if not len_data:
                break  # end of file
            ct_len = struct.unpack(">I", len_data)[0]
            ct = fin.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError("Unexpected EOF or corrupted file.")

            nonce = base + counter.to_bytes(8, "big")
            try:
                plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
            except Exception as e:
                raise ValueError(f"Decryption failed at chunk {counter} — wrong password or tampering.") from e
            fout.write(plaintext)
            counter += 1

    return outfile

# Minimal CLI wrapper for the streaming version
def main():
    parser = argparse.ArgumentParser(description="Secure file storage (streaming AES-GCM/chunked)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a (large) file")
    p_enc.add_argument("infile")
    p_enc.add_argument("-o", "--out")
    p_enc.add_argument("-c", "--chunk", type=int, default=DEFAULT_CHUNK, help="Chunk size in bytes")

    p_dec = sub.add_parser("decrypt", help="Decrypt a streaming-encrypted file")
    p_dec.add_argument("infile")
    p_dec.add_argument("-o", "--out")

    args = parser.parse_args()

    try:
        if args.cmd == "encrypt":
            pw = getpass("Enter new password: ")
            pw2 = getpass("Confirm password: ")
            if pw != pw2:
                print("Passwords do not match.")
                sys.exit(1)
            out = encrypt_stream(args.infile, pw, args.out, args.chunk)
            print("Encrypted ->", out)
        else:
            pw = getpass("Enter password: ")
            out = decrypt_stream(args.infile, pw, args.out)
            print("Decrypted ->", out)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(2)

if __name__ == "__main__":
    main()
