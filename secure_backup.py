#!/usr/bin/env python3
"""
secure_backup.py — Encrypt files/folders with a single passphrase before
uploading them to Google Drive, Dropbox, a USB stick, or anywhere else.

This file is both the command-line tool and the crypto core that the GUI
(app.py) is built on.

How it works:
  - You pick ONE passphrase. You use that same passphrase every time,
    both to encrypt and to decrypt. There's no separate key file or UUID
    to keep track of.
  - Each file gets its own random "salt". The salt is combined with your
    passphrase (via a slow, memory-hard function called Scrypt) to produce
    a unique 256-bit encryption key for that file. The salt itself isn't
    secret — it's stored in the encrypted file — but without your
    passphrase it's useless to an attacker.
  - The actual encryption is AES-256-GCM, which both scrambles the data
    and adds a tamper-proof "tag" so decryption will loudly fail if the
    file was corrupted, tampered with, or you typed the wrong passphrase
    — it will never silently hand you garbled output.
  - Files are processed in chunks, so this works fine on large videos
    without loading the whole file into memory.
  - Output is written to "<name>.part" and only renamed to its real name
    once complete, so an interrupted run never leaves a file that looks
    finished.

IMPORTANT: There is no "forgot passphrase" recovery option, by design —
that's what makes this actually private. If you lose the passphrase, the
files are unrecoverable.

Usage:
  Encrypt a single file:
      python secure_backup.py encrypt photo.jpg photo.jpg.enc

  Encrypt an entire folder (recursively, preserving subfolders):
      python secure_backup.py encrypt ./private_photos ./private_photos_encrypted

  Decrypt (same pattern, reversed):
      python secure_backup.py decrypt ./private_photos_encrypted ./private_photos_restored

  Decrypt every .enc file under a folder, right next to itself:
      python secure_backup.py .

  Re-running encrypt into an existing folder only encrypts new or changed
  files. Decrypt never overwrites a file that already exists.

  Then sync/upload the *_encrypted folder to Google Drive — Google only
  ever sees unreadable ciphertext.

Requires: pip install -r requirements.txt
"""

import argparse
import getpass
import os
import sys
from contextlib import contextmanager
from itertools import takewhile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB — good balance for large video files
ENCRYPTED_SUFFIX = ".enc"
PART_SUFFIX = ".part"  # output in progress; renamed to the real name once complete
JUNK = {".DS_Store", "Thumbs.db", "desktop.ini"}  # OS clutter, never worth encrypting


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Turn your passphrase into a 256-bit key. Scrypt is deliberately slow
    and memory-hungry, which makes brute-forcing the passphrase impractical
    even if someone steals your encrypted files."""
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2 ** 15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


@contextmanager
def atomic_output(output_path: Path, source: Path):
    """Write to `<output>.part` and rename it into place only when complete,
    carrying over the source's modified time. On any error (wrong passphrase,
    cancel, disk full) the partial file and any folders created for it are
    removed, and nothing is replaced."""
    new_dirs = list(takewhile(lambda p: not p.exists(), output_path.parents))  # deepest first
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_name(output_path.name + PART_SUFFIX)
    try:
        with open(tmp, "wb") as f:
            yield f
        os.replace(tmp, output_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        for d in new_dirs:
            try:
                d.rmdir()  # only succeeds while empty
            except OSError:
                break
        raise
    st = source.stat()
    os.utime(output_path, ns=(st.st_atime_ns, st.st_mtime_ns))


def encrypt_file(input_path: Path, output_path: Path, passphrase: str, progress=None) -> None:
    """`progress(nbytes)` is called after each chunk; raise from it to abort."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()

    with open(input_path, "rb") as fin, atomic_output(output_path, input_path) as fout:
        fout.write(salt)
        fout.write(nonce)
        while chunk := fin.read(CHUNK_SIZE):
            fout.write(encryptor.update(chunk))
            if progress:
                progress(len(chunk))
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)  # 16-byte authentication tag, appended last


def decrypt_file(input_path: Path, output_path: Path, passphrase: str, progress=None) -> None:
    """`progress(nbytes)` is called after each chunk; raise from it to abort."""
    file_size = input_path.stat().st_size
    ciphertext_size = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE
    if ciphertext_size < 0:
        raise ValueError(f"{input_path.name} is too small to be a valid encrypted file")

    with open(input_path, "rb") as fin:
        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)
        key = derive_key(passphrase, salt)

        fin.seek(-TAG_SIZE, os.SEEK_END)
        tag = fin.read(TAG_SIZE)
        fin.seek(SALT_SIZE + NONCE_SIZE)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()

        with atomic_output(output_path, input_path) as fout:
            remaining = ciphertext_size
            while remaining > 0:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                fout.write(decryptor.update(chunk))
                if progress:
                    progress(len(chunk))
            try:
                fout.write(decryptor.finalize())
            except InvalidTag:
                raise ValueError("wrong passphrase, or the file is corrupted/tampered with") from None


def gather_files(folder: Path):
    return [
        p for p in sorted(folder.rglob("*"))
        if p.is_file() and p.name not in JUNK and not p.name.endswith(PART_SUFFIX)
    ]


def detect_mode(path: Path) -> str:
    """'decrypt' if everything at `path` is already a .enc file, else 'encrypt'."""
    files = [path] if path.is_file() else gather_files(path)
    return "decrypt" if files and all(f.name.endswith(ENCRYPTED_SUFFIX) for f in files) else "encrypt"


def default_target(path: Path, mode: str) -> Path:
    """Output goes next to the source: Photos -> Photos_encrypted -> Photos_decrypted,
    photo.jpg -> photo.jpg.enc -> photo.jpg."""
    if path.is_file():
        name = path.name + ENCRYPTED_SUFFIX if mode == "encrypt" else path.name.removesuffix(ENCRYPTED_SUFFIX)
    else:
        name = path.name + "_encrypted" if mode == "encrypt" else path.name.removesuffix("_encrypted") + "_decrypted"
    return path.with_name(name)


def numbered(path: Path) -> Path:
    """First free "name (n)": Photos_encrypted (2), photo (2).jpg.enc, photo (2).jpg."""
    enc = ENCRYPTED_SUFFIX if path.name.endswith(ENCRYPTED_SUFFIX) else ""
    name = path.name.removesuffix(enc)
    base, ext = (name, "") if path.is_dir() else os.path.splitext(name)
    n = 2
    while (candidate := path.with_name(f"{base} ({n}){ext}{enc}")).exists():
        n += 1
    return candidate


def plan(mode: str, source: Path, target: Path) -> list[tuple[Path, Path]]:
    """Every (input, output) pair for encrypting/decrypting `source` into `target`."""
    if source.is_file():
        return [(source, target)]
    pairs = []
    for f in gather_files(source):
        rel = f.relative_to(source)
        if mode == "encrypt":
            pairs.append((f, target / rel.with_name(rel.name + ENCRYPTED_SUFFIX)))
        elif rel.name.endswith(ENCRYPTED_SUFFIX):
            pairs.append((f, target / rel.with_name(rel.name.removesuffix(ENCRYPTED_SUFFIX))))
    return pairs


def needs_work(mode: str, src: Path, out: Path) -> bool:
    """Encrypt: unless the .enc is already at least as new as its source.
    Decrypt: never overwrite a file that already exists."""
    if not out.exists():
        return True
    return mode == "encrypt" and out.stat().st_mtime_ns < src.stat().st_mtime_ns


def run_with_bar(mode: str, src: Path, out: Path, passphrase: str, label: str) -> None:
    from tqdm.auto import tqdm  # CLI only; the GUI draws its own progress bars

    func = encrypt_file if mode == "encrypt" else decrypt_file
    with tqdm(total=src.stat().st_size, unit="B", unit_scale=True, unit_divisor=1024, desc=label, leave=True) as bar:
        func(src, out, passphrase, bar.update)


def process(mode: str, source: Path, dest: Path, passphrase: str) -> None:
    pairs = plan(mode, source, dest)
    if not pairs:
        print(f"No files found under {source}")
        return

    todo = [(i, o) for i, o in pairs if needs_work(mode, i, o)]
    if len(todo) < len(pairs):
        print(f"Skipping {len(pairs) - len(todo)} file(s) that are already done.")

    for i, o in todo:
        rel = i.relative_to(source) if source.is_dir() else i.name
        try:
            run_with_bar(mode, i, o, passphrase, f"{mode.capitalize()}ing {rel}")
        except ValueError as e:
            print(f"  SKIPPED {rel} ({e})")
    print("Done.")


def decrypt_in_place(folder: Path) -> None:
    """List every .enc file under `folder`, then decrypt each one next to
    itself (photo.jpg.enc -> photo.jpg). The .enc files are left untouched."""
    encrypted = [p for p in gather_files(folder) if p.suffix == ENCRYPTED_SUFFIX]
    if not encrypted:
        print(f"No {ENCRYPTED_SUFFIX} files found under {folder}")
        return

    print(f"Found {len(encrypted)} encrypted file(s) under {folder}:")
    for f in encrypted:
        print(f"  {f.relative_to(folder)}")

    passphrase = getpass.getpass("Passphrase: ")
    if not passphrase:
        sys.exit("Passphrase cannot be empty.")

    for f in encrypted:
        rel = f.relative_to(folder)
        out = f.with_suffix("")
        if not needs_work("decrypt", f, out):
            print(f"  SKIPPED {rel} ({out.name} already exists)")
            continue
        try:
            run_with_bar("decrypt", f, out, passphrase, f"Decrypting {rel}")
        except ValueError as e:
            print(f"  SKIPPED {rel} ({e})")
    print("Done.")


def main():
    # Shortcut: `python secure_backup.py <folder>` decrypts every .enc file
    # under that folder in place.
    if len(sys.argv) == 2 and Path(sys.argv[1]).is_dir():
        decrypt_in_place(Path(sys.argv[1]))
        return

    examples = """
examples:
  Encrypt a file:
    python secure_backup.py encrypt photo.jpg photo.jpg.enc

  Decrypt a file:
    python secure_backup.py decrypt photo.jpg.enc photo.jpg

  Encrypt a folder (recursively, preserving subfolders):
    python secure_backup.py encrypt ./private_photos ./private_photos_encrypted

  Decrypt a folder:
    python secure_backup.py decrypt ./private_photos_encrypted ./private_photos_restored

  Decrypt every .enc file under a folder in place (photo.jpg.enc -> photo.jpg):
    python secure_backup.py .
"""
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files/folders with one passphrase.",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("source", type=Path, help="File or folder to read from")
    parser.add_argument("dest", type=Path, help="File or folder to write to")
    args = parser.parse_args()

    if not args.source.exists():
        sys.exit(f"Source not found: {args.source}")

    passphrase = getpass.getpass("Passphrase: ")
    if not passphrase:
        sys.exit("Passphrase cannot be empty.")

    if args.mode == "encrypt":
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            sys.exit("Passphrases did not match — nothing was encrypted.")

    process(args.mode, args.source, args.dest, passphrase)


if __name__ == "__main__":
    main()
