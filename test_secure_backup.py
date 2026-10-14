"""Self-check for secure_backup.py. Run: python test_secure_backup.py"""

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import secure_backup as sb


def expect_error(exc, fn, *args):
    try:
        fn(*args)
    except exc:
        return
    raise AssertionError(f"{fn.__name__} did not raise {exc.__name__}")


def main():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        photos = root / "Photos"
        (photos / "trip").mkdir(parents=True)
        video = photos / "trip" / "video.mp4"
        big = os.urandom(sb.CHUNK_SIZE + 123)  # crosses a chunk boundary
        video.write_bytes(big)
        (photos / "empty.txt").write_bytes(b"")
        (photos / ".DS_Store").write_bytes(b"junk")

        # Encrypt: mode detected, output next to the folder, OS junk skipped.
        assert sb.detect_mode(photos) == "encrypt"
        enc = sb.default_target(photos, "encrypt")
        assert enc == root / "Photos_encrypted"
        pairs = sb.plan("encrypt", photos, enc)
        assert len(pairs) == 2, pairs
        for i, o in pairs:
            sb.encrypt_file(i, o, "pw")
        assert (enc / "trip" / "video.mp4.enc").exists()
        assert not list(enc.rglob("*.part"))

        # Re-run: nothing to do until a source changes.
        assert not [p for p in pairs if sb.needs_work("encrypt", *p)]
        os.utime(photos / "empty.txt", ns=(2 * 10**18, 2 * 10**18))
        assert [o.name for i, o in pairs if sb.needs_work("encrypt", i, o)] == ["empty.txt.enc"]

        # Finder clutter and a leftover .part don't confuse decrypt detection.
        (enc / ".DS_Store").write_bytes(b"junk")
        (enc / "half.jpg.enc.part").write_bytes(b"half")
        assert sb.detect_mode(enc) == "decrypt"

        # Decrypt round trip; file dates survive.
        dec = sb.default_target(enc, "decrypt")
        assert dec == root / "Photos_decrypted"
        dpairs = sb.plan("decrypt", enc, dec)
        assert len(dpairs) == 2, dpairs
        for i, o in dpairs:
            sb.decrypt_file(i, o, "pw")
        assert (dec / "trip" / "video.mp4").read_bytes() == big
        assert (dec / "empty.txt").read_bytes() == b""
        assert (dec / "trip" / "video.mp4").stat().st_mtime_ns == video.stat().st_mtime_ns
        assert not [p for p in dpairs if sb.needs_work("decrypt", *p)]  # never overwrites

        # Wrong passphrase: error, nothing left behind — not even the new folders.
        out = root / "restore" / "trip" / "wrong.mp4"
        expect_error(ValueError, sb.decrypt_file, enc / "trip" / "video.mp4.enc", out, "nope")
        assert not (root / "restore").exists()

        # Cancel mid-file (progress callback raises): nothing left behind.
        class Stop(Exception):
            pass

        def stop(_):
            raise Stop

        out = root / "cancelled.enc"
        expect_error(Stop, sb.encrypt_file, video, out, "pw", stop)
        assert not out.exists() and not (root / "cancelled.enc.part").exists()

        # Files from the original CLI (salt | nonce | ciphertext | tag) still decrypt.
        salt, nonce = os.urandom(sb.SALT_SIZE), os.urandom(sb.NONCE_SIZE)
        legacy = root / "legacy.jpg.enc"
        legacy.write_bytes(salt + nonce + AESGCM(sb.derive_key("pw", salt)).encrypt(nonce, b"old photo", None))
        assert sb.detect_mode(legacy) == "decrypt"
        target = sb.default_target(legacy, "decrypt")
        sb.decrypt_file(legacy, target, "pw")
        assert target == root / "legacy.jpg" and target.read_bytes() == b"old photo"

        # "Save as a new copy" names.
        assert sb.numbered(target) == root / "legacy (2).jpg"
        assert sb.numbered(legacy) == root / "legacy (2).jpg.enc"
        assert sb.numbered(enc) == root / "Photos_encrypted (2)"

    print("All checks passed.")


if __name__ == "__main__":
    main()
