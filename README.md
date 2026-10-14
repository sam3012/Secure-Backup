# Secure Backup

Encrypt photos, videos, or any folder with one passphrase before uploading it
to Google Drive (or anywhere else). The cloud only ever sees unreadable `.enc`
files.

## Download

Grab the latest build from the **Releases** page:

| Platform | File |
|---|---|
| Windows | `SecureBackup-windows-x64.exe` (runs as is, no installer) |
| macOS (M1 and newer) | `SecureBackup-macos-arm64.zip` (unzip, then move `SecureBackup.app` to Applications) |
| Linux | `SecureBackup-linux-x64.tar.gz` (`tar -xzf` it, then run `./SecureBackup`) |

The apps aren't signed with a paid certificate, so the first launch shows a warning:

- **Windows**: "Windows protected your PC" → **More info** → **Run anyway**.
- **macOS**: "Apple could not verify…" → **Done**, then System Settings → Privacy & Security →
  scroll down → **Open Anyway**. If macOS says the app "is damaged", run
  `xattr -dr com.apple.quarantine /Applications/SecureBackup.app` once.

## Using it

1. Drop folders or files onto the window (or use **Add folder… / Add files…**).
2. Type your passphrase (twice when encrypting).
3. Press **Start**.

| You drop | You get, in the same place |
|---|---|
| `Photos/` | `Photos_encrypted/`: same subfolders, every file becomes `name.ext.enc` |
| `Photos_encrypted/` | `Photos_decrypted/` |
| `photo.jpg` | `photo.jpg.enc` |
| `photo.jpg.enc` | `photo.jpg` |

- It decides whether to encrypt or decrypt for you. A folder that holds only `.enc` files is decrypted; anything else is encrypted.
- If the output already exists, it asks you what to do:
  - **only new or changed files**: handy after you add photos to a folder.
  - **skip files already there**: when decrypting.
  - **save as a new copy**: for example `Photos_encrypted (2)`.
- It never deletes your originals and never overwrites a decrypted file.
- Cancel, a wrong passphrase, or a crash never leaves a half-written file behind.
- A wrong passphrase is caught on the first (smallest) file, before any big videos are processed.

> **There is no passphrase recovery.** Lose the passphrase and the files are gone. That's the point.
> Keep it in a password manager.

## Command line

The same code also works from the terminal:

```bash
pip install -r requirements.txt
python secure_backup.py encrypt ./Photos ./Photos_encrypted
python secure_backup.py decrypt ./Photos_encrypted ./Photos_restored
python secure_backup.py ./Photos_encrypted   # decrypt every .enc next to itself
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python app.py                 # run the GUI
.venv/bin/python test_secure_backup.py  # self-check
```

The icons in `assets/` are rendered from `app_icon()` in `app.py`.

**Releasing:** on GitHub, go to **Releases** → **Draft a new release**, type a new tag such as `v1.0.0`,
and press **Publish release**. GitHub Actions then builds Windows, macOS, and Linux and attaches the
files to that release, which takes about 10 minutes.

To build without releasing, open the Actions tab → **Build** → **Run workflow**. The files appear on the run's page.

## File format

Every `.enc` file is `salt (16 bytes) | nonce (12) | ciphertext | GCM tag (16)`.
The key is `scrypt(passphrase UTF-8, salt, n=2^15, r=8, p=1, 32 bytes)` and the cipher is AES-256-GCM.
That's enough to decrypt your files with any crypto library, even if this app disappears.
