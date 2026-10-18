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

1. Choose **Encrypt** or **Decrypt**. Each run does only that one thing.
2. Drop folders or files onto the window (or use **Choose a folder / choose files**), then press **Continue**.
3. Passphrase:
   - **Encrypting:** use the suggested passphrase (six random words) or type your own twice. Save it, tick
     **I've saved this passphrase somewhere safe**, and press **Encrypt**.
   - **Decrypting:** type the passphrase the files were encrypted with, and press **Decrypt**.

| You drop | You get, in the same place |
|---|---|
| `Photos/` | `Photos_encrypted/`: same subfolders, every file becomes `name.ext.enc` |
| `Photos_encrypted/` | `Photos_decrypted/` |
| `photo.jpg` | `photo.jpg.enc` |
| `photo.jpg.enc` | `photo.jpg` |

- Encrypt turns away anything that's already encrypted, and Decrypt turns away anything with no `.enc` files in it.
- Adding to an `_encrypted` folder that already exists asks for the passphrase you used last time instead of
  suggesting a new one, and checks it against a file already in there before it encrypts anything. One folder
  never ends up with two passphrases. The command line does the same check.
- If the output already exists, it asks you what to do:
  - **only new or changed files**: handy after you add photos to a folder.
  - **skip files already there**: when decrypting.
  - **save as a new copy**: for example `Photos_encrypted (2)`.
- It never deletes your originals and never overwrites a decrypted file.
- Cancel, a wrong passphrase, or a crash never leaves a half-written file behind.
- A wrong passphrase is caught on the first (smallest) file, before any big videos are processed.

> **There is no passphrase recovery.** Lose the passphrase and the files are gone. That's the point.
> Keep it in a password manager.

The suggested passphrase is six words picked with Python's `secrets` module from
[EFF's large wordlist](https://www.eff.org/dice) (7,776 words, in `wordlist.py`), about 77 bits. The list being
public doesn't weaken it: an attacker still has to try 7,776⁶ combinations, each costing a full scrypt run.
The word list is by the Electronic Frontier Foundation, licensed under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).

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

The icons in `assets/` are rendered from `app_icon()` in `app.py`. The interface font is
[IBM Plex Sans](https://github.com/IBM/plex), bundled in `assets/fonts/` under the SIL Open Font License
(`assets/fonts/LICENSE.txt`).

**Releasing:** on GitHub, go to **Releases** → **Draft a new release**, type a new tag such as `v1.0.0`,
and press **Publish release**. GitHub Actions then builds Windows, macOS, and Linux and attaches the
files to that release, which takes about 10 minutes.

To build without releasing, open the Actions tab → **Build** → **Run workflow**. The files appear on the run's page.

## File format

Every `.enc` file is `salt (16 bytes) | nonce (12) | ciphertext | GCM tag (16)`.
The key is `scrypt(passphrase UTF-8, salt, n=2^15, r=8, p=1, 32 bytes)` and the cipher is AES-256-GCM.
That's enough to decrypt your files with any crypto library, even if this app disappears.
