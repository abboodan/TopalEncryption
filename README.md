<div align="center">

<img src="assets/logo.svg" width="112" alt="Topal Encryption logo">

# Topal Encryption

**Password-protect any file or folder on Windows.**

Photos, videos, documents, anything. Drop it in, type a password, done.
Without the password, nobody can open the files. Not even you.

[![CI](https://github.com/abboodan/TopalEncryption/actions/workflows/ci.yml/badge.svg)](https://github.com/abboodan/TopalEncryption/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-5eead4.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/abboodan/TopalEncryption?color=38bdf8)](https://github.com/abboodan/TopalEncryption/releases/latest)

<img src="assets/screenshot.png" width="620" alt="Topal Encryption encrypting a folder of 1,248 files">

</div>

## Features

- **Any file, any size.** Files are streamed in 1 MB chunks, so a 50 GB video uses the same couple of megabytes of memory as a text file.
- **Whole folders at once.** Drop a folder with thousands of files: the password is processed once for the whole batch and files are encrypted in parallel on every CPU core.
- **Safe to interrupt.** Each output is written to a temporary file and renamed into place only when complete. Cancel, crash or power loss never leaves a half-written file, and running again picks up where it stopped.
- **Your originals stay** unless you tick the box. If you do, each encrypted file is decrypted back and checked before its original is removed.
- **Tamper-evident.** A flipped bit, a truncated file or a swapped block is detected and reported instead of producing garbage.
- **Hide file names.** Optionally give every output a random name and pack each folder into a single file, so names, folder structure and file count are encrypted too. The real names come back when decrypting.
- **Rename freely.** The original name is stored inside the encrypted file, so `a1.topal` still decrypts to `photo.jpg`.
- **Recovery key.** An optional second key, shown once for you to print, that opens your files if you forget the password.
- **Change the password in seconds.** Only the small header of each file is rewritten, not the content, even for a 50 GB file.
- **Verify.** Check that a backup still opens and is undamaged, without writing anything.
- **Save anywhere.** Write the results next to the originals or into another folder or drive, keeping the folder structure.
- **Passphrase generator.** One click for a strong passphrase made of six common words.
- **Explorer right-click menu.** The installer adds *Encrypt with Topal Encryption* to files and folders; double-clicking a `.topal` file opens it for decryption.
- **English and Arabic** interface, switchable at any time.
- **Small.** The installer is a few megabytes. No account, no network access, no telemetry.

## Download

Get the latest build from the [Releases page](https://github.com/abboodan/TopalEncryption/releases/latest):

| File | What it is |
|---|---|
| `TopalEncryption_x.y.z_x64-setup.exe` | Installer for the desktop app |
| `TopalEncryption.exe` | Portable desktop app, no installation |
| `topal-cli.exe` | Command-line tool |

The builds are not code-signed, so Windows SmartScreen may warn on first launch
(**More info → Run anyway**). The desktop app needs the WebView2 runtime, which ships with
Windows 10 and 11.

## Usage

### Desktop app

1. Choose **Encrypt**, **Decrypt**, **Verify** or **Change password**.
2. Drop files or folders onto the window (or use **Add files** / **Add folder**).
3. Type the password and press the button.

Encrypting `photo.jpg` creates `photo.jpg.topal` next to it. Decrypting does the reverse.

Options when encrypting: delete the originals once each encrypted file has been checked,
hide file names, and choose another folder for the results. The **Recovery key** button in
the header creates or turns off the recovery key. With the installer, you can also
right-click files or folders in Explorer (on Windows 11, under *Show more options*).

### Command line

```
topal-cli encrypt "D:\Vacation Photos"
topal-cli decrypt "D:\Vacation Photos"
topal-cli encrypt report.pdf video.mkv --delete-source
topal-cli encrypt "D:\Private" --hide-names --output "E:\Backup"
topal-cli verify "E:\Backup"
topal-cli change-password "E:\Backup"
topal-cli decrypt "E:\Backup" --recovery-key
topal-cli recovery create
topal-cli passphrase
```

| Command | What it does |
|---|---|
| `encrypt` | Encrypt files, or every file inside folders |
| `decrypt` | Decrypt `.topal` files, or every `.topal` file inside folders |
| `verify` | Check that files open with the password and are undamaged; writes nothing |
| `change-password` | Give files a new password without re-encrypting their content |
| `recovery create`, `status`, `disable` | Manage the recovery key |
| `passphrase` | Print a random passphrase |

| Option | Meaning |
|---|---|
| `--delete-source` | Delete each source once its output is written and verified |
| `--force` | Overwrite output files that already exist instead of skipping them. When decrypting, only an output named after the encrypted file is overwritten |
| `-o, --output <DIR>` | Write outputs to this folder, keeping the folder structure |
| `--hide-names` | Random output names, and each folder packed into a single file |
| `--no-recovery` | Do not add the recovery key to these files |
| `--recovery-key` | Open files with the recovery key instead of the password |
| `-j, --jobs <N>` | Files processed in parallel (default: all CPU cores) |

Secrets are prompted for without echo. For scripts, set `TOPAL_PASSWORD`,
`TOPAL_NEW_PASSWORD` or `TOPAL_RECOVERY_KEY` instead.

## How it works

Topal Encryption invents no cryptography. It combines standard, well-studied primitives from the
[RustCrypto](https://github.com/RustCrypto) project:

| Step | Primitive |
|---|---|
| Password → key | **Argon2id**, 256 MiB, 3 passes, 4 lanes, random 16-byte salt |
| Key wrapping and content | **XChaCha20-Poly1305** (256-bit key, authenticated) |
| Large files | **STREAM** construction: 1 MiB chunks, each bound to its position |
| Recovery key | **X25519** key agreement, **HKDF-SHA256**, then XChaCha20-Poly1305 |

```
password ──Argon2id──▶ key-encryption key ──unwraps──▶ random per-file key ──▶ file content
```

- Argon2id makes every password guess cost about a second and 256 MiB of memory, which is
  what makes brute-forcing a decent password impractical even on GPUs.
- Every file gets its own random 256-bit key. The password-derived key only wraps that key.
- A batch shares one salt, so 10,000 files cost one key derivation rather than 10,000. Each
  `.topal` file is still fully self-contained and decrypts on its own.
- Changing the password re-wraps the per-file key under the new password. The content, which
  is encrypted with the per-file key, is not touched.
- A recovery key is an X25519 key pair. Only the public half stays on the PC, so encrypting
  never needs the secret half; each file key is additionally sealed to that public key. The
  secret half is shown once and never stored by the app.

### File format (version 2)

All integers are little-endian.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 5 | Magic `TOPAL` |
| 5 | 1 | Format version (`2`) |
| 6 | 1 | Flags: `1` folder container, `2` has a recovery slot |
| 7 | 12 | Argon2id memory (KiB), passes, lanes |
| 19 | 16 | Argon2id salt |
| 35 | 4 | Plaintext chunk size |
| 39 | 19 | Stream nonce prefix |
| 58 | 24 | Key-wrap nonce |
| 82 | 48 | Per-file key, wrapped with the password key (32 bytes + 16-byte tag) |
| 130 | 32 | Recovery slot: ephemeral X25519 public key (only with flag `2`) |
| 162 | 48 | Recovery slot: per-file key, wrapped for the recovery key (only with flag `2`) |
| … | … | Encrypted chunks, each chunk size + 16-byte tag |

Bytes 0–57 are authenticated as associated data of the password-wrapped key, so they
cannot be altered without the password being rejected. The recovery slot authenticates the
same fields except the password salt and costs, which is what allows a password change
without the recovery key. Each way of opening a file checks its own slot only: damage to
the recovery slot is not noticed when opening or verifying with the password, and the
other way round.

The encrypted stream starts with the original name (2-byte length, then UTF-8), followed by
the file content. For a folder container it is followed by a sequence of entries instead:
kind (`1` file, `2` folder, `0` end), 2-byte path length, relative path, and for files an
8-byte size and the content. Nothing is compressed. When unpacking, every path component is
checked so that a crafted file cannot write outside its own folder.

Details needed to write another reader:

- **Chunk nonces.** Chunk *n* (from 0) uses the 24-byte nonce `prefix ‖ n as 32-bit
  big-endian ‖ last`, where `last` is `1` for the final chunk and `0` otherwise, and no
  associated data. A file with no content still has one (empty) final chunk.
- **Recovery slot.** `shared = X25519(ephemeral secret, recovery public key)`. The wrapping
  key is HKDF-SHA256 with salt `ephemeral public ‖ recovery public`, input `shared`, info
  `topal recovery key wrap v2`, 32 bytes out. The per-file key is sealed with
  XChaCha20-Poly1305 under an all-zero nonce (the key is used once) with associated data
  `"TOPAL recovery slot" ‖ version ‖ flags ‖ chunk size ‖ stream nonce prefix`.
- **Recovery key ID.** The first eight bytes of `SHA-256("TOPAL-PUB-ID" ‖ recovery public
  key)`, in upper-case hex, in groups of four.
- **Recovery key text.** `TOPAL-KEY-` followed by base32 (RFC 4648, no padding, grouped in
  fives) of the 32-byte X25519 secret and the first two bytes of
  `SHA-256("TOPAL-KEY" ‖ secret)`.

[`tools/topal_decrypt.py`](tools/topal_decrypt.py) is a reader written from this description
alone, in about a hundred lines of Python on top of libsodium and the reference Argon2. It
shares no code with the app, and [`tools/check.py`](tools/check.py) uses it to confirm that
files written by `topal-cli` are exactly what is documented here.

Version 1 files (no flags byte, no recorded name, no recovery slot) are still read.

## Security notes

Please read these before trusting Topal Encryption with data you cannot afford to lose.

- **There is no password recovery unless you create a recovery key first.** Without one, a
  forgotten password means the data is gone. That is the point of the design.
- **A recovery key is as powerful as the password.** Anyone who has it can open every file
  encrypted while it was on. Keep it on paper or in a password manager, away from the files.
- **Check the recovery key ID.** The public half of the key is an ordinary file on your PC.
  If something replaced it, new files would open with someone else's key instead of yours.
  The app and `topal-cli` show the ID of the key in use whenever you encrypt
  (`XXXX-XXXX-XXXX-XXXX`); it must be the ID that was shown, and saved, with your key.
- **Verify with the recovery key too.** `verify` with the password proves the password
  opens the file; it says nothing about the recovery slot. If you rely on a recovery key
  for a backup, run verify once with the key as well.
- **Links are not packed.** Shortcuts to other places inside a folder (symbolic links,
  junctions) are skipped when encrypting, and left where they are.
- **Changing a password does not reach old copies.** A backup made before the change still
  opens with the old password.
- **An encrypted file from someone else decides its own output name.** The original name
  is stored inside, so `photo.jpg.topal` can decrypt to a file of any name and type in the
  same folder. Topal Encryption never lets that name leave the folder or replace an existing
  file, refuses names built to display as something else, tells you when a program came
  out under a name you could not see, and passes Windows' "downloaded from the internet"
  mark on to what it decrypts. Still, treat what comes out of a stranger's file as you
  would any download.
- **Your password is the weak link.** The encryption is only as strong as the password.
  Use a long passphrase.
- **File names and folder structure are visible unless you tick *Hide file names*.** By
  default `tax-2025.pdf` becomes `tax-2025.pdf.topal`. Sizes are never hidden: an encrypted
  file is about as large as what it holds.
- **Deleting originals is not a secure wipe.** It is a normal delete; on SSDs in particular,
  deleted data can remain recoverable. For data that must not be recoverable, use full-disk
  encryption (BitLocker) underneath.
- **Topal Encryption has not had an independent security audit.** The primitives are standard and the
  format is documented above, but the code is young. Review is welcome.
- Topal Encryption protects files at rest. It cannot protect against malware already running on your
  PC while you type the password.

Found a vulnerability? Please report it privately through
[GitHub security advisories](https://github.com/abboodan/TopalEncryption/security/advisories/new).

## Build from source

Requirements: [Rust](https://rustup.rs) (stable), the Visual Studio C++ build tools, and
[Node.js](https://nodejs.org) for the desktop app.

```
git clone https://github.com/abboodan/TopalEncryption
cd TopalEncryption

cargo test                         # run the test suite
cargo build --release -p topal     # CLI      -> target/release/topal-cli.exe

cd gui
npm install
npx tauri build                    # app      -> target/release/TopalEncryption.exe
                                   # installer -> target/release/bundle/nsis/
```

### Project layout

| Path | Contents |
|---|---|
| `core/` | `topal-core`: file format, streaming cipher, batch engine, tests |
| `cli/` | `topal-cli` command-line tool |
| `gui/src-tauri/` | Desktop app backend ([Tauri](https://tauri.app)) |
| `gui/ui/` | Desktop app interface (plain HTML, CSS and JavaScript) |

## License

[MIT](LICENSE)
