# NoteVault

A local-first, encrypted note-taking desktop application written in Rust. Notes are stored as individual encrypted `.vault` files on disk and never depend on a shared database, which makes them straightforward to back up or synchronize with standard file-sync tools such as Nextcloud or ownCloud.

## Features

### Encryption
- Each note is stored as a separate `.vault` file. Files are independent of each other, so there are no merge conflicts during cloud sync and a corrupted file does not affect the rest of the vault.
- **Cryptographic Cascade (Defense in Depth):** Cascaded authenticated encryption combining **AES-256-GCM** (inner layer) and **XChaCha20-Poly1305** (outer layer). Both ciphers must be broken simultaneously to compromise note confidentiality.
- **Key Derivation & Keyfile Support:** [Argon2id](https://en.wikipedia.org/wiki/Argon2) derives 64 bytes of key material (32 bytes for AES-256-GCM and 32 bytes for XChaCha20-Poly1305) with a unique 32-byte random salt per file. When a physical Keyfile is provided, its [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash is passed as a pepper (`secret`) into Argon2id, acting as a second factor against offline brute-force attacks.
- **Backward Compatibility:** Seamlessly decrypts legacy format (`0x01` / 56-byte header with single XChaCha20-Poly1305) notes, automatically upgrading them to the cascaded version `0x02` upon the next save.
- **Memory Hygiene:** The [`zeroize`](https://crates.io/crates/zeroize) crate is used to overwrite master passwords, keyfile buffers, derived keys, and decrypted plaintext in memory as soon as they are no longer needed.

### Desktop GUI (`note_vault`)
- Three-panel layout: folder/category sidebar, note list, and editor.
- Notes can be organized into categories (mapped to subdirectories inside the vault folder).
- Tags are stored as metadata inside each encrypted file and are searchable without decrypting the full note body (metadata is decrypted on load; content is only decrypted on demand).
- Search across note titles and tags.
- **Quick Search overlay** — a small floating window accessible via a configurable global hotkey (default `Shift+Space`). It shows the five most recently updated notes matching the query and lets you open one in the main window.
- **Keyfile Management** — Easily add, change, or remove a keyfile from the Settings dialog with real-time atomic re-encryption of all notes. If a keyfile is moved or missing, the unlock dialog provides a direct file locator.
- System tray icon with a context menu; the main window can be minimized to tray.
- Note export to Markdown (with YAML front matter), plain text, and JSON.
- Light and dark themes.

### CLI (`note_vault_cli`)
A companion command-line tool for scripting and automation:

| Subcommand | Description |
|------------|-------------|
| `encrypt`  | Encrypts a plaintext file into a `.vault` file (supports optional `--keyfile <FILE>`). |
| `decrypt`  | Decrypts a `.vault` file back to plaintext (supports optional `--keyfile <FILE>`). |
| `info`     | Displays note metadata (ID, title, tags, timestamps) without printing the content (supports optional `--keyfile <FILE>`). |

Passphrases are read securely from the terminal (no echo) using [`rpassword`](https://crates.io/crates/rpassword).

## Configuration

On first run the GUI reads `config.json` from the working directory. An example with all available keys:

```json
{
  "vault_path": "C:\\Users\\you\\Documents\\vault",
  "keyfile_path": null,
  "use_multithreading": true,
  "theme": "dark",
  "global_hotkey": "Shift+Space",
  "minimize_to_tray": false,
  "editor_show_line_numbers": true,
  "editor_line_wrap": true,
  "editor_highlight_current_line": true,
  "editor_font_size": 14
}
```

| Key | Type | Description |
|-----|------|-------------|
| `vault_path` | string | Absolute path to the directory where `.vault` files are stored. |
| `keyfile_path` | string \| `null` | Optional path to a physical keyfile used as a second factor. |
| `use_multithreading` | bool | Load notes in parallel using Rayon. Useful for large vaults. |
| `theme` | `"dark"` \| `"light"` \| `"blue"` | UI color theme. |
| `global_hotkey` | string | System-wide hotkey to show/hide the Quick Search window (e.g. `"Shift+Space"`, `"Control+Shift+N"`). |
| `minimize_to_tray` | bool | Minimize the main window to the system tray instead of the taskbar. |
| `editor_show_line_numbers` | bool | Show line numbers in the note editor. |
| `editor_line_wrap` | bool | Wrap long lines in the editor. |
| `editor_highlight_current_line` | bool | Highlight the line the cursor is on. |
| `editor_font_size` | integer | Editor font size in points. |

The `--vault-path` command-line flag overrides `vault_path` from `config.json` for a single session.

## Building

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (stable, edition 2024)
- On Windows, a MSVC-compatible linker is required (installed as part of [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)).

### Debug build
```powershell
cargo build
```

### Release build
```powershell
cargo build --release
```

The compiled binaries are placed in `target\release\`:
- `note_vault.exe` — the desktop GUI application
- `note_vault_cli.exe` — the command-line tool

### Running directly
```powershell
# GUI (reads config.json from the current directory)
.\target\release\note_vault.exe

# GUI with a temporary vault path override
.\target\release\note_vault.exe --vault-path "C:\path\to\vault"

# CLI — show help
.\target\release\note_vault_cli.exe --help
```

## Testing

NoteVault features a comprehensive automated test suite covering unit tests, cryptographic cascade verification, validation and sanitization, note export formatting, and end-to-end vault integration workflows.

### Running all tests
```powershell
cargo test
```

### Running specific test suites
```powershell
# Core library unit tests (cryptography, cascade AEAD, config, export, validation)
cargo test --lib

# Desktop GUI binary tests (hotkey parsing, tray icon, search filtering)
cargo test --bin note_vault

# CLI binary tests (argument parsing, flags, subcommands)
cargo test --bin note_vault_cli

# Vault integration tests (lifecycle, atomic re-encryption, header resilience)
cargo test --test vault_integration

# Export and validation integration tests
cargo test --test export_and_validation
```

### Running tests with output
To view console prints or detailed progress logs during test execution:
```powershell
cargo test -- --nocapture
```

## Creating a Release Archive

A PowerShell script is provided to build the project and package the release binaries into a versioned `.zip` file:

```powershell
.\scripts\make_release.ps1
```

The script:
1. Reads the version from `Cargo.toml`.
2. Runs `cargo build --release`.
3. Collects `note_vault.exe`, `note_vault_cli.exe`, and `config.json` into a zip archive named `note_vault-<version>-windows-x86_64.zip` in the project root.

Run it from the project root directory.

## License

See [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) for dependency licenses.