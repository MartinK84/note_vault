# NoteVault

A local-first, encrypted note-taking desktop application written in Rust. Notes are stored as individual encrypted `.vault` files on disk and never depend on a shared database, which makes them straightforward to back up or synchronize with standard file-sync tools such as Nextcloud or ownCloud.

## Features

### Encryption
- Each note is stored as a separate `.vault` file. Files are independent of each other, so there are no merge conflicts during cloud sync and a corrupted file does not affect the rest of the vault.
- **Key derivation:** [Argon2id](https://en.wikipedia.org/wiki/Argon2) with a unique random salt per file.
- **Authenticated encryption:** [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) (AEAD) with a unique random nonce per file. Any tampering with the ciphertext is detected and rejected on decryption.
- **Memory hygiene:** The [`zeroize`](https://crates.io/crates/zeroize) crate is used to overwrite master passwords, derived keys, and decrypted plaintext in memory as soon as they are no longer needed.

### Desktop GUI (`note_vault`)
- Three-panel layout: folder/category sidebar, note list, and editor.
- Notes can be organized into categories (mapped to subdirectories inside the vault folder).
- Tags are stored as metadata inside each encrypted file and are searchable without decrypting the full note body (metadata is decrypted on load; content is only decrypted on demand).
- Search across note titles and tags.
- **Quick Search overlay** — a small floating window accessible via a configurable global hotkey (default `Shift+Space`). It shows the five most recently updated notes matching the query and lets you open one in the main window.
- System tray icon with a context menu; the main window can be minimized to tray.
- Note export to Markdown (with YAML front matter), plain text, and JSON.
- Light and dark themes.

### CLI (`note_vault_cli`)
A companion command-line tool for scripting and automation:

| Subcommand | Description |
|------------|-------------|
| `encrypt`  | Encrypts a plaintext file into a `.vault` file. |
| `decrypt`  | Decrypts a `.vault` file back to plaintext. |
| `info`     | Displays note metadata (ID, title, tags, timestamps) without printing the content. |

Passwords are read securely from the terminal (no echo) using [`rpassword`](https://crates.io/crates/rpassword).

## Configuration

On first run the GUI reads `config.json` from the working directory. An example with all available keys:

```json
{
  "vault_path": "C:\\Users\\you\\Documents\\vault",
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
| `use_multithreading` | bool | Load notes in parallel using Rayon. Useful for large vaults. |
| `theme` | `"dark"` \| `"light"` | UI color theme. |
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