# NoteVault

A local-first, encrypted desktop note-taking application written in Rust. Notes, attachments, and canvas drawings are stored as individual encrypted `.vault` files on disk and never depend on a shared database, which makes them straightforward to back up or synchronize with standard file-sync tools such as Nextcloud or ownCloud.

## Features

### Encryption
- Each note, attachment, and canvas drawing is stored as an independent `.vault` file. Files are self-contained, so there are no shared-database merge conflicts during cloud sync and a corrupted file does not affect the rest of the vault.
- **Cryptographic Cascade (Defense in Depth):** Cascaded authenticated encryption combining **AES-256-GCM** (inner layer) and **XChaCha20-Poly1305** (outer layer). Both ciphers must be broken simultaneously to compromise confidentiality.
- **Authenticated Header & Explicit KDF Params (`0x03`):** Each `.vault` file uses an 81-byte header storing explicit Argon2id parameters (`m_cost`, `t_cost`, `p_cost`), a unique 32-byte random salt, and separate random nonces (`12B` + `24B`), bound as Additional Authenticated Data (AAD) on both AEAD layers.
- **Key Derivation & Keyfile Support:** [Argon2id](https://en.wikipedia.org/wiki/Argon2) derives 64 bytes of key material (32 bytes for AES-256-GCM and 32 bytes for XChaCha20-Poly1305). When a physical Keyfile is provided, its [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash is passed as a pepper (`secret`) into Argon2id as a second factor against offline brute-force attacks.
- **Atomic File Writes & Backward Compatibility:** Writes use temp-file + fsync + atomic rename. Transparently decrypts legacy v1 (`56B` header) and cascade v2 (`0x02` / `69B` header) files, automatically upgrading them to `0x03` on next save or atomic re-encryption.
- **Memory Hygiene:** [`zeroize`](https://crates.io/crates/zeroize) (`Zeroizing` and `ZeroizeOnDrop`) overwrites master passwords, keyfile buffers, derived keys, and decrypted note/attachment data in memory on drop.

### Desktop GUI (`note_vault`)
- Three-panel layout with resizable folder/category sidebar, note list, and editor/canvas pane.
- **Markdown Editor & Preview:** GFM tables rendered with Unicode box drawing, task lists, code blocks, sanitized HTML, and LaTeX-to-Unicode math rendering.
- **Canvas / Drawing Notes:** `tiny-skia`-backed drawing notes with pen/eraser tools, solid/dashed/dotted strokes, custom HSL color picker, zoom/fit/pan, canvas extension, Windows stylus & palm rejection, and 30-step Undo/Redo (`Ctrl+Z` / `Ctrl+Y`).
- **Encrypted Attachments:** Attach, preview (images and text), replace, extract, and delete files encrypted alongside their parent note (`<note_id>_a<N>.vault`).
- **Quick Search & Global Hotkeys:** Floating overlay (`Shift+Space`) to copy or open notes, plus a main-window toggle hotkey (`Control+Shift+Space`).
- **Security Controls:** Configurable **Idle Auto-Lock** timeout and **Clipboard Auto-Clear** timer (clears clipboard automatically only if it still holds the copied note content).
- **Keyfile & Password Management:** Add, change, or remove a keyfile or rotate the master password from Settings with parallel atomic re-encryption across all vault files.
- **System Tray & Export:** Minimize to tray, launch at startup, dark/blue/light themes, and export to Markdown (YAML frontmatter), plain text, and JSON.

### CLI (`note_vault_cli`)
A companion command-line tool for scripting and automation:

| Subcommand | Description |
|------------|-------------|
| `encrypt`  | Encrypts a plaintext file into a `.vault` file (supports optional `--keyfile <FILE>`). |
| `decrypt`  | Decrypts a `.vault` file back to plaintext (supports optional `--keyfile <FILE>`). |
| `info`     | Displays note metadata (ID, title, tags, timestamps) without printing the content (supports optional `--keyfile <FILE>`). |

Passphrases are read securely from the terminal (no echo) using [`rpassword`](https://crates.io/crates/rpassword).

## Configuration

On first run the GUI reads `config.json` from the working directory. An example with all available keys and defaults:

```json
{
  "vault_path": "C:\\Users\\you\\Documents\\vault",
  "keyfile_path": null,
  "use_multithreading": true,
  "theme": "dark",
  "global_hotkey": "Shift+Space",
  "main_window_hotkey": "Control+Shift+Space",
  "minimize_to_tray": true,
  "editor_show_line_numbers": false,
  "editor_line_wrap": true,
  "editor_highlight_current_line": true,
  "editor_font_size": 14,
  "editor_markdown_mode": false,
  "launch_at_startup": false,
  "folder_pane_width": 210,
  "notes_pane_width": 300,
  "auto_lock_minutes": 0,
  "clipboard_clear_seconds": 30
}
```

| Key | Type | Description |
|-----|------|-------------|
| `vault_path` | string | Path to the directory where `.vault` files are stored (supports `%VAR%`, `$VAR`, `${VAR}`). |
| `keyfile_path` | string \| `null` | Optional path to a physical keyfile used as a second factor. |
| `use_multithreading` | bool | Load and re-encrypt notes in parallel using Rayon. |
| `theme` | `"dark"` \| `"blue"` \| `"light"` | UI color theme. |
| `global_hotkey` | string | System-wide hotkey to show/hide the Quick Search window (default `"Shift+Space"`). |
| `main_window_hotkey` | string | System-wide hotkey to show/hide/minimize the main window (default `"Control+Shift+Space"`). |
| `minimize_to_tray` | bool | Minimize the main window to the system tray instead of the taskbar (default `true`). |
| `editor_show_line_numbers` | bool | Show line numbers in the note editor (default `false`). |
| `editor_line_wrap` | bool | Wrap long lines in the editor (default `true`). |
| `editor_highlight_current_line` | bool | Highlight the line the cursor is on (default `true`). |
| `editor_font_size` | integer | Editor font size in points (default `14`). |
| `editor_markdown_mode` | bool | Default Markdown preview toggle state (default `false`). |
| `launch_at_startup` | bool | Register NoteVault to launch automatically on system startup (minimized if `minimize_to_tray` is enabled). |
| `folder_pane_width` | integer | Width of the folders sidebar in pixels (default `210`). |
| `notes_pane_width` | integer | Width of the notes list column in pixels (default `300`). |
| `auto_lock_minutes` | integer | Automatically lock the vault after N minutes of inactivity (`0` = disabled). |
| `clipboard_clear_seconds` | integer | Clear copied note text from the clipboard after N seconds (`0` = disabled, default `30`). |

The `--vault-path` command-line flag overrides `vault_path` from `config.json` for a single session.

## Building

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (stable, edition 2024)
- On Windows, a MSVC-compatible linker is required (installed as part of [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)).

### Debug & Release builds
```powershell
cargo build
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

### Running all tests
```powershell
cargo test
```

### Running specific test suites
```powershell
# Core library unit tests (cryptography v1/v2/v3, cascade AEAD, config, export, validation)
cargo test --lib

# Desktop GUI binary tests (hotkey parsing, tray icon, search filtering, canvas undo/redo)
cargo test --bin note_vault

# CLI binary tests (argument parsing, flags, subcommands)
cargo test --bin note_vault_cli

# Integration test suites
cargo test --test vault_integration
cargo test --test attachment_integration
cargo test --test canvas_integration
cargo test --test export_and_validation
```

## Creating a Release Archive

A PowerShell script is provided to build the project and package the release binaries into a versioned `.zip` file:

```powershell
.\scripts\make_release.ps1
```

The script reads the version from `Cargo.toml`, runs `cargo build --release`, and collects `note_vault.exe`, `note_vault_cli.exe`, and `config.json` (if present) into `note_vault-<version>-windows-x86_64.zip` in the project root.

## License

See [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) for dependency licenses.
