# NoteVault — Agent Guide

## 1. Project Overview & Tech Stack
- **NoteVault** is a local-first, encrypted desktop note-taking application written in Rust (`edition = "2024"`). Notes, attachments, and canvas drawings are stored as independent encrypted `.vault` files on disk (no shared database), designed for conflict-free file synchronization (e.g., Nextcloud/ownCloud).
- **Crate Targets (`Cargo.toml`)**:
  - `note_vault` (library, `src/lib.rs`)
  - `note_vault` (desktop GUI binary, `src/main.rs`, Slint `1.17.1`)
  - `note_vault_cli` (companion CLI binary, `src/cli.rs`, Clap `4.6.6`)
- **Primary Platform**: Windows (MSVC toolchain; Win32 FFI for system tray/taskbar visibility, window activation, `ShellExecuteW` URL opening, `GetLastInputInfo` idle detection, stylus/pen WndProc subclassing, registry autostart, and `winres` icon embedding). Linux fallbacks exist in `src/single_instance.rs`, `src/startup.rs`, and `src/gui/win_interop.rs`.

## 2. Repository Map
- `src/lib.rs`: Core cryptography (`derive_key_with_params`, `derive_key`, `encrypt_bytes`, `decrypt_bytes`, `atomic_write`, `save_note_encrypted`, `load_note_decrypted`, `reencrypt_vault_atomic` via Rayon), `Note` / `NoteType` (`Text` | `Canvas`), `VaultError`, canvas pixmap/coordinate helpers, and `slint::include_modules!()`.
- `src/main.rs` + `src/main_tests.rs`: Desktop GUI entrypoint, Slint window setup, tray & 50 ms `slint::Timer` loop (tray events, minimize-to-tray, quick-search focus, idle auto-lock, clipboard auto-clear), and global hotkey listener thread.
- `src/gui/`: Modularized GUI backend:
  - `state.rs`: `Args`, `NoteMetaSummary`, `ActiveCanvasState` (pixmap, cached `SharedPixelBuffer`, 30-step undo/redo stacks), and `AppState`.
  - `canvas.rs`: `sync_canvas_full`, `sync_canvas_dirty_rect` (partial un-premultiplication), undo/redo helpers, `draw_stroke_on_pixmap`, hex/color utilities.
  - `hotkey.rs`: `parse_hotkey_string`, `format_key_combination`, `create_tray_icon`.
  - `win_interop.rs`: Win32 taskbar/foreground FFI, `open_url_safely` (`ShellExecuteW` / `xdg-open`), `get_idle_duration`.
  - `win_pen.rs`: Stylus/pen WndProc subclass and palm suppression.
  - `vault_ops.rs`: `trigger_vault_reload`, `refresh_models`, `load_note_into_ui`, `init_blank_new_note_in_ui`, `lock_vault_session`, `filter_quick_search_results`, `get_suggested_tags`.
  - `handlers/`: Domain-split Slint callbacks (`auth.rs`, `notes.rs`, `folders.rs`, `attachments.rs`, `canvas.rs`, `settings.rs`, `export.rs`, `quick_search.rs`).
- `src/cli.rs` + `src/cli_tests.rs`: CLI subcommands `encrypt`, `decrypt`, and `info` with optional `--keyfile` and no-echo passphrase prompts via `rpassword`.
- `src/attachment.rs`: Encrypted attachment and canvas binary framing (`[4B BE header_len][AttachmentMetadata JSON][raw bytes]`), `_a<N>.vault` and `_canvas.vault` path helpers, atomic saves, listing, compaction, move, delete, and preview type detection.
- `src/markdown.rs`: `pulldown-cmark` + custom Slint `StyledText` / `MarkdownBlockData` renderer supporting GFM tables (Unicode box drawing), LaTeX-to-Unicode math, HTML tag sanitization, and image-to-link conversion.
- `src/config.rs`: `AppConfig` persisted atomically to `config.json` in the current working directory (includes `auto_lock_minutes` and `clipboard_clear_seconds`), plus `expand_path` / `expand_path_with`.
- `src/export.rs`: UTC timestamp formatting (`parse_unix_timestamp`, `format_unix_timestamp`, `format_unix_date`), line numbering, and JSON / TXT / Markdown (YAML frontmatter) export formatters.
- `src/validation.rs`: Cross-platform / Windows-safe `validate_folder_name` and `sanitize_filename` (blocks path traversal, Windows illegal chars, trailing `.`, `*All Notes*`, and Windows reserved device names `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
- `src/single_instance.rs`: Single-instance lock via Windows `CreateMutexW`, Linux abstract Unix socket, or temp-file fallback.
- `src/startup.rs`: Launch-at-startup registration via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (Windows) or XDG autostart `.desktop` (Linux).
- `ui/`: `mainwindow.slint` (single compilation root referenced by `build.rs`), `modals.slint`, `settings.slint`, `quick_search.slint`, `unlock_window.slint`, `theme.slint`.
- `build.rs`: Compiles `ui/mainwindow.slint` with `slint_build::compile` and embeds `assets/icon.ico` via `winres` on Windows.
- `scripts/`: `make_release.ps1` (release build + versioned zip packaging) and `create_key.ps1` (1024-byte `notevault.key` generator via `RandomNumberGenerator::Fill`).
- `.github/workflows/ci.yml`: Windows CI running `cargo clippy --all-targets` and `cargo test`.
- `tests/`: `vault_integration.rs`, `attachment_integration.rs`, `canvas_integration.rs`, `export_and_validation.rs`.

## 3. Critical Invariants & Architecture Rules

### Cryptography (`src/lib.rs`)
- **Cascade v`0x03` Layout (81-byte authenticated header)**:
  `[Version: 1B = 0x03][m_cost: 4B BE][t_cost: 4B BE][p_cost: 4B BE][Salt: 32B][AES Nonce: 12B][XChaCha Nonce: 24B][Outer Ciphertext]`
- **Key Derivation, AAD & Ciphers**:
  - Argon2id (`Version::V0x13`) derives 64 bytes using the explicit `(m_cost, t_cost, p_cost)` parameters from the header: `[0..32]` = AES-256-GCM (inner layer), `[32..64]` = XChaCha20-Poly1305 (outer layer).
  - Both AEAD layers authenticate the full 81-byte header as AAD (`Payload { msg, aad: &header }`).
  - If a keyfile is provided, its 32-byte BLAKE3 hash is passed as the Argon2id `secret` (pepper).
- **Backward Compatibility**:
  - Must continue decrypting Cascade v`0x02` (`69B` header, no AAD, `Params::default()`) and Legacy v1 (`56B` header, single XChaCha20-Poly1305, no keyfile pepper), including the `keyfile_bytes.is_none()` fallback when a legacy v1 file's first random salt byte equals `0x02` or `0x03`.
  - Older files are upgraded to v`0x03` on next save or via `reencrypt_vault_atomic`.
- **Memory & File Hygiene**:
  - Passwords, keyfile bytes, derived keys, attachment serialization payloads, and decrypted plaintext buffers must be wrapped in `Zeroizing`. `Note` and `NoteAttachment` implement `Drop` + `ZeroizeOnDrop`.
  - Single-file writes (`save_note_encrypted`, `save_attachment_encrypted`, `AppConfig::save_to_path`) must use `atomic_write` (temp file + `sync_all` + `rename`).

### On-Disk Vault Layout
- **Notes**: Stored at `<vault_path>/<Category>/<uuid>.vault`. Top-level subdirectories map to categories; files at the vault root default to `"General"`. `"*All Notes*"` is a reserved virtual category name.
- **Attachments & Canvas**:
  - Attachments use `<note_stem>_a<N>.vault` (1-based index; compacted via `compact_note_attachments` when deleted) and must be moved/deleted alongside their parent note (`move_note_attachments`, `delete_note_attachments`).
  - Canvas drawings use `<note_stem>_canvas.vault` storing PNG bytes inside the `NoteAttachment` framing; the parent note's `content` stores the background hex color (default `#ffffff`).
- **Discovery vs. Re-encryption**:
  - `trigger_vault_reload` in `src/gui/vault_ops.rs` **must** skip `is_attachment_file(p)` and `is_canvas_file(p)` when indexing notes.
  - `reencrypt_vault_atomic` in `src/lib.rs` **must** process **all** `.vault` files recursively in parallel (notes, attachments, and canvas files) using `.vault.new` staging before renaming.
- **On-Demand Content**: `metadata_store` (`HashMap<String, NoteMetaSummary>`) holds only metadata in memory; full note content, attachments, and canvas PNGs are decrypted on demand when opened.

### Slint UI Rules
- `ui/mainwindow.slint` is the **only** Slint entrypoint compiled by `build.rs`, and `slint::include_modules!()` is invoked once in `src/lib.rs`. Any new Slint component/window/struct accessed from Rust must be imported and `export`ed from `ui/mainwindow.slint`.
- Never run Argon2id encryption/decryption or heavy file I/O on the Slint UI thread. Spawn a worker thread and marshal state updates back via `slint::invoke_from_event_loop` using `slint::Weak<MainWindow>`.
- Keep `Theme` (`theme` and `is_dark`) synchronized across all three windows (`MainWindow`, `QuickSearchWindow`, `UnlockWindow`).
- Never pass user-controlled URLs or paths through `cmd.exe` or shells; use `open_url_safely` (`ShellExecuteW` on Windows) and `validate_folder_name` + canonical prefix checks on destructive filesystem operations.

## 4. Build, Run & Test Commands
- **Build**: `cargo build` / `cargo build --release`
- **Lint**: `cargo clippy --all-targets`
- **Tests**:
  - Full suite: `cargo test`
  - Library unit tests: `cargo test --lib`
  - GUI binary tests: `cargo test --bin note_vault`
  - CLI binary tests: `cargo test --bin note_vault_cli`
  - Integration suites: `cargo test --test vault_integration`, `cargo test --test attachment_integration`, `cargo test --test canvas_integration`, `cargo test --test export_and_validation`
- **Release Packaging (Windows)**: `.\scripts\make_release.ps1`

## 5. Known Caveats
- **Argon2id Debug Runtime**: In debug builds, Argon2id is unoptimized, so crypto-heavy unit/integration tests take ~8–12s per binary/test target.
