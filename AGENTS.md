# NoteVault — Agent Guide

## 1. Project Overview & Tech Stack
- **NoteVault** is a local-first, encrypted desktop note-taking application written in Rust (`edition = "2024"`). Notes, attachments, and canvas drawings are stored as independent encrypted `.vault` files on disk (no shared database), designed for conflict-free file synchronization (e.g., Nextcloud/ownCloud).
- **Crate Targets (`Cargo.toml`)**:
  - `note_vault` (library, `src/lib.rs`)
  - `note_vault` (desktop GUI binary, `src/main.rs`, Slint `1.17.1`)
  - `note_vault_cli` (companion CLI binary, `src/cli.rs`, Clap `4.6.6`)
- **Primary Platform**: Windows (MSVC toolchain; Win32 FFI for system tray/taskbar visibility, window activation, stylus/pen WndProc subclassing, registry autostart, and `winres` icon embedding). Linux fallbacks exist in `src/single_instance.rs` and `src/startup.rs`.

## 2. Repository Map
- `src/lib.rs`: Core cryptography (`derive_key`, `encrypt_bytes`, `decrypt_bytes`, `save_note_encrypted`, `load_note_decrypted`, `reencrypt_vault_atomic`), `Note` / `NoteType` (`Text` | `Canvas`), `VaultError`, canvas pixmap/coordinate helpers (`extend_canvas_pixmap`, `hsl_to_rgb`, `rgb_to_hsl`, `clamp_zoom_percent`, `parse_zoom_input`, `scale_coordinate_to_canvas`, `fit_canvas_zoom_percent`), and `slint::include_modules!()`.
- `src/main.rs` + `src/main_tests.rs`: Monolithic Slint GUI application, shared `Arc<Mutex<...>>` state, system tray + 50 ms `slint::Timer` polling loop, `global-hotkey` handling, Win32 FFI (`ITaskbarList`, foreground activation, `win_pen` stylus/palm handling), and all Slint UI callbacks.
- `src/cli.rs` + `src/cli_tests.rs`: CLI subcommands `encrypt`, `decrypt`, and `info` with optional `--keyfile` and no-echo passphrase prompts via `rpassword`.
- `src/attachment.rs`: Encrypted attachment and canvas binary framing (`[4B BE header_len][AttachmentMetadata JSON][raw bytes]`), `_a<N>.vault` and `_canvas.vault` path helpers, listing, compaction, move, delete, and preview type detection.
- `src/markdown.rs`: `pulldown-cmark` + custom Slint `StyledText` / `MarkdownBlockData` renderer supporting GFM tables (Unicode box drawing), LaTeX-to-Unicode math, HTML tag sanitization, and image-to-link conversion.
- `src/config.rs`: `AppConfig` persisted to `config.json` in the current working directory, plus `expand_path` (`%VAR%`, `$VAR`, `${VAR}`, relative-to-CWD resolution).
- `src/export.rs`: UTC timestamp formatting (`parse_unix_timestamp`, `format_unix_timestamp`, `format_unix_date`), line numbering, and JSON / TXT / Markdown (YAML frontmatter) export formatters.
- `src/validation.rs`: Cross-platform / Windows-safe `validate_folder_name` and `sanitize_filename` (blocks path traversal, Windows illegal chars, trailing `.`, `*All Notes*`, and Windows reserved device names `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
- `src/single_instance.rs`: Single-instance lock via Windows `CreateMutexW`, Linux abstract Unix socket, or temp-file fallback.
- `src/startup.rs`: Launch-at-startup registration via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (Windows) or XDG autostart `.desktop` (Linux).
- `ui/`:
  - `mainwindow.slint`: Single compilation root referenced by `build.rs`; re-exports `Theme`, `Palette`, `QuickSearchWindow`, `QuickSearchResult`, `UnlockWindow`, `TagSuggestion`, `MainWindow`, `AttachmentItem`, `TableRowData`, `MarkdownBlockData`, and `NoteMetadata`.
  - `modals.slint`: Modal overlays (`UnlockModal`, `LoadingModal`, `UnsavedWarningModal`, `DeleteFolderModal`, `DeleteNoteModal`, `DeleteAttachmentModal`, `FolderModal`, `RenameFolderModal`, `MoveNoteModal`, `AddTagModal`, `WelcomeModal`, `ExportModal`, `WarningModal`, `AttachmentPreviewModal`, `NewNoteModal`, `ClearCanvasModal`, `CustomColorModal`, `ExitConfirmModal`).
  - `settings.slint`: `SettingsDialog` component.
  - `quick_search.slint`: Frameless floating `QuickSearchWindow`.
  - `unlock_window.slint`: Frameless floating `UnlockWindow` (used when unlocking via Quick Search while locked).
  - `theme.slint`: `Theme` global (`"dark"`, `"blue"`, `"light"`) and `TooltipBubble`.
- `build.rs`: Compiles `ui/mainwindow.slint` with `slint_build::compile` and embeds `assets/icon.ico` via `winres` on Windows.
- `scripts/`: `make_release.ps1` (release build + versioned zip packaging) and `create_key.ps1` (1024-byte `notevault.key` generator).
- `tests/`: `vault_integration.rs`, `attachment_integration.rs`, `canvas_integration.rs`, `export_and_validation.rs`.

## 3. Critical Invariants & Architecture Rules

### Cryptography (`src/lib.rs`)
- **Cascade v`0x02` Layout (69-byte header)**:
  `[Version: 1B = 0x02][Salt: 32B][AES Nonce: 12B][XChaCha Nonce: 24B][Outer Ciphertext]`
- **Key Derivation & Ciphers**:
  - Argon2id (`Version::V0x13`, `Params::default()`) derives 64 bytes: `[0..32]` = AES-256-GCM (inner layer), `[32..64]` = XChaCha20-Poly1305 (outer layer).
  - If a keyfile is provided, its 32-byte BLAKE3 hash is passed as the Argon2id `secret` (pepper).
- **Backward Compatibility**:
  - Legacy v1 format has a 56-byte header (`[Salt: 32B][XChaCha Nonce: 24B][Ciphertext]`) using 32-byte `derive_key_legacy` without keyfile pepper.
  - `decrypt_bytes` must remain backward-compatible with legacy files, including the fallback when `keyfile_bytes.is_none()` and a legacy file's random first salt byte happens to equal `0x02`.
  - Legacy notes are upgraded to v`0x02` on next save or via `reencrypt_vault_atomic`.
- **Memory Hygiene**:
  - Wrap passwords, keyfile bytes, derived keys, and decrypted plaintext buffers in `Zeroizing`. Call `.zeroize()` on decrypted `Note` structs after extracting metadata.

### On-Disk Vault Layout
- **Notes**: Stored at `<vault_path>/<Category>/<uuid>.vault`. Top-level subdirectories map to categories; files at the vault root default to `"General"`. `"*All Notes*"` is a reserved virtual category name.
- **Attachments & Canvas**:
  - Attachments use `<note_stem>_a<N>.vault` (1-based index; compacted via `compact_note_attachments` when deleted) and must be moved/deleted alongside their parent note (`move_note_attachments`, `delete_note_attachments`).
  - Canvas drawings use `<note_stem>_canvas.vault` storing PNG bytes inside the `NoteAttachment` framing; the parent note's `content` stores the background hex color (default `#ffffff`).
- **Discovery vs. Re-encryption**:
  - `trigger_vault_reload` in `src/main.rs` **must** skip `is_attachment_file(p)` and `is_canvas_file(p)` when indexing notes.
  - `reencrypt_vault_atomic` in `src/lib.rs` **must** process **all** `.vault` files recursively (notes, attachments, and canvas files) using `.vault.new` staging before renaming.
- **On-Demand Content**: `metadata_store` (`HashMap<String, NoteMetaSummary>`) holds only metadata in memory; full note content, attachments, and canvas PNGs are decrypted on demand when opened.

### Slint UI Rules
- `ui/mainwindow.slint` is the **only** Slint entrypoint compiled by `build.rs`, and `slint::include_modules!()` is invoked once in `src/lib.rs`. Any new Slint component/window/struct accessed from Rust must be imported and `export`ed from `ui/mainwindow.slint`.
- Never run Argon2id encryption/decryption or heavy file I/O on the Slint UI thread. Spawn a worker thread and marshal state updates back via `slint::invoke_from_event_loop` using `slint::Weak<MainWindow>`.
- Keep `Theme` (`theme` and `is_dark`) synchronized across all three windows (`MainWindow`, `QuickSearchWindow`, `UnlockWindow`).

## 4. Build, Run & Test Commands
- **Build**:
  - `cargo build`
  - `cargo build --release`
- **Tests**:
  - Full suite: `cargo test`
  - Library unit tests: `cargo test --lib`
  - GUI binary tests: `cargo test --bin note_vault`
  - CLI binary tests: `cargo test --bin note_vault_cli`
  - Integration suites: `cargo test --test vault_integration`, `cargo test --test attachment_integration`, `cargo test --test canvas_integration`, `cargo test --test export_and_validation`
- **Release Packaging (Windows)**:
  - `.\scripts\make_release.ps1` (builds `--release` and creates `note_vault-<version>-windows-x86_64.zip`).

## 5. Known Pitfalls & Caveats
- **Real Registry Mutation in Tests**: `startup::tests::test_windows_set_and_query_startup_lifecycle` (`src/startup.rs`) modifies and deletes the real Windows registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NoteVault`.
- **Shared Process Env in Tests**: `config::tests` (`src/config.rs`) uses `unsafe { std::env::set_var(...) }` / `remove_var(...)` during `expand_path` tests.
- **Argon2id Debug Runtime**: In debug builds, Argon2id is unoptimized, so crypto-heavy unit/integration tests take ~8–12s per binary/test target.
- **Existing Compiler Warning**: `src/main.rs` currently emits a `dead_code` warning for `NoteMetaSummary.date`.
- **Stale `README.md`**: `README.md` does not yet document canvas notes, attachments, Markdown preview, `main_window_hotkey`, or editor pane/markdown config keys, and lists `minimize_to_tray: false` / `editor_show_line_numbers: true` whereas `AppConfig::default()` sets `minimize_to_tray: true` and `editor_show_line_numbers: false`.
