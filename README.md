# NoteVault 🔐

A secure, local-first, encrypted note-taking desktop application built with Rust and Slint that encrypts each note individually

## Features
* **Individual File Encryption:** Each note is stored as a separate `.vault` file, making it perfectly suited for cloud sync (Nextcloud, ownCloud) without the risk of database conflicts.
* **Cryptography:** Uses **Argon2id** for Key Derivation and **XChaCha20-Poly1305** for Authenticated Encryption with Associated Data (AEAD). Unique salts and nonces are generated per file.
* **Memory Safety:** Integrates the `zeroize` crate to ensure that master passwords, derived keys, and decrypted plaintext are securely erased from RAM immediately after use.
* **Native Desktop UI:** A lightweight, cross-platform UI built with [Slint](https://slint.dev/).

## Build Instructions
Ensure you have the [Rust Toolchain](https://rustup.rs/) installed.

```bash
# Build the release binary
cargo build --release
```