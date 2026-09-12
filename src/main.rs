use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use note_vault::{load_note_decrypted, save_note_encrypted, Note};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "note_vault",
    version,
    about = "A highly secure, local-first encrypted note-taking vault CLI",
    long_about = "NoteVault securely encrypts and decrypts notes using Argon2id for key derivation, XChaCha20-Poly1305 for authenticated encryption, and Zeroize for memory safety."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a plaintext file into a secure .vault file
    Encrypt {
        /// Path to the plaintext file to be encrypted
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Destination path for the encrypted .vault file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Decrypt an encrypted .vault file back into plaintext
    Decrypt {
        /// Path to the encrypted .vault file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Destination path to save the decrypted plaintext content
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Commands::Encrypt { input, output } => {
            // 1. Verify input file exists
            if !input.exists() {
                return Err(format!("Input plaintext file not found: '{}'", input.display()).into());
            }

            if !input.is_file() {
                return Err(format!("Input path is not a file: '{}'", input.display()).into());
            }

            // 2. Read plaintext file content
            let content = fs::read_to_string(&input)
                .map_err(|e| format!("Failed to read input file '{}': {}", input.display(), e))?;

            // 3. Use input filename as note title
            let title = input
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Untitled Note");

            let note = Note::new(title, content);

            // 4. Securely prompt for password without terminal echo and wrap in Zeroizing
            let password_str = rpassword::prompt_password("Enter password to encrypt note: ")
                .map_err(|e| format!("Failed to read password: {}", e))?;

            let password = Zeroizing::new(password_str);
            if password.is_empty() {
                return Err("Password cannot be empty.".into());
            }

            // 5. Encrypt and save note to target destination
            save_note_encrypted(&note, &password, &output)
                .map_err(|e| format!("Encryption failed: {}", e))?;

            println!(
                "Successfully encrypted '{}' to '{}'.",
                input.display(),
                output.display()
            );
        }
        Commands::Decrypt { input, output } => {
            // 1. Verify encrypted vault file exists
            if !input.exists() {
                return Err(format!("Encrypted vault file not found: '{}'", input.display()).into());
            }

            if !input.is_file() {
                return Err(format!("Input path is not a file: '{}'", input.display()).into());
            }

            // 2. Securely prompt for password without terminal echo and wrap in Zeroizing
            let password_str = rpassword::prompt_password("Enter vault password: ")
                .map_err(|e| format!("Failed to read password: {}", e))?;

            let password = Zeroizing::new(password_str);
            if password.is_empty() {
                return Err("Password cannot be empty.".into());
            }

            // 3. Decrypt and verify note integrity
            let note = load_note_decrypted(&password, &input)
                .map_err(|e| format!("Decryption failed: {}", e))?;

            // 4. Ensure destination parent directory exists if necessary
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| {
                        format!("Failed to create destination directory '{}': {}", parent.display(), e)
                    })?;
                }
            }

            // 5. Write decrypted plaintext content to output path
            fs::write(&output, note.content.as_bytes())
                .map_err(|e| format!("Failed to write decrypted content to '{}': {}", output.display(), e))?;

            println!(
                "Successfully decrypted '{}' (Title: '{}') to '{}'.",
                input.display(),
                note.title,
                output.display()
            );
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("Error: {}", err);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
