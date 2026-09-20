use super::*;
use clap::Parser;
use std::path::PathBuf;

#[test]
fn test_cli_encrypt_args_parsing() {
    let args = vec![
        "note_vault",
        "encrypt",
        "-i",
        "secret.txt",
        "-o",
        "secret.vault",
        "-k",
        "physical.key",
        "--tags",
        "personal,important",
    ];

    let cli = Cli::try_parse_from(args).expect("Valid encrypt CLI args should parse");
    match cli.command {
        Some(Commands::Encrypt {
            input,
            output,
            keyfile,
            tags,
        }) => {
            assert_eq!(input, PathBuf::from("secret.txt"));
            assert_eq!(output, PathBuf::from("secret.vault"));
            assert_eq!(keyfile, Some(PathBuf::from("physical.key")));
            assert_eq!(tags, vec!["personal".to_string(), "important".to_string()]);
        }
        _ => panic!("Expected Encrypt command"),
    }
}

#[test]
fn test_cli_decrypt_args_parsing() {
    let args = vec![
        "note_vault",
        "decrypt",
        "-i",
        "encrypted.vault",
        "-o",
        "decrypted.txt",
    ];

    let cli = Cli::try_parse_from(args).expect("Valid decrypt CLI args should parse");
    match cli.command {
        Some(Commands::Decrypt {
            input,
            output,
            keyfile,
        }) => {
            assert_eq!(input, PathBuf::from("encrypted.vault"));
            assert_eq!(output, PathBuf::from("decrypted.txt"));
            assert_eq!(keyfile, None);
        }
        _ => panic!("Expected Decrypt command"),
    }
}

#[test]
fn test_cli_info_args_parsing() {
    let args = vec!["note_vault", "info", "-i", "note.vault", "-k", "token.key"];

    let cli = Cli::try_parse_from(args).expect("Valid info CLI args should parse");
    match cli.command {
        Some(Commands::Info { input, keyfile }) => {
            assert_eq!(input, PathBuf::from("note.vault"));
            assert_eq!(keyfile, Some(PathBuf::from("token.key")));
        }
        _ => panic!("Expected Info command"),
    }
}

#[test]
fn test_cli_no_subcommand_is_none() {
    let args = vec!["note_vault"];
    let cli = Cli::try_parse_from(args).expect("No subcommand should parse to None command");
    assert!(cli.command.is_none());
}

#[test]
fn test_cli_missing_required_args_fails() {
    // Encrypt without output
    let args = vec!["note_vault", "encrypt", "-i", "input.txt"];
    assert!(Cli::try_parse_from(args).is_err());

    // Decrypt without input
    let args2 = vec!["note_vault", "decrypt", "-o", "output.txt"];
    assert!(Cli::try_parse_from(args2).is_err());

    // Unknown command
    let args3 = vec!["note_vault", "unknown_command"];
    assert!(Cli::try_parse_from(args3).is_err());
}
