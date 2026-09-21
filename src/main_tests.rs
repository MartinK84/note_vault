use super::*;
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn test_filter_quick_search_results() {
    let mut store = HashMap::new();
    for i in 1..=10 {
        store.insert(
            format!("note-{}", i),
            NoteMetaSummary {
                title: format!("Title {}", i),
                category: "General".to_string(),
                tags: if i % 2 == 0 { vec!["even".to_string(), "special".to_string()] } else { vec!["odd".to_string()] },
                date: "2026-01-01".to_string(),
                updated_at: i * 100,
                file_path: PathBuf::from(format!("/vault/note-{}.vault", i)),
            },
        );
    }

    // 1. Empty query should return top 5 sorted by updated_at desc (10, 9, 8, 7, 6)
    let top5 = filter_quick_search_results("", &store);
    assert_eq!(top5.len(), 5);
    assert_eq!(top5[0].title.as_str(), "Title 10");
    assert_eq!(top5[1].title.as_str(), "Title 9");
    assert_eq!(top5[2].title.as_str(), "Title 8");
    assert_eq!(top5[3].title.as_str(), "Title 7");
    assert_eq!(top5[4].title.as_str(), "Title 6");

    // 2. Query matching by tag
    let special = filter_quick_search_results("special", &store);
    assert_eq!(special.len(), 5); // 10, 8, 6, 4, 2
    assert_eq!(special[0].title.as_str(), "Title 10");
    assert_eq!(special[1].title.as_str(), "Title 8");

    // 3. Query matching specific title
    let note3 = filter_quick_search_results("Title 3", &store);
    assert_eq!(note3.len(), 1);
    assert_eq!(note3[0].id.as_str(), "note-3");

    // 4. Non-matching query
    let empty = filter_quick_search_results("nonexistent-search-term", &store);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_hotkey_manager_reregister() {
    if let Ok(mgr) = GlobalHotKeyManager::new() {
        let hk1 = "Control+Alt+F11".parse::<HotKey>().unwrap();
        let hk2 = "Control+Alt+F12".parse::<HotKey>().unwrap();
        if mgr.register(hk1).is_ok() {
            assert!(mgr.unregister(hk1).is_ok());
        }
        if mgr.register(hk2).is_ok() {
            assert!(mgr.unregister(hk2).is_ok());
        }
    }
}

#[test]
fn test_parse_hotkey_string() {
    // Standard formats
    let (hk1, s1) = parse_hotkey_string("Shift+Space").unwrap();
    assert_eq!(s1, "Shift+Space");
    assert_eq!(hk1, "Shift+Space".parse::<HotKey>().unwrap());

    // Spaced formats
    let (_hk2, s2) = parse_hotkey_string("Shift + Space").unwrap();
    assert_eq!(s2, "Shift+Space");

    // Lowercase and aliases
    let (_hk3, s3) = parse_hotkey_string("ctrl+shift+space").unwrap();
    assert_eq!(s3, "Control+Shift+Space");

    let (_hk4, s4) = parse_hotkey_string("control + shift + n").unwrap();
    assert_eq!(s4, "Control+Shift+N");

    let (_hk5, s5) = parse_hotkey_string("Alt + Space").unwrap();
    assert_eq!(s5, "Alt+Space");

    // Invalid
    assert!(parse_hotkey_string("").is_err());
    assert!(parse_hotkey_string("   ").is_err());
}

#[test]
fn test_format_key_combination() {
    // Shift + Space
    assert_eq!(
        format_key_combination(" ", false, false, true, false),
        Some("Shift+Space".to_string())
    );

    // Control + Shift + N
    assert_eq!(
        format_key_combination("n", true, false, true, false),
        Some("Control+Shift+N".to_string())
    );

    // Alt + Space
    assert_eq!(
        format_key_combination(" ", false, true, false, false),
        Some("Alt+Space".to_string())
    );

    // F12 without modifiers
    assert_eq!(
        format_key_combination("F12", false, false, false, false),
        Some("F12".to_string())
    );

    // Plain key without modifiers should be rejected for global hotkeys
    assert_eq!(
        format_key_combination("a", false, false, false, false),
        None
    );

    // Only modifier should be rejected
    assert_eq!(
        format_key_combination("\u{0010}", false, false, true, false),
        None
    );
    assert_eq!(
        format_key_combination("", false, false, true, false),
        None
    );
}

#[test]
fn test_create_tray_icon_succeeds() {
    let icon_res = create_tray_icon();
    assert!(icon_res.is_ok(), "Tray icon creation from logo.svg must succeed");
}

#[test]
fn test_args_minimized_flag_parsing() {
    let args1 = Args::parse_from(["note_vault_gui"]);
    assert!(!args1.minimized);
    assert_eq!(args1.vault_path, None);

    let args2 = Args::parse_from(["note_vault_gui", "--minimized"]);
    assert!(args2.minimized);

    let args3 = Args::parse_from(["note_vault_gui", "--vault-path", "C:\\my_vault", "--minimized"]);
    assert!(args3.minimized);
    assert_eq!(args3.vault_path, Some(PathBuf::from("C:\\my_vault")));
}

#[test]
fn test_get_suggested_tags_empty_store() {
    let store = HashMap::new();
    let current_tags = vec!["work".to_string()];
    let suggestions = get_suggested_tags(&store, &current_tags, "");
    assert!(suggestions.is_empty());
}

#[test]
fn test_get_suggested_tags_aggregation_and_counts() {
    let mut store = HashMap::new();

    store.insert(
        "note-1".to_string(),
        NoteMetaSummary {
            title: "Note 1".to_string(),
            category: "General".to_string(),
            tags: vec!["Rust".to_string(), "Slint".to_string(), "GUI".to_string()],
            date: "2026-01-01".to_string(),
            updated_at: 100,
            file_path: PathBuf::from("/vault/note-1.vault"),
        },
    );

    store.insert(
        "note-2".to_string(),
        NoteMetaSummary {
            title: "Note 2".to_string(),
            category: "General".to_string(),
            tags: vec!["rust".to_string(), "crypto".to_string()],
            date: "2026-01-02".to_string(),
            updated_at: 200,
            file_path: PathBuf::from("/vault/note-2.vault"),
        },
    );

    store.insert(
        "note-3".to_string(),
        NoteMetaSummary {
            title: "Note 3".to_string(),
            category: "Work".to_string(),
            tags: vec!["crypto".to_string(), "Security".to_string(), "Rust".to_string()],
            date: "2026-01-03".to_string(),
            updated_at: 300,
            file_path: PathBuf::from("/vault/note-3.vault"),
        },
    );

    // Current note already has "GUI"
    let current_tags = vec!["GUI".to_string()];
    let suggestions = get_suggested_tags(&store, &current_tags, "");

    // Expected:
    // Rust (count: 3)
    // crypto (count: 2)
    // Security (count: 1)
    // Slint (count: 1)
    // "GUI" must be excluded!
    assert_eq!(suggestions.len(), 4);
    assert_eq!(suggestions[0].name.to_lowercase(), "rust");
    assert_eq!(suggestions[0].count, 3);
    assert_eq!(suggestions[1].name.to_lowercase(), "crypto");
    assert_eq!(suggestions[1].count, 2);
    assert_eq!(suggestions[2].count, 1);
    assert_eq!(suggestions[3].count, 1);
    assert!(!suggestions.iter().any(|s| s.name.to_lowercase() == "gui"));
}

#[test]
fn test_get_suggested_tags_case_insensitive_exclusion() {
    let mut store = HashMap::new();
    store.insert(
        "note-1".to_string(),
        NoteMetaSummary {
            title: "Note 1".to_string(),
            category: "General".to_string(),
            tags: vec!["ProjectX".to_string(), "personal".to_string()],
            date: "2026-01-01".to_string(),
            updated_at: 100,
            file_path: PathBuf::from("/vault/note-1.vault"),
        },
    );

    // Current note has "projectx" in lower case, store has "ProjectX"
    let current_tags = vec!["projectx".to_string()];
    let suggestions = get_suggested_tags(&store, &current_tags, "");

    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].name, "personal");
    assert_eq!(suggestions[0].count, 1);
}

#[test]
fn test_get_suggested_tags_query_filtering() {
    let mut store = HashMap::new();
    store.insert(
        "note-1".to_string(),
        NoteMetaSummary {
            title: "Note 1".to_string(),
            category: "General".to_string(),
            tags: vec!["development".to_string(), "devops".to_string(), "finance".to_string()],
            date: "2026-01-01".to_string(),
            updated_at: 100,
            file_path: PathBuf::from("/vault/note-1.vault"),
        },
    );

    let current_tags = vec![];
    let dev_matches = get_suggested_tags(&store, &current_tags, "dev");
    assert_eq!(dev_matches.len(), 2);
    assert!(dev_matches.iter().any(|s| s.name == "development"));
    assert!(dev_matches.iter().any(|s| s.name == "devops"));

    let ops_matches = get_suggested_tags(&store, &current_tags, "OPS");
    assert_eq!(ops_matches.len(), 1);
    assert_eq!(ops_matches[0].name, "devops");

    let no_matches = get_suggested_tags(&store, &current_tags, "nonexistent");
    assert!(no_matches.is_empty());
}

#[test]
fn test_get_suggested_tags_deduplication_and_whitespace() {
    let mut store = HashMap::new();
    store.insert(
        "note-1".to_string(),
        NoteMetaSummary {
            title: "Note 1".to_string(),
            category: "General".to_string(),
            // Contains duplicates within the same note and whitespace tags
            tags: vec!["tag1 ".to_string(), " tag1".to_string(), "   ".to_string()],
            date: "2026-01-01".to_string(),
            updated_at: 100,
            file_path: PathBuf::from("/vault/note-1.vault"),
        },
    );

    let current_tags = vec![];
    let suggestions = get_suggested_tags(&store, &current_tags, "");
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].name, "tag1");
    assert_eq!(suggestions[0].count, 1);
}

#[test]
fn test_render_note_markdown() {
    let note_content = "# Project Meeting\n\n- [x] Discuss architecture\n- [ ] Write documentation\n\nSee `main.rs` for details.";
    let rendered = render_markdown_styled(note_content);
    assert_ne!(rendered, slint::StyledText::default());
}

#[test]
fn test_table_rendering() {
    let table = "`┌──────────┬─────────────┐`\n`│ Syntax   │ Description │`\n`├──────────┼─────────────┤`\n`│ Header   │ Title       │`\n`│ Paragraph│ Text        │`\n`└──────────┴─────────────┘`";
    let res = slint::StyledText::from_markdown(table);
    assert!(res.is_ok());
}

#[test]
fn test_line_breaks_and_paragraphs() {
    let md = "Line 1  \nLine 2\n\nParagraph 2\n\n**<u>Heading</u>**\n\nParagraph 3";
    let res = slint::StyledText::from_markdown(md);
    assert!(res.is_ok());
}

#[test]
fn test_end_to_end_github_markdown_rendering() {
    let raw_md = r#"# Architecture Overview

Here is a summary of NoteVault's core architecture.
Every note is encrypted with AES-256-GCM.

## Components & Modules

| Component | Purpose | Status |
| :--- | :---: | ---: |
| Crypto | AES-GCM + Argon2id | Complete |
| Markdown | GFM Preprocessor | Complete |
| UI | Slint Native | Complete |

### Quick Tasks
- [x] Implement table support
- [x] Fix paragraph squishing
- [ ] Add PDF export

> Security is not a product, but a process.

```rust
fn get_vault() -> Vault {
    Vault::open("vault.vault")
}
```
"#;
    let styled = render_markdown_styled(raw_md);
    assert_ne!(styled, slint::StyledText::default());
}

#[test]
fn test_parse_markdown_into_blocks_in_main() {
    let raw_md = r#"# Architecture Overview

Here is a summary of NoteVault's core architecture.
Every note is encrypted with AES-256-GCM.

## Components & Modules

| Component | Purpose | Status |
| :--- | :---: | ---: |
| Crypto | AES-GCM + Argon2id | Complete |
| Markdown | GFM Preprocessor | Complete |
| UI | Slint Native | Complete |

### Quick Tasks
- [x] Implement table support
- [x] Fix paragraph squishing
- [ ] Add PDF export

> Security is not a product, but a process.

```rust
fn get_vault() -> Vault {
    Vault::open("vault.vault")
}
```

$$
E = mc^2
$$
"#;
    let blocks = parse_markdown_into_blocks(raw_md);
    assert!(blocks.iter().any(|b| b.block_type == 0 && b.heading_level == 1));
    assert!(blocks.iter().any(|b| b.block_type == 2 && b.code_lang == "rust"));
    assert!(blocks.iter().any(|b| b.block_type == 3 && b.table_headers.row_count() == 3));
    assert!(blocks.iter().any(|b| b.block_type == 4));
    assert!(blocks.iter().any(|b| b.block_type == 5 && b.text.contains("E = mc²")));
    assert!(blocks.iter().any(|b| b.block_type == 7 && b.is_task_checked));
    assert!(blocks.iter().any(|b| b.block_type == 7 && !b.is_task_checked));
}


