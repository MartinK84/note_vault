use serde::Serialize;
use crate::Note;

/// Helper to extract date components (year, month, day, hours, minutes, seconds) from Unix timestamp.
pub fn parse_unix_timestamp(ts: i64) -> (u32, u32, u32, u64, u64, u64) {
    if ts <= 0 {
        return (1970, 1, 1, 0, 0, 0);
    }
    let secs = ts as u64;
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    let mut year = 1970;
    let mut day_count = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if day_count < days_in_year {
            break;
        }
        day_count -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for &d in &month_days {
        if day_count < d {
            break;
        }
        day_count -= d;
        month += 1;
    }
    let day = (day_count + 1) as u32;
    (year as u32, month, day, hours, minutes, seconds)
}

/// Formats a Unix timestamp (seconds) into a readable UTC date string.
pub fn format_unix_timestamp(ts: i64) -> String {
    if ts <= 0 {
        return "Unknown".to_string();
    }
    let (year, month, day, hours, minutes, seconds) = parse_unix_timestamp(ts);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", year, month, day, hours, minutes, seconds)
}

/// Formats a Unix timestamp (seconds) into a compact date string (YYYY-MM-DD) for note cards.
pub fn format_unix_date(ts: i64) -> String {
    if ts <= 0 {
        return "Unknown".to_string();
    }
    let (year, month, day, _, _, _) = parse_unix_timestamp(ts);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// Formats line numbers as a newline-separated string ("1\n2\n3\n...").
pub fn format_line_numbers(content: &str) -> String {
    let count = if content.is_empty() {
        1
    } else {
        content.split('\n').count()
    };
    (1..=count)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct DecryptedNoteExport<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub category: &'a str,
    pub tags: &'a [String],
    pub date: &'a str,
    pub content: &'a str,
}

/// Serializes a decrypted note into formatted, human-readable JSON.
pub fn format_decrypted_json_export(
    id: &str,
    title: &str,
    category: &str,
    tags: &[String],
    date: &str,
    content: &str,
) -> Result<String, serde_json::Error> {
    let export_data = DecryptedNoteExport {
        id,
        title,
        category,
        tags,
        date,
        content,
    };
    serde_json::to_string_pretty(&export_data)
}

/// Formats a decrypted note into readable plain text with title and metadata header.
pub fn format_decrypted_txt_export(
    title: &str,
    category: &str,
    tags: &[String],
    date: &str,
    content: &str,
) -> String {
    let mut txt_str = String::new();
    if !title.is_empty() {
        txt_str.push_str(&format!("Title: {}\n", title));
    }
    if !category.is_empty() {
        txt_str.push_str(&format!("Category: {}\n", category));
    }
    if !tags.is_empty() {
        txt_str.push_str(&format!("Tags: {}\n", tags.join(", ")));
    }
    if !date.is_empty() {
        txt_str.push_str(&format!("Date: {}\n", date));
    }
    if !txt_str.is_empty() {
        txt_str.push_str("----------------------------------------\n\n");
    }
    txt_str.push_str(content);
    txt_str
}

/// Formats a note into a Markdown document with YAML frontmatter.
/// Contains `title`, `category`, `tags` (as a JSON/YAML array), and `date`.
pub fn format_markdown_export(note: &Note, category: &str, date_str: &str) -> String {
    let title_escaped = serde_json::to_string(&note.title).unwrap_or_else(|_| "\"\"".to_string());
    let category_escaped = serde_json::to_string(category).unwrap_or_else(|_| "\"\"".to_string());
    let tags_array = serde_json::to_string(&note.tags).unwrap_or_else(|_| "[]".to_string());
    let date_escaped = serde_json::to_string(date_str).unwrap_or_else(|_| "\"\"".to_string());

    format!(
        "---\ntitle: {}\ncategory: {}\ntags: {}\ndate: {}\n---\n\n{}",
        title_escaped, category_escaped, tags_array, date_escaped, note.content
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_markdown_export() {
        let note = Note::new(
            "Project Ideas: 2026",
            vec!["work".to_string(), "rust".to_string()],
            "# Heading\n\nThis is a secret note.",
        );
        let category = "Projects";
        let date_str = "2026-09-13 14:00:00 UTC";

        let md = format_markdown_export(&note, category, date_str);

        assert!(md.starts_with("---\n"));
        assert!(md.contains("title: \"Project Ideas: 2026\"\n"));
        assert!(md.contains("category: \"Projects\"\n"));
        assert!(md.contains("tags: [\"work\",\"rust\"]\n"));
        assert!(md.contains("date: \"2026-09-13 14:00:00 UTC\"\n"));
        assert!(md.contains("---\n\n# Heading\n\nThis is a secret note."));
    }

    #[test]
    fn test_format_markdown_export_special_chars() {
        let note = Note::new(
            "Note with \"Quotes\" and \n Newlines and : colons",
            vec!["tag:with:colon".to_string(), "normal".to_string()],
            "Body content with --- yaml delimiter",
        );
        let md = format_markdown_export(&note, "Category: Subcategory", "2026-01-01");
        assert!(md.contains(r#"title: "Note with \"Quotes\" and \n Newlines and : colons""#));
        assert!(md.contains(r#"category: "Category: Subcategory""#));
        assert!(md.contains(r#"tags: ["tag:with:colon","normal"]"#));
        assert!(md.ends_with("Body content with --- yaml delimiter"));
    }

    #[test]
    fn test_format_line_numbers() {
        assert_eq!(format_line_numbers(""), "1");
        assert_eq!(format_line_numbers("hello world"), "1");
        assert_eq!(format_line_numbers("line 1\nline 2"), "1\n2");
        assert_eq!(format_line_numbers("line 1\nline 2\nline 3\n"), "1\n2\n3\n4");
    }

    #[test]
    fn test_format_decrypted_json_export() {
        let tags = vec!["finance".to_string(), "taxes".to_string()];
        let json_result = format_decrypted_json_export(
            "note-1234",
            "Financial Statement",
            "Work",
            &tags,
            "2026-09-20",
            "Confidential notes content",
        );
        assert!(json_result.is_ok());
        let json_str = json_result.unwrap();
        assert!(json_str.contains("\"id\": \"note-1234\""));
        assert!(json_str.contains("\"title\": \"Financial Statement\""));
        assert!(json_str.contains("\"category\": \"Work\""));
        assert!(json_str.contains("\"finance\""));
        assert!(json_str.contains("\"taxes\""));
        assert!(json_str.contains("\"Confidential notes content\""));

        // Verify it round-trips into valid JSON
        let val: serde_json::Value = serde_json::from_str(&json_str).expect("Export must be valid JSON");
        assert_eq!(val["id"], "note-1234");
        assert_eq!(val["title"], "Financial Statement");
    }

    #[test]
    fn test_format_decrypted_txt_export() {
        let tags = vec!["tag1".to_string(), "tag2".to_string()];
        let txt = format_decrypted_txt_export(
            "My Note Title",
            "Personal",
            &tags,
            "2026-09-20",
            "Hello decrypted world!",
        );
        assert!(txt.contains("Title: My Note Title\n"));
        assert!(txt.contains("Category: Personal\n"));
        assert!(txt.contains("Tags: tag1, tag2\n"));
        assert!(txt.contains("Date: 2026-09-20\n"));
        assert!(txt.contains("----------------------------------------\n\n"));
        assert!(txt.contains("Hello decrypted world!"));
    }

    #[test]
    fn test_format_decrypted_txt_export_minimal() {
        let empty_tags = Vec::new();
        let txt = format_decrypted_txt_export("", "", &empty_tags, "", "Just content");
        assert_eq!(txt, "Just content");
    }

    #[test]
    fn test_unix_timestamp_formatting() {
        assert_eq!(format_unix_timestamp(0), "Unknown");
        assert_eq!(format_unix_timestamp(-100), "Unknown");
        assert_eq!(format_unix_date(0), "Unknown");

        // 1774000000 -> 2026-03-20 09:46:40 UTC
        let ts = 1774000000;
        let formatted = format_unix_timestamp(ts);
        assert!(formatted.starts_with("2026-03-20"));
        assert!(formatted.ends_with("UTC"));

        let date_only = format_unix_date(ts);
        assert_eq!(date_only, "2026-03-20");
    }
}
