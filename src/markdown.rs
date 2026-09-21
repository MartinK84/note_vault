//! Markdown preprocessing and rendering support for Slint StyledText in NoteVault.
//! Emulates GitHub Flavored Markdown (GFM) styling, paragraph separation,
//! aligned Unicode box tables, task lists, block elements, and LaTeX math mode.

use crate::{MarkdownBlockData, TableRowData};
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use slint::{ModelRc, SharedString, StyledText, VecModel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnAlign {
    Left,
    Center,
    Right,
}

/// Converts markdown images `![alt](url)` to clickable links `[🖼️ alt](url)` so that
/// Slint's CommonMark parser does not reject them with "Markdown images are not supported".
fn convert_images_to_links(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    let mut last_idx = 0;

    while let Some((i, ch)) = chars.next() {
        if ch == '!' {
            if let Some(&(_, '[')) = chars.peek() {
                chars.next(); // consume '['
                let mut alt = String::new();
                let mut found_close_bracket = false;
                while let Some((_, c)) = chars.next() {
                    if c == ']' {
                        found_close_bracket = true;
                        break;
                    }
                    alt.push(c);
                }
                if found_close_bracket {
                    if let Some(&(_, '(')) = chars.peek() {
                        chars.next(); // consume '('
                        let mut url = String::new();
                        let mut found_close_paren = false;
                        while let Some((_, c)) = chars.next() {
                            if c == ')' {
                                found_close_paren = true;
                                break;
                            }
                            url.push(c);
                        }
                        if found_close_paren {
                            result.push_str(&line[last_idx..i]);
                            let display_text = if alt.trim().is_empty() {
                                "Image".to_string()
                            } else {
                                format!("🖼️ {}", alt.trim())
                            };
                            result.push_str(&format!("[{}]({})", display_text, url.trim()));
                            if let Some(&(next_idx, _)) = chars.peek() {
                                last_idx = next_idx;
                            } else {
                                last_idx = line.len();
                            }
                            continue;
                        }
                    }
                }
            }
        }
    }
    result.push_str(&line[last_idx..]);
    result
}

/// Checks if a trimmed line is a horizontal rule (e.g. `---`, `***`, `___`).
pub fn is_horizontal_rule(trimmed: &str) -> bool {
    if trimmed.len() < 3 {
        return false;
    }
    let chars: Vec<char> = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.len() >= 3
        && (chars.iter().all(|&c| c == '-')
            || chars.iter().all(|&c| c == '*')
            || chars.iter().all(|&c| c == '_'))
    {
        return true;
    }
    false
}

/// Checks if a line is a markdown table separator line (e.g. `| --- | :---: | ---: |`).
pub fn is_table_separator_line(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.contains('|') {
        return false;
    }
    let content = trimmed.strip_prefix('|').unwrap_or(trimmed);
    let content = content.strip_suffix('|').unwrap_or(content);
    let cells: Vec<&str> = content.split('|').map(|c| c.trim()).collect();
    if cells.is_empty() {
        return false;
    }
    for cell in cells {
        if cell.is_empty() {
            return false;
        }
        let has_hyphen = cell.contains('-');
        let valid_chars = cell.chars().all(|c| c == '-' || c == ':' || c.is_whitespace());
        if !has_hyphen || !valid_chars {
            return false;
        }
    }
    true
}

/// Parses table row cells from a line containing `|`.
pub fn parse_table_cells(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let content = trimmed.strip_prefix('|').unwrap_or(trimmed);
    let content = content.strip_suffix('|').unwrap_or(content);
    content.split('|').map(|c| c.trim().to_string()).collect()
}

/// Extracts column alignments from a separator line.
pub fn parse_column_alignments(separator_line: &str) -> Vec<ColumnAlign> {
    let cells = parse_table_cells(separator_line);
    cells
        .into_iter()
        .map(|cell| {
            let left = cell.starts_with(':');
            let right = cell.ends_with(':');
            if left && right {
                ColumnAlign::Center
            } else if right {
                ColumnAlign::Right
            } else {
                ColumnAlign::Left
            }
        })
        .collect()
}

/// Calculates the rendered visual character count of a table cell,
/// stripping markdown formatting delimiters (~~, **, *, __, _, `, [text](url), etc.)
/// that Slint consumes during rendering.
pub fn visual_cell_width(cell: &str) -> usize {
    let mut s = cell.trim().to_string();

    // 1. Resolve markdown links [text](url) -> text
    while let Some(open_b) = s.find('[') {
        if let Some(close_b) = s[open_b..].find(']') {
            let abs_close_b = open_b + close_b;
            if s[abs_close_b..].starts_with("](") {
                if let Some(close_p) = s[abs_close_b + 2..].find(')') {
                    let abs_close_p = abs_close_b + 2 + close_p;
                    let text = s[open_b + 1..abs_close_b].to_string();
                    s.replace_range(open_b..=abs_close_p, &text);
                    continue;
                }
            }
        }
        break;
    }

    // 2. Count visible characters, skipping markdown formatting syntax characters
    let mut count = 0;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '~' => {
                if let Some(&'~') = chars.peek() {
                    chars.next(); // skip second '~'
                }
            }
            '*' | '_' | '`' => {
                // skip formatting markers
            }
            '\\' => {
                // Escaped character like \< or \> or \* or \_ -> counts as 1 visual character
                if let Some(&next_c) = chars.peek() {
                    if next_c == '<'
                        || next_c == '>'
                        || next_c == '\\'
                        || next_c == '*'
                        || next_c == '_'
                        || next_c == '`'
                        || next_c == '~'
                    {
                        chars.next();
                        count += 1;
                    } else {
                        count += 1;
                    }
                } else {
                    count += 1;
                }
            }
            _ => count += 1,
        }
    }
    count
}

/// Aligns a table cell's content within `width` visual characters according to `align`.
pub fn align_cell_content(cell: &str, width: usize, align: ColumnAlign) -> String {
    let vis_count = visual_cell_width(cell);
    if vis_count >= width {
        return cell.to_string();
    }
    let diff = width - vis_count;
    match align {
        ColumnAlign::Left => format!("{}{}", cell, " ".repeat(diff)),
        ColumnAlign::Right => format!("{}{}", " ".repeat(diff), cell),
        ColumnAlign::Center => {
            let left = diff / 2;
            let right = diff - left;
            format!("{}{}{}", " ".repeat(left), cell, " ".repeat(right))
        }
    }
}

/// Escapes special markdown syntax characters in code lines so that CommonMark does not
/// accidentally parse them as bold, italic, code badges, or HTML tags.
pub fn escape_code_line(line: &str) -> String {
    let mut escaped = String::with_capacity(line.len() + 16);
    for ch in line.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '`' => escaped.push_str("\\`"),
            '*' => escaped.push_str("\\*"),
            '_' => escaped.push_str("\\_"),
            '~' => escaped.push_str("\\~"),
            '<' => escaped.push_str("\\<"),
            '>' => escaped.push_str("\\>"),
            '[' => escaped.push_str("\\["),
            ']' => escaped.push_str("\\]"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Sanitizes angle brackets `<` and `>` in normal text so Slint does not reject them
/// as unsupported HTML tags (like `<String>`, `x < y`, etc.).
pub fn sanitize_html_tags(line: &str) -> String {
    let mut result = String::with_capacity(line.len() + 16);
    let mut chars = line.char_indices().peekable();
    let mut last_idx = 0;

    while let Some((i, ch)) = chars.next() {
        if ch == '<' {
            let remainder = &line[i..];
            let is_allowed = remainder.starts_with("<u>")
                || remainder.starts_with("</u>")
                || remainder.starts_with("<font ")
                || remainder.starts_with("</font>");
            if !is_allowed {
                result.push_str(&line[last_idx..i]);
                result.push_str("\\<");
                last_idx = i + 1;
            }
        } else if ch == '>' {
            let remainder_before = &line[..i];
            let closes_allowed = remainder_before.ends_with("<u")
                || remainder_before.ends_with("</u")
                || remainder_before.ends_with("</font")
                || (remainder_before.contains("<font ") && !remainder_before.ends_with("\\<"));
            if !closes_allowed {
                result.push_str(&line[last_idx..i]);
                result.push_str("\\>");
                last_idx = i + 1;
            }
        }
    }
    result.push_str(&line[last_idx..]);
    result
}

/// Formats a code block as a unified framed 4-sided container with language header.
pub fn format_code_block(lang: &str, lines: &[&str]) -> String {
    let mut result = String::new();
    let display_lang = if lang.trim().is_empty() {
        "code"
    } else {
        lang.trim()
    };
    let min_width = 46usize;
    let max_len = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let inner_width = max_len.max(display_lang.len() + 2).max(min_width);
    let total_width = inner_width + 4; // 2 spaces left padding, 2 spaces right padding

    let top_bar_len = total_width.saturating_sub(display_lang.len() + 5);
    result.push_str(&format!("┌── {} {}┐  \n", display_lang, "─".repeat(top_bar_len)));

    for line in lines {
        let esc = escape_code_line(line);
        let pad = inner_width.saturating_sub(line.chars().count());
        result.push_str(&format!("│  {}{}  │  \n", esc, " ".repeat(pad)));
    }

    result.push_str(&format!("└{}┘  \n", "─".repeat(total_width)));
    result
}

/// Formats a markdown table into an aligned Unicode box-drawing table without backticks.
/// Uses visual cell widths to ensure that formatted cells (strikethrough, bold, code)
/// align with 100% precision.
pub fn format_table_as_unicode_box(
    header_line: &str,
    separator_line: &str,
    data_lines: &[&str],
) -> String {
    let mut headers = parse_table_cells(header_line);
    let alignments = parse_column_alignments(separator_line);
    let mut rows: Vec<Vec<String>> =
        data_lines.iter().map(|line| parse_table_cells(line)).collect();

    let num_cols = headers
        .len()
        .max(alignments.len())
        .max(rows.iter().map(|r| r.len()).max().unwrap_or(0));

    if num_cols == 0 {
        return String::new();
    }

    // Pad headers to num_cols and escape HTML brackets
    for h in &mut headers {
        *h = sanitize_html_tags(h);
    }
    while headers.len() < num_cols {
        headers.push(String::new());
    }

    // Pad rows to num_cols and escape HTML brackets
    for row in &mut rows {
        for cell in row.iter_mut() {
            *cell = sanitize_html_tags(cell);
        }
        while row.len() < num_cols {
            row.push(String::new());
        }
    }

    // Alignments padding
    let mut aligns = alignments;
    while aligns.len() < num_cols {
        aligns.push(ColumnAlign::Left);
    }

    // Calculate column character widths using visual_cell_width (minimum 3)
    let mut col_widths = vec![3usize; num_cols];
    for (i, h) in headers.iter().enumerate() {
        col_widths[i] = col_widths[i].max(visual_cell_width(h));
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            col_widths[i] = col_widths[i].max(visual_cell_width(cell));
        }
    }

    let mut result = String::new();

    // Top border: ┌───┬───┐
    result.push('┌');
    for (i, &w) in col_widths.iter().enumerate() {
        if i > 0 {
            result.push('┬');
        }
        for _ in 0..(w + 2) {
            result.push('─');
        }
    }
    result.push('┐');
    result.push_str("  \n");

    // Header row: │ **H1** │ **H2** │
    result.push('│');
    for (i, h) in headers.iter().enumerate() {
        result.push(' ');
        let formatted_h = format!("**{}**", h);
        result.push_str(&align_cell_content(&formatted_h, col_widths[i], aligns[i]));
        result.push(' ');
        result.push('│');
    }
    result.push_str("  \n");

    // Header separator: ├───┼───┤
    result.push('├');
    for (i, &w) in col_widths.iter().enumerate() {
        if i > 0 {
            result.push('┼');
        }
        for _ in 0..(w + 2) {
            result.push('─');
        }
    }
    result.push('┤');
    result.push_str("  \n");

    // Data rows: │ D1 │ D2 │
    for row in &rows {
        result.push('│');
        for (i, cell) in row.iter().enumerate() {
            result.push(' ');
            result.push_str(&align_cell_content(cell, col_widths[i], aligns[i]));
            result.push(' ');
            result.push('│');
        }
        result.push_str("  \n");
    }

    // Bottom border: └───┴───┘
    result.push('└');
    for (i, &w) in col_widths.iter().enumerate() {
        if i > 0 {
            result.push('┴');
        }
        for _ in 0..(w + 2) {
            result.push('─');
        }
    }
    result.push('┘');
    result.push_str("  \n");

    result
}

// -------------------------------------------------------------------------------------------------
// Math Mode (LaTeX to Unicode Math) Support
// -------------------------------------------------------------------------------------------------

/// Maps an ASCII character to its superscript Unicode counterpart.
fn char_to_superscript(c: char) -> Option<char> {
    match c {
        '0' => Some('⁰'),
        '1' => Some('¹'),
        '2' => Some('²'),
        '3' => Some('³'),
        '4' => Some('⁴'),
        '5' => Some('⁵'),
        '6' => Some('⁶'),
        '7' => Some('⁷'),
        '8' => Some('⁸'),
        '9' => Some('⁹'),
        '+' => Some('⁺'),
        '-' => Some('⁻'),
        '=' => Some('⁼'),
        '(' => Some('⁽'),
        ')' => Some('⁾'),
        'a' => Some('ᵃ'),
        'b' => Some('ᵇ'),
        'c' => Some('ᶜ'),
        'd' => Some('ᵈ'),
        'e' => Some('ᵉ'),
        'f' => Some('ᶠ'),
        'g' => Some('ᵍ'),
        'h' => Some('ʰ'),
        'i' => Some('ⁱ'),
        'j' => Some('ʲ'),
        'k' => Some('ᵏ'),
        'l' => Some('ˡ'),
        'm' => Some('ᵐ'),
        'n' => Some('ⁿ'),
        'o' => Some('ᵒ'),
        'p' => Some('ᵖ'),
        'r' => Some('ʳ'),
        's' => Some('ˢ'),
        't' => Some('ᵗ'),
        'u' => Some('ᵘ'),
        'v' => Some('ᵛ'),
        'w' => Some('ʷ'),
        'x' => Some('ˣ'),
        'y' => Some('ʸ'),
        'z' => Some('ᶻ'),
        'A' => Some('ᴬ'),
        'B' => Some('ᴮ'),
        'D' => Some('ᴰ'),
        'E' => Some('ᴱ'),
        'G' => Some('ᴳ'),
        'H' => Some('ᴴ'),
        'I' => Some('ᴵ'),
        'J' => Some('ᴶ'),
        'K' => Some('ᴷ'),
        'L' => Some('ᴸ'),
        'M' => Some('ᴹ'),
        'N' => Some('ᴺ'),
        'O' => Some('ᴼ'),
        'P' => Some('ᴾ'),
        'R' => Some('ᴿ'),
        'T' => Some('ᵀ'),
        'U' => Some('ᵁ'),
        'V' => Some('ⱽ'),
        'W' => Some('ᵂ'),
        _ => None,
    }
}

/// Maps an ASCII character to its subscript Unicode counterpart.
fn char_to_subscript(c: char) -> Option<char> {
    match c {
        '0' => Some('₀'),
        '1' => Some('₁'),
        '2' => Some('₂'),
        '3' => Some('₃'),
        '4' => Some('₄'),
        '5' => Some('₅'),
        '6' => Some('₆'),
        '7' => Some('₇'),
        '8' => Some('₈'),
        '9' => Some('₉'),
        '+' => Some('₊'),
        '-' => Some('₋'),
        '=' => Some('₌'),
        '(' => Some('₍'),
        ')' => Some('₎'),
        'a' => Some('ₐ'),
        'e' => Some('ₑ'),
        'h' => Some('ₕ'),
        'i' => Some('ᵢ'),
        'j' => Some('ⱼ'),
        'k' => Some('ₖ'),
        'l' => Some('ₗ'),
        'm' => Some('ₘ'),
        'n' => Some('ₙ'),
        'o' => Some('ₒ'),
        'p' => Some('ₚ'),
        'r' => Some('ᵣ'),
        's' => Some('ₛ'),
        't' => Some('ₜ'),
        'u' => Some('ᵤ'),
        'v' => Some('ᵥ'),
        'x' => Some('ₓ'),
        _ => None,
    }
}

/// Helper to convert LaTeX accents (\hat, \bar, \vec, \dot, \ddot, \tilde) to Unicode combining marks.
fn apply_latex_accents(input: &str) -> String {
    let mut s = input.to_string();
    let accents = [
        ("\\hat", '\u{0302}'),
        ("\\bar", '\u{0304}'),
        ("\\vec", '\u{20D7}'),
        ("\\dot", '\u{0307}'),
        ("\\ddot", '\u{0308}'),
        ("\\tilde", '\u{0303}'),
        ("\\acute", '\u{0301}'),
        ("\\grave", '\u{0300}'),
    ];

    for (cmd, mark) in accents {
        // Form 1: \hat{x}
        let brace_prefix = format!("{}{{", cmd);
        while let Some(idx) = s.find(&brace_prefix) {
            let after = &s[idx + brace_prefix.len()..];
            if let Some(close) = after.find('}') {
                let inner = &after[..close];
                let mut converted = String::new();
                for (ci, c) in inner.chars().enumerate() {
                    converted.push(c);
                    if ci == 0 {
                        converted.push(mark);
                    }
                }
                let full_len = brace_prefix.len() + close + 1;
                s.replace_range(idx..idx + full_len, &converted);
                continue;
            }
            break;
        }

        // Form 2: \hat x (single token)
        let space_prefix = format!("{} ", cmd);
        while let Some(idx) = s.find(&space_prefix) {
            let after = &s[idx + space_prefix.len()..];
            if let Some(first_char) = after.chars().next() {
                let char_len = first_char.len_utf8();
                let replacement = format!("{}{}", first_char, mark);
                let full_len = space_prefix.len() + char_len;
                s.replace_range(idx..idx + full_len, &replacement);
                continue;
            }
            break;
        }
    }
    s
}

/// Removes wrapper commands like \text{...}, \mathrm{...}, \mathbf{...}, etc.
fn clean_text_commands(input: &str) -> String {
    let mut s = input.to_string();
    let cmds = ["\\text{", "\\mathrm{", "\\mathbf{", "\\mathit{", "\\operatorname{"];
    for cmd in cmds {
        while let Some(idx) = s.find(cmd) {
            let after = &s[idx + cmd.len()..];
            if let Some(close) = after.find('}') {
                let inner = &after[..close];
                let replacement = inner.to_string();
                let full_len = cmd.len() + close + 1;
                s.replace_range(idx..idx + full_len, &replacement);
                continue;
            }
            break;
        }
    }
    s
}

/// Formats calculus integrals and bounds cleanly.
fn apply_calculus_bounds(input: &str) -> String {
    let mut s = input.to_string();

    s = s.replace("\\int_{-\\infty}^\\infty", "∫[-∞, ∞]");
    s = s.replace("\\int_{-\\infty}^{+\\infty}", "∫[-∞, ∞]");
    s = s.replace("\\int_0^\\infty", "∫[0, ∞]");
    s = s.replace("\\int_0^{+\\infty}", "∫[0, ∞]");
    s = s.replace("\\int_0^1", "∫₀¹");
    s = s.replace("\\int_0^t", "∫₀ᵗ");
    s = s.replace("\\int_{0}^{\\infty}", "∫[0, ∞]");
    s = s.replace("\\int_{-\\infty}^{0}", "∫[-∞, 0]");

    // Generic \int_{lower}^{upper} -> ∫[lower, upper]
    while let Some(idx) = s.find("\\int_{") {
        let after = &s[idx + 6..];
        if let Some(close_low) = after.find('}') {
            let lower = &after[..close_low];
            let after_low = &after[close_low + 1..];
            if after_low.starts_with("^{") {
                if let Some(close_up) = after_low[2..].find('}') {
                    let upper = &after_low[2..2 + close_up];
                    let replacement = format!("∫[{}, {}]", lower, upper);
                    let full_end = idx + 6 + close_low + 1 + 2 + close_up + 1;
                    s.replace_range(idx..full_end, &replacement);
                    continue;
                }
            }
        }
        break;
    }

    s
}

/// Converts LaTeX math formulas into clear, beautiful Unicode representations.
pub fn convert_latex_math_to_unicode(latex: &str) -> String {
    let mut s = latex.trim().to_string();

    // 1. Calculus bounds & integrals
    s = apply_calculus_bounds(&s);

    // 2. Text command wrappers
    s = clean_text_commands(&s);

    // 3. LaTeX accents (\hat, \bar, \vec, etc.)
    s = apply_latex_accents(&s);

    // 4. Fractions: \frac{a}{b} -> (a)/(b)
    while let Some(idx) = s.find("\\frac{") {
        let after_first_brace = &s[idx + 6..];
        if let Some(close_first) = after_first_brace.find('}') {
            let num = &after_first_brace[..close_first];
            let after_second = &after_first_brace[close_first + 1..];
            if after_second.starts_with('{') {
                if let Some(close_second) = after_second[1..].find('}') {
                    let den = &after_second[1..=close_second];
                    let replacement = format!("({})/({})", num, den);
                    let full_end = idx + 6 + close_first + 1 + 1 + close_second + 1;
                    s.replace_range(idx..full_end, &replacement);
                    continue;
                }
            }
        }
        break;
    }

    // 5. Roots: \sqrt{x} -> √(x)
    while let Some(idx) = s.find("\\sqrt{") {
        let after = &s[idx + 6..];
        if let Some(close) = after.find('}') {
            let inner = &after[..close];
            let replacement = format!("√({})", inner);
            s.replace_range(idx..idx + 6 + close + 1, &replacement);
            continue;
        }
        break;
    }

    // 6. LaTeX symbols replacements table
    let symbols = [
        // Greek lowercase
        ("\\alpha", "α"),
        ("\\beta", "β"),
        ("\\gamma", "γ"),
        ("\\delta", "δ"),
        ("\\varepsilon", "ε"),
        ("\\epsilon", "ε"),
        ("\\zeta", "ζ"),
        ("\\eta", "η"),
        ("\\vartheta", "ϑ"),
        ("\\theta", "θ"),
        ("\\iota", "ι"),
        ("\\kappa", "κ"),
        ("\\lambda", "λ"),
        ("\\mu", "μ"),
        ("\\nu", "ν"),
        ("\\xi", "ξ"),
        ("\\varpi", "ϖ"),
        ("\\pi", "π"),
        ("\\varrho", "ϱ"),
        ("\\rho", "ρ"),
        ("\\varsigma", "ς"),
        ("\\sigma", "σ"),
        ("\\tau", "τ"),
        ("\\upsilon", "υ"),
        ("\\varphi", "ϕ"),
        ("\\phi", "φ"),
        ("\\chi", "χ"),
        ("\\psi", "ψ"),
        ("\\omega", "ω"),
        // Greek uppercase
        ("\\Gamma", "Γ"),
        ("\\Delta", "Δ"),
        ("\\Theta", "Θ"),
        ("\\Lambda", "Λ"),
        ("\\Xi", "Ξ"),
        ("\\Pi", "Π"),
        ("\\Sigma", "Σ"),
        ("\\Upsilon", "Υ"),
        ("\\Phi", "Φ"),
        ("\\Psi", "Ψ"),
        ("\\Omega", "Ω"),
        // Standard Functions
        ("\\sin", "sin"),
        ("\\cos", "cos"),
        ("\\tan", "tan"),
        ("\\sec", "sec"),
        ("\\csc", "csc"),
        ("\\cot", "cot"),
        ("\\arcsin", "arcsin"),
        ("\\arccos", "arccos"),
        ("\\arctan", "arctan"),
        ("\\sinh", "sinh"),
        ("\\cosh", "cosh"),
        ("\\tanh", "tanh"),
        ("\\ln", "ln"),
        ("\\log", "log"),
        ("\\exp", "exp"),
        ("\\lim", "lim"),
        ("\\det", "det"),
        ("\\dim", "dim"),
        ("\\ker", "ker"),
        ("\\deg", "deg"),
        ("\\gcd", "gcd"),
        ("\\min", "min"),
        ("\\max", "max"),
        ("\\sup", "sup"),
        ("\\inf", "inf"),
        // Operators & Calculus
        ("\\partial", "∂"),
        ("\\nabla", "∇"),
        ("\\infty", "∞"),
        ("\\sqrt", "√"),
        ("\\sum", "∑"),
        ("\\prod", "∏"),
        ("\\iiint", "∭"),
        ("\\iint", "∬"),
        ("\\oint", "∮"),
        ("\\int", "∫"),
        ("\\pm", "±"),
        ("\\mp", "∓"),
        ("\\times", "×"),
        ("\\div", "÷"),
        ("\\cdot", "·"),
        ("\\circ", "∘"),
        ("\\bullet", "•"),
        ("\\oplus", "⊕"),
        ("\\otimes", "⊗"),
        // Relations & Logic
        ("\\neq", "≠"),
        ("\\ne", "≠"),
        ("\\leq", "≤"),
        ("\\le", "≤"),
        ("\\geq", "≥"),
        ("\\ge", "≥"),
        ("\\approx", "≈"),
        ("\\simeq", "≃"),
        ("\\cong", "≅"),
        ("\\equiv", "≡"),
        ("\\sim", "∼"),
        ("\\propto", "∝"),
        ("\\ll", "≪"),
        ("\\gg", "≫"),
        ("\\notin", "∉"),
        ("\\in", "∈"),
        ("\\ni", "∋"),
        ("\\subset", "⊂"),
        ("\\subseteq", "⊆"),
        ("\\supset", "⊃"),
        ("\\supseteq", "⊇"),
        ("\\setminus", "∖"),
        ("\\cup", "∪"),
        ("\\cap", "∩"),
        ("\\emptyset", "∅"),
        ("\\empty", "∅"),
        ("\\forall", "∀"),
        ("\\exists", "∃"),
        ("\\nexists", "∄"),
        ("\\neg", "¬"),
        ("\\land", "∧"),
        ("\\wedge", "∧"),
        ("\\lor", "∨"),
        ("\\vee", "∨"),
        // Arrows
        ("\\iff", "⇔"),
        ("\\implies", "⇒"),
        ("\\Rightarrow", "⇒"),
        ("\\Leftarrow", "⇐"),
        ("\\Leftrightarrow", "⇔"),
        ("\\rightarrow", "→"),
        ("\\leftarrow", "←"),
        ("\\leftrightarrow", "↔"),
        ("\\to", "→"),
        ("\\mapsto", "↦"),
        ("\\uparrow", "↑"),
        ("\\downarrow", "↓"),
        // Sets
        ("\\mathbb{R}", "ℝ"),
        ("\\mathbb{N}", "ℕ"),
        ("\\mathbb{Z}", "ℤ"),
        ("\\mathbb{Q}", "ℚ"),
        ("\\mathbb{C}", "ℂ"),
        ("\\mathbb{P}", "ℙ"),
        ("\\mathbb{H}", "ℍ"),
        // Brackets & delimiters
        ("\\left(", "("),
        ("\\right)", ")"),
        ("\\left[", "["),
        ("\\right]", "]"),
        ("\\left\\{", "{"),
        ("\\right\\}", "}"),
        ("\\left|", "|"),
        ("\\right|", "|"),
        ("\\langle", "⟨"),
        ("\\rangle", "⟩"),
        ("\\lfloor", "⌊"),
        ("\\rfloor", "⌋"),
        ("\\lceil", "⌈"),
        ("\\rceil", "⌉"),
        // Punctuation & spaces
        ("\\cdots", "…"),
        ("\\ldots", "…"),
        ("\\dots", "…"),
        ("\\quad", "  "),
        ("\\qquad", "    "),
        ("\\,", " "),
        ("\\;", " "),
        ("\\!", ""),
        ("\\left", ""),
        ("\\right", ""),
        ("\\{", "{"),
        ("\\}", "}"),
    ];

    for (cmd, sym) in symbols {
        s = s.replace(cmd, sym);
    }

    // 7. Superscripts & Subscripts
    apply_superscripts_and_subscripts(&s)
}

/// Helper to safely convert superscripts and subscripts character-by-character without UTF-8 slicing errors.
fn apply_superscripts_and_subscripts(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '^' {
            if let Some(&'{') = chars.peek() {
                chars.next(); // consume '{'
                let mut content = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    content.push(c);
                }
                let mut converted = String::new();
                let mut all_converted = true;
                for c in content.chars() {
                    if let Some(sup) = char_to_superscript(c) {
                        converted.push(sup);
                    } else {
                        all_converted = false;
                        break;
                    }
                }
                if all_converted {
                    out.push_str(&converted);
                } else {
                    let clean = content.trim();
                    out.push_str(&format!("^({})", clean));
                }
            } else if let Some(&next_c) = chars.peek() {
                if let Some(sup) = char_to_superscript(next_c) {
                    chars.next(); // consume next_c
                    out.push(sup);
                } else {
                    out.push('^');
                }
            } else {
                out.push('^');
            }
        } else if ch == '_' {
            if let Some(&'{') = chars.peek() {
                chars.next(); // consume '{'
                let mut content = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    content.push(c);
                }
                let mut converted = String::new();
                let mut all_converted = true;
                for c in content.chars() {
                    if let Some(sub) = char_to_subscript(c) {
                        converted.push(sub);
                    } else {
                        all_converted = false;
                        break;
                    }
                }
                if all_converted {
                    out.push_str(&converted);
                } else {
                    let clean = content.trim();
                    out.push_str(&format!("_({})", clean));
                }
            } else if let Some(&next_c) = chars.peek() {
                if let Some(sub) = char_to_subscript(next_c) {
                    chars.next(); // consume next_c
                    out.push(sub);
                } else {
                    out.push('_');
                }
            } else {
                out.push('_');
            }
        } else {
            out.push(ch);
        }
    }

    out
}

/// Escapes special markdown characters inside math expressions so they do not conflict
/// with CommonMark emphasis (e.g. `*`, `_`) or Slint HTML parsing (`<`, `>`).
pub fn escape_math_for_markdown(math: &str) -> String {
    let mut out = String::with_capacity(math.len() + 8);
    for ch in math.chars() {
        match ch {
            '<' => out.push_str("\\<"),
            '>' => out.push_str("\\>"),
            '*' => out.push_str("\\*"),
            '_' => out.push_str("\\_"),
            _ => out.push(ch),
        }
    }
    out
}

/// Processes inline math `$formula$` within a line, converting it to clean Unicode math.
pub fn process_inline_math(line: &str) -> String {
    let mut result = String::with_capacity(line.len() + 16);
    let mut chars = line.char_indices().peekable();
    let mut last_idx = 0;

    while let Some((i, ch)) = chars.next() {
        if ch == '$' {
            // Ensure not escaped \$ and not $$
            if i > 0 && line.as_bytes()[i - 1] == b'\\' {
                continue;
            }
            if let Some(&(_, '$')) = chars.peek() {
                continue; // part of $$ block math
            }
            // Find closing $
            let mut close_idx = None;
            for (j, c) in line[i + 1..].char_indices() {
                let abs_j = i + 1 + j;
                if c == '$' && line.as_bytes()[abs_j - 1] != b'\\' {
                    close_idx = Some(abs_j);
                    break;
                }
            }

            if let Some(c_idx) = close_idx {
                let formula = &line[i + 1..c_idx];
                // Don't treat standalone dollar amounts like $50 as math
                let is_currency = formula.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ',');
                if !formula.is_empty() && !is_currency {
                    result.push_str(&line[last_idx..i]);
                    let unicode_math = convert_latex_math_to_unicode(formula);
                    let safe_math = escape_math_for_markdown(&unicode_math);
                    result.push_str(&format!("*{}*", safe_math));
                    last_idx = c_idx + 1;
                    // Advance peekable iterator to after closing $
                    while let Some(&(curr_idx, _)) = chars.peek() {
                        if curr_idx <= c_idx {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    continue;
                }
            }
        }
    }

    result.push_str(&line[last_idx..]);
    result
}

/// Ensures an additional vertical space before an element starts.
fn ensure_element_vertical_spacing(output: &mut String) {
    if output.is_empty() {
        return;
    }
    if !output.ends_with("\u{00A0}\n\n") {
        if !output.ends_with("\n\n") {
            if output.ends_with('\n') {
                output.push('\n');
            } else {
                output.push_str("\n\n");
            }
        }
        output.push_str("\u{00A0}\n\n");
    }
}

/// Helper to ensure standard paragraph boundary (`\n\n`).
fn ensure_blank_line(output: &mut String) {
    if output.is_empty() {
        return;
    }
    if !output.ends_with("\n\n") {
        if output.ends_with('\n') {
            output.push('\n');
        } else {
            output.push_str("\n\n");
        }
    }
}

/// Checks if a trimmed line is a block boundary element (heading, hr, code fence, math fence, blockquote, list, table).
fn is_block_start(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("```")
        || trimmed.starts_with("~~~")
        || trimmed.starts_with("$$")
        || trimmed.starts_with('>')
        || trimmed.starts_with('|')
        || trimmed.starts_with("- ")
        || trimmed.starts_with("* ")
        || trimmed.starts_with("+ ")
        || is_horizontal_rule(trimmed)
        || is_ordered_list_item(trimmed)
}

/// Checks if a trimmed line is an ordered list item (e.g. `1. `, `12. `).
fn is_ordered_list_item(trimmed: &str) -> bool {
    if let Some(pos) = trimmed.find(". ") {
        if pos > 0 && trimmed[..pos].chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Preprocesses raw Markdown text into a CommonMark subset that Slint's `StyledText::from_markdown`
/// parses cleanly, styled like GitHub Flavored Markdown (GFM) with full math mode support.
pub fn preprocess_markdown_for_slint(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut output = String::with_capacity(input.len() + 256);
    let mut i = 0;
    let mut prev_was_list = false;
    let mut prev_was_quote = false;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // 1. Empty lines: preserve as visible blank line
        if trimmed.is_empty() {
            ensure_element_vertical_spacing(&mut output);
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        }

        // 2. Display / Block Math ($$ ... $$)
        if trimmed.starts_with("$$") {
            ensure_element_vertical_spacing(&mut output);

            // Check if single-line block math ($$formula$$)
            if trimmed.len() > 4 && trimmed.ends_with("$$") {
                let formula = &trimmed[2..trimmed.len() - 2];
                let math = convert_latex_math_to_unicode(formula);
                let safe_math = escape_math_for_markdown(&math);
                output.push_str(&format!("   *{}*  \n", safe_math));
                ensure_element_vertical_spacing(&mut output);
                prev_was_list = false;
                prev_was_quote = false;
                i += 1;
                continue;
            }

            // Multi-line block math ($$\n...\n$$)
            let mut math_lines = Vec::new();
            i += 1;
            while i < lines.len() {
                let m_line = lines[i];
                if m_line.trim().starts_with("$$") {
                    i += 1;
                    break;
                }
                math_lines.push(m_line);
                i += 1;
            }

            for m_line in math_lines {
                let math = convert_latex_math_to_unicode(m_line);
                let safe_math = escape_math_for_markdown(&math);
                output.push_str(&format!("   *{}*  \n", safe_math));
            }
            ensure_element_vertical_spacing(&mut output);
            prev_was_list = false;
            prev_was_quote = false;
            continue;
        }

        // 3. Code blocks (``` or ~~~)
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let fence = if trimmed.starts_with("```") { "```" } else { "~~~" };
            let lang = trimmed.strip_prefix(fence).unwrap_or("").trim();

            ensure_element_vertical_spacing(&mut output);

            let mut code_lines = Vec::new();
            i += 1;
            while i < lines.len() {
                let code_line = lines[i];
                if code_line.trim().starts_with(fence) {
                    i += 1;
                    break;
                }
                code_lines.push(code_line);
                i += 1;
            }

            output.push_str(&format_code_block(lang, &code_lines));
            ensure_blank_line(&mut output);
            prev_was_list = false;
            prev_was_quote = false;
            continue;
        }

        // 4. Table detection: header row followed by separator row
        if trimmed.contains('|') && i + 1 < lines.len() && is_table_separator_line(lines[i + 1]) {
            let header_line = lines[i];
            let separator_line = lines[i + 1];
            let mut data_lines = Vec::new();

            let mut k = i + 2;
            while k < lines.len() {
                let next_line = lines[k];
                if next_line.trim().is_empty() || !next_line.contains('|') {
                    break;
                }
                data_lines.push(next_line);
                k += 1;
            }

            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format_table_as_unicode_box(
                header_line,
                separator_line,
                &data_lines,
            ));
            ensure_blank_line(&mut output);
            i = k;
            prev_was_list = false;
            prev_was_quote = false;
            continue;
        }

        // 5. Horizontal Rule
        if is_horizontal_rule(trimmed) {
            ensure_element_vertical_spacing(&mut output);
            output.push_str("──────────────────────────────────────────────────\n\n");
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        }

        // 6. ATX Headings (# Heading)
        if let Some(rest) = trimmed.strip_prefix("# ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("**<u>{}</u>**\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("## ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("**{}**\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("### ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("***{}***\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("#### ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("**{}**\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("##### ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("*{}*\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("###### ") {
            let text = sanitize_html_tags(rest.trim().trim_end_matches('#').trim());
            ensure_element_vertical_spacing(&mut output);
            output.push_str(&format!("*{}*\n\n", text));
            prev_was_list = false;
            prev_was_quote = false;
            i += 1;
            continue;
        }

        // 7. Setext Headings (Heading\n=== or Heading\n---)
        if !is_block_start(trimmed) && i + 1 < lines.len() {
            let next_trimmed = lines[i + 1].trim();
            if next_trimmed.len() >= 3 && next_trimmed.chars().all(|c| c == '=') {
                ensure_element_vertical_spacing(&mut output);
                output.push_str(&format!("**<u>{}</u>**\n\n", sanitize_html_tags(trimmed)));
                prev_was_list = false;
                prev_was_quote = false;
                i += 2;
                continue;
            } else if next_trimmed.len() >= 3 && next_trimmed.chars().all(|c| c == '-') {
                ensure_element_vertical_spacing(&mut output);
                output.push_str(&format!("**{}**\n\n", sanitize_html_tags(trimmed)));
                prev_was_list = false;
                prev_was_quote = false;
                i += 2;
                continue;
            }
        }

        // 8. Blockquotes (> quote)
        if trimmed.starts_with('>') {
            let mut depth = 0;
            let mut content = trimmed;
            while let Some(stripped) = content.strip_prefix('>') {
                depth += 1;
                content = stripped.trim_start();
            }
            if !prev_was_quote {
                ensure_element_vertical_spacing(&mut output);
            }
            let bars = "│ ".repeat(depth);
            if content.is_empty() {
                output.push_str(&format!("{} \n", bars));
            } else {
                let math_quote = process_inline_math(content);
                output.push_str(&format!("{}*{}*  \n", bars, sanitize_html_tags(&math_quote)));
            }

            if i + 1 >= lines.len() || !lines[i + 1].trim().starts_with('>') {
                ensure_blank_line(&mut output);
                prev_was_quote = false;
            } else {
                prev_was_quote = true;
            }
            prev_was_list = false;
            i += 1;
            continue;
        }

        // 9. Image replacement and inline math in normal lines
        let processed_images = if line.contains("![") {
            convert_images_to_links(line)
        } else {
            line.to_string()
        };
        let processed_math = if processed_images.contains('$') {
            process_inline_math(&processed_images)
        } else {
            processed_images
        };
        let sanitized_line = sanitize_html_tags(&processed_math);
        let p_trimmed = sanitized_line.trim();

        // 10. Task lists & List items
        let is_task_list = p_trimmed.starts_with("- [ ] ")
            || p_trimmed.starts_with("- [x] ")
            || p_trimmed.starts_with("- [X] ")
            || p_trimmed.starts_with("* [ ] ")
            || p_trimmed.starts_with("* [x] ")
            || p_trimmed.starts_with("* [X] ");
        let is_regular_list = p_trimmed.starts_with("- ")
            || p_trimmed.starts_with("* ")
            || p_trimmed.starts_with("+ ")
            || is_ordered_list_item(p_trimmed);

        if is_task_list || is_regular_list {
            if !prev_was_list {
                ensure_element_vertical_spacing(&mut output);
            }

            // Preserve leading indentation for nested sub-lists
            let indent_len = line.len() - line.trim_start().len();
            let indent = " ".repeat(indent_len);

            if let Some(rest) = p_trimmed.strip_prefix("- [ ] ") {
                output.push_str(&format!("{}- ☐ {}\n", indent, rest));
            } else if let Some(rest) = p_trimmed
                .strip_prefix("- [x] ")
                .or_else(|| p_trimmed.strip_prefix("- [X] "))
            {
                output.push_str(&format!("{}- ☑ {}\n", indent, rest));
            } else if let Some(rest) = p_trimmed.strip_prefix("* [ ] ") {
                output.push_str(&format!("{}* ☐ {}\n", indent, rest));
            } else if let Some(rest) = p_trimmed
                .strip_prefix("* [x] ")
                .or_else(|| p_trimmed.strip_prefix("* [X] "))
            {
                output.push_str(&format!("{}* ☑ {}\n", indent, rest));
            } else {
                output.push_str(&indent);
                output.push_str(p_trimmed);
                output.push('\n');
            }

            if i + 1 >= lines.len() || lines[i + 1].trim().is_empty() {
                ensure_blank_line(&mut output);
                prev_was_list = false;
            } else {
                prev_was_list = true;
            }
            prev_was_quote = false;
            i += 1;
            continue;
        }

        // 11. Regular paragraph text line
        // End each line with `  \n` (two spaces + newline) so all typed line wraps are preserved!
        output.push_str(&sanitized_line);
        output.push_str("  \n");

        if i + 1 < lines.len() && lines[i + 1].trim().is_empty() {
            ensure_blank_line(&mut output);
        }

        prev_was_list = false;
        prev_was_quote = false;
        i += 1;
    }

    output
}

/// Renders markdown text into Slint's `StyledText` representation.
///
/// Preprocesses unsupported elements (such as headings, code blocks, tables, and math) so they render
/// smoothly with GitHub Flavored Markdown visual elegance. If parsing fails for any reason,
/// falls back to plain text so note content is never lost.
pub fn render_markdown_styled(input: &str) -> slint::StyledText {
    if input.trim().is_empty() {
        return slint::StyledText::default();
    }

    let preprocessed = preprocess_markdown_for_slint(input);
    match slint::StyledText::from_markdown(&preprocessed) {
        Ok(styled) => styled,
        Err(e) => {
            eprintln!(
                "[Markdown] Failed to parse styled text: {:?}. Falling back to plain text.",
                e
            );
            slint::StyledText::from_plain_text(input)
        }
    }
}

fn empty_string_model() -> ModelRc<SharedString> {
    ModelRc::new(VecModel::default())
}

fn empty_row_model() -> ModelRc<TableRowData> {
    ModelRc::new(VecModel::default())
}

fn empty_int_model() -> ModelRc<i32> {
    ModelRc::new(VecModel::default())
}

fn empty_float_model() -> ModelRc<f32> {
    ModelRc::new(VecModel::default())
}

/// Cleans inline formatting markers (bold **, italic *, strikethrough ~~, links [text](url))
/// so text is readable, clean, and selectable in a TextInput.
pub fn clean_inline_formatting(input: &str) -> String {
    // 1. Process inline math: convert $...$ to Unicode math
    let with_math = process_inline_math(input);

    let mut s = with_math;

    // Convert links [text](url) -> text (url) if url != text, or url if identical
    while let Some(open_b) = s.find('[') {
        if let Some(close_b) = s[open_b..].find(']') {
            let abs_close_b = open_b + close_b;
            if s[abs_close_b..].starts_with("](") {
                if let Some(close_p) = s[abs_close_b + 2..].find(')') {
                    let abs_close_p = abs_close_b + 2 + close_p;
                    let text = s[open_b + 1..abs_close_b].to_string();
                    let url = s[abs_close_b + 2..abs_close_p].to_string();
                    let replacement = if text.is_empty() || text == url {
                        url
                    } else {
                        format!("{} ({})", text, url)
                    };
                    s.replace_range(open_b..=abs_close_p, &replacement);
                    continue;
                }
            }
        }
        break;
    }

    // Convert strikethrough ~~text~~ to combining strike
    while let Some(start) = s.find("~~") {
        if let Some(end) = s[start + 2..].find("~~") {
            let abs_end = start + 2 + end;
            let inner = &s[start + 2..abs_end];
            let mut struck = String::with_capacity(inner.len() * 2);
            for c in inner.chars() {
                struck.push(c);
                struck.push('\u{0336}');
            }
            s.replace_range(start..=abs_end + 1, &struck);
        } else {
            break;
        }
    }

    // Remove ***bold+italic***, **bold**, *italic*, __bold__, _italic_
    let mut cleaned = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' | '_' => {
                // skip bold / italic delimiters
            }
            '\\' => {
                // Escaped characters like \* or \_ -> output literal character
                if let Some(&next_ch) = chars.peek() {
                    if next_ch == '*' || next_ch == '_' || next_ch == '`' || next_ch == '\\' || next_ch == '[' || next_ch == ']' {
                        chars.next();
                        cleaned.push(next_ch);
                    } else {
                        cleaned.push(ch);
                    }
                } else {
                    cleaned.push(ch);
                }
            }
            _ => cleaned.push(ch),
        }
    }
    cleaned
}

/// Formats markdown content into clean, readable text suitable for selectable TextInput display.
/// Preserves structure (bullets, numbers, indentation, code quotes, links) while removing raw markdown delimiters.
pub fn format_markdown_for_display(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let trimmed = line.trim_start();
        let indent_len = line.len() - trimmed.len();
        let indent = " ".repeat(indent_len);

        // Convert list bullets to clean Unicode bullets
        let clean_line = if let Some(rest) = trimmed.strip_prefix("* ") {
            format!("{}• {}", indent, clean_inline_formatting(rest))
        } else if let Some(rest) = trimmed.strip_prefix("- ") {
            format!("{}• {}", indent, clean_inline_formatting(rest))
        } else if let Some(rest) = trimmed.strip_prefix("+ ") {
            format!("{}• {}", indent, clean_inline_formatting(rest))
        } else {
            format!("{}{}", indent, clean_inline_formatting(trimmed))
        };

        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&clean_line);
    }
    out
}

fn create_styled_text(md: &str) -> StyledText {
    let sanitized = convert_images_to_links(md);
    let with_math = process_inline_math(&sanitized);
    StyledText::from_markdown(&with_math).unwrap_or_else(|_| {
        StyledText::from_markdown(&sanitize_html_tags(&with_math))
            .unwrap_or_else(|_| StyledText::from_plain_text(&with_math))
    })
}

/// Parses a Markdown document into structured visual blocks for native Slint rendering.
/// Emulates GitHub Flavored Markdown (GFM) with true component-based rendering:
/// - Headings: font sizes, line heights, and 1px dividers on H1/H2
/// - Paragraphs: styled text with inline code, links, bold, italics, and math
/// - Code Blocks: native framed containers with language badges and cascadia code font
/// - Tables: native 1px border grid with shaded header and alternating row background
/// - Blockquotes: 4px accent-colored left bar
/// - Math Blocks: centered mathematical formula cards
/// - Horizontal Rules: 1px subtle divider lines
/// - Task Lists: native checkbox widgets
pub fn parse_markdown_into_blocks(input: &str) -> Vec<MarkdownBlockData> {
    if input.trim().is_empty() {
        return Vec::new();
    }

    let mut blocks = Vec::new();

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_MATH);
    options.insert(Options::ENABLE_HEADING_ATTRIBUTES);

    let parser = Parser::new_ext(input, options);

    enum State {
        None,
        Heading {
            level: i32,
            text: String,
        },
        CodeBlock {
            lang: String,
            content: String,
        },
        Table {
            alignments: Vec<i32>,
            headers: Vec<String>,
            rows: Vec<Vec<String>>,
            current_row: Vec<String>,
            current_cell: String,
            in_head: bool,
            in_strikethrough: bool,
        },
        Paragraph {
            start: usize,
        },
    }

    let mut state = State::None;
    let mut blockquote_depth: usize = 0;
    let mut blockquote_start: usize = 0;
    let mut list_depth: usize = 0;
    let mut top_list_start: usize = 0;
    let mut has_task_marker: bool = false;
    let mut current_item_is_task: bool = false;
    let mut current_item_checked: bool = false;
    let mut current_item_text: String = String::new();
    let mut in_item: bool = false;

    for (event, range) in parser.into_offset_iter() {
        match event {
            // --- Headings ---
            Event::Start(Tag::Heading { level, .. }) => {
                let lvl = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    HeadingLevel::H4 => 4,
                    HeadingLevel::H5 => 5,
                    HeadingLevel::H6 => 6,
                };
                state = State::Heading {
                    level: lvl,
                    text: String::new(),
                };
            }
            Event::End(TagEnd::Heading(_)) => {
                if let State::Heading { level, text } = std::mem::replace(&mut state, State::None) {
                    blocks.push(MarkdownBlockData {
                        block_type: 0,
                        heading_level: level,
                        text: text.trim().into(),
                        styled_content: StyledText::default(),
                        code_lang: SharedString::default(),
                        code_content: SharedString::default(),
                        table_headers: empty_string_model(),
                        table_alignments: empty_int_model(),
                        table_col_fractions: empty_float_model(),
                        table_rows: empty_row_model(),
                        is_task_checked: false,
                    });
                }
            }

            // --- Code Blocks ---
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match kind {
                    CodeBlockKind::Fenced(l) => l.to_string(),
                    CodeBlockKind::Indented => String::new(),
                };
                state = State::CodeBlock {
                    lang,
                    content: String::new(),
                };
            }
            Event::End(TagEnd::CodeBlock) => {
                if let State::CodeBlock { lang, content } = std::mem::replace(&mut state, State::None) {
                    blocks.push(MarkdownBlockData {
                        block_type: 2,
                        heading_level: 0,
                        text: SharedString::default(),
                        styled_content: StyledText::default(),
                        code_lang: lang.trim().into(),
                        code_content: content.trim_end().into(),
                        table_headers: empty_string_model(),
                        table_alignments: empty_int_model(),
                        table_col_fractions: empty_float_model(),
                        table_rows: empty_row_model(),
                        is_task_checked: false,
                    });
                }
            }

            // --- Tables ---
            Event::Start(Tag::Table(alignments)) => {
                let aligns = alignments
                    .into_iter()
                    .map(|a| match a {
                        pulldown_cmark::Alignment::Center => 1,
                        pulldown_cmark::Alignment::Right => 2,
                        _ => 0,
                    })
                    .collect();
                state = State::Table {
                    alignments: aligns,
                    headers: Vec::new(),
                    rows: Vec::new(),
                    current_row: Vec::new(),
                    current_cell: String::new(),
                    in_head: false,
                    in_strikethrough: false,
                };
            }
            Event::Start(Tag::TableHead) => {
                if let State::Table { ref mut in_head, .. } = state {
                    *in_head = true;
                }
            }
            Event::End(TagEnd::TableHead) => {
                if let State::Table { ref mut in_head, .. } = state {
                    *in_head = false;
                }
            }
            Event::Start(Tag::TableRow) => {
                if let State::Table { ref mut current_row, .. } = state {
                    current_row.clear();
                }
            }
            Event::End(TagEnd::TableRow) => {
                if let State::Table {
                    ref mut rows,
                    ref mut current_row,
                    ..
                } = state
                {
                    rows.push(std::mem::take(current_row));
                }
            }
            Event::Start(Tag::TableCell) => {
                if let State::Table {
                    ref mut current_cell,
                    ..
                } = state
                {
                    current_cell.clear();
                }
            }
            Event::End(TagEnd::TableCell) => {
                if let State::Table {
                    ref mut headers,
                    ref mut current_row,
                    ref current_cell,
                    in_head,
                    ..
                } = state
                {
                    let cell = current_cell.trim().to_string();
                    if in_head {
                        headers.push(cell);
                    } else {
                        current_row.push(cell);
                    }
                }
            }
            Event::End(TagEnd::Table) => {
                if let State::Table {
                    alignments,
                    headers,
                    rows,
                    ..
                } = std::mem::replace(&mut state, State::None)
                {
                    let num_cols = headers.len();
                    let mut max_col_lens = vec![4.0f32; num_cols];
                    for c in 0..num_cols {
                        let h_len = headers.get(c).map(|h| h.chars().count()).unwrap_or(3).max(3) as f32;
                        let mut col_max = h_len;
                        for row in &rows {
                            if let Some(cell) = row.get(c) {
                                col_max = col_max.max(cell.chars().count() as f32);
                            }
                        }
                        max_col_lens[c] = col_max.max(4.0);
                    }
                    let adjusted_weights: Vec<f32> = max_col_lens.iter().map(|&w| w.powf(0.6)).collect();
                    let total_adj: f32 = adjusted_weights.iter().sum();
                    let col_fractions: Vec<f32> = if total_adj > 0.0 {
                        adjusted_weights.iter().map(|&w| w / total_adj).collect()
                    } else {
                        vec![1.0 / (num_cols as f32); num_cols]
                    };

                    let headers_model: Vec<SharedString> =
                        headers.into_iter().map(SharedString::from).collect();
                    let rows_model: Vec<TableRowData> = rows
                        .into_iter()
                        .map(|mut row_cells| {
                            while row_cells.len() < num_cols {
                                row_cells.push(String::new());
                            }
                            if row_cells.len() > num_cols {
                                row_cells.truncate(num_cols);
                            }
                            TableRowData {
                                cells: ModelRc::new(VecModel::from(
                                    row_cells.into_iter().map(SharedString::from).collect::<Vec<_>>(),
                                )),
                            }
                        })
                        .collect();

                    blocks.push(MarkdownBlockData {
                        block_type: 3,
                        heading_level: 0,
                        text: SharedString::default(),
                        styled_content: StyledText::default(),
                        code_lang: SharedString::default(),
                        code_content: SharedString::default(),
                        table_headers: ModelRc::new(VecModel::from(headers_model)),
                        table_alignments: ModelRc::new(VecModel::from(alignments)),
                        table_col_fractions: ModelRc::new(VecModel::from(col_fractions)),
                        table_rows: ModelRc::new(VecModel::from(rows_model)),
                        is_task_checked: false,
                    });
                }
            }

            // --- Blockquotes ---
            Event::Start(Tag::BlockQuote(_)) => {
                if blockquote_depth == 0 {
                    blockquote_start = range.start;
                }
                blockquote_depth += 1;
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                blockquote_depth = blockquote_depth.saturating_sub(1);
                if blockquote_depth == 0 {
                    let raw_bq = &input[blockquote_start..range.end];
                    let cleaned_bq: String = raw_bq
                        .lines()
                        .map(|l| {
                            let mut trimmed = l.trim_start();
                            while let Some(rest) = trimmed.strip_prefix('>') {
                                trimmed = rest.strip_prefix(' ').unwrap_or(rest).trim_start();
                            }
                            trimmed
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    blocks.push(MarkdownBlockData {
                        block_type: 4,
                        heading_level: 0,
                        text: format_markdown_for_display(&cleaned_bq).into(),
                        styled_content: create_styled_text(&cleaned_bq),
                        code_lang: SharedString::default(),
                        code_content: SharedString::default(),
                        table_headers: empty_string_model(),
                        table_alignments: empty_int_model(),
                        table_col_fractions: empty_float_model(),
                        table_rows: empty_row_model(),
                        is_task_checked: false,
                    });
                }
            }

            // --- Lists & Task Items ---
            Event::Start(Tag::List(_)) => {
                if list_depth == 0 {
                    top_list_start = range.start;
                    has_task_marker = false;
                }
                list_depth += 1;
            }
            Event::End(TagEnd::List(_)) => {
                list_depth = list_depth.saturating_sub(1);
                if list_depth == 0 && !has_task_marker {
                    let list_slice = input[top_list_start..range.end].trim();
                    if !list_slice.is_empty() {
                        blocks.push(MarkdownBlockData {
                            block_type: 1,
                            heading_level: 0,
                            text: format_markdown_for_display(list_slice).into(),
                            styled_content: create_styled_text(list_slice),
                            code_lang: SharedString::default(),
                            code_content: SharedString::default(),
                            table_headers: empty_string_model(),
                            table_alignments: empty_int_model(),
                            table_col_fractions: empty_float_model(),
                            table_rows: empty_row_model(),
                            is_task_checked: false,
                        });
                    }
                }
            }
            Event::Start(Tag::Item) => {
                in_item = true;
                current_item_is_task = false;
                current_item_checked = false;
                current_item_text.clear();
            }
            Event::TaskListMarker(checked) => {
                current_item_is_task = true;
                current_item_checked = checked;
                has_task_marker = true;
            }
            Event::End(TagEnd::Item) => {
                in_item = false;
                if current_item_is_task {
                    let indent = if list_depth > 1 {
                        "    ".repeat(list_depth - 1)
                    } else {
                        String::new()
                    };
                    let item_md = format!("{}{}", indent, current_item_text.trim());
                    blocks.push(MarkdownBlockData {
                        block_type: 7,
                        heading_level: 0,
                        text: clean_inline_formatting(current_item_text.trim()).into(),
                        styled_content: create_styled_text(&item_md),
                        code_lang: SharedString::default(),
                        code_content: SharedString::default(),
                        table_headers: empty_string_model(),
                        table_alignments: empty_int_model(),
                        table_col_fractions: empty_float_model(),
                        table_rows: empty_row_model(),
                        is_task_checked: current_item_checked,
                    });
                }
            }

            // --- Paragraphs & Inline Elements ---
            Event::Start(Tag::Paragraph) => {
                if blockquote_depth == 0 && list_depth == 0 {
                    state = State::Paragraph { start: range.start };
                }
            }
            Event::End(TagEnd::Paragraph) => {
                if blockquote_depth == 0 && list_depth == 0 {
                    if let State::Paragraph { start } = std::mem::replace(&mut state, State::None) {
                        if range.end > start {
                            let text = input[start..range.end].trim();
                            if !text.is_empty() {
                                blocks.push(MarkdownBlockData {
                                    block_type: 1,
                                    heading_level: 0,
                                    text: format_markdown_for_display(text).into(),
                                    styled_content: create_styled_text(text),
                                    code_lang: SharedString::default(),
                                    code_content: SharedString::default(),
                                    table_headers: empty_string_model(),
                                    table_alignments: empty_int_model(),
                                    table_col_fractions: empty_float_model(),
                                    table_rows: empty_row_model(),
                                    is_task_checked: false,
                                });
                            }
                        }
                    }
                }
            }

            // --- Math Blocks ($$ ... $$) ---
            Event::DisplayMath(math) => {
                if let State::Paragraph { ref mut start } = state {
                    if range.start > *start {
                        let text_before = input[*start..range.start].trim();
                        if !text_before.is_empty() {
                            blocks.push(MarkdownBlockData {
                                block_type: 1,
                                heading_level: 0,
                                text: format_markdown_for_display(text_before).into(),
                                styled_content: create_styled_text(text_before),
                                code_lang: SharedString::default(),
                                code_content: SharedString::default(),
                                table_headers: empty_string_model(),
                                table_alignments: empty_int_model(),
                                table_col_fractions: empty_float_model(),
                                table_rows: empty_row_model(),
                                is_task_checked: false,
                            });
                        }
                    }
                    *start = range.end;
                }

                let clean_math = convert_latex_math_to_unicode(&math);
                blocks.push(MarkdownBlockData {
                    block_type: 5,
                    heading_level: 0,
                    text: clean_math.trim().into(),
                    styled_content: StyledText::default(),
                    code_lang: SharedString::default(),
                    code_content: SharedString::default(),
                    table_headers: empty_string_model(),
                    table_alignments: empty_int_model(),
                    table_col_fractions: empty_float_model(),
                    table_rows: empty_row_model(),
                    is_task_checked: false,
                });
            }

            // --- Horizontal Rule (---) ---
            Event::Rule => {
                blocks.push(MarkdownBlockData {
                    block_type: 6,
                    heading_level: 0,
                    text: SharedString::default(),
                    styled_content: StyledText::default(),
                    code_lang: SharedString::default(),
                    code_content: SharedString::default(),
                    table_headers: empty_string_model(),
                    table_alignments: empty_int_model(),
                    table_col_fractions: empty_float_model(),
                    table_rows: empty_row_model(),
                    is_task_checked: false,
                });
            }

            // --- Inner Event Handling ---
            Event::Start(Tag::Strikethrough) => {
                if let State::Table { ref mut in_strikethrough, .. } = state {
                    *in_strikethrough = true;
                }
            }
            Event::End(TagEnd::Strikethrough) => {
                if let State::Table { ref mut in_strikethrough, .. } = state {
                    *in_strikethrough = false;
                }
            }
            Event::Text(t) => {
                match state {
                    State::Heading { ref mut text, .. } => {
                        text.push_str(&t);
                    }
                    State::CodeBlock { ref mut content, .. } => {
                        content.push_str(&t);
                    }
                    State::Table {
                        ref mut current_cell,
                        in_strikethrough,
                        ..
                    } => {
                        if in_strikethrough {
                            for c in t.chars() {
                                current_cell.push(c);
                                current_cell.push('\u{0336}');
                            }
                        } else {
                            current_cell.push_str(&t);
                        }
                    }
                    _ => {}
                }
                if in_item && current_item_is_task {
                    current_item_text.push_str(&t);
                }
            }
            Event::Code(c) => {
                match state {
                    State::Heading { ref mut text, .. } => {
                        text.push_str(&c);
                    }
                    State::Table {
                        ref mut current_cell,
                        ..
                    } => {
                        current_cell.push('`');
                        current_cell.push_str(&c);
                        current_cell.push('`');
                    }
                    _ => {}
                }
                if in_item && current_item_is_task {
                    current_item_text.push('`');
                    current_item_text.push_str(&c);
                    current_item_text.push('`');
                }
            }
            Event::InlineMath(m) => {
                let unicode_m = convert_latex_math_to_unicode(&m);
                match state {
                    State::Heading { ref mut text, .. } => {
                        text.push_str(&unicode_m);
                    }
                    State::Table {
                        ref mut current_cell,
                        ..
                    } => {
                        current_cell.push_str(&unicode_m);
                    }
                    _ => {}
                }
                if in_item && current_item_is_task {
                    current_item_text.push_str(&unicode_m);
                }
            }
            _ => {}
        }
    }

    // Flush any unclosed paragraph at EOF
    if let State::Paragraph { start } = state {
        if input.len() > start {
            let text = input[start..].trim();
            if !text.is_empty() {
                blocks.push(MarkdownBlockData {
                    block_type: 1,
                    heading_level: 0,
                    text: format_markdown_for_display(text).into(),
                    styled_content: create_styled_text(text),
                    code_lang: SharedString::default(),
                    code_content: SharedString::default(),
                    table_headers: empty_string_model(),
                    table_alignments: empty_int_model(),
                    table_col_fractions: empty_float_model(),
                    table_rows: empty_row_model(),
                    is_task_checked: false,
                });
            }
        }
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::Model;

    #[test]
    fn test_preprocess_headings() {
        let input = "Intro text\n# Heading 1\nParagraph text\n## Heading 2\n### Heading 3\n#### Heading 4";
        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains("**<u>Heading 1</u>**"));
        assert!(preprocessed.contains("**Heading 2**"));
        assert!(preprocessed.contains("***Heading 3***"));
        assert!(preprocessed.contains("**Heading 4**"));
        assert!(!preprocessed.contains("──────────────────────────────────────────────────"));
        assert!(preprocessed.contains("\u{00A0}\n\n**<u>Heading 1</u>**"));
        assert!(preprocessed.contains("\u{00A0}\n\n**Heading 2**"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_setext_headings() {
        let input = "Intro text\n\nMain Title\n==========\nSubtitle Section\n----------------";
        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains("**<u>Main Title</u>**"));
        assert!(preprocessed.contains("**Subtitle Section**"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_tables_rendering_without_gray_boxes() {
        let input = r#"| Column 1 | Column 2 | Column 3 |
| :--- | :---: | ---: |
| Left | Center | Right |
| Longer Data Item | Short | 42 |"#;

        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains('┌'));
        assert!(preprocessed.contains('┬'));
        assert!(preprocessed.contains('┐'));
        assert!(preprocessed.contains('├'));
        assert!(preprocessed.contains('┼'));
        assert!(preprocessed.contains('┤'));
        assert!(preprocessed.contains('│'));
        assert!(preprocessed.contains('└'));
        assert!(preprocessed.contains('┴'));
        assert!(preprocessed.contains('┘'));
        assert!(preprocessed.contains("Column 1"));
        assert!(preprocessed.contains("Longer Data Item"));

        assert!(!preprocessed.contains("`┌"));
        assert!(!preprocessed.contains("`│"));
        assert!(!preprocessed.contains("`└"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_tables_with_generics_and_symbols() {
        let input = "| Type | Condition |\n|---|---|\n| Vec<String> | x < 10 |\n| Option<T> | a > b |";
        let preprocessed = preprocess_markdown_for_slint(input);
        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
        assert!(preprocessed.contains("Vec"));
    }

    #[test]
    fn test_tables_alignment_and_padding() {
        let sep = "| :--- | :---: | ---: |";
        let aligns = parse_column_alignments(sep);
        assert_eq!(aligns, vec![ColumnAlign::Left, ColumnAlign::Center, ColumnAlign::Right]);

        let formatted = format_table_as_unicode_box(
            "| Item | Qty | Price |",
            "| --- | :---: | ---: |",
            &["| Apple | 10 | $1.50 |", "| Banana | 5 | $0.75 |"],
        );
        assert!(formatted.contains('┌'));
        assert!(formatted.contains("Apple"));
        assert!(formatted.contains("$1.50"));
        assert!(!formatted.contains('`'));
    }

    #[test]
    fn test_paragraphs_and_newlines_not_squished() {
        let input = "Line 1\nLine 2\n\nParagraph 2 line 1\nParagraph 2 line 2";
        let preprocessed = preprocess_markdown_for_slint(input);

        assert!(preprocessed.contains("Line 1  \n"));
        assert!(preprocessed.contains("Line 2  \n"));
        assert!(preprocessed.contains("Paragraph 2 line 1  \n"));
        assert!(preprocessed.contains("\u{00A0}\n\n"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_preprocess_code_block_as_framed_block() {
        let input = "```rust\nfn main() {\n    let v: Vec<String> = vec![];\n    if x < 10 { println!(\"hi\"); }\n}\n```";
        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains("┌── rust"));
        assert!(preprocessed.contains("│  fn main() {"));
        assert!(preprocessed.contains("Vec\\<String\\>"));
        assert!(preprocessed.contains("x \\< 10"));
        assert!(preprocessed.contains("└──────────────────"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_element_vertical_spacing_before_all_blocks() {
        let input = "Some intro text\n# Heading\nText\n- List item\nText\n```python\nx = 1\n```\nText\n| A | B |\n|---|---|\n| 1 | 2 |";
        let preprocessed = preprocess_markdown_for_slint(input);

        assert!(preprocessed.contains("\u{00A0}\n\n**<u>Heading</u>**"));
        assert!(preprocessed.contains("\u{00A0}\n\n- List item"));
        assert!(preprocessed.contains("\u{00A0}\n\n┌── python"));
        assert!(preprocessed.contains("\u{00A0}\n\n┌──"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_math_mode_inline_and_block() {
        let inline_doc = "Equation: $x^2 + y^2 = z^2$ and $\\alpha + \\beta = \\gamma$.";
        let preprocessed_inline = preprocess_markdown_for_slint(inline_doc);
        assert!(preprocessed_inline.contains("*x² + y² = z²*"));
        assert!(preprocessed_inline.contains("*α + β = γ*"));

        let styled_inline = render_markdown_styled(inline_doc);
        assert_ne!(styled_inline, slint::StyledText::default());

        let block_doc = "$$\n\\sum_{i=1}^n x_i = X\n$$";
        let preprocessed_block = preprocess_markdown_for_slint(block_doc);
        assert!(preprocessed_block.contains("∑ᵢ₌₁ⁿ xᵢ = X"));

        let styled_block = render_markdown_styled(block_doc);
        assert_ne!(styled_block, slint::StyledText::default());
    }

    #[test]
    fn test_math_latex_symbols() {
        let latex = "\\int_0^\\infty e^{-x} dx = 1 \\land \\forall x \\in \\mathbb{R}, x \\le x + 1";
        let unicode = convert_latex_math_to_unicode(latex);
        assert!(unicode.contains('∫'));
        assert!(unicode.contains('∞'));
        assert!(unicode.contains('⁻'));
        assert!(unicode.contains('∧'));
        assert!(unicode.contains('∀'));
        assert!(unicode.contains('∈'));
        assert!(unicode.contains('ℝ'));
        assert!(unicode.contains('≤'));
    }

    #[test]
    fn test_preprocess_blockquotes_and_hr() {
        let input = "Intro\n> This is a quote\n---\nAnother line";
        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains("│ *This is a quote*"));
        assert!(preprocessed.contains("──────────────────────────────────────────────────"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_preprocess_images_and_tasks() {
        let input = "Check ![Logo](https://example.com/logo.png)\n- [ ] Todo item\n- [x] Done item";
        let preprocessed = preprocess_markdown_for_slint(input);
        assert!(preprocessed.contains("[🖼️ Logo](https://example.com/logo.png)"));
        assert!(preprocessed.contains("- ☐ Todo item"));
        assert!(preprocessed.contains("- ☑ Done item"));

        let styled = render_markdown_styled(input);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_empty_and_plain_markdown() {
        let empty_styled = render_markdown_styled("");
        assert_eq!(empty_styled, slint::StyledText::default());

        let plain = "Just plain text without markdown.";
        let plain_styled = render_markdown_styled(plain);
        assert_ne!(plain_styled, slint::StyledText::default());
    }

    #[test]
    fn test_complex_markdown_document() {
        let doc = r#"# NoteVault Project

A secure, offline-first notes application with end-to-end encryption.

## Features
- [x] AES-256-GCM encryption
- [ ] Markdown preview mode
- 1. First ordered item
- 2. Second ordered item

| Feature | Status | Priority |
| :--- | :---: | ---: |
| Encryption | Done | High |
| Search | Done | Medium |
| Markdown Tables | In Progress | High |

### Math
The circle formula is $x^2 + y^2 = r^2$.
Euler's identity: $e^{i\pi} + 1 = 0$.

$$
\int_{-\infty}^\infty e^{-x^2} dx = \sqrt{\pi}
$$

> Simplicity is prerequisite for reliability.
> — Edsger W. Dijkstra

```rust
fn authenticate<T>(vault: &Vault) -> Result<T, Error> {
    if x < 10 {
        return Ok(vault);
    }
}
```

---

Link: [GitHub](https://github.com)
"#;
        let preprocessed = preprocess_markdown_for_slint(doc);
        assert!(preprocessed.contains("**<u>NoteVault Project</u>**"));
        assert!(preprocessed.contains("**Features**"));
        assert!(preprocessed.contains('┌'));
        assert!(preprocessed.contains("Encryption"));
        assert!(preprocessed.contains("*x² + y² = r²*"));
        assert!(preprocessed.contains('∫'));
        assert!(preprocessed.contains("Simplicity is prerequisite"));
        assert!(preprocessed.contains("┌── rust"));
        assert!(preprocessed.contains("authenticate\\<T\\>"));

        let styled = render_markdown_styled(doc);
        assert_ne!(styled, slint::StyledText::default());
    }

    #[test]
    fn test_user_exact_document() {
        let doc = r#"# Markdown Rendering Test Document

This document contains a variety of common Markdown elements to help test your rendering engine's capabilities. 

## 1. Text Formatting

This is a standard paragraph demonstrating basic text formatting. You can make text **bold** using double asterisks or __double underscores__. You can make text *italic* using single asterisks or _single underscores_. For maximum emphasis, you can use ***bold and italic*** together. You can also use ~~strikethrough~~ for deleted text.

## 2. Headings

### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

## 3. Lists

### Unordered List
* Apples
* Oranges
  * Mandarin
  * Clementine
* Bananas

### Ordered List
1. First item
2. Second item
   1. Sub-item A
   2. Sub-item B
3. Third item

### Task List
- [x] Write test document
- [ ] Test rendering engine
- [ ] Fix parsing bugs

## 4. Links and Images

Here is an [inline link to Google](https://www.google.com), and here is a reference link to [Wikipedia][wiki].

[wiki]: https://www.wikipedia.org/

Here is an example of an image:
![Placeholder Image](https://via.placeholder.com/300x100.png?text=Test+Image "Optional Title")

## 5. Blockquotes

> This is a blockquote.
> It can span multiple lines.
>
> > It can also be nested.
> > Like this.

## 6. Code

You can include `inline code` within a paragraph by wrapping it in backticks. 

For longer blocks of code, use fenced code blocks, optionally specifying the language for syntax highlighting:

```javascript
// A simple JavaScript function
function greet(name) {
  console.log(`Hello, ${name}!`);
  return true;
}

greet('World');
```

## 7. Tables

| Syntax      | Description | Test Text     |
| :---        |    :----:   |          ---: |
| Header      | Title       | Here's this   |
| Paragraph   | Text        | And more      |
| Strikethrough | ~~Text~~  | ~~Deleted~~   |

## 8. Mathematical Notation

Your engine might support LaTeX-style math rendering. 

Here is an inline equation: The area of a circle is $A = \pi r^2$.

Here is a block equation:
$$
f(x) = \int_{-\infty}^\infty \hat f(\xi)\,e^{2 \pi i \xi x} \,d\xi
$$

## 9. Horizontal Rule

Below is a horizontal rule:

---
End of test document.
"#;
        let preprocessed = preprocess_markdown_for_slint(doc);
        println!("=== PREPROCESSED ===\n{}\n====================", preprocessed);
        let styled_result = slint::StyledText::from_markdown(&preprocessed);
        println!("=== STYLED RESULT ===\n{:?}\n====================", styled_result);
        assert!(styled_result.is_ok(), "Failed to parse markdown: {:?}", styled_result.err());
    }

    #[test]
    fn test_cmark_events_on_user_doc() {
        let doc = r#"# Markdown Rendering Test Document

This document contains a variety of common Markdown elements to help test your rendering engine's capabilities. 

## 1. Text Formatting

This is a standard paragraph demonstrating basic text formatting. You can make text **bold** using double asterisks or __double underscores__. You can make text *italic* using single asterisks or _single underscores_. For maximum emphasis, you can use ***bold and italic*** together. You can also use ~~strikethrough~~ for deleted text.

## 2. Headings

### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

## 3. Lists

### Unordered List
* Apples
* Oranges
  * Mandarin
  * Clementine
* Bananas

### Ordered List
1. First item
2. Second item
   1. Sub-item A
   2. Sub-item B
3. Third item

### Task List
- [x] Write test document
- [ ] Test render
- [ ] Fix bugs
  - [x] Minor bug
  - [ ] Major bug

## 4. Links and Images

Here is an [inline link to Google](https://www.google.com), and here is a reference link to [Wikipedia][wiki].

[wiki]: https://www.wikipedia.org/

Here is an example of an image:
![Placeholder Image](https://via.placeholder.com/300x100.png?text=Test+Image "Optional Title")

## 5. Blockquotes

> This is a blockquote.
> It can span multiple lines.
>
> > It can also be nested.
> > Like this.

## 6. Code

You can include `inline code` within a paragraph by wrapping it in backticks. 

For longer blocks of code, use fenced code blocks, optionally specifying the language for syntax highlighting:

```javascript
// A simple JavaScript function
function greet(name) {
  console.log(`Hello, ${name}!`);
  return true;
}

greet('World');
```

## 7. Tables

| Syntax      | Description | Test Text     |
| :---        |    :----:   |          ---: |
| Header      | Title       | Here's this   |
| Paragraph   | Text        | And more      |
| Strikethrough | ~~Text~~  | ~~Deleted~~   |

## 8. Mathematical Notation

Your engine might support LaTeX-style math rendering. 

Here is an inline equation: The area of a circle is $A = \pi r^2$.

Here is a block equation:
$$
f(x) = \int_{-\infty}^\infty \hat f(\xi)\,e^{2 \pi i \xi x} \,d\xi
$$

## 9. Horizontal Rule

Below is a horizontal rule:

---
End of test document.
"#;
        let mut options = pulldown_cmark::Options::empty();
        options.insert(pulldown_cmark::Options::ENABLE_TABLES);
        options.insert(pulldown_cmark::Options::ENABLE_TASKLISTS);
        options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
        options.insert(pulldown_cmark::Options::ENABLE_MATH);
        let parser = pulldown_cmark::Parser::new_ext(doc, options);
        for (event, range) in parser.into_offset_iter() {
            println!("{:?} => {:?}", event, &doc[range.clone()]);
        }
    }

    #[test]
    fn test_parse_markdown_into_blocks_on_user_doc() {
        let doc = r#"# Markdown Rendering Test Document

This document contains a variety of common Markdown elements to help test your rendering engine's capabilities. 

## 1. Text Formatting

This is a standard paragraph demonstrating basic text formatting. You can make text **bold** using double asterisks or __double underscores__. You can make text *italic* using single asterisks or _single underscores_. For maximum emphasis, you can use ***bold and italic*** together. You can also use ~~strikethrough~~ for deleted text.

## 2. Headings

### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

## 3. Lists

### Unordered List
* Apples
* Oranges
  * Mandarin
  * Clementine
* Bananas

### Ordered List
1. First item
2. Second item
   1. Sub-item A
   2. Sub-item B
3. Third item

### Task List
- [x] Write test document
- [ ] Test render
- [ ] Fix bugs
  - [x] Minor bug
  - [ ] Major bug

## 4. Links and Images

Here is an [inline link to Google](https://www.google.com), and here is a reference link to [Wikipedia][wiki].

[wiki]: https://www.wikipedia.org/

Here is an example of an image:
![Placeholder Image](https://via.placeholder.com/300x100.png?text=Test+Image "Optional Title")

## 5. Blockquotes

> This is a blockquote.
> It can span multiple lines.
>
> > It can also be nested.
> > Like this.

## 6. Code

You can include `inline code` within a paragraph by wrapping it in backticks. 

For longer blocks of code, use fenced code blocks, optionally specifying the language for syntax highlighting:

```javascript
// A simple JavaScript function
function greet(name) {
  console.log(`Hello, ${name}!`);
  return true;
}

greet('World');
```

## 7. Tables

| Syntax      | Description | Test Text     |
| :---        |    :----:   |          ---: |
| Header      | Title       | Here's this   |
| Paragraph   | Text        | And more      |
| Strikethrough | ~~Text~~  | ~~Deleted~~   |

## 8. Mathematical Notation

Your engine might support LaTeX-style math rendering. 

Here is an inline equation: The area of a circle is $A = \pi r^2$.

Here is a block equation:
$$
f(x) = \int_{-\infty}^\infty \hat f(\xi)\,e^{2 \pi i \xi x} \,d\xi
$$

## 9. Horizontal Rule

Below is a horizontal rule:

---
End of test document.
"#;
        let blocks = parse_markdown_into_blocks(doc);
        println!("=== PARSED BLOCKS: count = {} ===", blocks.len());
        for (idx, b) in blocks.iter().enumerate() {
            println!(
                "Block {}: type={}, h_lvl={}, text={:?}, lang={:?}, code_len={}, headers_cnt={}, rows_cnt={}, task_chk={}",
                idx,
                b.block_type,
                b.heading_level,
                b.text,
                b.code_lang,
                b.code_content.len(),
                b.table_headers.row_count(),
                b.table_rows.row_count(),
                b.is_task_checked
            );
        }

        // 1. Heading verification
        assert!(blocks.iter().any(|b| b.block_type == 0 && b.heading_level == 1 && b.text.contains("Markdown Rendering Test Document")));
        assert!(blocks.iter().any(|b| b.block_type == 0 && b.heading_level == 2 && b.text.contains("7. Tables")));

        // 2. Code Block verification
        let code_block = blocks.iter().find(|b| b.block_type == 2).expect("Must find a code block");
        assert_eq!(code_block.code_lang.as_str(), "javascript");
        assert!(code_block.code_content.contains("function greet(name)"));

        // 3. Table verification
        let table_block = blocks.iter().find(|b| b.block_type == 3).expect("Must find a table block");
        assert_eq!(table_block.table_headers.row_count(), 3);
        assert_eq!(table_block.table_rows.row_count(), 3);
        assert_eq!(table_block.table_headers.row_data(0).unwrap().as_str(), "Syntax");
        assert_eq!(table_block.table_headers.row_data(1).unwrap().as_str(), "Description");
        assert_eq!(table_block.table_headers.row_data(2).unwrap().as_str(), "Test Text");
        // Column alignment verification: Left (0), Center (1), Right (2)
        assert_eq!(table_block.table_alignments.row_count(), 3);
        assert_eq!(table_block.table_alignments.row_data(0).unwrap(), 0); // :---
        assert_eq!(table_block.table_alignments.row_data(1).unwrap(), 1); // :---:
        assert_eq!(table_block.table_alignments.row_data(2).unwrap(), 2); // ---:
        // Ensure all rows have exactly 3 cells matching the header column count
        for r in 0..table_block.table_rows.row_count() {
            let row = table_block.table_rows.row_data(r).unwrap();
            assert_eq!(row.cells.row_count(), 3, "Row {} must have exactly 3 cells for aligned columns", r);
        }

        // 4. Blockquote verification
        assert!(blocks.iter().any(|b| b.block_type == 4));

        // 5. Math Block verification
        let math_block = blocks.iter().find(|b| b.block_type == 5).expect("Must find a math block");
        assert!(math_block.text.contains("∫"), "Math block must contain integral sign: {}", math_block.text);

        // 6. Horizontal Rule verification
        assert!(blocks.iter().any(|b| b.block_type == 6));

        // 7. Task List verification
        assert!(blocks.iter().any(|b| b.block_type == 7 && b.is_task_checked));
        assert!(blocks.iter().any(|b| b.block_type == 7 && !b.is_task_checked));
    }

    #[test]
    fn test_table_row_padding_for_column_alignment() {
        let md = r#"
| Col A | Col B | Col C |
| :--- | :---: | ---: |
| Single cell |
| Two | cells |
| Exact | three | cells |
| Extra | fourth | cell | dropped |
"#;
        let blocks = parse_markdown_into_blocks(md);
        let table = blocks.iter().find(|b| b.block_type == 3).expect("Table must be found");
        assert_eq!(table.table_headers.row_count(), 3);
        assert_eq!(table.table_alignments.row_count(), 3);
        assert_eq!(table.table_alignments.row_data(0).unwrap(), 0);
        assert_eq!(table.table_alignments.row_data(1).unwrap(), 1);
        assert_eq!(table.table_alignments.row_data(2).unwrap(), 2);

        // All rows must have exactly 3 cells so columns align perfectly
        assert_eq!(table.table_rows.row_count(), 4);
        for r in 0..table.table_rows.row_count() {
            let row = table.table_rows.row_data(r).unwrap();
            assert_eq!(row.cells.row_count(), 3, "Row {} must have exactly 3 cells", r);
        }
        // Check row 0 padding
        let row0 = table.table_rows.row_data(0).unwrap();
        assert_eq!(row0.cells.row_data(0).unwrap().as_str(), "Single cell");
        assert_eq!(row0.cells.row_data(1).unwrap().as_str(), "");
        assert_eq!(row0.cells.row_data(2).unwrap().as_str(), "");
    }
}
