//! Secret-file detection and value masking.

use crate::pathx::{basename, is_file, is_link, py_is_space, py_rstrip, py_strip, realpath};
use regex::Regex;
use std::fs;
use std::sync::LazyLock;

pub const MASK: &str = "****";
pub const MAX_LINES: usize = 500;
const TEMPLATE_SUFFIXES: [&str; 5] = [".example", ".sample", ".template", ".dist", ".tpl"];

// `\s` in Python also covers the ASCII separators 0x1c-0x1f.
static PROPS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([\s\x1c-\x1f]*)((?:\\.|[^\s\x1c-\x1f=:\\])+)([\s\x1c-\x1f]*[=:][\s\x1c-\x1f]*|[\s\x1c-\x1f]+)(.*)$").unwrap()
});
static ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([\s\x1c-\x1f]*(?:export[\s\x1c-\x1f]+)?[A-Za-z_][A-Za-z0-9_.\-]*[\s\x1c-\x1f]*=[\s\x1c-\x1f]*)(.*)$").unwrap()
});
static ENV_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[\s\x1c-\x1f]*(?:export[\s\x1c-\x1f]+)?[A-Za-z_][A-Za-z0-9_.\-]*[\s\x1c-\x1f]*=[\s\x1c-\x1f]*(.*)$").unwrap()
});

pub fn is_target(path: &str) -> bool {
    let name = basename(path.trim_end_matches('/'));
    if name.is_empty() {
        return false;
    }
    let low = name.to_lowercase();
    if TEMPLATE_SUFFIXES.iter().any(|s| low.ends_with(s)) {
        return false;
    }
    low == ".env"
        || low.starts_with(".env.")
        || low.ends_with(".env")
        || low.ends_with(".properties")
}

/// A regular file that is, or is a symlink to, a secret-bearing file.
pub fn is_secret_file(path: &str) -> bool {
    if !is_file(path) {
        return false;
    }
    is_target(path) || (is_link(path) && is_target(&realpath(path)))
}

fn mask_properties_line(line: &str) -> String {
    match PROPS_RE.captures(line) {
        None => line.to_string(),
        Some(c) => format!(
            "{}{}{}{}",
            &c[1],
            &c[2],
            &c[3],
            if c[4].is_empty() { "" } else { MASK }
        ),
    }
}

fn mask_env_line(line: &str) -> String {
    match ENV_RE.captures(line) {
        None => line.to_string(),
        Some(c) => format!(
            "{}{}",
            &c[1],
            if py_strip(&c[2]).is_empty() { "" } else { MASK }
        ),
    }
}

fn has_closing_quote(text: &str, quote: char) -> bool {
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return true;
        }
    }
    false
}

/// Python's `str.splitlines()`: splits on every Unicode line boundary, not just `\n`.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        lines.push(&text[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r'
            && let Some(&(j, '\n')) = chars.peek()
        {
            chars.next();
            end = j + 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

pub fn mask_text(path: &str, text: &str) -> String {
    let is_props = path.to_lowercase().ends_with(".properties");
    let comment_chars: &[char] = if is_props { &['#', '!'] } else { &['#'] };
    let mut out: Vec<String> = Vec::new();
    let mut continued = false; // .properties value continued with a trailing backslash
    let mut env_quote: Option<char> = None;
    for line in splitlines(text) {
        let stripped = py_strip(line);
        if let Some(q) = env_quote {
            out.push(if stripped.is_empty() {
                line.to_string()
            } else {
                MASK.to_string()
            });
            if has_closing_quote(line, q) {
                env_quote = None;
            }
            continue;
        }
        if continued {
            out.push(if stripped.is_empty() {
                line.to_string()
            } else {
                MASK.to_string()
            });
            continued = py_rstrip(line).ends_with('\\');
            continue;
        }
        if stripped.is_empty() || stripped.starts_with(comment_chars) {
            out.push(line.to_string());
            continue;
        }
        out.push(if is_props {
            mask_properties_line(line)
        } else {
            mask_env_line(line)
        });
        if is_props {
            continued = py_rstrip(line).ends_with('\\');
        } else {
            let value = ENV_VALUE_RE
                .captures(line)
                .map(|c| c[1].trim_start_matches(py_is_space).to_string())
                .unwrap_or_default();
            if let Some(first) = value.chars().next()
                && (first == '"' || first == '\'')
                && !has_closing_quote(&value[first.len_utf8()..], first)
            {
                env_quote = Some(first);
            }
        }
    }
    out.join("\n")
}

pub fn render(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let masked_text = mask_text(path, &text);
    let masked: Vec<&str> = masked_text.split('\n').collect();
    let mut lines: Vec<String> = masked.iter().map(|s| s.to_string()).collect();
    if lines.len() > MAX_LINES {
        let extra = lines.len() - MAX_LINES;
        lines.truncate(MAX_LINES);
        lines.push(format!("... ({extra} more lines truncated)"));
    }
    Some(
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:>6}\t{}", i + 1, l))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_names() {
        for yes in [
            ".env",
            "a.env",
            ".env.local",
            "App.PROPERTIES",
            "dir/.env",
            "x/.ENV/",
        ] {
            assert!(is_target(yes), "{yes}");
        }
        for no in [
            ".env.example",
            "a.properties.template",
            "env",
            "config.txt",
            "",
            "environment",
            ".environment",
        ] {
            assert!(!is_target(no), "{no}");
        }
    }

    #[test]
    fn masks_env_values_and_keeps_structure() {
        let masked = mask_text(
            ".env",
            "# c\nTOKEN=FAKE\nEMPTY=\nexport HOST=https://x\nQ=\"a\n  b\"\nNEXT=3",
        );
        assert_eq!(
            masked,
            "# c\nTOKEN=****\nEMPTY=\nexport HOST=****\nQ=****\n****\nNEXT=****"
        );
    }

    #[test]
    fn masks_properties_with_continuations() {
        let masked = mask_text(
            "app.properties",
            "# c\n! c2\npassword: FAKE\nuser FAKE2\ncont=A\\\n  B\nkey=",
        );
        assert_eq!(
            masked,
            "# c\n! c2\npassword: ****\nuser ****\ncont=****\n****\nkey="
        );
    }

    #[test]
    fn escaped_quote_does_not_close_value() {
        let masked = mask_text(
            ".env",
            "TOKEN=\"FAKE_1\\\"FAKE_2\"\n# kept comment\nNEXT=FAKE_3",
        );
        assert_eq!(masked, "TOKEN=****\n# kept comment\nNEXT=****");
    }

    #[test]
    fn unicode_line_breaks_cannot_hide_values() {
        let masked = mask_text(".env", "# note\u{2028}TOKEN=FAKE\u{85}OTHER=FAKE2");
        assert!(!masked.contains("FAKE"), "{masked}");
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\r\nb\rc\nd"), ["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n"), ["a"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("a\n\nb"), ["a", "", "b"]);
    }
}
