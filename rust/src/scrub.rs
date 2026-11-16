//! `<search> | mask-secrets --scrub`: mask the content of grep-style output lines that start with the path of a
//! secret file (`path:12:KEY=value`, `path-13-KEY=value`, `path\0KEY=value`).
//!
//! grep, ag and ack have no equivalent of rg's `--pre`, so their output is filtered instead. It only works for output
//! shapes it understands; the rewrite is limited to a list of known-benign flags (see `bash::search_args_ok`).

use crate::mask::{ENV_RE, MASK, PROPS_RE, is_target, mask_env_line, mask_lines, mask_properties_line, splitlines};
use crate::pathx::py_strip;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::sync::LazyLock;

/// Like grep: exit 1 when nothing came out, so `grep ... || echo none` keeps working.
pub const NO_OUTPUT_STATUS: i32 = 1;

static NUMBERS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[0-9]+[:\-]){1,3}").unwrap());

/// Heuristic for a line out of a secret file when the file itself cannot be consulted.
fn scrub_body(path: &str, body: &str) -> String {
    let props = path.to_lowercase().ends_with(".properties");
    let stripped = py_strip(body);
    let comment: &[char] = if props { &['#', '!'] } else { &['#'] };
    if stripped.is_empty() || stripped.starts_with(comment) {
        return body.to_string();
    }
    let re = if props { &*PROPS_RE } else { &*ENV_RE };
    if !re.is_match(body) {
        return MASK.to_string(); // a continuation line, a quoted multi-line value, a fragment: it is all value
    }
    if props {
        mask_properties_line(body)
    } else {
        mask_env_line(body)
    }
}

#[derive(Default)]
pub struct Scrubber {
    files: HashMap<String, Option<(Vec<String>, Vec<String>)>>,
}

impl Scrubber {
    /// (raw lines, masked lines) of a secret file. Knowing the whole file tells a continuation line (`  part2 part3`)
    /// from a new `key value` line, which one line of grep output cannot.
    fn file_lines(&mut self, path: &str) -> Option<&(Vec<String>, Vec<String>)> {
        self.files
            .entry(path.to_string())
            .or_insert_with(|| {
                let bytes = std::fs::read(path).ok()?;
                let text = String::from_utf8_lossy(&bytes);
                let raw = splitlines(&text).into_iter().map(String::from).collect();
                Some((raw, mask_lines(path, &text)))
            })
            .as_ref()
    }

    fn content(&mut self, path: &str, number: Option<usize>, body: &str) -> String {
        if let Some((raw, masked)) = self.file_lines(path) {
            if let Some(n) = number
                && (1..=raw.len()).contains(&n)
                && raw[n - 1] == body
            {
                return masked[n - 1].clone();
            }
            // no line number, or it does not fit the file: find the line by its text
            let same: HashSet<&String> = raw
                .iter()
                .zip(masked.iter())
                .filter(|(r, _)| r.as_str() == body)
                .map(|(_, m)| m)
                .collect();
            if !same.is_empty() {
                return if same.len() == 1 {
                    (*same.iter().next().unwrap()).clone()
                } else {
                    MASK.to_string()
                };
            }
        }
        scrub_body(path, body)
    }

    /// Mask the content of one line of grep-style output when it starts with the path of a secret file.
    pub fn scrub_line(&mut self, line: &str, counts: bool) -> String {
        let text = line.trim_end_matches(['\r', '\n']);
        let ending = &line[text.len()..];
        for (i, ch) in text.char_indices() {
            if !matches!(ch, ':' | '-' | '\0') {
                continue;
            }
            let path = &text[..i];
            if is_target(path) {
                let cut = i + ch.len_utf8();
                let rest = &text[cut..];
                let head = NUMBERS_RE.find(rest).map_or("", |m| m.as_str());
                let body = &rest[head.len()..];
                let body = if counts
                    && head.is_empty()
                    && !body.is_empty()
                    && body.bytes().all(|b| b.is_ascii_digit())
                {
                    body.to_string()
                } else {
                    // a line number too large for usize cannot be in the file: usize::MAX is out of range
                    let number = (!head.is_empty()).then(|| {
                        head.split(|c: char| !c.is_ascii_digit())
                            .next()
                            .and_then(|d| d.parse::<usize>().ok())
                            .unwrap_or(usize::MAX)
                    });
                    self.content(path, number, body)
                };
                return format!("{}{}{}{}", &text[..cut], head, body, ending);
            }
            if ch != '-' {
                break; // a `:` or NUL ends the path part: whatever follows is not the file name any more
            }
        }
        line.to_string()
    }

    fn scrub_bytes(&mut self, raw: &[u8], counts: bool) -> Vec<u8> {
        match std::str::from_utf8(raw) {
            Ok(s) => self.scrub_line(s, counts).into_bytes(),
            Err(_) => {
                let lossy = String::from_utf8_lossy(raw);
                let out = self.scrub_line(&lossy, counts);
                if out == lossy { raw.to_vec() } else { out.into_bytes() }
            }
        }
    }
}

/// stdin -> stdout. Returns the exit status.
pub fn run(counts: bool) -> i32 {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let (mut seen, mut scrubber, mut buf) = (false, Scrubber::default(), Vec::new());
    loop {
        buf.clear();
        match input.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                seen = true;
                if out.write_all(&scrubber.scrub_bytes(&buf, counts)).is_err() {
                    return 0; // `| head` stopped reading: not an error
                }
            }
        }
    }
    let _ = out.flush();
    if seen { 0 } else { NO_OUTPUT_STATUS }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(l: &str, counts: bool) -> String {
        Scrubber::default().scrub_line(l, counts)
    }

    #[test]
    fn masks_lines_that_start_with_a_secret_path() {
        for (input, counts, want) in [
            ("./.env:1:DB_PASSWORD=hunter2\n", false, "./.env:1:DB_PASSWORD=****\n"),
            ("./a/my-app.properties:7:db.password = s3cr3t\n", false, "./a/my-app.properties:7:db.password = ****\n"),
            ("./a/my-app.properties-8-continued value\n", false, "./a/my-app.properties-8-continued ****\n"),
            ("./.ENV:3:export TOKEN='abc def'\n", false, "./.ENV:3:export TOKEN=****\n"),
            ("APP.PROPERTIES:key hello world\n", false, "APP.PROPERTIES:key ****\n"),
            ("./x.env:5:12:K=v\n", false, "./x.env:5:12:K=****\n"),
            ("./x.env\0K=v\n", false, "./x.env\0K=****\n"),
            ("./x.env:3\n", true, "./x.env:3\n"),
            ("./x.env:3\n", false, "./x.env:****\n"),
            ("./x.env:# a comment\n", false, "./x.env:# a comment\n"),
            ("./x.env:EMPTY=\n", false, "./x.env:EMPTY=\n"),
            ("./.env.example:1:TOKEN=example\n", false, "./.env.example:1:TOKEN=example\n"),
            ("src/Main.java:12:  // see app.properties: x=y\n", false, "src/Main.java:12:  // see app.properties: x=y\n"),
            ("./.env\n", false, "./.env\n"),
            ("--\n", false, "--\n"),
            ("./.env:1:hunter2\r\n", false, "./.env:1:****\r\n"),
            ("Binary file ./a.env matches\n", false, "Binary file ./a.env matches\n"),
            ("./a.env:1:K=v:with:colons\n", false, "./a.env:1:K=****\n"),
            ("./a.env:99999999999999999999999:K=v\n", false, "./a.env:99999999999999999999999:K=****\n"),
        ] {
            assert_eq!(line(input, counts), want, "{input:?}");
        }
    }

    #[test]
    fn reads_the_file_to_recognise_continuation_lines() {
        let dir = std::env::temp_dir().join(format!("ms-scrub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.properties");
        std::fs::write(&file, "a=1\nlong=FAKE_A\\\n  FAKE_B FAKE_C\nlast=end\n").unwrap();
        let p = file.to_string_lossy();
        let mut s = Scrubber::default();
        assert_eq!(s.scrub_line(&format!("{p}:3:  FAKE_B FAKE_C\n"), false), format!("{p}:3:****\n"));
        assert_eq!(s.scrub_line(&format!("{p}:  FAKE_B FAKE_C\n"), false), format!("{p}:****\n"));
        assert_eq!(s.scrub_line(&format!("{p}-3-  FAKE_B FAKE_C\n"), false), format!("{p}-3-****\n"));
        assert_eq!(s.scrub_line(&format!("{p}:4:last=end\n"), false), format!("{p}:4:last=****\n"));
        // a line number that does not fit the text: the line is found by its text
        assert_eq!(s.scrub_line(&format!("{p}:1:  FAKE_B FAKE_C\n"), false), format!("{p}:1:****\n"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
