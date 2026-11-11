//! Small ports of the Python `os.path` / `fnmatch` / `glob` behaviour the policy relies on.

use regex::Regex;
use std::env;
use std::fs;
use std::sync::LazyLock;

/// Python's `str.isspace`: Unicode whitespace plus the ASCII separators 0x1c-0x1f.
pub fn py_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_is_space)
}

pub fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(py_is_space)
}

fn is_sep(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

pub fn basename(p: &str) -> &str {
    p.rfind(is_sep).map_or(p, |i| &p[i + 1..])
}

pub fn is_abs(p: &str) -> bool {
    std::path::Path::new(p).is_absolute()
}

pub fn join(a: &str, b: &str) -> String {
    if is_abs(b) {
        b.to_string()
    } else if a.is_empty() || a.ends_with(is_sep) {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `posixpath.normpath`: purely lexical.
pub fn normpath(path: &str) -> String {
    let owned;
    let path = if cfg!(windows) {
        owned = path.replace('\\', "/");
        owned.as_str()
    } else {
        path
    };
    if path.is_empty() {
        return ".".into();
    }
    let mut initial = if path.starts_with('/') { 1 } else { 0 };
    if path.starts_with("//") && !path.starts_with("///") {
        initial = 2;
    }
    let mut out: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        let keeps = comp != ".." || (initial == 0 && out.is_empty()) || out.last() == Some(&"..");
        if keeps {
            out.push(comp);
        } else {
            out.pop();
        }
    }
    let joined = out.join("/");
    let result = format!("{}{}", "/".repeat(initial), joined);
    if result.is_empty() {
        ".".into()
    } else {
        result
    }
}

#[cfg(unix)]
fn passwd_home(user: &str) -> Option<String> {
    let text = fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() > 5 && f[0] == user).then(|| f[5].to_string())
    })
}

#[cfg(not(unix))]
fn passwd_home(_user: &str) -> Option<String> {
    None
}

pub fn expanduser(p: &str) -> String {
    if !p.starts_with('~') {
        return p.to_string();
    }
    let i = p[1..].find(is_sep).map_or(p.len(), |k| k + 1);
    let user = &p[1..i];
    let home = if user.is_empty() {
        env::var("HOME")
            .ok()
            .or_else(|| env::var("USERPROFILE").ok())
    } else {
        passwd_home(user)
    };
    match home {
        Some(h) => {
            let r = format!("{}{}", h.trim_end_matches('/'), &p[i..]);
            if r.is_empty() { "/".into() } else { r }
        }
        None => p.to_string(),
    }
}

static VAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$([A-Za-z0-9_]+|\{[^}]*\})").unwrap());

/// `os.path.expandvars`: unknown variables are left untouched.
pub fn expandvars(p: &str) -> String {
    if !p.contains('$') {
        return p.to_string();
    }
    VAR_RE
        .replace_all(p, |caps: &regex::Captures| {
            let raw = &caps[1];
            let name = raw
                .strip_prefix('{')
                .and_then(|n| n.strip_suffix('}'))
                .unwrap_or(raw);
            match env::var_os(name) {
                Some(v) => v.to_string_lossy().into_owned(),
                None => caps[0].to_string(),
            }
        })
        .into_owned()
}

pub fn resolve(path: &str, cwd: &str) -> String {
    let p = expanduser(path);
    if is_abs(&p) { p } else { join(cwd, &p) }
}

pub fn is_file(p: &str) -> bool {
    fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

pub fn is_dir(p: &str) -> bool {
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

pub fn is_link(p: &str) -> bool {
    fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

pub fn lexists(p: &str) -> bool {
    fs::symlink_metadata(p).is_ok()
}

pub fn realpath(p: &str) -> String {
    fs::canonicalize(p)
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string())
}

/// `os.path.relpath` for already-absolute paths.
pub fn relpath(path: &str, start: &str) -> String {
    let (p, s) = (normpath(path), normpath(start));
    let pp: Vec<&str> = p.split('/').filter(|x| !x.is_empty()).collect();
    let sp: Vec<&str> = s.split('/').filter(|x| !x.is_empty()).collect();
    let common = pp.iter().zip(&sp).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<&str> = vec![".."; sp.len() - common];
    parts.extend(&pp[common..]);
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

// ---------------------------------------------------------------------------------------------
// fnmatch
// ---------------------------------------------------------------------------------------------

struct Class {
    negate: bool,
    ranges: Vec<(char, char)>,
}

impl Class {
    fn matches(&self, c: char) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) != self.negate
    }
}

/// Parse `[...]` at `pat[i]`; `None` means a literal `[` (no closing bracket), like Python.
fn parse_class(pat: &[char], i: usize) -> Option<(Class, usize)> {
    let n = pat.len();
    let mut j = i + 1;
    if j < n && pat[j] == '!' {
        j += 1;
    }
    if j < n && pat[j] == ']' {
        j += 1;
    }
    while j < n && pat[j] != ']' {
        j += 1;
    }
    if j >= n {
        return None;
    }
    let mut stuff = &pat[i + 1..j];
    let negate = stuff.first() == Some(&'!');
    if negate {
        stuff = &stuff[1..];
    }
    let mut ranges = Vec::new();
    let mut k = 0;
    while k < stuff.len() {
        if k + 2 < stuff.len() && stuff[k + 1] == '-' {
            ranges.push((stuff[k], stuff[k + 2]));
            k += 3;
        } else {
            ranges.push((stuff[k], stuff[k]));
            k += 1;
        }
    }
    Some((Class { negate, ranges }, j + 1))
}

fn fnmatch_chars(name: &[char], pat: &[char]) -> bool {
    let (mut ni, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pi < pat.len() {
            let advanced = match pat[pi] {
                '*' => {
                    star = Some((pi + 1, ni));
                    pi += 1;
                    continue;
                }
                '?' if ni < name.len() => {
                    ni += 1;
                    pi += 1;
                    true
                }
                '[' => match parse_class(pat, pi) {
                    Some((class, next)) => {
                        if ni < name.len() && class.matches(name[ni]) {
                            ni += 1;
                            pi = next;
                            true
                        } else {
                            false
                        }
                    }
                    None if ni < name.len() && name[ni] == '[' => {
                        ni += 1;
                        pi += 1;
                        true
                    }
                    None => false,
                },
                c if c != '?' && ni < name.len() && name[ni] == c => {
                    ni += 1;
                    pi += 1;
                    true
                }
                _ => false,
            };
            if advanced {
                continue;
            }
        } else if ni == name.len() {
            return true;
        }
        match star {
            Some((spi, sni)) if sni < name.len() => {
                star = Some((spi, sni + 1));
                pi = spi;
                ni = sni + 1;
            }
            _ => return false,
        }
    }
}

/// `fnmatch.fnmatch`: case-sensitive on POSIX, case-insensitive on Windows.
pub fn fnmatch(name: &str, pat: &str) -> bool {
    let (n, p): (Vec<char>, Vec<char>) = if cfg!(windows) {
        (
            name.to_lowercase().chars().collect(),
            pat.to_lowercase().chars().collect(),
        )
    } else {
        (name.chars().collect(), pat.chars().collect())
    };
    fnmatch_chars(&n, &p)
}

// ---------------------------------------------------------------------------------------------
// glob
// ---------------------------------------------------------------------------------------------

pub fn has_magic(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn split(p: &str) -> (&str, &str) {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let (head, tail) = p.split_at(i);
    if !head.is_empty() && head.chars().any(|c| c != '/') {
        (head.trim_end_matches('/'), tail)
    } else {
        (head, tail)
    }
}

fn glob1(dir: &str, pattern: &str) -> Vec<String> {
    let Ok(rd) = fs::read_dir(if dir.is_empty() { "." } else { dir }) else {
        return Vec::new();
    };
    let allow_hidden = pattern.starts_with('.');
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| allow_hidden || !n.starts_with('.'))
        .filter(|n| fnmatch(n, pattern))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| if dir.is_empty() { n } else { join(dir, &n) })
        .collect()
}

/// `glob.glob` (non-recursive; `**` behaves like `*`). Dotfiles only match patterns starting with `.`.
pub fn glob(pattern: &str) -> Vec<String> {
    if !has_magic(pattern) {
        return if lexists(pattern) {
            vec![pattern.to_string()]
        } else {
            Vec::new()
        };
    }
    let (dir, base) = split(pattern);
    let dirs = if !dir.is_empty() && has_magic(dir) {
        glob(dir)
    } else {
        vec![dir.to_string()]
    };
    let mut out = Vec::new();
    for d in dirs {
        if has_magic(base) {
            out.extend(glob1(&d, base));
        } else {
            let full = join(&d, base);
            if !base.is_empty() && lexists(&full) {
                out.push(full);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_posix() {
        assert_eq!(normpath("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(normpath("a//b/.."), "a");
        assert_eq!(normpath("../x"), "../x");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(normpath("///a"), "/a");
        assert_eq!(normpath(""), ".");
    }

    #[test]
    fn fnmatch_cases() {
        assert!(fnmatch("a.env", "*.env"));
        assert!(fnmatch(".env", ".env*"));
        assert!(fnmatch("file1", "file[0-9]"));
        assert!(!fnmatch("file1", "file[!0-9]"));
        assert!(fnmatch("a[", "a["));
        assert!(fnmatch("abc", "a?c"));
        assert!(!fnmatch("abc", "a?"));
        assert!(fnmatch("a.properties", "*.properties"));
        assert!(!fnmatch("A.ENV", "*.env") || cfg!(windows));
    }

    #[test]
    fn relpath_basic() {
        assert_eq!(relpath("/a/b/c", "/a"), "b/c");
        assert_eq!(relpath("/a", "/a/b"), "..");
        assert_eq!(relpath("/a", "/a"), ".");
    }
}
