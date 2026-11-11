//! Analysis of Bash (and Codex shell) commands: which secret files could they print?

use crate::mask::{is_secret_file, is_target};
use crate::pathx::{
    basename, expanduser, expandvars, fnmatch, glob, is_abs, is_dir, is_file, is_link, join,
    normpath, relpath, resolve,
};
use crate::tokenize::tokenize;
use crate::walk::{Budget, walk_targets};
use regex::Regex;
use std::sync::LazyLock;

const READERS: &[&str] = &[
    "cat", "tac", "head", "tail", "less", "more", "bat", "batcat", "nl", "grep", "egrep", "fgrep",
    "rg", "ag", "ack", "sed", "awk", "gawk", "cut", "sort", "uniq", "strings", "xxd", "od",
    "hexdump", "diff", "column", "paste", "tee", "source", ".", "view", "vim", "vi", "nano",
    "bash", "sh", "zsh",
];
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];
const WRAPPERS: &[&str] = &[
    "rtk", "sudo", "pkexec", "doas", "command", "env", "time", "nohup", "nice", "ionice", "stdbuf",
    "timeout", "exec", "builtin",
];
const LEADING_KEYWORDS: &[&str] = &[
    "while", "until", "if", "elif", "then", "else", "do", "!", "{", "time",
];
const LIST_KEYWORDS: &[&str] = &["for", "select", "case"];
const BLOCK_END: &[&str] = &["done", "fi", "esac", "}", "in"];
/// Commands that never print the content of a file operand.
const SAFE_HEADS: &[&str] = &[
    "ls",
    "stat",
    "file",
    "wc",
    "test",
    "[",
    "[[",
    "echo",
    "printf",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "true",
    "false",
    ":",
    "cd",
    "pushd",
    "popd",
    "pwd",
    "touch",
    "mkdir",
    "rm",
    "rmdir",
    "mv",
    "cp",
    "ln",
    "chmod",
    "chown",
    "du",
    "df",
    "which",
    "type",
    "export",
    "unset",
    "set",
    "exit",
    "return",
    "sleep",
    "date",
    "id",
    "whoami",
    "uname",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "cksum",
    "tree",
];
const RECURSIVE_SEARCHERS: &[&str] = &["grep", "egrep", "fgrep", "rg", "ag", "ack"];
const FIND_EXEC: &[&str] = &[
    "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf",
];
const SEPARATORS: &[&str] = &[";", ";;", "&&", "||", "|", "&", "|&"];
const GROUPERS: &[&str] = &["(", ")", "((", "))", "<(", ">("];
const WRITE_REDIRECTS: &[&str] = &[">", ">>", ">|", "&>", "&>>"];
const SAMPLE_SECRET_NAMES: &[&str] = &["a.properties", ".env", "a.env", ".env.local"];
const GIT_OPTS_WITH_VALUE: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--super-prefix",
    "--config-env",
];
const GIT_NO_CONTENT: &[&str] = &[
    "--stat",
    "--name-only",
    "--name-status",
    "--numstat",
    "--shortstat",
    "--summary",
    "--dirstat",
    "--check",
    "--quiet",
    "-q",
    "--no-patch",
    "-s",
    "--raw",
    "--compact-summary",
];
const GIT_GREP_NO_CONTENT: &[&str] = &[
    "-l",
    "--files-with-matches",
    "-L",
    "--files-without-match",
    "-c",
    "--count",
    "-q",
    "--quiet",
];
const GIT_EXCLUDE_ADVICE: &str =
    "-- . ':(exclude)*.properties' ':(exclude)*.env' ':(exclude).env*'";

pub const SEARCH_ADVICE: &str = "Search without them instead: exclude those file types (grep: --exclude='*.properties' \
--exclude='*.env' --exclude='.env*'; rg: -g '!*.properties' -g '!*.env' -g '!.env*'), restrict it \
to specific source files or types (--include='*.java', -t java), or search a subdirectory that \
has none.";
pub const GREP_TOOL_ADVICE: &str = "Search without them instead: set glob to specific source files (e.g. \"*.java\") or type \
(e.g. \"java\"), use output_mode files_with_matches, or search a subdirectory that has none.";

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z_][A-Za-z0-9_]*\+?="));
static NUMBER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9][0-9smhd.]*$"));
static WORD_SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| re(r#"[\s\x1c-\x1f'"`()<>|&;{},:=]+"#));
static SUBST_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\$\(([^()]*)\)"));
static BACKTICK_RE: LazyLock<Regex> = LazyLock::new(|| re(r"`([^`]*)`"));
static REDIRECT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9]*[<>]+&?[0-9-]*$"));
static SHELL_C_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^-[A-Za-z]*c[A-Za-z]*$"));
static RECURSIVE_FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^-[A-Za-z0-9]*[rR][A-Za-z0-9]*$"));
static GIT_PATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^(-p|-u|--patch|--patch-with-stat|--patch-with-raw|--cc|--combined|--dd|-L.*|-U\d*|--unified(=\d+)?)$",
    )
});
static GIT_MAGIC_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^:(?:\(([^)]*)\)|([!^]+))(.*)$"));
static EXCLUDE_MAGIC_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^:(\([^)]*exclude[^)]*\)|[!^])"));
static BRACE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\{([^{}]*)\}"));
static STAR_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^(\*\*/)+"));

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Assign,
    Neutral,
    Reader,
    Safe,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub head: String,
    pub args: Vec<String>,
    pub words: Vec<String>,
    pub reads: Vec<String>,
    pub kind: Kind,
    pub piped: bool,
    pub dynamic: bool,
}

fn has(set: &[&str], s: &str) -> bool {
    set.contains(&s)
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

fn is_wild(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

// ---------------------------------------------------------------------------------------------
// Words, globs and candidate resolution
// ---------------------------------------------------------------------------------------------

fn exclusion_indexes(words: &[String]) -> std::collections::HashSet<usize> {
    let mut skip = std::collections::HashSet::new();
    for (i, w) in words.iter().enumerate() {
        let nxt = words.get(i + 1).map_or("", |s| s.as_str());
        if ["--exclude=", "--ignore=", "--exclude-from=", "-g!"]
            .iter()
            .any(|p| w.starts_with(p))
            || w.starts_with('!')
            || EXCLUDE_MAGIC_RE.is_match(w)
        {
            skip.insert(i);
        } else if w == "--exclude"
            || w == "--ignore"
            || ((w == "-g" || w == "--glob") && nxt.starts_with('!'))
        {
            skip.insert(i);
            skip.insert(i + 1);
        } else if w.starts_with("--glob=!") {
            skip.insert(i);
        }
    }
    skip
}

/// Shell-style brace expansion (`*.{properties,txt}` -> two patterns), capped to stay cheap.
pub fn expand_braces(pattern: &str) -> Vec<String> {
    const LIMIT: usize = 256;
    let Some(m) = BRACE_RE.captures(pattern) else {
        return vec![pattern.to_string()];
    };
    let whole = m.get(0).unwrap();
    let mut out = Vec::new();
    for alt in m[1].split(',') {
        let next = format!(
            "{}{}{}",
            &pattern[..whole.start()],
            alt,
            &pattern[whole.end()..]
        );
        out.extend(expand_braces(&next));
        if out.len() >= LIMIT {
            break;
        }
    }
    out.truncate(LIMIT);
    out
}

/// Secret-looking file names mentioned anywhere inside one shell word.
pub fn candidates_in_word(word: &str) -> Vec<String> {
    expand_braces(word)
        .iter()
        .flat_map(|w| {
            WORD_SPLIT_RE
                .split(w)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|p| !p.is_empty() && is_target(p))
        .collect()
}

fn resolve_candidate(cand: &str, cwds: &[String], wide: bool, budget: &mut Budget) -> Vec<String> {
    let c = expandvars(&expanduser(cand.trim_start_matches(['!', '@'])));
    if c.contains('$') || c.is_empty() {
        return Vec::new(); // run-time value; handled by the "dynamic reader" rule
    }
    let wild = is_wild(&c);
    let mut hits: Vec<String> = Vec::new();
    let recursive_pattern = c.contains("**");
    if !recursive_pattern {
        for base in cwds {
            let full = if is_abs(&c) {
                c.clone()
            } else {
                join(base, &c)
            };
            if wild {
                hits.extend(glob(&full).into_iter().filter(|p| is_secret_file(p)));
            } else if is_secret_file(&full) {
                hits.push(full);
            }
        }
    }
    if hits.is_empty() && (wide || recursive_pattern) && (!c.contains('/') || recursive_pattern) {
        let pattern = basename(&c).to_lowercase();
        for base in cwds {
            let matcher = |name: &str| fnmatch(&name.to_lowercase(), &pattern);
            hits.extend(walk_targets(base, budget, Some(&matcher)));
        }
    }
    hits.iter().map(|p| normpath(p)).collect()
}

// ---------------------------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------------------------

fn git_parts(args: &[String]) -> (String, Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if has(GIT_OPTS_WITH_VALUE, a) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return (a.clone(), args[i + 1..].to_vec());
        }
    }
    (String::new(), Vec::new())
}

fn git_reads_content(sub: &str, rest: &[String]) -> bool {
    let has_patch = rest
        .iter()
        .any(|a| GIT_PATCH_RE.is_match(a) || (a == "-c" && sub != "grep"));
    let any_in = |set: &[&str]| rest.iter().any(|a| has(set, a));
    match sub {
        "log" | "whatchanged" | "reflog" | "stash" | "diff-tree" | "diff-index" | "diff-files"
        | "range-diff" => has_patch,
        "diff" | "show" | "difftool" => has_patch || !any_in(GIT_NO_CONTENT),
        "grep" => !any_in(GIT_GREP_NO_CONTENT),
        "cat-file" => !any_in(&["-t", "-s", "-e"]),
        _ => sub == "blame" || sub == "annotate",
    }
}

fn git_exposure(seg: &Segment, cwds: &[String]) -> Option<String> {
    let (sub, rest) = git_parts(&seg.args);
    if !git_reads_content(&sub, &rest) {
        return None;
    }
    let mut excluded: Vec<String> = Vec::new();
    for a in &rest {
        if let Some(m) = GIT_MAGIC_RE.captures(a) {
            let magic = m.get(1).map_or("", |x| x.as_str());
            if magic.contains("exclude") || m.get(2).is_some() {
                excluded.push(m[3].to_string());
            }
        }
    }
    let covers = |name: &str| {
        excluded
            .iter()
            .any(|p| fnmatch(name, &STAR_PREFIX_RE.replace(p, "")))
    };
    if SAMPLE_SECRET_NAMES.iter().all(|n| covers(n)) {
        return None;
    }
    let operands: Vec<&String> = rest
        .iter()
        .filter(|a| !a.starts_with('-') && !a.starts_with(':'))
        .collect();
    let (mut safe_files, mut dangerous) = (0, 0);
    for a in operands {
        let resolved: Vec<String> = cwds.iter().map(|b| resolve(a, b)).collect();
        if is_wild(a) || a == "." || a == ".." || resolved.iter().any(|p| is_dir(p)) || is_target(a)
        {
            dangerous += 1;
        } else if resolved.iter().any(|p| is_file(p) && !is_secret_file(p)) {
            safe_files += 1;
        }
    }
    if safe_files > 0 && dangerous == 0 {
        return None;
    }
    Some(format!(
        "Blocked: `git {sub}` can print the content of .properties/.env files (values are secrets). \
Use --stat / --name-only / --name-status, name specific non-secret files, or exclude them: \
git {sub} ... {GIT_EXCLUDE_ADVICE}"
    ))
}

// ---------------------------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------------------------

fn make_segment(words: Vec<String>, reads: Vec<String>, piped: bool) -> Segment {
    let mut w: &[String] = &words;
    while let Some(first) = w.first() {
        let is_wrapper = has(WRAPPERS, basename(first));
        if !(is_wrapper || has(LEADING_KEYWORDS, first) || ASSIGN_RE.is_match(first)) {
            break;
        }
        w = &w[1..];
        while is_wrapper
            && w.first()
                .is_some_and(|x| x.starts_with('-') || NUMBER_RE.is_match(x))
        {
            w = &w[1..];
        }
    }
    let head = w.first().map_or("", |h| basename(h)).to_string();
    let args: Vec<String> = w.iter().skip(1).cloned().collect();
    let kind = if w.is_empty() {
        if words.is_empty() {
            Kind::Neutral
        } else {
            Kind::Assign
        }
    } else if has(LIST_KEYWORDS, &head) || has(BLOCK_END, &head) {
        Kind::Neutral
    } else if has(READERS, &head) {
        Kind::Reader
    } else if head == "git" {
        let (sub, rest) = git_parts(&args);
        if git_reads_content(&sub, &rest) {
            Kind::Reader
        } else {
            Kind::Safe
        }
    } else if head == "find" {
        if args.iter().any(|a| has(FIND_EXEC, a)) {
            Kind::Reader
        } else {
            Kind::Safe
        }
    } else if has(SAFE_HEADS, &head) {
        Kind::Safe
    } else {
        Kind::Unknown
    };
    let dynamic = matches!(kind, Kind::Reader | Kind::Unknown)
        && (words.iter().any(|x| x.contains('$')) || head == "xargs" || head == "parallel");
    Segment {
        head,
        args,
        words,
        reads,
        kind,
        piped,
        dynamic,
    }
}

pub fn collect_segments(cmd: &str, segments: &mut Vec<Segment>, depth: u32) {
    if depth > 3 {
        return;
    }
    for m in BACKTICK_RE.captures_iter(cmd) {
        collect_segments(&m[1], segments, depth + 1);
    }
    let mut chunks: Vec<(Vec<String>, bool)> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut piped = false;
    for t in tokenize(cmd) {
        if has(SEPARATORS, &t) || has(GROUPERS, &t) {
            chunks.push((std::mem::take(&mut cur), piped));
            piped = t == "|" || t == "|&";
        } else {
            cur.push(t);
        }
    }
    chunks.push((cur, piped));
    for (toks, was_piped) in chunks {
        let (mut words, mut reads) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < toks.len() {
            let t = &toks[i];
            if has(WRITE_REDIRECTS, t) && i + 1 < toks.len() {
                i += 2; // skip write target
                continue;
            }
            if t == "<" && i + 1 < toks.len() {
                reads.push(toks[i + 1].clone());
                i += 2;
                continue;
            }
            if REDIRECT_RE.is_match(t) {
                i += 1;
                continue;
            }
            words.push(t.clone());
            i += 1;
        }
        let seg = make_segment(words, reads, was_piped);
        segments.push(seg.clone());
        for token in seg.words.iter().chain(seg.reads.iter()) {
            for m in SUBST_RE.captures_iter(token) {
                if !m[1].is_empty() {
                    collect_segments(&m[1], segments, depth + 1);
                }
            }
        }
        if has(SHELLS, &seg.head) {
            let n = seg.args.len().saturating_sub(1);
            if let Some(idx) = seg.args[..n].iter().position(|a| SHELL_C_RE.is_match(a)) {
                collect_segments(&seg.args[idx + 1], segments, depth + 1);
            }
        } else if seg.head == "eval" {
            collect_segments(&seg.args.join(" "), segments, depth + 1);
        }
    }
}

/// Base cwd plus every directory the command could be running in after cd / pushd / git -C.
fn cwd_candidates(segments: &[Segment], cwd: &str) -> Vec<String> {
    let mut out = vec![cwd.to_string()];
    let mut cur = cwd.to_string();
    for s in segments {
        if s.head == "cd" || s.head == "pushd" {
            let raw = s
                .args
                .iter()
                .find(|a| !a.starts_with('-'))
                .map_or("~", |a| a.as_str());
            let target = expandvars(&expanduser(raw));
            if target.contains('$') {
                continue;
            }
            cur = normpath(&if is_abs(&target) {
                target.clone()
            } else {
                join(&cur, &target)
            });
            out.push(cur.clone());
            out.push(normpath(&if is_abs(&target) {
                target
            } else {
                join(cwd, &target)
            }));
        } else if s.head == "git" {
            for idx in 0..s.args.len().saturating_sub(1) {
                if s.args[idx] == "-C" {
                    let d = expanduser(&s.args[idx + 1]);
                    out.push(normpath(&if is_abs(&d) { d } else { join(&cur, &d) }));
                }
            }
        }
    }
    dedup(out).into_iter().filter(|d| is_dir(d)).collect()
}

// ---------------------------------------------------------------------------------------------
// Recursive searches
// ---------------------------------------------------------------------------------------------

/// include globs, exclude globs, narrowed-by-type flag for grep / rg / ag style options.
pub fn parse_filters(args: &[String]) -> (Vec<String>, Vec<String>, bool) {
    let (mut inc, mut exc) = (Vec::new(), Vec::new());
    let mut narrowed = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let nxt = args.get(i + 1).map_or("", |s| s.as_str());
        let mut item: Option<(&str, String)> = None;
        if let Some(v) = a
            .strip_prefix("--exclude=")
            .or_else(|| a.strip_prefix("--ignore="))
        {
            item = Some(("exc", v.to_string()));
        } else if a == "--exclude" || a == "--ignore" {
            item = Some(("exc", nxt.to_string()));
            i += 1;
        } else if let Some(v) = a.strip_prefix("--include=") {
            item = Some(("inc", v.to_string()));
        } else if a == "--include" {
            item = Some(("inc", nxt.to_string()));
            i += 1;
        } else if let Some(v) = a.strip_prefix("--glob=") {
            item = Some(("glob", v.to_string()));
        } else if a == "--glob" || a == "-g" {
            item = Some(("glob", nxt.to_string()));
            i += 1;
        } else if a.starts_with("-g") && !a.starts_with("--") && a.len() > 2 {
            item = Some(("glob", a[2..].to_string()));
        } else if matches!(a, "-t" | "--type" | "-G" | "--file-search-regex")
            || a.starts_with("--type=")
        {
            narrowed = true;
        }
        match item {
            Some(("exc", v)) => exc.push(v),
            Some(("inc", v)) => inc.push(v),
            Some((_, v)) => {
                if v.starts_with('!') {
                    exc.push(v.trim_start_matches('!').to_string());
                } else {
                    inc.push(v);
                }
            }
            None => {}
        }
        i += 1;
    }
    (inc, exc, narrowed)
}

fn filter_hits(hits: Vec<String>, inc: &[String], exc: &[String], narrowed: bool) -> Vec<String> {
    if narrowed {
        return Vec::new();
    }
    let inc: Vec<String> = inc.iter().flat_map(|i| expand_braces(i)).collect();
    let exc: Vec<String> = exc.iter().flat_map(|e| expand_braces(e)).collect();
    hits.into_iter()
        .filter(|p| {
            let name = basename(p);
            !((!inc.is_empty() && !inc.iter().any(|i| fnmatch(name, i)))
                || exc.iter().any(|e| fnmatch(name, e)))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn search_exposure(
    label: &str,
    dirs: &[String],
    inc: &[String],
    exc: &[String],
    narrowed: bool,
    cwd: &str,
    budget: &mut Budget,
    advice: &str,
) -> Option<String> {
    let mut hits: Vec<String> = Vec::new();
    for d in dirs {
        hits.extend(walk_targets(d, budget, None));
    }
    let hits = filter_hits(dedup(hits), inc, exc, narrowed);
    if hits.is_empty() && !budget.incomplete {
        return None;
    }
    let found = if hits.is_empty() {
        "the tree is too large to verify".to_string()
    } else {
        let rel: Vec<String> = hits
            .iter()
            .take(8)
            .map(|p| {
                if p.starts_with(cwd) {
                    relpath(p, cwd)
                } else {
                    p.clone()
                }
            })
            .collect();
        format!("{} secret file(s) such as: {}", hits.len(), rel.join(", "))
    };
    Some(format!(
        "Blocked: this {label} would read .properties/.env files ({found}). Their values are secrets. {advice}"
    ))
}

fn recursive_exposure(
    seg: &Segment,
    cwds: &[String],
    cwd: &str,
    budget: &mut Budget,
) -> Option<String> {
    let (head, args) = (seg.head.as_str(), &seg.args);
    let recursive = matches!(head, "rg" | "ag" | "ack")
        || args.iter().any(|a| {
            RECURSIVE_FLAG_RE.is_match(a)
                || matches!(
                    a.as_str(),
                    "--recursive" | "--dereference-recursive" | "--directories=recurse"
                )
        })
        || args.windows(2).any(|w| w[0] == "-d" && w[1] == "recurse");
    if !recursive {
        return None;
    }
    let mut dirs: Vec<String> = Vec::new();
    for a in args.iter().filter(|a| !a.starts_with('-')) {
        for base in cwds {
            let p = resolve(a, base);
            if is_dir(&p) {
                dirs.push(p);
            }
        }
    }
    if dirs.is_empty() && !seg.piped {
        dirs = cwds.to_vec();
    }
    let (inc, exc, narrowed) = parse_filters(args);
    search_exposure(
        &format!("recursive {head}"),
        &dirs,
        &inc,
        &exc,
        narrowed,
        cwd,
        budget,
        SEARCH_ADVICE,
    )
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

/// Returns (secret files that would be printed, other reasons to block).
pub fn analyze_bash(cmd: &str, cwd: &str, budget: &mut Budget) -> (Vec<String>, Vec<String>) {
    let mut segments: Vec<Segment> = Vec::new();
    collect_segments(cmd, &mut segments, 0);
    let cwds = cwd_candidates(&segments, cwd);
    let wide = segments
        .iter()
        .any(|s| matches!(s.head.as_str(), "find" | "fd" | "fdfind" | "locate"));

    let mut direct: Vec<String> = Vec::new();
    let mut mentioned: Vec<String> = Vec::new();
    for s in &segments {
        let skip = exclusion_indexes(&s.words);
        let mut word_hits: Vec<String> = Vec::new();
        for (i, w) in s.words.iter().enumerate() {
            if skip.contains(&i) {
                continue;
            }
            for cand in candidates_in_word(w) {
                word_hits.extend(resolve_candidate(&cand, &cwds, wide, budget));
            }
        }
        let mut read_hits: Vec<String> = Vec::new();
        for w in &s.reads {
            for cand in candidates_in_word(w) {
                read_hits.extend(resolve_candidate(&cand, &cwds, wide, budget));
            }
        }
        mentioned.extend(word_hits.iter().cloned());
        mentioned.extend(read_hits.iter().cloned());
        match s.kind {
            Kind::Reader | Kind::Unknown => {
                direct.extend(word_hits);
                direct.extend(read_hits);
                // a symlink with an innocent name that points at a secret file
                for a in s.args.iter().filter(|a| !a.starts_with('-')) {
                    for base in &cwds {
                        let p = resolve(a, base);
                        if is_link(&p) && is_secret_file(&p) {
                            direct.push(normpath(&p));
                        }
                    }
                }
            }
            Kind::Neutral | Kind::Assign => direct.extend(read_hits), // `while read l; do ...; done < file`
            Kind::Safe => {}
        }
    }
    if direct.is_empty() && !mentioned.is_empty() && segments.iter().any(|s| s.dynamic) {
        direct = mentioned.clone(); // the filename is fed to a reader through a variable / xargs / $(...)
    }

    let mut issues: Vec<String> = Vec::new();
    for s in segments.iter().filter(|s| s.kind == Kind::Reader) {
        let msg = if s.head == "git" {
            git_exposure(s, &cwds)
        } else if has(RECURSIVE_SEARCHERS, &s.head) {
            recursive_exposure(s, &cwds, cwd, budget)
        } else {
            None
        };
        if let Some(m) = msg
            && !issues.contains(&m)
        {
            issues.push(m);
        }
    }
    (dedup(direct), issues)
}
