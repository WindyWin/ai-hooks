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
    /// output goes straight into this hook's --scrub filter
    pub scrubbed: bool,
    /// `<this hook> --cat FILE...`: prints the files masked, whatever they are
    pub masked: bool,
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
    if !git_reads_content(&sub, &rest) || git_masks_secrets(&seg.args, None) {
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
        scrubbed: false,
        masked: false,
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
        } else if let Some(v) = a.strip_prefix("--iglob=") {
            item = Some(("iglob", v.to_string()));
        } else if a == "--iglob" {
            item = Some(("iglob", nxt.to_string()));
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
            Some(("iglob", v)) => {
                // case-insensitive: marked so filter_hits compares lower-cased names
                let marked = format!("{ICASE}{}", v.trim_start_matches('!').to_lowercase());
                if v.starts_with('!') {
                    exc.push(marked);
                } else {
                    inc.push(marked);
                }
            }
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

const ICASE: &str = "\0i:";

fn glob_match(name: &str, pattern: &str) -> bool {
    match pattern.strip_prefix(ICASE) {
        Some(p) => fnmatch(&name.to_lowercase(), p),
        None => fnmatch(name, pattern),
    }
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
            !((!inc.is_empty() && !inc.iter().any(|i| glob_match(name, i)))
                || exc.iter().any(|e| glob_match(name, e)))
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
    if !recursive || (head == "rg" && rg_masks_secrets(args)) {
        return None;
    }
    if head != "rg" {
        let (ok, _, quiet) = search_args_ok(head, args);
        // -q prints nothing; --scrub masks what it prints
        if (ok && quiet) || scrubbed_search(seg, preprocessor().as_deref()) {
            return None;
        }
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

// rg can search the output of a preprocessor instead of the file (`--pre CMD` runs `CMD FILE`). With this
// binary as CMD the secret files are searched in masked form: path, line number and key still show, the value
// is ****. --pre-glob limits it to secret-looking names; character classes make the globs case-insensitive
// (.ENV), which --pre-glob is not even with --glob-case-insensitive. Template files (.env.example) match the
// globs but pass raw.
pub const RG_PRE_GLOBS: [&str; 4] = [
    "*.[pP][rR][oO][pP][eE][rR][tT][iI][eE][sS]",
    "*.[eE][nN][vV]",
    ".[eE][nN][vV]",
    ".[eE][nN][vV].*",
];
const REWRITE_UNSAFE: &[&str] = &["`", "$(", "<<", "<(", ">("];
const READONLY_FILTERS: &[(&str, &str)] = &[
    ("head", "nqcv"),
    ("tail", "nqcv"),
    ("wc", "lwcmL"),
    ("sort", "unrfhVbdgMsk"),
    ("uniq", "cdui"),
];
static RG_FOLLOW_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(--follow|-[A-Za-z0-9]*L[A-Za-z0-9]*)$"));
static READONLY_REDIRECT_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|\s)(?:[12]?>\s*/dev/null|&>\s*/dev/null|2>&1)(\s|$|[;|&])"));
static EXPANSION_RE: LazyLock<Regex> = LazyLock::new(|| re(r"\$[A-Za-z_{(@*#?!0-9-]"));
static READONLY_OPERAND_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[-+]?\d+$"));
static READONLY_FLAG_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^-([A-Za-z]+)\d*$"));
static SHELL_PUNCT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[<>&|();]+$"));

pub fn rg_notice() -> String {
    "mask-secrets: this rg search was rewritten to run with --pre mask-secrets --pre-glob ... so values in \
.env / .properties files show up as KEY=****. Path, line number and key are still searchable; the real \
values are never printed, do not try to read them."
        .to_string()
}

/// The command rg runs on each secret file: this binary.
pub fn preprocessor() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Like Python's `shlex.quote`.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

pub fn rg_mask_flags(pre: &str) -> String {
    let mut out = format!("--pre {}", shell_quote(pre));
    for g in RG_PRE_GLOBS {
        out.push_str(&format!(" --pre-glob {}", shell_quote(g)));
    }
    out
}

/// User-supplied --pre / --pre-glob could override ours, -L follows symlinks that hide a secret file under
/// another name, --hostname-bin runs a program.
fn rg_flag_blocks_rewrite(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.starts_with("--pre") || a.starts_with("--hostname-bin") || RG_FOLLOW_RE.is_match(a)
    })
}

/// True when the rg arguments carry exactly the masking flags this hook adds.
fn rg_masks_secrets(args: &[String]) -> bool {
    let Some(pre) = preprocessor() else {
        return false;
    };
    let (mut pres, mut globs): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    for (i, a) in args.iter().enumerate() {
        let nxt = args.get(i + 1).map_or("", |s| s.as_str());
        if a == "--pre" {
            pres.push(nxt);
        } else if let Some(v) = a.strip_prefix("--pre=") {
            pres.push(v);
        } else if a == "--pre-glob" {
            globs.push(nxt);
        } else if let Some(v) = a.strip_prefix("--pre-glob=") {
            globs.push(v);
        } else if RG_FOLLOW_RE.is_match(a) {
            return false;
        }
    }
    !pres.is_empty() && pres.iter().all(|p| *p == pre) && RG_PRE_GLOBS.iter().all(|g| globs.contains(g))
}

/// rg searches optionally after `cd`, piped through head/tail/wc/sort/uniq with plain flags: nothing in them can
/// change anything. Codex only accepts a rewritten command together with an approval, so only such commands
/// are approved that way.
pub fn readonly_search_pipeline(cmd: &str) -> bool {
    if REWRITE_UNSAFE.iter().any(|p| cmd.contains(p)) || EXPANSION_RE.is_match(cmd) {
        return false;
    }
    // drop `2>/dev/null`, `2>&1` ... (the only redirections allowed)
    let mut cmd = cmd.to_string();
    loop {
        let next = READONLY_REDIRECT_RE.replace_all(&cmd, "$1 $2").into_owned();
        if next == cmd {
            break;
        }
        cmd = next;
    }
    let mut commands: Vec<Vec<String>> = vec![Vec::new()];
    for t in tokenize(&cmd) {
        if matches!(t.as_str(), "|" | "&&" | "||" | ";") {
            commands.push(Vec::new());
        } else if SHELL_PUNCT_RE.is_match(&t) {
            return false; // background, subshell, other redirections
        } else {
            commands.last_mut().unwrap().push(t);
        }
    }
    for words in &commands {
        let Some((head, args)) = words.split_first() else {
            continue;
        };
        let ok = match head.as_str() {
            "rg" => !rg_flag_blocks_rewrite(args),
            "cd" => args.len() == 1 && !args[0].starts_with('-'),
            h => match READONLY_FILTERS.iter().find(|(name, _)| *name == h) {
                Some((_, letters)) => args.iter().all(|a| {
                    READONLY_OPERAND_RE.is_match(a)
                        || READONLY_FLAG_RE
                            .captures(a)
                            .is_some_and(|m| m[1].chars().all(|c| letters.contains(c)))
                }),
                None => false,
            },
        };
        if !ok {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Masked git and masked grep/ag/ack (see the Python hook for the long explanation)
//
// git: `-c core.attributesFile=<file>` gives secret-looking names a `diff=` driver whose textconv is this binary
// (`--mask env|properties FILE`), so diff / show / log -p / blame / grep print KEY=**** instead of the file.
// grep, ag, ack: their output is piped through `--scrub`, which masks lines that start with a secret file's path.
// ---------------------------------------------------------------------------------------------

pub const GIT_DRIVERS: [(&str, &str); 2] = [("maskenv", "env"), ("maskprops", "properties")];
pub const GIT_ATTRIBUTES: &str = "*.[pP][rR][oO][pP][eE][rR][tT][iI][eE][sS] diff=maskprops\n\
*.[eE][nN][vV] diff=maskenv\n\
.[eE][nN][vV].* diff=maskenv\n";
const DIFF_OPTS: &[&str] = &["--textconv", "--no-ext-diff"];
/// options that bring the raw content back, or send it somewhere the filter does not see
const GIT_MASK_BLOCKERS: &[&str] = &[
    "--no-textconv",
    "--ext-diff",
    "--no-index",
    "--open-files-in-pager",
    "--output",
    "--binary",
    "--attr-source",
];
const GIT_ATTR_SAMPLES: [(&str, &str); 8] = [
    ("a.properties", "maskprops"),
    ("a.PROPERTIES", "maskprops"),
    ("a.env", "maskenv"),
    ("a.ENV", "maskenv"),
    (".env", "maskenv"),
    (".ENV", "maskenv"),
    (".env.local", "maskenv"),
    (".ENV.prod", "maskenv"),
];
const GREP_SHORT: &str = "iyIaUZTnwxFEGPrHsvclLq";
const GREP_SHORT_VALUE: &str = "efmABCdD";
const GREP_LONG: &[&str] = &[
    "--recursive",
    "--ignore-case",
    "--no-ignore-case",
    "--word-regexp",
    "--line-regexp",
    "--fixed-strings",
    "--extended-regexp",
    "--basic-regexp",
    "--perl-regexp",
    "--invert-match",
    "--line-number",
    "--with-filename",
    "--count",
    "--files-with-matches",
    "--files-without-match",
    "--no-messages",
    "--text",
    "--null",
    "--initial-tab",
    "--line-buffered",
    "--quiet",
    "--silent",
];
const GREP_LONG_VALUE: &[&str] = &[
    "--include",
    "--exclude",
    "--exclude-dir",
    "--exclude-from",
    "--regexp",
    "--file",
    "--max-count",
    "--after-context",
    "--before-context",
    "--context",
    "--binary-files",
    "--directories",
    "--devices",
];
const AGACK_SHORT: &str = "iwQsSvclLauU";
const AGACK_SHORT_VALUE: &str = "ABC";
const AGACK_LONG: &[&str] = &[
    "--ignore-case",
    "--word-regexp",
    "--literal",
    "--smart-case",
    "--case-sensitive",
    "--invert-match",
    "--count",
    "--files-with-matches",
    "--files-without-matches",
    "--hidden",
    "--unrestricted",
    "--all-types",
    "--nocolor",
    "--nogroup",
    "--numbers",
];
const AGACK_LONG_VALUE: &[&str] = &["--after", "--before", "--context", "--depth", "--ignore"];

pub const GIT_MASK_NOTICE: &str = "mask-secrets: this git command was rewritten to run with a textconv filter, so values in .env / \
.properties files show up as KEY=****. A change that only touches a value shows no diff because both \
sides are masked. The real values are never printed, do not try to read them.";
pub const SCRUB_NOTICE: &str = "mask-secrets: the output of this search is piped through mask-secrets --scrub, so values in .env / \
.properties matches show up as KEY=****. Path, line number and key are still reported. The real values \
are never printed, do not try to read them.";

fn cache_dir() -> String {
    let nonempty = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let base = nonempty("XDG_CACHE_HOME").or_else(|| {
        if cfg!(windows) {
            nonempty("LOCALAPPDATA")
        } else {
            Some(join(&expanduser("~"), ".cache"))
        }
    });
    join(&base.unwrap_or_else(|| expanduser("~")), "mask-secrets")
}

pub fn git_attributes_path() -> String {
    join(&cache_dir(), "gitattributes")
}

/// The attributes file textconv needs, written on first use. None when it cannot be written.
fn ensure_git_attributes() -> Option<String> {
    let path = git_attributes_path();
    if std::fs::read_to_string(&path).is_ok_and(|t| t == GIT_ATTRIBUTES) {
        return Some(path);
    }
    std::fs::create_dir_all(std::path::Path::new(&path).parent()?).ok()?;
    let tmp = format!("{path}.{}", std::process::id());
    std::fs::write(&tmp, GIT_ATTRIBUTES).ok()?;
    std::fs::rename(&tmp, &path).ok()?;
    Some(path)
}

/// The three `-c` values that turn textconv masking on.
fn git_mask_configs(pre: &str) -> Vec<String> {
    let mut out = vec![format!("core.attributesFile={}", git_attributes_path())];
    for (drv, kind) in GIT_DRIVERS {
        out.push(format!("diff.{drv}.textconv={} --mask {kind}", shell_quote(pre)));
    }
    out
}

/// Index of the subcommand word in `git ARGS` (skips global options).
fn git_sub_index(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if has(GIT_OPTS_WITH_VALUE, a) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return Some(i);
        }
    }
    None
}

fn git_mask_opts(sub: &str) -> Option<&'static [&'static str]> {
    match sub {
        "diff" | "show" | "log" | "reflog" | "whatchanged" | "stash" | "diff-tree" | "diff-index"
        | "diff-files" => Some(DIFF_OPTS),
        "grep" => Some(&["--textconv"]),
        "blame" | "annotate" => Some(&[]),
        _ => None,
    }
}

/// (index of the word after which the options go, the options) when this git command can be masked.
fn git_mask_target(args: &[String]) -> Option<(usize, &'static [&'static str])> {
    let k = git_sub_index(args)?;
    let (sub, rest) = (&args[k], &args[k + 1..]);
    let opts = git_mask_opts(sub)?;
    if rest.iter().any(|a| {
        has(GIT_MASK_BLOCKERS, a.split('=').next().unwrap_or("")) || a.starts_with("-O")
    }) {
        return None;
    }
    let mut at = k;
    if sub == "stash" {
        // `git stash show -p` / `git stash list -p`: the options belong after show / list
        if !matches!(rest.first().map(String::as_str), Some("show" | "list")) {
            return None;
        }
        at = k + 1;
    }
    Some((at, opts))
}

/// True when the git arguments carry exactly the masking options this hook adds.
fn git_masks_secrets(args: &[String], pre: Option<&str>) -> bool {
    let own;
    let pre = match pre {
        Some(p) => p,
        None => match preprocessor() {
            Some(p) => {
                own = p;
                &own
            }
            None => return false,
        },
    };
    let Some((at, opts)) = git_mask_target(args) else {
        return false;
    };
    let Some(k) = git_sub_index(args) else {
        return false;
    };
    let configs: Vec<&String> = (0..k)
        .filter(|&i| args[i] == "-c" && i + 1 < k)
        .map(|i| &args[i + 1])
        .collect();
    git_mask_configs(pre).iter().all(|c| configs.contains(&c))
        && opts.iter().all(|o| args[at + 1..].iter().any(|a| a == o))
}

/// A repository's own .gitattributes (or .git/info/attributes) beats the attributes file the masking uses: when it
/// gives secret-looking names another diff driver, or `-diff`, textconv would not run. Ask git. False when that is
/// the case or when git cannot be run; directories that are not repositories do not count.
fn git_attributes_win(pre: &str, dirs: &[String]) -> bool {
    use std::process::{Command, Stdio};
    let mut args: Vec<String> = Vec::new();
    for c in git_mask_configs(pre) {
        args.push("-c".into());
        args.push(c);
    }
    args.extend(["check-attr".into(), "diff".into(), "--".into()]);
    args.extend(GIT_ATTR_SAMPLES.iter().map(|(n, _)| n.to_string()));
    let expected: std::collections::BTreeMap<&str, &str> = GIT_ATTR_SAMPLES.into_iter().collect();
    let here = [".".to_string()];
    for d in if dirs.is_empty() { &here[..] } else { dirs } {
        let Ok(mut child) = Command::new("git")
            .args(&args)
            .current_dir(d)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        };
        if !status.success() {
            continue;
        }
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            use std::io::Read;
            let _ = pipe.read_to_string(&mut stdout);
        }
        let mut seen: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for line in stdout.lines() {
            match line.rsplit_once(": diff: ") {
                Some((name, value)) => {
                    seen.insert(name, value);
                }
                None => {
                    seen.insert("", line);
                }
            }
        }
        if seen != expected {
            return false;
        }
    }
    true
}

/// (the flags only produce output shapes --scrub understands, -c / --count given, -q / --quiet given)
pub fn search_args_ok(head: &str, args: &[String]) -> (bool, bool, bool) {
    let Some(flags) = search_flags(head, args) else {
        return (false, false, false);
    };
    let grep = matches!(head, "grep" | "egrep" | "fgrep");
    let given = |names: &[&str]| flags.iter().any(|f| names.contains(&f.as_str()));
    (
        true,
        given(&["c", "--count"]),
        given(&["--quiet", "--silent"]) || (grep && given(&["q"])),
    )
}

/// The flags of a grep / ag / ack command line (short letters and long names) when they only produce output shapes
/// --scrub understands, else None.
pub fn search_flags(head: &str, args: &[String]) -> Option<Vec<String>> {
    let grep = matches!(head, "grep" | "egrep" | "fgrep");
    let (short, short_value, long, long_value) = if grep {
        (GREP_SHORT, GREP_SHORT_VALUE, GREP_LONG, GREP_LONG_VALUE)
    } else {
        (AGACK_SHORT, AGACK_SHORT_VALUE, AGACK_LONG, AGACK_LONG_VALUE)
    };
    let mut flags: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            break;
        }
        if a.starts_with("--") {
            let (name, eq) = match a.split_once('=') {
                Some((n, _)) => (n, true),
                None => (a.as_str(), false),
            };
            if has(long_value, name) {
                if !eq {
                    i += 1;
                }
            } else if !has(long, name) || eq {
                return None;
            }
            flags.push(name.to_string());
        } else if a.starts_with('-') && a.chars().count() > 1 {
            let chars: Vec<char> = a.chars().collect();
            let mut j = 1;
            while j < chars.len() {
                let c = chars[j];
                if short_value.contains(c) {
                    // the value is the rest of the word, or the next word
                    if j == chars.len() - 1 {
                        i += 1;
                    }
                    break;
                }
                if c.is_ascii_digit() && grep {
                    j += 1;
                    continue;
                }
                if !short.contains(c) {
                    return None;
                }
                flags.push(c.to_string());
                j += 1;
            }
        }
    }
    Some(flags)
}

/// A grep / ag / ack whose output goes straight into this hook's --scrub filter, with flags it understands.
fn scrubbed_search(seg: &Segment, pre: Option<&str>) -> bool {
    pre.is_some() && seg.scrubbed && search_args_ok(&seg.head, &seg.args).0
}

/// Word spans (start, end) in chars of every simple command in the text, and whether it reads a pipe.
/// Separators outside quotes end a command. None when a quote is left open.
type CommandSpans = Vec<(Vec<(usize, usize)>, bool)>;

fn command_spans(chars: &[char]) -> Option<CommandSpans> {
    let n = chars.len();
    let mut cmds: CommandSpans = vec![(Vec::new(), false)];
    let (mut start, mut quote): (Option<usize>, Option<char>) = (None, None);
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' && q == '"' {
                i += 1;
            }
        } else if c == '\'' || c == '"' {
            start.get_or_insert(i);
            quote = Some(c);
        } else if c == '\\' {
            start.get_or_insert(i);
            i += 1;
        } else if " \t\r\n;|&()".contains(c) {
            if let Some(st) = start.take() {
                cmds.last_mut().unwrap().0.push((st, i.min(n)));
            }
            if !matches!(c, ' ' | '\t' | '\r') {
                let mut piped = c == '|';
                if (c == '|' || c == '&') && matches!(chars.get(i + 1), Some('|' | '&')) {
                    // ||  &&  |&
                    piped = c == '|' && chars[i + 1] == '&';
                    i += 1;
                }
                cmds.push((Vec::new(), piped));
            }
        } else {
            start.get_or_insert(i);
        }
        i += 1;
    }
    if quote.is_some() {
        return None;
    }
    if let Some(st) = start {
        cmds.last_mut().unwrap().0.push((st, n));
    }
    Some(cmds)
}

// ---------------------------------------------------------------------------------------------
// Direct reads of a secret file, and `find -exec`
//
// `mask-secrets --cat FILE...` prints the masked view of each file (secret files masked, other files as they are).
// A reader that names a secret file gets that operand moved in front of it, so it works on masked text:
//     head -1 .env        ->  <hook> --cat .env | head -1
// In `find ... -exec cat {} +` the hook takes the place of cat. `find ... -exec grep -H ... {} +` gets the --scrub
// filter like any other grep. Whatever cannot be rewritten that way stays blocked.
// ---------------------------------------------------------------------------------------------

pub const CAT_NOTICE: &str = "mask-secrets: the secret file this command reads is fed through mask-secrets --cat, so values in .env / \
.properties files show up as KEY=****. The command itself runs as written on the masked text. The real \
values are never printed, do not try to read them.";

/// (start, end, replacement) in chars
type Edit = (usize, usize, String);

struct ReaderSpec {
    short: String,
    short_value: String,
    long: Vec<&'static str>,
    long_value: Vec<&'static str>,
    /// the first operand is a script / pattern unless -e / -f gives one
    script: bool,
    /// -NUM allowed
    digits: bool,
}

/// Only options whose output is the (masked) text: nothing that writes files (sed -i, sort -o), reads more files
/// (sed -f) or recurses (grep -r).
fn reader_spec(head: &str) -> Option<ReaderSpec> {
    let spec = |short: &str,
                short_value: &str,
                long: &[&'static str],
                long_value: &[&'static str],
                script: bool,
                digits: bool| ReaderSpec {
        short: short.to_string(),
        short_value: short_value.to_string(),
        long: long.to_vec(),
        long_value: long_value.to_vec(),
        script,
        digits,
    };
    Some(match head {
        "cat" => spec(
            "AbeEnstTuv",
            "",
            &[
                "--show-all",
                "--number-nonblank",
                "--show-ends",
                "--number",
                "--squeeze-blank",
                "--show-tabs",
                "--show-nonprinting",
            ],
            &[],
            false,
            false,
        ),
        "tac" => spec("br", "s", &["--before", "--regex"], &["--separator"], false, false),
        "nl" => spec("p", "bdfhilnsvw", &[], &[], false, false),
        "head" | "tail" => spec(
            "qvz",
            "nc",
            &["--quiet", "--silent", "--verbose", "--zero-terminated"],
            &["--lines", "--bytes"],
            false,
            true,
        ),
        "sort" => spec(
            "bdfghiMnRrsuVzcCm",
            "ktTS",
            &[
                "--reverse",
                "--numeric-sort",
                "--unique",
                "--ignore-case",
                "--stable",
                "--ignore-leading-blanks",
                "--dictionary-order",
                "--version-sort",
                "--general-numeric-sort",
                "--human-numeric-sort",
                "--month-sort",
            ],
            &["--key", "--field-separator"],
            false,
            false,
        ),
        "cut" => spec(
            "nsz",
            "bcdf",
            &["--complement", "--only-delimited", "--zero-terminated"],
            &["--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"],
            false,
            false,
        ),
        "uniq" => spec(
            "cdiuD",
            "fsw",
            &["--count", "--repeated", "--ignore-case", "--unique"],
            &["--skip-fields", "--skip-chars", "--check-chars"],
            false,
            false,
        ),
        "sed" => spec(
            "nEsrzu",
            "el",
            &["--quiet", "--silent", "--regexp-extended", "--null-data", "--unbuffered", "--separate"],
            &["--expression", "--line-length"],
            true,
            false,
        ),
        "awk" | "gawk" => spec("", "Fv", &[], &[], true, false),
        "grep" | "egrep" | "fgrep" => ReaderSpec {
            short: GREP_SHORT.chars().filter(|c| *c != 'r').collect(),
            short_value: GREP_SHORT_VALUE.chars().filter(|c| !matches!(c, 'd' | 'D')).collect(),
            long: GREP_LONG.iter().copied().filter(|l| *l != "--recursive").collect(),
            long_value: GREP_LONG_VALUE
                .iter()
                .copied()
                .filter(|l| !matches!(*l, "--directories" | "--devices"))
                .collect(),
            script: true,
            digits: true,
        },
        _ => return None,
    })
}

static OPERAND_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^(?:~/)?[A-Za-z0-9_.+@%,:=/-]+$"));

/// Indexes of the file operands in a command line of one of the readers above, None when a flag is not one it knows.
fn reader_operands(head: &str, args: &[String]) -> Option<Vec<usize>> {
    let spec = reader_spec(head)?;
    let mut positional: Vec<usize> = Vec::new();
    let mut have_script = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            positional.extend(i + 1..args.len());
            break;
        }
        if a.starts_with("--") {
            let (name, eq) = match a.split_once('=') {
                Some((n, _)) => (n, true),
                None => (a.as_str(), false),
            };
            if spec.long_value.contains(&name) {
                if !eq {
                    i += 1;
                }
                have_script = have_script || matches!(name, "--regexp" | "--file" | "--expression");
            } else if !spec.long.contains(&name) || eq {
                return None;
            }
        } else if a.starts_with('-') && a.chars().count() > 1 {
            let chars: Vec<char> = a.chars().collect();
            let mut j = 1;
            while j < chars.len() {
                let c = chars[j];
                if spec.short_value.contains(c) {
                    have_script = have_script || c == 'e' || c == 'f';
                    if j == chars.len() - 1 {
                        i += 1;
                    }
                    break;
                }
                if spec.digits && c.is_ascii_digit() {
                    j += 1;
                    continue;
                }
                if !spec.short.contains(c) {
                    return None;
                }
                j += 1;
            }
        } else {
            positional.push(i);
        }
        i += 1;
    }
    if spec.script && !have_script {
        if positional.is_empty() {
            return None;
        }
        positional.remove(0); // the sed script / awk program / grep pattern
    }
    Some(positional)
}

/// What the shell makes of one word of the command (quotes removed), None when it is not exactly one token.
fn word_token(raw: &str) -> Option<String> {
    let mut toks = tokenize(raw);
    if toks.len() == 1 { toks.pop() } else { None }
}

fn span_text(chars: &[char], span: &(usize, usize)) -> String {
    chars[span.0..span.1].iter().collect()
}

/// Edits that move the secret-file operand of a reader into `<hook> --cat FILE |`, or None (nothing to do, or the
/// command is not one that can be rewritten safely: other redirects, expansions, several operands, flags unknown).
fn reader_edits(
    chars: &[char],
    words: &[(usize, usize)],
    k: usize,
    head: &str,
    cwds: &[String],
    pre: &str,
) -> Option<Vec<Edit>> {
    let mut idx: Vec<usize> = Vec::new();
    let mut toks: Vec<String> = Vec::new();
    for m in k + 1..words.len() {
        let raw = span_text(chars, &words[m]);
        let e = words[m].1;
        let follows: String = chars[e..(e + 2).min(chars.len())].iter().collect();
        if raw == "2>/dev/null" || (raw == "2>" && follows == "&1") {
            continue;
        }
        let tok = word_token(&raw)?;
        if REDIRECT_RE.is_match(&tok) {
            return None;
        }
        idx.push(m);
        toks.push(tok);
    }
    let ops = reader_operands(head, &toks)?;
    if ops.is_empty() {
        return None;
    }
    let names: Vec<&String> = ops.iter().map(|&o| &toks[o]).collect();
    if (head != "cat" && ops.len() != 1)
        || !names.iter().all(|n| OPERAND_RE.is_match(n) && !n.starts_with('-'))
    {
        return None;
    }
    if matches!(head, "awk" | "gawk") && names.iter().any(|n| n.contains('=')) {
        return None; // `awk ... var=value file`
    }
    if !names
        .iter()
        .any(|n| cwds.iter().any(|b| is_secret_file(&resolve(n, b))))
    {
        return None;
    }
    let raw_ops: Vec<String> = ops.iter().map(|&o| span_text(chars, &words[idx[o]])).collect();
    let mut edits: Vec<Edit> = vec![(
        words[k].0,
        words[k].0,
        format!("{} --cat {} | ", shell_quote(pre), raw_ops.join(" ")),
    )];
    for &o in &ops {
        let m = idx[o];
        edits.push((words[m - 1].1, words[m].1, String::new()));
    }
    Some(edits)
}

/// What tokenize() makes of an escaped or quoted `;`
const FIND_TERMINATOR: &str = r"\;";

/// (index of -exec / -execdir / -ok / -okdir, index of its terminator or len(words), terminated) for each of them.
fn find_exec_groups(words: &[String]) -> Vec<(usize, usize, bool)> {
    let mut groups = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if matches!(words[i].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            let mut j = i + 1;
            while j < words.len()
                && !(words[j] == FIND_TERMINATOR || (words[j] == "+" && words[j - 1] == "{}"))
            {
                j += 1;
            }
            groups.push((i, j, j < words.len()));
            i = j;
        }
        i += 1;
    }
    groups
}

/// One `-exec CMD ARGS {}` whose output cannot show secret values: `<hook> --cat {}`, or a grep that names its files
/// (-H) and whose find output goes through --scrub.
fn exec_group_masked(group: &[String], pre: Option<&str>, scrubbed: bool) -> bool {
    let Some(pre) = pre else {
        return false;
    };
    if group.is_empty() {
        return false;
    }
    if group[0] == pre && group.get(1).map(String::as_str) == Some("--cat") {
        return true;
    }
    let head = basename(&group[0]);
    if matches!(head, "grep" | "egrep" | "fgrep") && scrubbed {
        let args: Vec<String> = group[1..].iter().filter(|w| *w != "{}").cloned().collect();
        return search_flags(head, &args)
            .is_some_and(|f| f.iter().any(|x| x == "H" || x == "--with-filename"));
    }
    false
}

const FIND_WRITERS: &[&str] = &["-fprint", "-fprint0", "-fprintf"];

/// (every -exec of this find prints masked output, at least one -exec could print secret values raw)
fn find_exec_state(seg: &Segment, pre: Option<&str>) -> (bool, bool) {
    let args = &seg.args;
    let (mut seen_masked, mut unsafe_) = (false, false);
    for (i, j, done) in find_exec_groups(args) {
        let group = &args[i + 1..j];
        if done && exec_group_masked(group, pre, seg.scrubbed) {
            seen_masked = true;
        } else if done && group.first().is_some_and(|g| has(SAFE_HEADS, basename(g))) {
            continue;
        } else {
            unsafe_ = true;
        }
    }
    let ok = !args.iter().any(|a| has(FIND_WRITERS, a));
    (seen_masked && !unsafe_ && ok, unsafe_)
}

static FIND_OPT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^-O[0-3]$"));

/// A `find` whose -exec hands files to a program that could print them, over a tree with secret files.
fn find_exposure(seg: &Segment, cwds: &[String], cwd: &str, budget: &mut Budget) -> Option<String> {
    let args = &seg.args;
    let groups = find_exec_groups(args);
    let outside: Vec<&String> = args
        .iter()
        .enumerate()
        .filter(|(n, _)| !groups.iter().any(|(i, j, _)| i <= n && n <= j))
        .map(|(_, a)| a)
        .collect();
    let mut first = 0;
    while first < args.len()
        && (matches!(args[first].as_str(), "-H" | "-L" | "-P") || FIND_OPT_RE.is_match(&args[first]))
    {
        first += 1;
    }
    let mut last = first;
    while last < args.len() && !(args[last].starts_with('-') || matches!(args[last].as_str(), "!" | r"\(")) {
        last += 1;
    }
    let default_root = [".".to_string()];
    let roots: &[String] = if first < last { &args[first..last] } else { &default_root };
    let mut dirs: Vec<String> = Vec::new();
    for r in roots {
        for base in cwds {
            let p = resolve(r, base);
            if is_dir(&p) {
                dirs.push(p);
            }
        }
    }
    let mut hits: Vec<String> = Vec::new();
    for d in &dirs {
        hits.extend(walk_targets(d, budget, None));
    }
    let mut filters: Vec<(bool, &String)> = Vec::new();
    // a plain conjunction narrows what -exec sees
    if !outside
        .iter()
        .any(|a| matches!(a.as_str(), "-o" | "-or" | "!" | "-not" | r"\("))
    {
        for w in outside.windows(2) {
            if matches!(w[0].as_str(), "-name" | "-iname") {
                filters.push((w[0] == "-iname", w[1]));
            }
        }
    }
    let hits: Vec<String> = dedup(hits)
        .into_iter()
        .filter(|p| {
            filters.iter().all(|(ic, v)| {
                if *ic {
                    fnmatch(&basename(p).to_lowercase(), &v.to_lowercase())
                } else {
                    fnmatch(basename(p), v)
                }
            })
        })
        .collect();
    if hits.is_empty() && !budget.incomplete {
        return None;
    }
    let found = if hits.is_empty() {
        "the tree is too large to verify".to_string()
    } else {
        let rel: Vec<String> = hits
            .iter()
            .take(8)
            .map(|p| if p.starts_with(cwd) { relpath(p, cwd) } else { p.clone() })
            .collect();
        format!("{} secret file(s) such as: {}", hits.len(), rel.join(", "))
    };
    Some(format!(
        "Blocked: this find -exec would hand .properties/.env files to a program that prints them ({found}). Their \
values are secrets. `-exec cat {{}} +` and `-exec grep -H ... {{}} +` are rewritten to print them masked. \
For anything else exclude them (! -name '.env' ! -name '*.env' ! -name '*.properties'), restrict -name \
to specific source files, or search a subdirectory that has none."
    ))
}

/// `-exec cat {}` becomes `-exec <hook> --cat {}`; `-exec grep ... {}` gets -H and the whole find is piped through
/// --scrub. Other -exec actions are left alone (the caller's second analysis blocks what is still unsafe).
/// Returns the edits and whether a cat / a scrub filter was used.
fn find_edits(
    chars: &[char],
    words: &[(usize, usize)],
    k: usize,
    pre: &str,
) -> (Vec<Edit>, bool, bool) {
    let base = k + 1;
    let texts: Vec<String> = words[base..]
        .iter()
        .map(|w| word_token(&span_text(chars, w)).unwrap_or_else(|| "\0".to_string()))
        .collect();
    let mut edits: Vec<Edit> = Vec::new();
    let (mut cat, mut scrub, mut counts) = (false, false, true);
    for (i, j, done) in find_exec_groups(&texts) {
        let group = &texts[i + 1..j];
        if !done || group.is_empty() || group.iter().any(|g| g == "\0") {
            continue;
        }
        let head = basename(&group[0]);
        let at = words[base + i + 1];
        if head == "cat" && group[1..] == ["{}"] {
            edits.push((at.0, at.1, format!("{} --cat", shell_quote(pre))));
            cat = true;
        } else if matches!(head, "grep" | "egrep" | "fgrep")
            && group.last().is_some_and(|g| g == "{}")
            && group.iter().filter(|g| *g == "{}").count() == 1
        {
            let Some(flags) = search_flags(head, &group[1..group.len() - 1]) else {
                continue;
            };
            let has_flag = |names: &[&str]| flags.iter().any(|f| names.contains(&f.as_str()));
            if !has_flag(&["H", "--with-filename"]) {
                edits.push((at.1, at.1, " -H".to_string()));
            }
            counts = counts && has_flag(&["c", "--count"]);
            scrub = true;
        }
    }
    if scrub {
        let end = words[words.len() - 1].1;
        edits.push((
            end,
            end,
            format!(" | {} --scrub{}", shell_quote(pre), if counts { " --counts" } else { "" }),
        ));
    }
    (edits, cat, scrub)
}

pub struct Rewrite {
    pub command: String,
    pub rg: bool,
    pub git: bool,
    pub scrub: bool,
    pub cat: bool,
}

/// Make a command that would be blocked print its secrets masked instead.
///
///   rg                  gets --pre <hook> --pre-glob ... (rg searches the masked files)
///   git (diff, ...)     gets the textconv options (git prints the masked files)
///   grep -r, ag, ack    get `| <hook> --scrub` (a filter that masks lines that start with a secret file's path)
///   reader FILE         (cat, head, sed, awk, grep ...) a secret file operand moves into `<hook> --cat FILE |`
///   find -exec          `-exec cat {}` becomes `-exec <hook> --cat {}`, `-exec grep` gets -H and `| <hook> --scrub`
///
/// Returns None when the command is too complex to edit safely (nested shells, substitutions, heredocs, quoted or
/// redirected command words), a flag cannot be masked, or an rg segment brings its own --pre. Codex gets rg only.
/// The caller analyses the result again.
pub fn rewrite_command(cmd: &str, cwd: &str, pre: &str, codex: bool) -> Option<Rewrite> {
    if REWRITE_UNSAFE.iter().any(|p| cmd.contains(p)) {
        return None;
    }
    let mut segments: Vec<Segment> = Vec::new();
    collect_segments(cmd, &mut segments, 0);
    if segments
        .iter()
        .any(|s| s.head == "rg" && rg_flag_blocks_rewrite(&s.args))
    {
        return None;
    }
    let chars: Vec<char> = cmd.chars().collect();
    let cmds = command_spans(&chars)?;
    let cwds = cwd_candidates(&segments, cwd);
    let mut budget = Budget::new();
    let mut inserts: Vec<Edit> = Vec::new();
    let mut out = Rewrite {
        command: String::new(),
        rg: false,
        git: false,
        scrub: false,
        cat: false,
    };
    let word = |&(s, e): &(usize, usize)| -> String { chars[s..e].iter().collect() };
    for (words, piped) in &cmds {
        let mut k = 0;
        // only keywords (`if`, `do`, `!` ...) before the command: a wrapper or assignment changes what it reads
        let mut lead_ok = true;
        while k < words.len() {
            let w = word(&words[k]);
            if w.contains(['\'', '"', '\\']) {
                break;
            }
            let wrapper = has(WRAPPERS, basename(&w));
            if wrapper || has(LEADING_KEYWORDS, &w) || ASSIGN_RE.is_match(&w) {
                lead_ok = lead_ok && !(wrapper || ASSIGN_RE.is_match(&w));
                k += 1;
                while wrapper && k < words.len() {
                    let x = word(&words[k]);
                    if !(x.starts_with('-') || NUMBER_RE.is_match(&x)) {
                        break;
                    }
                    k += 1;
                }
                continue;
            }
            let head = basename(&w).to_string();
            let direct = if !codex && lead_ok && reader_spec(&head).is_some() {
                reader_edits(&chars, words, k, &head, &cwds, pre)
            } else {
                None
            };
            if head == "rg" {
                inserts.push((words[k].1, words[k].1, format!(" {}", rg_mask_flags(pre))));
                out.rg = true;
            } else if let Some(edits) = direct {
                inserts.extend(edits);
                out.cat = true;
            } else if head == "find" && !codex {
                let (edits, cat, scrub) = find_edits(&chars, words, k, pre);
                inserts.extend(edits);
                out.cat |= cat;
                out.scrub |= scrub;
            } else if matches!(head.as_str(), "git" | "grep" | "egrep" | "fgrep" | "ag" | "ack")
                && !codex
            {
                let text: String = chars[words[0].0..words[words.len() - 1].1].iter().collect();
                let mut own: Vec<Segment> = Vec::new();
                collect_segments(&text, &mut own, 0);
                if own.len() != 1 {
                    return None;
                }
                let mut seg = own.remove(0);
                seg.piped = *piped;
                if head == "git" {
                    let (sub, rest) = git_parts(&seg.args);
                    if git_reads_content(&sub, &rest) && !git_masks_secrets(&seg.args, Some(pre)) {
                        let target = git_mask_target(&seg.args)?;
                        if ensure_git_attributes().is_none() || !git_attributes_win(pre, &cwds) {
                            return None;
                        }
                        let (at, opts) = target;
                        if !opts.is_empty() {
                            // the options go right after the subcommand (after `show` for `git stash show`)
                            let wrd = words.get(k + 1 + at)?;
                            if word(wrd) != seg.args[at] {
                                return None;
                            }
                            inserts.push((wrd.1, wrd.1, format!(" {}", opts.join(" "))));
                        }
                        let configs: Vec<String> = git_mask_configs(pre)
                            .iter()
                            .map(|c| format!("-c {}", shell_quote(c)))
                            .collect();
                        inserts.push((words[k].1, words[k].1, format!(" {}", configs.join(" "))));
                        out.git = true;
                    }
                } else if recursive_exposure(&seg, &cwds, cwd, &mut budget).is_some() {
                    let (ok, counts, _) = search_args_ok(&head, &seg.args);
                    if !ok {
                        return None;
                    }
                    inserts.push((
                        words[words.len() - 1].1,
                        words[words.len() - 1].1,
                        format!(
                            " | {} --scrub{}",
                            shell_quote(pre),
                            if counts { " --counts" } else { "" }
                        ),
                    ));
                    out.scrub = true;
                }
            }
            break;
        }
    }
    if inserts.is_empty() {
        return None;
    }
    inserts.sort_by(|a, b| (b.0, b.1).cmp(&(a.0, a.1)));
    let mut result = chars.clone();
    for (start, end, text) in inserts {
        result.splice(start..end, text.chars());
    }
    out.command = result.into_iter().collect();
    Some(out)
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
    let pre = preprocessor();
    for i in 1..segments.len() {
        // `grep ... | <this hook> --scrub`
        let nxt = &segments[i];
        let scrub_args = nxt.args == ["--scrub"] || nxt.args == ["--scrub", "--counts"];
        if let Some(p) = &pre
            && nxt.piped
            && scrub_args
            && nxt.words.contains(p)
        {
            segments[i - 1].scrubbed = true;
        }
    }
    // `<this hook> --cat FILE...`: prints the files masked, whatever they are. The words before the arguments are
    // keywords, then the command.
    for s in segments.iter_mut() {
        let lead = &s.words[..s.words.len() - s.args.len()];
        s.masked = pre.as_deref().is_some_and(|p| {
            s.args.first().map(String::as_str) == Some("--cat")
                && lead.last().map(String::as_str) == Some(p)
                && lead[..lead.len() - 1].iter().all(|w| has(LEADING_KEYWORDS, w))
        });
    }

    let mut direct: Vec<String> = Vec::new();
    let mut mentioned: Vec<String> = Vec::new();
    for s in &segments {
        if s.masked {
            continue;
        }
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
        if s.head == "git" && git_masks_secrets(&s.args, pre.as_deref()) {
            continue; // textconv masks every file this git command prints, whatever it is named
        }
        if s.head == "find" && find_exec_state(s, pre.as_deref()).0 {
            continue; // every -exec prints masked output
        }
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
        } else if s.head == "find" && find_exec_state(s, pre.as_deref()).1 {
            find_exposure(s, &cwds, cwd, budget)
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
