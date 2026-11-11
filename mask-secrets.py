#!/usr/bin/env python3
"""Shared Claude/Codex PreToolUse hook: keep .properties and .env values out of the conversation.

PreToolUse cannot rewrite tool output, so when an agent tries to read one of these files the
call is denied and, where a single file is involved, the masked content (KEY=****) is returned in
the deny reason instead. Both agents use this single policy.

What it covers
  * Read / Grep tools pointing at a secret file (also through a symlink).
  * Bash: a secret file named anywhere in a command that can print file content. That includes
    readers (cat, grep, sed ...), unknown programs (python, awk, curl ...), loop lists and
    variables (`for f in a.properties; do cat "$f"; done`), `$(...)`, backticks, `bash -c`,
    `< file`, relative names after `cd`, globs, and `find -exec`/`xargs`.
  * git commands that print content (diff, show, log -p, blame, grep, ...) unless limited to
    explicit non-secret files or the secret file types are excluded with pathspecs.
  * Recursive searches (grep -r, rg, ag, ack, Grep tool in content mode) over a tree holding
    secret files unless the command excludes them.
  * MCP tools: any string argument that names an existing secret file.
  * Fail closed: if the hook itself errors on a request that mentions a secret file, deny.

Remaining limitations (use `permissions.deny` Read rules and a sandbox for a hard guarantee):
programs that build the filename at run time, copies of the file under another name, and
`git diff`-style commands whose output happens to include a secret file the command never names
(only handled for the git commands above).
"""
import fnmatch
import glob
import json
import os
import re
import shlex
import sys
import time

MASK = "****"
MAX_LINES = 500
MAX_PREVIEW_FILES = 5
WALK_BUDGET_SECONDS = 2.0
WALK_MAX_ENTRIES = 60000
SKIP_DIRS = {".git", "node_modules"}
GREP_TOOL_DIR_CHECK = True
# Template files normally hold no real secrets; let them through unmasked.
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tpl")

READERS = {
    "cat", "tac", "head", "tail", "less", "more", "bat", "batcat", "nl", "grep",
    "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "cut", "sort",
    "uniq", "strings", "xxd", "od", "hexdump", "diff", "column", "paste", "tee",
    "source", ".", "view", "vim", "vi", "nano", "bash", "sh", "zsh",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"rtk", "sudo", "pkexec", "doas", "command", "env", "time", "nohup", "nice", "ionice",
            "stdbuf", "timeout", "exec", "builtin"}
LEADING_KEYWORDS = {"while", "until", "if", "elif", "then", "else", "do", "!", "{", "time"}
LIST_KEYWORDS = {"for", "select", "case"}
BLOCK_END = {"done", "fi", "esac", "}", "in"}
# Commands that never print the content of a file operand.
SAFE_HEADS = {
    "ls", "stat", "file", "wc", "test", "[", "[[", "echo", "printf", "basename", "dirname", "realpath",
    "readlink", "true", "false", ":", "cd", "pushd", "popd", "pwd", "touch", "mkdir", "rm", "rmdir", "mv",
    "cp", "ln", "chmod", "chown", "du", "df", "which", "type", "export", "unset", "set", "exit", "return",
    "sleep", "date", "id", "whoami", "uname", "md5sum", "sha1sum", "sha256sum", "cksum", "tree",
}
RECURSIVE_SEARCHERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf"}
SEPARATORS = {";", ";;", "&&", "||", "|", "&", "|&"}
GROUPERS = {"(", ")", "((", "))", "<(", ">("}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
NUMBER_RE = re.compile(r"^[0-9][0-9smhd.]*$")
WORD_SPLIT_RE = re.compile(r"""[\s'"`()<>|&;{},:=]+""")
SUBST_RE = re.compile(r"\$\(([^()]*)\)")
SAMPLE_SECRET_NAMES = ("a.properties", ".env", "a.env", ".env.local")
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                       "--config-env"}
GIT_PATCH_RE = re.compile(r"^(-p|-u|--patch|--patch-with-stat|--patch-with-raw|--cc|--combined|--dd|-L.*|-U\d*|--unified(=\d+)?)$")
GIT_NO_CONTENT = {"--stat", "--name-only", "--name-status", "--numstat", "--shortstat", "--summary", "--dirstat",
                  "--check", "--quiet", "-q", "--no-patch", "-s", "--raw", "--compact-summary"}
GIT_GREP_NO_CONTENT = {"-l", "--files-with-matches", "-L", "--files-without-match", "-c", "--count", "-q", "--quiet"}
GIT_EXCLUDE_ADVICE = "-- . ':(exclude)*.properties' ':(exclude)*.env' ':(exclude).env*'"


class Budget:
    """Bounds directory walks so the hook always finishes inside its timeout."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + WALK_BUDGET_SECONDS
        self.entries = 0
        self.incomplete = False

    def exhausted(self) -> bool:
        if not self.incomplete and (time.monotonic() > self.deadline or self.entries > WALK_MAX_ENTRIES):
            self.incomplete = True
        return self.incomplete


def is_target(path: str) -> bool:
    name = os.path.basename(path.rstrip("/"))
    if not name or name.lower().endswith(TEMPLATE_SUFFIXES):
        return False
    low = name.lower()
    return low == ".env" or low.startswith(".env.") or low.endswith(".env") or low.endswith(".properties")


def is_secret_file(path: str) -> bool:
    """A regular file that is, or is a symlink to, a secret-bearing file."""
    if not os.path.isfile(path):
        return False
    return is_target(path) or (os.path.islink(path) and is_target(os.path.realpath(path)))


def mask_properties_line(line: str) -> str:
    m = re.match(r"^(\s*)((?:\\.|[^\s=:\\])+)(\s*[=:]\s*|\s+)(.*)$", line)
    if not m:
        return line
    indent, key, sep, value = m.groups()
    return f"{indent}{key}{sep}{MASK if value else ''}"


def mask_env_line(line: str) -> str:
    m = re.match(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*=\s*)(.*)$", line)
    if not m:
        return line
    prefix, value = m.groups()
    return f"{prefix}{MASK if value.strip() else ''}"


def has_closing_quote(text: str, quote: str) -> bool:
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return True
    return False


def mask_text(path: str, text: str) -> str:
    is_props = path.lower().endswith(".properties")
    out = []
    continued = False  # .properties value continued with trailing backslash
    env_quote = None
    for line in text.splitlines():
        stripped = line.strip()
        if env_quote:
            out.append(MASK if stripped else line)
            if has_closing_quote(line, env_quote):
                env_quote = None
            continue
        if continued:
            out.append(MASK if stripped else line)
            continued = line.rstrip().endswith("\\")
            continue
        comment_chars = "#!" if is_props else "#"
        if not stripped or stripped[0] in comment_chars:
            out.append(line)
            continue
        out.append(mask_properties_line(line) if is_props else mask_env_line(line))
        if is_props:
            continued = line.rstrip().endswith("\\")
        else:
            assignment = re.match(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*=\s*(.*)$", line)
            value = assignment.group(1).lstrip() if assignment else ""
            if value and value[0] in "\"'" and not has_closing_quote(value[1:], value[0]):
                env_quote = value[0]
    return "\n".join(out)


def render(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    masked = mask_text(path, text).split("\n")
    if len(masked) > MAX_LINES:
        extra = len(masked) - MAX_LINES
        masked = masked[:MAX_LINES] + [f"... ({extra} more lines truncated)"]
    return "\n".join(f"{i:>6}\t{l}" for i, l in enumerate(masked, 1))


def resolve(path: str, cwd: str) -> str:
    path = os.path.expanduser(path)
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def tokenize(cmd: str) -> list[str]:
    cmd = cmd.replace("\n", " ; ")
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return cmd.split()


# ---------------------------------------------------------------------------------------------
# Directory walks and candidate resolution
# ---------------------------------------------------------------------------------------------
def walk_targets(root: str, budget: Budget, matcher=None) -> list[str]:
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        budget.entries += len(dirnames) + len(filenames)
        if budget.exhausted():
            break
        for name in filenames:
            if is_target(name) and (matcher is None or matcher(name)):
                hits.append(os.path.join(dirpath, name))
    return hits


def exclusion_indexes(words: list[str]) -> set[int]:
    """Words that only EXCLUDE secret files (--exclude=*.properties, -g '!*.env', :(exclude)*.env)."""
    skip: set[int] = set()
    for i, w in enumerate(words):
        nxt = words[i + 1] if i + 1 < len(words) else ""
        if w.startswith(("--exclude=", "--ignore=", "--exclude-from=", "-g!")) or w.startswith("!") \
                or re.match(r"^:(\([^)]*exclude[^)]*\)|[!^])", w):
            skip.add(i)
        elif w in {"--exclude", "--ignore"} or (w in {"-g", "--glob"} and nxt.startswith("!")):
            skip.update({i, i + 1})
        elif w.startswith("--glob=!"):
            skip.add(i)
    return skip


def expand_braces(pattern: str, limit: int = 256) -> list[str]:
    """Shell-style brace expansion (`*.{properties,txt}` -> two patterns), capped to stay cheap."""
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out += expand_braces(pattern[:m.start()] + alt + pattern[m.end():], limit)
        if len(out) >= limit:
            break
    return out[:limit]


def candidates_in_word(word: str) -> list[str]:
    """Secret-looking file names mentioned anywhere inside one shell word (quotes, $(), a=b, a:b, {a,b} ...)."""
    return [p for w in expand_braces(word) for p in WORD_SPLIT_RE.split(w) if p and is_target(p)]


def resolve_candidate(cand: str, cwds: list[str], wide: bool, budget: Budget) -> list[str]:
    c = os.path.expandvars(os.path.expanduser(cand.lstrip("!@")))
    if "$" in c or not c:
        return []  # run-time value; handled by the "dynamic reader" rule
    wild = any(ch in c for ch in "*?[")
    hits: list[str] = []
    recursive_pattern = "**" in c
    if not recursive_pattern:
        for base in cwds:
            full = c if os.path.isabs(c) else os.path.join(base, c)
            if wild:
                hits += [p for p in glob.glob(full) if is_secret_file(p)]
            elif is_secret_file(full):
                hits.append(full)
    if not hits and (wide or recursive_pattern) and ("/" not in c or recursive_pattern):
        pattern = os.path.basename(c).lower()
        for base in cwds:
            hits += walk_targets(base, budget, lambda name: fnmatch.fnmatch(name.lower(), pattern))
    return [os.path.normpath(p) for p in hits]


# ---------------------------------------------------------------------------------------------
# Bash analysis
# ---------------------------------------------------------------------------------------------
def git_parts(args: list[str]) -> tuple[str, list[str]]:
    i = 0
    while i < len(args):
        a = args[i]
        if a in GIT_OPTS_WITH_VALUE:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1:]
    return "", []


def git_reads_content(sub: str, rest: list[str]) -> bool:
    has_patch = any(GIT_PATCH_RE.match(a) or (a == "-c" and sub != "grep") for a in rest)
    if sub in {"log", "whatchanged", "reflog", "stash", "diff-tree", "diff-index", "diff-files", "range-diff"}:
        return has_patch
    if sub in {"diff", "show", "difftool"}:
        return has_patch or not any(a in GIT_NO_CONTENT for a in rest)
    if sub == "grep":
        return not any(a in GIT_GREP_NO_CONTENT for a in rest)
    if sub == "cat-file":
        return not any(a in {"-t", "-s", "-e"} for a in rest)
    return sub in {"blame", "annotate"}


def make_segment(words: list[str], reads: list[str], piped: bool) -> dict:
    w = list(words)
    while w and (os.path.basename(w[0]) in WRAPPERS or w[0] in LEADING_KEYWORDS or ASSIGN_RE.match(w[0])):
        was_wrapper = os.path.basename(w[0]) in WRAPPERS
        w.pop(0)
        while was_wrapper and w and (w[0].startswith("-") or NUMBER_RE.match(w[0])):
            w.pop(0)
    head = os.path.basename(w[0]) if w else ""
    args = w[1:]
    if not w:
        kind = "assign" if words else "neutral"
    elif head in LIST_KEYWORDS or head in BLOCK_END:
        kind = "neutral"
    elif head in READERS:
        kind = "reader"
    elif head == "git":
        sub, rest = git_parts(args)
        kind = "reader" if git_reads_content(sub, rest) else "safe"
    elif head == "find":
        kind = "reader" if any(a in FIND_EXEC for a in args) else "safe"
    elif head in SAFE_HEADS:
        kind = "safe"
    else:
        kind = "unknown"
    dynamic = kind in {"reader", "unknown"} and (any("$" in x for x in words) or head in {"xargs", "parallel"})
    return {"head": head, "args": args, "words": words, "reads": reads, "kind": kind, "piped": piped,
            "dynamic": dynamic}


def collect_segments(cmd: str, segments: list[dict], depth: int = 0) -> None:
    if depth > 3:
        return
    for m in re.finditer(r"`([^`]*)`", cmd):
        collect_segments(m.group(1), segments, depth + 1)
    tokens = tokenize(cmd)
    chunks: list[tuple[list[str], bool]] = []
    cur: list[str] = []
    piped = False
    for t in tokens:
        if t in SEPARATORS or t in GROUPERS:
            chunks.append((cur, piped))
            cur, piped = [], t in {"|", "|&"}
        else:
            cur.append(t)
    chunks.append((cur, piped))
    for toks, was_piped in chunks:
        words, reads, i = [], [], 0
        while i < len(toks):
            t = toks[i]
            if t in WRITE_REDIRECTS and i + 1 < len(toks):
                i += 2  # skip write target
                continue
            if t == "<" and i + 1 < len(toks):
                reads.append(toks[i + 1])
                i += 2
                continue
            if re.fullmatch(r"[0-9]*[<>]+&?[0-9-]*", t):
                i += 1
                continue
            words.append(t)
            i += 1
        seg = make_segment(words, reads, was_piped)
        segments.append(seg)
        for token in words + reads:  # nested commands inside one shell word
            for m in SUBST_RE.finditer(token):
                if m.group(1):
                    collect_segments(m.group(1), segments, depth + 1)
        if seg["head"] in SHELLS:
            for idx, a in enumerate(seg["args"][:-1]):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a):
                    collect_segments(seg["args"][idx + 1], segments, depth + 1)
                    break
        elif seg["head"] == "eval":
            collect_segments(" ".join(seg["args"]), segments, depth + 1)


def cwd_candidates(segments: list[dict], cwd: str) -> list[str]:
    """Base cwd plus every directory the command could be running in after cd / pushd / git -C."""
    out = [cwd]
    cur = cwd
    for s in segments:
        args = s["args"]
        if s["head"] in {"cd", "pushd"}:
            targets = [a for a in args if not a.startswith("-")]
            raw = targets[0] if targets else "~"
            target = os.path.expandvars(os.path.expanduser(raw))
            if "$" in target:
                continue
            cur = os.path.normpath(target if os.path.isabs(target) else os.path.join(cur, target))
            out += [cur, os.path.normpath(target if os.path.isabs(target) else os.path.join(cwd, target))]
        elif s["head"] == "git":
            for idx, a in enumerate(args[:-1]):
                if a == "-C":
                    d = os.path.expanduser(args[idx + 1])
                    out.append(os.path.normpath(d if os.path.isabs(d) else os.path.join(cur, d)))
    return [d for d in dict.fromkeys(out) if os.path.isdir(d)]


def parse_filters(args: list[str]) -> tuple[list[str], list[str], bool]:
    """include globs, exclude globs, narrowed-by-type flag for grep / rg / ag style options."""
    inc: list[str] = []
    exc: list[str] = []
    narrowed = False
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        value = None
        kind = None
        if a.startswith("--exclude=") or a.startswith("--ignore="):
            kind, value = "exc", a.split("=", 1)[1]
        elif a in {"--exclude", "--ignore"}:
            kind, value, i = "exc", nxt, i + 1
        elif a.startswith("--include="):
            kind, value = "inc", a.split("=", 1)[1]
        elif a == "--include":
            kind, value, i = "inc", nxt, i + 1
        elif a.startswith("--glob="):
            kind, value = "glob", a.split("=", 1)[1]
        elif a in {"--glob", "-g"}:
            kind, value, i = "glob", nxt, i + 1
        elif a.startswith("-g") and not a.startswith("--") and len(a) > 2:
            kind, value = "glob", a[2:]
        elif a in {"-t", "--type", "-G", "--file-search-regex"} or a.startswith("--type="):
            narrowed = True
        if kind == "exc":
            exc.append(value)
        elif kind == "inc":
            inc.append(value)
        elif kind == "glob":
            (exc if value.startswith("!") else inc).append(value.lstrip("!"))
        i += 1
    return inc, exc, narrowed


def filter_hits(hits: list[str], inc: list[str], exc: list[str], narrowed: bool) -> list[str]:
    if narrowed:
        return []
    inc = [x for i in inc for x in expand_braces(i)]
    exc = [x for e in exc for x in expand_braces(e)]
    out = []
    for p in hits:
        name = os.path.basename(p)
        if inc and not any(fnmatch.fnmatch(name, i) for i in inc):
            continue
        if any(fnmatch.fnmatch(name, e) for e in exc):
            continue
        out.append(p)
    return out


SEARCH_ADVICE = ("Search without them instead: exclude those file types (grep: --exclude='*.properties' "
                 "--exclude='*.env' --exclude='.env*'; rg: -g '!*.properties' -g '!*.env' -g '!.env*'), restrict it "
                 "to specific source files or types (--include='*.java', -t java), or search a subdirectory that "
                 "has none.")
GREP_TOOL_ADVICE = ("Search without them instead: set glob to specific source files (e.g. \"*.java\") or type "
                    "(e.g. \"java\"), use output_mode files_with_matches, or search a subdirectory that has none.")


def search_exposure(label: str, dirs: list[str], inc: list[str], exc: list[str], narrowed: bool,
                    cwd: str, budget: Budget, advice: str = SEARCH_ADVICE) -> str | None:
    hits: list[str] = []
    for d in dirs:
        hits += walk_targets(d, budget)
    hits = filter_hits(list(dict.fromkeys(hits)), inc, exc, narrowed)
    if not hits and not budget.incomplete:
        return None
    rel = [os.path.relpath(p, cwd) if p.startswith(cwd) else p for p in hits[:8]]
    found = (f"{len(hits)} secret file(s) such as: " + ", ".join(rel)) if hits else "the tree is too large to verify"
    return (f"Blocked: this {label} would read .properties/.env files ({found}). Their values are secrets. "
            + advice)


def recursive_exposure(seg: dict, cwds: list[str], cwd: str, budget: Budget) -> str | None:
    head, args = seg["head"], seg["args"]
    recursive = head in {"rg", "ag", "ack"} or any(
        re.fullmatch(r"-[A-Za-z0-9]*[rR][A-Za-z0-9]*", a) or a in {"--recursive", "--dereference-recursive",
                                                                      "--directories=recurse"}
        for a in args
    ) or any(a == "-d" and n == "recurse" for a, n in zip(args, args[1:]))
    if not recursive:
        return None
    dirs = []
    for a in args:
        if a.startswith("-"):
            continue
        for base in cwds:
            p = resolve(a, base)
            if os.path.isdir(p):
                dirs.append(p)
    if not dirs and not seg["piped"]:
        dirs = list(cwds)
    inc, exc, narrowed = parse_filters(args)
    return search_exposure(f"recursive {head}", dirs, inc, exc, narrowed, cwd, budget)


def git_exposure(seg: dict, cwds: list[str]) -> str | None:
    sub, rest = git_parts(seg["args"])
    if not git_reads_content(sub, rest):
        return None
    excluded = []
    for a in rest:
        m = re.match(r"^:(?:\((?P<magic>[^)]*)\)|(?P<short>[!^]+))(?P<pat>.*)$", a)
        if m and ("exclude" in (m.group("magic") or "") or m.group("short")):
            excluded.append(m.group("pat"))
    covers = lambda name: any(fnmatch.fnmatch(name, re.sub(r"^(\*\*/)+", "", p)) for p in excluded)
    if all(covers(n) for n in SAMPLE_SECRET_NAMES):
        return None
    operands = [a for a in rest if not a.startswith("-") and not a.startswith(":")]
    safe_files = dangerous = 0
    for a in operands:
        resolved = [resolve(a, b) for b in cwds]
        if any(ch in a for ch in "*?[") or a in {".", ".."} or any(os.path.isdir(p) for p in resolved) or is_target(a):
            dangerous += 1
        elif any(os.path.isfile(p) and not is_secret_file(p) for p in resolved):
            safe_files += 1
    if safe_files and not dangerous:
        return None
    return (f"Blocked: `git {sub}` can print the content of .properties/.env files (values are secrets). "
            f"Use --stat / --name-only / --name-status, name specific non-secret files, or exclude them: "
            f"git {sub} ... {GIT_EXCLUDE_ADVICE}")


def analyze_bash(cmd: str, cwd: str, budget: Budget | None = None) -> tuple[list[str], list[str]]:
    budget = budget or Budget()
    segments: list[dict] = []
    collect_segments(cmd, segments)
    cwds = cwd_candidates(segments, cwd)
    wide = any(s["head"] in {"find", "fd", "fdfind", "locate"} for s in segments)

    direct: list[str] = []
    mentioned: list[str] = []
    for s in segments:
        word_hits: list[str] = []
        skip = exclusion_indexes(s["words"])
        for i, w in enumerate(s["words"]):
            if i in skip:
                continue
            for cand in candidates_in_word(w):
                word_hits += resolve_candidate(cand, cwds, wide, budget)
        read_hits: list[str] = []
        for w in s["reads"]:
            for cand in candidates_in_word(w):
                read_hits += resolve_candidate(cand, cwds, wide, budget)
        mentioned += word_hits + read_hits
        if s["kind"] in {"reader", "unknown"}:
            direct += word_hits + read_hits
            # a symlink with an innocent name that points at a secret file
            for a in s["args"]:
                if not a.startswith("-"):
                    for base in cwds:
                        p = resolve(a, base)
                        if os.path.islink(p) and is_secret_file(p):
                            direct.append(os.path.normpath(p))
        elif s["kind"] in {"neutral", "assign"}:
            direct += read_hits  # `while read l; do ...; done < file`
    if not direct and mentioned and any(s["dynamic"] for s in segments):
        direct = list(mentioned)  # the filename is fed to a reader through a variable / xargs / $(...)

    issues: list[str] = []
    for s in segments:
        if s["kind"] != "reader":
            continue
        if s["head"] == "git":
            msg = git_exposure(s, cwds)
        elif s["head"] in RECURSIVE_SEARCHERS:
            msg = recursive_exposure(s, cwds, cwd, budget)
        else:
            msg = None
        if msg and msg not in issues:
            issues.append(msg)
    return list(dict.fromkeys(direct)), issues


# ---------------------------------------------------------------------------------------------
# Other tools
# ---------------------------------------------------------------------------------------------
def expand(token: str, cwd: str) -> list[str]:
    full = resolve(token, cwd)
    paths = glob.glob(full) if any(c in full for c in "*?[") else [full]
    return [p for p in paths if is_secret_file(p)]


def grep_tool_targets(inp: dict, cwd: str, budget: Budget) -> tuple[list[str], list[str]]:
    targets: list[str] = []
    for key in ("path", "glob"):
        v = inp.get(key)
        if v and is_target(v):
            targets += expand(v, cwd)
    targets = list(dict.fromkeys(targets))
    issues: list[str] = []
    if GREP_TOOL_DIR_CHECK and not targets and inp.get("output_mode") == "content":
        root = resolve(inp.get("path") or cwd, cwd)
        if os.path.isdir(root):
            glob_value = inp.get("glob") or ""
            inc = [glob_value] if glob_value and not glob_value.startswith("!") else []
            exc = [glob_value.lstrip("!")] if glob_value.startswith("!") else []
            msg = search_exposure("content search", [root], inc, exc, bool(inp.get("type")), cwd, budget,
                                  GREP_TOOL_ADVICE)
            if msg:
                issues.append(msg)
    return targets, issues


def iter_strings(obj, depth: int = 0):
    if depth > 6:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v, depth + 1)


def deny_with(reason: str) -> None:
    json.dump(
        {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                "permissionDecisionReason": reason}},
        sys.stdout,
    )


def deny(paths: list[str], cwd: str, issues: list[str] | None = None) -> None:
    blocks = []
    for p in paths[:MAX_PREVIEW_FILES]:
        body = render(p)
        if body is not None:
            rel = os.path.relpath(p, cwd) if p.startswith(cwd) else p
            blocks.append(f"=== {rel} (values masked) ===\n{body}")
    if len(paths) > MAX_PREVIEW_FILES:
        blocks.append(f"... and {len(paths) - MAX_PREVIEW_FILES} more secret file(s) not previewed")
    parts = []
    if blocks:
        parts.append(
            "Blocked: reading .env / .properties files directly is disabled to keep secret values out of the "
            "conversation. Here is the masked content instead (KEY=" + MASK + "). Do NOT retry the raw read or "
            "work around this hook; if you need an actual value, ask the user.\n\n" + "\n\n".join(blocks)
        )
    parts += issues or []
    if parts:
        deny_with("\n\n".join(parts))


def evaluate(data: dict) -> tuple[list[str], list[str], str]:
    tool, inp = data.get("tool_name"), data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    # Codex shell calls can run in a directory different from the session cwd.
    if tool in {"Bash", "exec_command", "shell_command", "shell"}:
        workdir = inp.get("workdir") or inp.get("cwd")
        if workdir:
            cwd = resolve(workdir, cwd)
    budget = Budget()
    targets: list[str] = []
    issues: list[str] = []

    if tool == "Read":
        fp = inp.get("file_path", "")
        p = resolve(fp, cwd) if fp else ""
        if p and is_secret_file(p):
            targets = [p]
    elif tool == "Grep":
        targets, issues = grep_tool_targets(inp, cwd, budget)
    elif tool in {"Bash", "exec_command", "shell_command", "shell"}:
        command = inp.get("command") or inp.get("cmd") or ""
        if isinstance(command, str):
            targets, issues = analyze_bash(command, cwd, budget)
    elif isinstance(tool, str) and tool.startswith("mcp__"):
        for s in iter_strings(inp):
            for cand in [s] + candidates_in_word(s):
                if is_target(cand):
                    targets += expand(cand, cwd)
        targets = list(dict.fromkeys(targets))
    return targets, issues, cwd


def main() -> None:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return
    try:
        targets, issues, cwd = evaluate(data)
        if targets or issues:
            deny(targets, cwd, issues)
    except Exception as exc:  # fail closed when the request touches a secret file name
        if re.search(r"\.properties|\.env", raw, re.IGNORECASE):
            deny_with(
                "Blocked: the secret-masking hook hit an internal error (" + type(exc).__name__ + ") on a request "
                "that mentions a .properties/.env file, so it was denied to be safe. Ask the user to check "
                "~/.local/share/ai-hooks/mask-secrets.py."
            )


if __name__ == "__main__":
    main()
