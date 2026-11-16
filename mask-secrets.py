#!/usr/bin/env python3
"""Shared Claude/Codex PreToolUse hook: keep .properties and .env values out of the conversation.

PreToolUse cannot rewrite tool output, so when an agent tries to read one of these files the
call is denied and, where a single file is involved, the masked content (KEY=****) is returned in
the deny reason instead. Where a command can be made to print the files masked, it is rewritten
(updatedInput) and runs instead of being blocked. Both agents use this single policy.

What it covers
  * Read / Grep tools pointing at a secret file (also through a symlink).
  * Bash: a secret file named anywhere in a command that can print file content. That includes
    readers (cat, grep, sed ...), unknown programs (python, awk, curl ...), loop lists and
    variables (`for f in a.properties; do cat "$f"; done`), `$(...)`, backticks, `bash -c`,
    `< file`, relative names after `cd`, globs, and `find -exec`/`xargs`.
  * git commands that print content (diff, show, log -p, blame, grep, ...) unless limited to
    explicit non-secret files or the secret file types are excluded with pathspecs. Otherwise they are
    rewritten to run with git's textconv filter pointed at this script (`--mask env|properties FILE`), so
    they print KEY=**** instead of the values (Claude only; see rewrite_command).
  * Recursive searches (grep -r, rg, ag, ack, Grep tool in content mode) over a tree holding
    secret files unless the command excludes them. A plain `rg` is rewritten (updatedInput) to
    `rg --pre <this script> --pre-glob ...`, so the secret files are still searched but in masked form (path,
    line number and key show up, the value is ****). grep / ag / ack get `| <this script> --scrub`, a filter
    that masks lines starting with a secret file's path. Codex only accepts a rewrite together with an
    approval, so there it is limited to rg piped into head/tail/wc/sort/uniq; the rest stays blocked.
  * Direct reads of a named secret file (`cat`, `tac`, `nl`, `head`, `tail`, `sort`, `cut`, `uniq`, `sed`, `awk`,
    `grep`) are rewritten so the file operand goes through the masked view: `head -1 .env` becomes
    `<this script> --cat .env | head -1`, which really runs and prints KEY=****. Only for one plain literal operand
    (several for `cat`), no redirects but `2>/dev/null` / `2>&1`, no wrapper or assignment before the command and
    flags the reader's table knows (not `sed -i`, `sort -o`, `tail -f`, `grep -r`); the rewrite is analysed again
    and the block stands unless that is clean. Claude only.
  * `find ... -exec cat {}` runs `<this script> --cat {}` instead; `-exec grep ... {}` gets `-H` and the whole find
    is piped through `--scrub`. Other -exec programs that could print a secret file stay blocked (Claude only).
  * MCP tools: any string argument that names an existing secret file.
  * Fail closed: if the hook itself errors on a request that mentions a secret file, deny.

Remaining limitations (use `permissions.deny` Read rules and a sandbox for a hard guarantee):
programs that build the filename at run time, copies of the file under another name, and
`git diff`-style commands whose output happens to include a secret file the command never names
(only handled for the git commands above), and `git format-patch` / `git range-diff`.
"""
import fnmatch
import glob
import io
import json
import os
import re
import shlex
import subprocess
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


PROPS_RE = re.compile(r"^(\s*)((?:\\.|[^\s=:\\])+)(\s*[=:]\s*|\s+)(.*)$")
ENV_RE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*=\s*)(.*)$")


def mask_properties_line(line: str) -> str:
    m = PROPS_RE.match(line)
    if not m:
        return line
    indent, key, sep, value = m.groups()
    return f"{indent}{key}{sep}{MASK if value else ''}"


def mask_env_line(line: str) -> str:
    m = ENV_RE.match(line)
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


def mask_lines(path: str, text: str) -> list[str]:
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
    return out


def mask_text(path: str, text: str) -> str:
    return "\n".join(mask_lines(path, text))


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


LITERAL_SPECIALS = ";()&|<>"
_PROTECT = {c: chr(0xE000 + i) for i, c in enumerate(LITERAL_SPECIALS)}
_UNPROTECT = {v: k for k, v in _PROTECT.items()}


def protect_literals(cmd: str) -> str:
    """Swap the shell punctuation that bash takes literally (`\\;`, `\\(`, `';'`, "a;b") for private characters, so the
    tokenizer does not mistake `find -exec ... \\;` or `\\( -name a \\)` for a separator. Only the characters
    change: the quotes and every other backslash stay for shlex."""
    out: list[str] = []
    quote = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if quote:
            if c == quote:
                quote = None
                out.append(c)
            elif c == "\\" and quote == '"' and i + 1 < n:
                out.append(c)
                out.append(_PROTECT.get(cmd[i + 1], cmd[i + 1]))
                i += 1
            else:
                out.append(_PROTECT.get(c, c))
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "\\" and i + 1 < n:
            nxt = cmd[i + 1]
            if nxt in _PROTECT:
                out.append(_PROTECT[nxt])
            else:
                out.append(c)
                out.append(nxt)
            i += 1
        else:
            out.append(c)
        i += 1
    return "".join(out)


def unprotect_token(tok: str) -> str:
    """Back to the original characters. A token that is nothing but literal punctuation keeps a backslash (`\\;`) so it
    is not taken for a separator any more."""
    if not any(ch in _UNPROTECT for ch in tok):
        return tok
    text = "".join(_UNPROTECT.get(ch, ch) for ch in tok)
    return "\\" + text if all(ch in _UNPROTECT for ch in tok) else text


def tokenize(cmd: str) -> list[str]:
    cmd = cmd.replace("\n", " ; ")
    try:
        lex = shlex.shlex(protect_literals(cmd), posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        # shlex would drop everything after a `#` (even mid-word, and after the newlines turned into
        # `;` above), but bash only starts a comment at the beginning of a word. Never skip text.
        lex.commenters = ""
        return [unprotect_token(t) for t in lex]
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
        elif a.startswith("--iglob="):
            kind, value = "iglob", a.split("=", 1)[1]
        elif a == "--iglob":
            kind, value, i = "iglob", nxt, i + 1
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
        elif kind == "iglob":  # case-insensitive: marked so filter_hits compares lower-cased names
            (exc if value.startswith("!") else inc).append(ICASE + value.lstrip("!").lower())
        i += 1
    return inc, exc, narrowed


ICASE = "\0i:"


def glob_match(name: str, pattern: str) -> bool:
    if pattern.startswith(ICASE):
        return fnmatch.fnmatchcase(name.lower(), pattern[len(ICASE):])
    return fnmatch.fnmatch(name, pattern)


def filter_hits(hits: list[str], inc: list[str], exc: list[str], narrowed: bool) -> list[str]:
    if narrowed:
        return []
    inc = [x for i in inc for x in expand_braces(i)]
    exc = [x for e in exc for x in expand_braces(e)]
    out = []
    for p in hits:
        name = os.path.basename(p)
        if inc and not any(glob_match(name, i) for i in inc):
            continue
        if any(glob_match(name, e) for e in exc):
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
    if not recursive or (head == "rg" and rg_masks_secrets(args)):
        return None
    if head != "rg":
        ok, _, quiet = search_args_ok(head, args)
        if (ok and quiet) or scrubbed_search(seg, preprocessor()):  # -q prints nothing; --scrub masks what it prints
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
    if not git_reads_content(sub, rest) or git_masks_secrets(seg["args"]):
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


# rg can search the output of a preprocessor instead of the file (`--pre CMD` runs `CMD FILE`). With this script as
# CMD the secret files are searched in masked form: path, line number and key still show, the value is ****.
# --pre-glob limits it to secret-looking names; character classes make the globs case-insensitive (.ENV), which
# --pre-glob is not even with --glob-case-insensitive. Template files (.env.example) match the globs but pass raw.
RG_PRE_GLOBS = ("*.[pP][rR][oO][pP][eE][rR][tT][iI][eE][sS]", "*.[eE][nN][vV]", ".[eE][nN][vV]", ".[eE][nN][vV].*")
RG_FOLLOW_RE = re.compile(r"^(--follow|-[A-Za-z0-9]*L[A-Za-z0-9]*)$")
RG_NOTICE = ("mask-secrets: this rg search was rewritten to run with --pre mask-secrets --pre-glob ... so values in "
             ".env / .properties files show up as KEY=****. Path, line number and key are still searchable; the real "
             "values are never printed, do not try to read them.")
REWRITE_UNSAFE = ("`", "$(", "<<", "<(", ">(")
READONLY_FILTERS = {"head": "nqcv", "tail": "nqcv", "wc": "lwcmL", "sort": "unrfhVbdgMsk", "uniq": "cdui"}
READONLY_REDIRECT_RE = re.compile(r"(^|\s)(?:[12]?>\s*/dev/null|&>\s*/dev/null|2>&1)(\s|$|[;|&])")
EXPANSION_RE = re.compile(r"\$[A-Za-z_{(@*#?!0-9-]")
READONLY_OPERAND_RE = re.compile(r"^[-+]?\d+$")
READONLY_FLAG_RE = re.compile(r"^-([A-Za-z]+)\d*$")


def preprocessor() -> str | None:
    """The command rg runs on each secret file: this script, which therefore has to be executable."""
    path = os.path.abspath(__file__)
    return path if os.access(path, os.X_OK) else None


def rg_mask_flags(pre: str) -> str:
    return " ".join(["--pre", shlex.quote(pre)] + [f"--pre-glob {shlex.quote(g)}" for g in RG_PRE_GLOBS])


def rg_flag_blocks_rewrite(args: list[str]) -> bool:
    """User-supplied --pre / --pre-glob could override ours, -L follows symlinks that hide a secret file under
    another name, --hostname-bin runs a program."""
    return any(a.startswith(("--pre", "--hostname-bin")) or RG_FOLLOW_RE.match(a) for a in args)


def rg_masks_secrets(args: list[str]) -> bool:
    """True when the rg arguments carry exactly the masking flags this hook adds."""
    pre = preprocessor()
    if not pre:
        return False
    pres: list[str] = []
    globs: list[str] = []
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "--pre":
            pres.append(nxt)
        elif a.startswith("--pre="):
            pres.append(a[len("--pre="):])
        elif a == "--pre-glob":
            globs.append(nxt)
        elif a.startswith("--pre-glob="):
            globs.append(a[len("--pre-glob="):])
        elif RG_FOLLOW_RE.match(a):
            return False
    return bool(pres) and all(p == pre for p in pres) and set(RG_PRE_GLOBS) <= set(globs)


# ---------------------------------------------------------------------------------------------
# Masked git and masked grep/ag/ack
#
# rg has --pre. git has textconv: with `-c core.attributesFile=<file>` pointing at a file that gives secret-looking
# names a `diff=` driver whose textconv is this script (`--mask env|properties FILE`), diff / show / log -p / blame /
# grep print KEY=**** instead of the file. Both sides of a diff are masked, so a changed value shows no change, and
# -S / -G / grep patterns match masked text, so values cannot be probed.
# grep, ag and ack have nothing like it. Their output is piped through `--scrub`: a line that starts with the path
# of a secret file (`path:12:KEY=value`, `path-13-KEY=value`, `path\0KEY=value`) has its value replaced. That only
# works for output shapes it understands, so the rewrite is limited to a list of known-benign flags (no -o, -h,
# --color, ...). Unlike rg --pre it does not stop a value from being probed with a pattern (the line shows up).
# ---------------------------------------------------------------------------------------------
GIT_DRIVERS = {"maskenv": "env", "maskprops": "properties"}
GIT_ATTRIBUTES = (
    "*.[pP][rR][oO][pP][eE][rR][tT][iI][eE][sS] diff=maskprops\n"
    "*.[eE][nN][vV] diff=maskenv\n"
    ".[eE][nN][vV].* diff=maskenv\n"
)
_DIFF_OPTS = ("--textconv", "--no-ext-diff")
# git commands that print file content, and the options that make textconv apply to them
GIT_MASK_OPTS = {
    "diff": _DIFF_OPTS, "show": _DIFF_OPTS, "log": _DIFF_OPTS, "reflog": _DIFF_OPTS, "whatchanged": _DIFF_OPTS,
    "stash": _DIFF_OPTS, "diff-tree": _DIFF_OPTS, "diff-index": _DIFF_OPTS, "diff-files": _DIFF_OPTS,
    "grep": ("--textconv",), "blame": (), "annotate": (),
}
# options that bring the raw content back, or send it somewhere the filter does not see
GIT_MASK_BLOCKERS = {"--no-textconv", "--ext-diff", "--no-index", "--open-files-in-pager", "--output", "--binary",
                     "--attr-source"}
GIT_MASK_NOTICE = ("mask-secrets: this git command was rewritten to run with a textconv filter, so values in .env / "
                   ".properties files show up as KEY=****. A change that only touches a value shows no diff because both "
                   "sides are masked. The real values are never printed, do not try to read them.")
SCRUB_NOTICE = ("mask-secrets: the output of this search is piped through mask-secrets --scrub, so values in .env / "
                ".properties matches show up as KEY=****. Path, line number and key are still reported. The real values "
                "are never printed, do not try to read them.")
SCRUB_NO_OUTPUT_STATUS = 1  # like grep: exit 1 when nothing came out, so `grep ... || echo none` keeps working
SCRUB_NUMBERS_RE = re.compile(r"(?:[0-9]+[:\-]){1,3}")
SCRUB_SEPARATORS_RE = re.compile(r"[:\-\0]")

# Output shapes the scrub filter understands: path:line:text, path:count, path. Anything else is not rewritten.
GREP_SHORT = set("iyIaUZTnwxFEGPrHsvclLq")
GREP_SHORT_VALUE = set("efmABCdD")
GREP_LONG = {"--recursive", "--ignore-case", "--no-ignore-case", "--word-regexp", "--line-regexp", "--fixed-strings",
             "--extended-regexp", "--basic-regexp", "--perl-regexp", "--invert-match", "--line-number", "--with-filename",
             "--count", "--files-with-matches", "--files-without-match", "--no-messages", "--text", "--null",
             "--initial-tab", "--line-buffered", "--quiet", "--silent"}
GREP_LONG_VALUE = {"--include", "--exclude", "--exclude-dir", "--exclude-from", "--regexp", "--file", "--max-count",
                   "--after-context", "--before-context", "--context", "--binary-files", "--directories", "--devices"}
AGACK_SHORT = set("iwQsSvclLauU")
AGACK_SHORT_VALUE = set("ABC")
AGACK_LONG = {"--ignore-case", "--word-regexp", "--literal", "--smart-case", "--case-sensitive", "--invert-match",
              "--count", "--files-with-matches", "--files-without-matches", "--hidden", "--unrestricted", "--all-types",
              "--nocolor", "--nogroup", "--numbers"}
AGACK_LONG_VALUE = {"--after", "--before", "--context", "--depth", "--ignore"}


def cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or (
        os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.path.join(os.path.expanduser("~"), ".cache"))
    return os.path.join(base or os.path.expanduser("~"), "mask-secrets")


def git_attributes_path() -> str:
    return os.path.join(cache_dir(), "gitattributes")


def ensure_git_attributes() -> str | None:
    """The attributes file textconv needs, written on first use. None when it cannot be written."""
    path = git_attributes_path()
    try:
        with open(path, encoding="utf-8") as fh:
            if fh.read() == GIT_ATTRIBUTES:
                return path
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(GIT_ATTRIBUTES)
        os.replace(tmp, path)
        return path
    except OSError:
        return None


def git_mask_configs(pre: str) -> list[str]:
    """The three `-c` values that turn textconv masking on."""
    return ([f"core.attributesFile={git_attributes_path()}"]
            + [f"diff.{drv}.textconv={shlex.quote(pre)} --mask {kind}" for drv, kind in GIT_DRIVERS.items()])


def git_sub_index(args: list[str]) -> int | None:
    """Index of the subcommand word in `git ARGS` (skips global options), or None."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in GIT_OPTS_WITH_VALUE:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return i
    return None


def git_mask_target(args: list[str]) -> tuple[int, tuple[str, ...]] | None:
    """(index of the word after which the options go, the options) when this git command can be masked."""
    k = git_sub_index(args)
    if k is None:
        return None
    sub, rest = args[k], args[k + 1:]
    if sub not in GIT_MASK_OPTS or any(a.split("=", 1)[0] in GIT_MASK_BLOCKERS or a.startswith("-O") for a in rest):
        return None
    at = k
    if sub == "stash":  # `git stash show -p` / `git stash list -p`: the options belong after show / list
        if not rest or rest[0] not in {"show", "list"}:
            return None
        at = k + 1
    return at, GIT_MASK_OPTS[sub]


def git_masks_secrets(args: list[str], pre: str | None = None) -> bool:
    """True when the git arguments carry exactly the masking options this hook adds."""
    pre = pre or preprocessor()
    target = git_mask_target(args)
    if not pre or not target:
        return False
    at, opts = target
    k = git_sub_index(args)
    configs = [args[i + 1] for i in range(k) if args[i] == "-c" and i + 1 < k]
    return set(git_mask_configs(pre)) <= set(configs) and all(o in args[at + 1:] for o in opts)


GIT_ATTR_SAMPLES = {"a.properties": "maskprops", "a.PROPERTIES": "maskprops", "a.env": "maskenv", "a.ENV": "maskenv",
                    ".env": "maskenv", ".ENV": "maskenv", ".env.local": "maskenv", ".ENV.prod": "maskenv"}


def git_attributes_win(pre: str, dirs: list[str]) -> bool:
    """A repository's own .gitattributes (or .git/info/attributes) beats the attributes file the masking uses: when
    it gives secret-looking names another diff driver, or `-diff`, textconv would not run. Ask git. False when
    that is the case or when git cannot be run; directories that are not repositories do not count."""
    cmd = ["git"]
    for c in git_mask_configs(pre):
        cmd += ["-c", c]
    cmd += ["check-attr", "diff", "--", *GIT_ATTR_SAMPLES]
    for d in dirs or ["."]:
        try:
            res = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return False
        if res.returncode != 0:
            continue
        seen = {}
        for line in res.stdout.splitlines():
            name, _, value = line.rpartition(": diff: ")
            seen[name] = value
        if seen != GIT_ATTR_SAMPLES:
            return False
    return True


def search_flags(head: str, args: list[str]) -> set[str] | None:
    """The flags of a grep / ag / ack command line (short letters and long names) when they only produce output shapes
    --scrub understands, else None."""
    grep = head in {"grep", "egrep", "fgrep"}
    short, short_value = (GREP_SHORT, GREP_SHORT_VALUE) if grep else (AGACK_SHORT, AGACK_SHORT_VALUE)
    long_, long_value = (GREP_LONG, GREP_LONG_VALUE) if grep else (AGACK_LONG, AGACK_LONG_VALUE)
    flags: set[str] = set()
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            break
        if a.startswith("--"):
            name, eq, _ = a.partition("=")
            if name in long_value:
                i += 0 if eq else 1
            elif name not in long_ or eq:
                return None
            flags.add(name)
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                c = a[j]
                if c in short_value:  # the value is the rest of the word, or the next word
                    i += 1 if j == len(a) - 1 else 0
                    break
                if c in "0123456789" and grep:
                    j += 1
                    continue
                if c not in short:
                    return None
                flags.add(c)
                j += 1
    return flags


def search_args_ok(head: str, args: list[str]) -> tuple[bool, bool, bool]:
    """(the flags only produce output shapes --scrub understands, -c / --count given, -q / --quiet given)."""
    flags = search_flags(head, args)
    if flags is None:
        return False, False, False
    grep = head in {"grep", "egrep", "fgrep"}
    return True, bool(flags & {"c", "--count"}), bool(flags & {"--quiet", "--silent"}) or (grep and "q" in flags)


def scrubbed_search(seg: dict, pre: str | None) -> bool:
    """A grep / ag / ack whose output goes straight into this hook's --scrub filter, with flags it understands."""
    return bool(pre and seg.get("scrubbed") and search_args_ok(seg["head"], seg["args"])[0])


def scrub_body(path: str, body: str) -> str:
    """Heuristic for a line out of a secret file when the file itself cannot be consulted."""
    props = path.lower().endswith(".properties")
    stripped = body.strip()
    if not stripped or stripped[0] in ("#!" if props else "#"):
        return body
    if not (PROPS_RE if props else ENV_RE).match(body):
        return MASK  # a continuation line, a quoted multi-line value, a fragment: it is all value
    return mask_properties_line(body) if props else mask_env_line(body)


_FILE_LINES: dict[str, tuple[list[str], list[str]] | None] = {}


def file_lines(path: str) -> tuple[list[str], list[str]] | None:
    """(raw lines, masked lines) of a secret file. Knowing the whole file tells a continuation line (`  part2 part3`)
    from a new `key value` line, which one line of grep output cannot."""
    if path not in _FILE_LINES:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            _FILE_LINES[path] = (text.splitlines(), mask_lines(path, text))
        except OSError:
            _FILE_LINES[path] = None
    return _FILE_LINES[path]


def scrub_content(path: str, number: int | None, body: str) -> str:
    state = file_lines(path)
    if state:
        raw, masked = state
        if number is not None and 1 <= number <= len(raw) and raw[number - 1] == body:
            return masked[number - 1]
        same = {masked[i] for i, r in enumerate(raw) if r == body}  # no line number, or it does not fit the file
        if same:
            return same.pop() if len(same) == 1 else MASK
    return scrub_body(path, body)


def scrub_line(line: str, counts: bool) -> str:
    """Mask the content of one line of grep-style output when it starts with the path of a secret file."""
    text = line.rstrip("\r\n")
    ending = line[len(text):]
    for m in SCRUB_SEPARATORS_RE.finditer(text):
        path = text[:m.start()]
        if is_target(path):
            rest = text[m.end():]
            numbers = SCRUB_NUMBERS_RE.match(rest)
            head = numbers.group(0) if numbers else ""
            body = rest[len(head):]
            if not (counts and not head and re.fullmatch(r"[0-9]+", body)):
                number = int(re.match(r"[0-9]+", head).group(0)) if head else None
                body = scrub_content(path, number, body)
            return text[:m.end()] + head + body + ending
        if text[m.start()] != "-":
            break  # a `:` or NUL ends the path part: whatever follows is not the file name any more
    return line


def scrub_stream(counts: bool) -> int:
    seen = False
    out = sys.stdout.buffer
    try:
        for raw in sys.stdin.buffer:
            seen = True
            line = raw.decode("utf-8", errors="surrogateescape")
            out.write(scrub_line(line, counts).encode("utf-8", errors="surrogateescape"))
        out.flush()
    except BrokenPipeError:  # `| head` stopped reading: not an error, and no traceback in the agent's output
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
    return 0 if seen else SCRUB_NO_OUTPUT_STATUS


def readonly_search_pipeline(cmd: str) -> bool:
    """rg searches optionally after `cd`, piped through head/tail/wc/sort/uniq with plain flags: nothing in them can
    change anything. Codex only accepts a rewritten command together with an approval, so only such commands
    are approved that way."""
    if any(p in cmd for p in REWRITE_UNSAFE) or EXPANSION_RE.search(cmd):
        return False
    prev = None
    while prev != cmd:  # drop `2>/dev/null`, `2>&1` ... (the only redirections allowed)
        prev, cmd = cmd, READONLY_REDIRECT_RE.sub(r"\1 \2", cmd)
    commands: list[list[str]] = [[]]
    for t in tokenize(cmd):
        if t in {"|", "&&", "||", ";"}:
            commands.append([])
        elif re.fullmatch(r"[<>&|();]+", t):
            return False  # background, subshell, other redirections
        else:
            commands[-1].append(t)
    for words in commands:
        if not words:
            continue
        head, args = words[0], words[1:]
        if head == "rg":
            ok = not rg_flag_blocks_rewrite(args)
        elif head == "cd":
            ok = len(args) == 1 and not args[0].startswith("-")
        elif head in READONLY_FILTERS:
            ok = all(READONLY_OPERAND_RE.match(a) or ((m := READONLY_FLAG_RE.match(a)) and
                                                      all(c in READONLY_FILTERS[head] for c in m.group(1)))
                     for a in args)
        else:
            ok = False
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------------------------
# Direct reads of a secret file, and `find -exec`
#
# `mask-secrets --cat FILE...` prints the masked view of each file (secret files masked, other files as they are).
# A reader that names a secret file gets that operand moved in front of it, so it works on masked text:
#     head -1 .env        ->  <hook> --cat .env | head -1
# In `find ... -exec cat {} +` the hook takes the place of cat. `find ... -exec grep -H ... {} +` gets the --scrub
# filter like any other grep. Whatever cannot be rewritten that way stays blocked.
# ---------------------------------------------------------------------------------------------
CAT_NOTICE = ("mask-secrets: the secret file this command reads is fed through mask-secrets --cat, so values in .env / "
              ".properties files show up as KEY=****. The command itself runs as written on the masked text. The real "
              "values are never printed, do not try to read them.")
_SORT_SHORT = "bdfghiMnRrsuVzcCm"
# head: (short flags, short flags with a value, long flags, long flags with a value, first operand is a script /
# pattern unless -e / -f gives one, -NUM allowed). Only options whose output is the (masked) text, nothing that
# writes files (sed -i, sort -o), reads more files (sed -f) or recurses (grep -r).
DIRECT_READERS: dict[str, tuple[str, str, set[str], set[str], bool, bool]] = {
    "cat": ("AbeEnstTuv", "", {"--show-all", "--number-nonblank", "--show-ends", "--number", "--squeeze-blank",
                               "--show-tabs", "--show-nonprinting"}, set(), False, False),
    "tac": ("br", "s", {"--before", "--regex"}, {"--separator"}, False, False),
    "nl": ("p", "bdfhilnsvw", set(), set(), False, False),
    "head": ("qvz", "nc", {"--quiet", "--silent", "--verbose", "--zero-terminated"}, {"--lines", "--bytes"}, False, True),
    "tail": ("qvz", "nc", {"--quiet", "--silent", "--verbose", "--zero-terminated"}, {"--lines", "--bytes"}, False, True),
    "sort": (_SORT_SHORT, "ktTS", {"--reverse", "--numeric-sort", "--unique", "--ignore-case", "--stable",
                                   "--ignore-leading-blanks", "--dictionary-order", "--version-sort",
                                   "--general-numeric-sort", "--human-numeric-sort", "--month-sort"},
             {"--key", "--field-separator"}, False, False),
    "cut": ("nsz", "bcdf", {"--complement", "--only-delimited", "--zero-terminated"},
            {"--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"}, False, False),
    "uniq": ("cdiuD", "fsw", {"--count", "--repeated", "--ignore-case", "--unique"},
             {"--skip-fields", "--skip-chars", "--check-chars"}, False, False),
    "sed": ("nEsrzu", "el", {"--quiet", "--silent", "--regexp-extended", "--null-data", "--unbuffered", "--separate"},
            {"--expression", "--line-length"}, True, False),
    "awk": ("", "Fv", set(), set(), True, False),
    "gawk": ("", "Fv", set(), set(), True, False),
}
for _grep in ("grep", "egrep", "fgrep"):
    DIRECT_READERS[_grep] = (
        "".join(sorted(GREP_SHORT - {"r"})), "".join(sorted(GREP_SHORT_VALUE - {"d", "D"})),
        GREP_LONG - {"--recursive"}, GREP_LONG_VALUE - {"--directories", "--devices"}, True, True)
REDIRECT_TOKEN_RE = re.compile(r"^[0-9]*[<>]+&?[0-9-]*$")
OPERAND_RE = re.compile(r"^(?:~/)?[A-Za-z0-9_.+@%,:=/-]+$")


def cat_files(paths: list[str]) -> int:
    """`--cat FILE...`: like cat, but secret files come out masked (symlinks to them too)."""
    status = 0
    out = sys.stdout.buffer
    try:
        for p in paths:
            if p == "-":
                data = sys.stdin.buffer.read()
            else:
                try:
                    data = masked_view(p)
                except OSError as exc:
                    sys.stderr.write(f"mask-secrets --cat: {p}: {exc.strerror}\n")
                    status = 1
                    continue
            out.write(data)
        out.flush()
    except BrokenPipeError:  # `| head` stopped reading
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
    return status


def reader_operands(head: str, args: list[str]) -> list[int] | None:
    """Indexes of the file operands in a DIRECT_READERS command line, None when a flag is not one it knows."""
    spec = DIRECT_READERS.get(head)
    if not spec:
        return None
    short, short_value, long_, long_value, script, digits = spec
    positional: list[int] = []
    have_script = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            positional += range(i + 1, len(args))
            break
        if a.startswith("--"):
            name, eq, _ = a.partition("=")
            if name in long_value:
                i += 0 if eq else 1
                have_script = have_script or name in {"--regexp", "--file", "--expression"}
            elif name not in long_ or eq:
                return None
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                c = a[j]
                if c in short_value:
                    have_script = have_script or c in "ef"
                    i += 1 if j == len(a) - 1 else 0
                    break
                if digits and c in "0123456789":
                    j += 1
                    continue
                if c not in short:
                    return None
                j += 1
        else:
            positional.append(i)
        i += 1
    if script and not have_script:
        if not positional:
            return None
        positional = positional[1:]  # the sed script / awk program / grep pattern
    return positional


def word_token(raw: str) -> str | None:
    """What the shell makes of one word of the command (quotes removed), None when it is not exactly one token."""
    toks = tokenize(raw)
    return toks[0] if len(toks) == 1 else None


def reader_edits(cmd: str, words: list[tuple[int, int]], k: int, head: str, cwds: list[str],
                 pre: str) -> list[tuple[int, int, str]] | None:
    """Edits that move the secret-file operand of a reader into `<hook> --cat FILE |`, or None (nothing to do, or the
    command is not one that can be rewritten safely: other redirects, expansions, several operands, flags unknown)."""
    idx: list[int] = []
    toks: list[str] = []
    for m in range(k + 1, len(words)):
        s, e = words[m]
        raw = cmd[s:e]
        if raw == "2>/dev/null" or (raw == "2>" and cmd[e:e + 2] == "&1"):
            continue
        tok = word_token(raw)
        if tok is None or REDIRECT_TOKEN_RE.match(tok):
            return None
        idx.append(m)
        toks.append(tok)
    ops = reader_operands(head, toks)
    if not ops:
        return None
    names = [toks[o] for o in ops]
    if (head != "cat" and len(ops) != 1) or not all(OPERAND_RE.match(n) and not n.startswith("-") for n in names):
        return None
    if head in {"awk", "gawk"} and any("=" in n for n in names):
        return None  # `awk ... var=value file`
    if not any(is_secret_file(resolve(n, b)) for n in names for b in cwds):
        return None
    raw_ops = [cmd[words[idx[o]][0]:words[idx[o]][1]] for o in ops]
    edits = [(words[k][0], words[k][0], f"{shlex.quote(pre)} --cat {' '.join(raw_ops)} | ")]
    edits += [(words[idx[o] - 1][1], words[idx[o]][1], "") for o in ops]
    return edits


FIND_TERMINATOR = "\\;"  # what tokenize() makes of an escaped or quoted `;`


def find_exec_groups(words: list[str]) -> list[tuple[int, int, bool]]:
    """(index of -exec / -execdir / -ok / -okdir, index of its terminator or len(words), terminated) for each of them."""
    groups = []
    i = 0
    while i < len(words):
        if words[i] in {"-exec", "-execdir", "-ok", "-okdir"}:
            j = i + 1
            while j < len(words) and not (words[j] == FIND_TERMINATOR or (words[j] == "+" and words[j - 1] == "{}")):
                j += 1
            groups.append((i, j, j < len(words)))
            i = j
        i += 1
    return groups


def exec_group_masked(group: list[str], pre: str | None, scrubbed: bool) -> bool:
    """One `-exec CMD ARGS {}` whose output cannot show secret values: `<hook> --cat {}`, or a grep that names its
    files (-H) and whose find output goes through --scrub."""
    if not group or not pre:
        return False
    if group[0] == pre and group[1:2] == ["--cat"]:
        return True
    head = os.path.basename(group[0])
    if head in {"grep", "egrep", "fgrep"} and scrubbed:
        flags = search_flags(head, [w for w in group[1:] if w != "{}"])
        return flags is not None and bool(flags & {"H", "--with-filename"})
    return False


FIND_WRITERS = {"-fprint", "-fprint0", "-fprintf"}  # write names to a file: not -exec, but not something to mask either


def find_exec_state(seg: dict, pre: str | None) -> tuple[bool, bool]:
    """(every -exec of this find prints masked output, at least one -exec could print secret values raw)."""
    args = seg["args"]
    ok = True
    seen_masked = unsafe = False
    for i, j, done in find_exec_groups(args):
        group = args[i + 1:j]
        if done and exec_group_masked(group, pre, bool(seg.get("scrubbed"))):
            seen_masked = True
        elif done and group and os.path.basename(group[0]) in SAFE_HEADS:
            continue
        else:
            unsafe = True
    if any(a in FIND_WRITERS for a in args):
        ok = False
    return seen_masked and not unsafe and ok, unsafe


def find_exposure(seg: dict, cwds: list[str], cwd: str, budget: Budget) -> str | None:
    """A `find` whose -exec hands files to a program that could print them, over a tree with secret files."""
    args = seg["args"]
    groups = find_exec_groups(args)
    outside = [a for n, a in enumerate(args) if not any(i <= n <= j for i, j, _ in groups)]
    first = 0
    while first < len(args) and (args[first] in {"-H", "-L", "-P"} or re.fullmatch(r"-O[0-3]", args[first])):
        first += 1
    last = first
    while last < len(args) and not (args[last].startswith("-") or args[last] in {"!", "\\("}):
        last += 1
    roots = args[first:last] or ["."]
    dirs = []
    for r in roots:
        for base in cwds:
            p = resolve(r, base)
            if os.path.isdir(p):
                dirs.append(p)
    hits: list[str] = []
    for d in dirs:
        hits += walk_targets(d, budget)
    filters: list[tuple[bool, str]] = []
    if not any(a in {"-o", "-or", "!", "-not", "\\("} for a in outside):  # a plain conjunction narrows what -exec sees
        filters = [(a == "-iname", v) for a, v in zip(outside, outside[1:]) if a in {"-name", "-iname"}]
    hits = [p for p in dict.fromkeys(hits)
            if all(fnmatch.fnmatch(os.path.basename(p).lower(), v.lower()) if ic else fnmatch.fnmatch(os.path.basename(p), v)
                   for ic, v in filters)]
    if not hits and not budget.incomplete:
        return None
    rel = [os.path.relpath(p, cwd) if p.startswith(cwd) else p for p in hits[:8]]
    found = (f"{len(hits)} secret file(s) such as: " + ", ".join(rel)) if hits else "the tree is too large to verify"
    return (f"Blocked: this find -exec would hand .properties/.env files to a program that prints them ({found}). Their "
            "values are secrets. `-exec cat {} +` and `-exec grep -H ... {} +` are rewritten to print them masked. "
            "For anything else exclude them (! -name '.env' ! -name '*.env' ! -name '*.properties'), restrict -name "
            "to specific source files, or search a subdirectory that has none.")


def find_edits(cmd: str, words: list[tuple[int, int]], k: int, pre: str) -> tuple[list[tuple[int, int, str]], set[str]]:
    """`-exec cat {}` becomes `-exec <hook> --cat {}`; `-exec grep ... {}` gets -H and the whole find is piped
    through --scrub. Other -exec actions are left alone (the caller's second analysis blocks what is still unsafe)."""
    base = k + 1
    toks = [word_token(cmd[s:e]) for s, e in words[base:]]
    texts = [t if t is not None else "\0" for t in toks]
    edits: list[tuple[int, int, str]] = []
    kinds: set[str] = set()
    counts = True
    for i, j, done in find_exec_groups(texts):
        group = texts[i + 1:j]
        if not done or not group or "\0" in group:
            continue
        head = os.path.basename(group[0])
        at = words[base + i + 1]
        if head == "cat" and group[1:] == ["{}"]:
            edits.append((at[0], at[1], f"{shlex.quote(pre)} --cat"))
            kinds.add("cat")
        elif head in {"grep", "egrep", "fgrep"} and group[-1] == "{}" and group.count("{}") == 1:
            flags = search_flags(head, group[1:-1])
            if flags is None:
                continue
            if not flags & {"H", "--with-filename"}:
                edits.append((at[1], at[1], " -H"))
            counts = counts and bool(flags & {"c", "--count"})
            kinds.add("scrub")
    if "scrub" in kinds:
        end = words[-1][1]
        edits.append((end, end, f" | {shlex.quote(pre)} --scrub" + (" --counts" if counts else "")))
    return edits, kinds


def command_spans(cmd: str) -> list[tuple[list[tuple[int, int]], bool]] | None:
    """Word spans (start, end) of every simple command in the text, and whether it reads a pipe.

    Separators outside quotes end a command. None when a quote is left open."""
    cmds: list[tuple[list[tuple[int, int]], bool]] = [([], False)]
    start = quote = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"':
                i += 1
        elif c in "'\"":
            start = i if start is None else start
            quote = c
        elif c == "\\":
            start = i if start is None else start
            i += 1
        elif c in " \t\r\n;|&()":
            if start is not None:
                cmds[-1][0].append((start, min(i, n)))
                start = None
            if c not in " \t\r":
                piped = c == "|"
                if c in "|&" and cmd[i + 1:i + 2] in {"|", "&"}:  # ||  &&  |&
                    piped = cmd[i:i + 2] == "|&"
                    i += 1
                cmds.append(([], piped))
        elif start is None:
            start = i
        i += 1
    if quote:
        return None
    if start is not None:
        cmds[-1][0].append((start, n))
    return cmds


def rewrite_command(cmd: str, cwd: str, pre: str, codex: bool = False) -> tuple[str, set[str]] | None:
    """Make a command that would be blocked print its secrets masked instead.

      rg               gets --pre <hook> --pre-glob ... (rg searches the masked files)
      git (diff, ...)  gets the textconv options (git prints the masked files)
      grep -r, ag, ack get `| <hook> --scrub` (a filter that masks lines that start with a secret file's path)

      reader FILE      (cat, head, sed, awk, grep ...) a secret file operand moves into `<hook> --cat FILE |`
      find -exec       `-exec cat {}` becomes `-exec <hook> --cat {}`, `-exec grep` gets -H and `| <hook> --scrub`

    Returns the new command and which of "rg" / "git" / "scrub" / "cat" were used, or None when the command is too complex to
    edit safely (nested shells, substitutions, heredocs, quoted or redirected command words), a flag cannot be
    masked, or an rg segment brings its own --pre. Codex gets rg only. The caller analyses the result again."""
    if any(p in cmd for p in REWRITE_UNSAFE):
        return None
    segments: list[dict] = []
    collect_segments(cmd, segments)
    if any(rg_flag_blocks_rewrite(s["args"]) for s in segments if s["head"] == "rg"):
        return None
    cmds = command_spans(cmd)
    if cmds is None:
        return None
    cwds = cwd_candidates(segments, cwd)
    budget = Budget()
    edits: list[tuple[int, int, str]] = []
    kinds: set[str] = set()
    for words, piped in cmds:
        k = 0
        lead_ok = True  # only keywords (`if`, `do`, `!` ...) before the command: a wrapper or assignment changes what it reads
        while k < len(words):
            w = cmd[words[k][0]:words[k][1]]
            if any(ch in w for ch in "'\"\\"):
                break
            wrapper = os.path.basename(w) in WRAPPERS
            if wrapper or w in LEADING_KEYWORDS or ASSIGN_RE.match(w):
                lead_ok = lead_ok and not (wrapper or ASSIGN_RE.match(w))
                k += 1
                while wrapper and k < len(words):
                    x = cmd[words[k][0]:words[k][1]]
                    if not (x.startswith("-") or NUMBER_RE.match(x)):
                        break
                    k += 1
                continue
            head = os.path.basename(w)
            direct = None
            if not codex and lead_ok and head in DIRECT_READERS:
                direct = reader_edits(cmd, words, k, head, cwds, pre)
            if head == "rg":
                edits.append((words[k][1], words[k][1], " " + rg_mask_flags(pre)))
                kinds.add("rg")
            elif direct:
                edits += direct
                kinds.add("cat")
            elif head == "find" and not codex:
                found, found_kinds = find_edits(cmd, words, k, pre)
                edits += found
                kinds |= found_kinds
            elif head in {"git", "grep", "egrep", "fgrep", "ag", "ack"} and not codex:
                own: list[dict] = []
                collect_segments(cmd[words[0][0]:words[-1][1]], own)
                if len(own) != 1:
                    return None
                seg = own[0]
                seg["piped"] = piped
                if head == "git":
                    sub, rest = git_parts(seg["args"])
                    if not git_reads_content(sub, rest) or git_masks_secrets(seg["args"], pre):
                        break
                    target = git_mask_target(seg["args"])
                    if not target or not ensure_git_attributes() or not git_attributes_win(pre, cwds):
                        return None
                    at, opts = target
                    if opts:  # the options go right after the subcommand (after `show` for `git stash show`)
                        word = words[k + 1 + at] if k + 1 + at < len(words) else None
                        if not word or cmd[word[0]:word[1]] != seg["args"][at]:
                            return None
                        edits.append((word[1], word[1], " " + " ".join(opts)))
                    configs = " ".join(f"-c {shlex.quote(c)}" for c in git_mask_configs(pre))
                    edits.append((words[k][1], words[k][1], " " + configs))
                    kinds.add("git")
                elif recursive_exposure(seg, cwds, cwd, budget):
                    ok, counts, _ = search_args_ok(head, seg["args"])
                    if not ok:
                        return None
                    edits.append((words[-1][1], words[-1][1],
                                  f" | {shlex.quote(pre)} --scrub" + (" --counts" if counts else "")))
                    kinds.add("scrub")
            break
    if not edits:
        return None
    for start, end, text in sorted(edits, key=lambda x: (x[0], x[1]), reverse=True):
        cmd = cmd[:start] + text + cmd[end:]
    return cmd, kinds


def analyze_bash(cmd: str, cwd: str, budget: Budget | None = None) -> tuple[list[str], list[str]]:
    budget = budget or Budget()
    segments: list[dict] = []
    collect_segments(cmd, segments)
    cwds = cwd_candidates(segments, cwd)
    wide = any(s["head"] in {"find", "fd", "fdfind", "locate"} for s in segments)
    pre = preprocessor()
    for prev, nxt in zip(segments, segments[1:]):  # `grep ... | <this hook> --scrub`
        if pre and nxt["piped"] and pre in nxt["words"] and nxt["args"] in (["--scrub"], ["--scrub", "--counts"]):
            prev["scrubbed"] = True
    for s in segments:  # `<this hook> --cat FILE...`: prints the files masked, whatever they are
        lead = s["words"][:len(s["words"]) - len(s["args"])]  # the words before the arguments: keywords, then the command
        s["masked"] = bool(pre and s["args"][:1] == ["--cat"] and lead[-1:] == [pre]
                           and all(w in LEADING_KEYWORDS for w in lead[:-1]))

    direct: list[str] = []
    mentioned: list[str] = []
    for s in segments:
        if s["masked"]:
            continue
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
        if s["head"] == "git" and git_masks_secrets(s["args"], pre):
            continue  # textconv masks every file this git command prints, whatever it is named
        if s["head"] == "find" and find_exec_state(s, pre)[0]:
            continue  # every -exec prints masked output
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
        elif s["head"] == "find" and find_exec_state(s, pre)[1]:
            msg = find_exposure(s, cwds, cwd, budget)
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


def evaluate(data: dict) -> tuple[list[str], list[str], str, tuple[str, set[str]] | None]:
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
    rewritten: tuple[str, set[str]] | None = None

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
            # Bash tool: instead of blocking, make rg / git / grep print the secret files masked (see rewrite_command).
            # Codex cannot rewrite without approving the call, so there only for rg commands that cannot change
            # anything. The rewritten command is analysed again with a fresh budget (a tree too large to verify
            # does not matter for masked rg or git, but the rest of the command still has to finish and come
            # out clean), and the original block stands when it does not.
            pre = preprocessor()
            if (tool == "Bash" and (issues or targets) and pre and inp.get("command") == command
                    and ("turn_id" not in data or readonly_search_pipeline(command))):
                result = rewrite_command(command, cwd, pre, codex="turn_id" in data)
                if result:
                    fresh = Budget()
                    if not any(analyze_bash(result[0], cwd, fresh)) and not fresh.incomplete:
                        rewritten = result
    elif isinstance(tool, str) and tool.startswith("mcp__"):
        for s in iter_strings(inp):
            for cand in [s] + candidates_in_word(s):
                if is_target(cand):
                    targets += expand(cand, cwd)
        targets = list(dict.fromkeys(targets))
    return targets, issues, cwd, rewritten


def masked_bytes(name: str, data: bytes) -> bytes:
    masked = mask_text(name, data.decode("utf-8", errors="replace"))
    return (masked + "\n").encode("utf-8") if masked else b""


def masked_view(path: str) -> bytes:
    """What `rg --pre` searches instead of FILE: the masked text of a secret file, other files unchanged."""
    with open(path, "rb") as fh:
        data = fh.read()
    name = path if is_target(path) or not os.path.islink(path) else os.path.realpath(path)
    if not is_target(name):
        return data  # templates (.env.example) and anything the --pre-glob caught by accident
    return masked_bytes(name, data)


# --- Event log (block / mask counters). Same file and format as the Rust hook; see rust/src/stats.rs. -------------
# One JSON line per blocked or masked call: when, agent, tool, action and a short detail (the secret file's base
# name or the command's first word). Never values, content or a full command line. MASK_SECRETS_LOG=off disables it.
SHELL_TOOLS_LOG = {"Bash", "exec_command", "shell_command", "shell"}
LOG_PREFIX_WORDS = {"cd", "export", "set", "true", "false", ":", "source", "."}


def event_log_path() -> str | None:
    env = os.environ.get("MASK_SECRETS_LOG", "")
    if env in ("off", "0", "false"):
        return None
    if env:
        return env
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("USERPROFILE")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "mask-secrets", "events.jsonl") if base else None


def log_command_head(command: str) -> str:
    first = None
    for segment in re.split(r"&&|\|\||[;|&\n]", command):
        word = next((w for w in segment.split() if not ("=" in w and not w.startswith(("/", ".", '"', "'")))), None)
        if word is None:
            continue
        word = re.split(r"[/\\]", word.strip("\"'({"))[-1]
        if not word:
            continue
        if word not in LOG_PREFIX_WORDS:
            return word[:32]
        first = first or word
    return (first or "")[:32]


def record_event(raw: str, output: str) -> None:
    """Append one line to the event log when `output` denies or rewrites the call. Never raises, never prints."""
    try:
        path = event_log_path()
        if not path or not output:
            return
        hook = json.loads(output)["hookSpecificOutput"]
        if hook.get("permissionDecision") == "deny":
            action = "blocked"
        elif "updatedInput" in hook:
            action = "masked"
        else:
            return
        data = json.loads(raw)
        tool = str(data.get("tool_name") or "")
        tool_input = data.get("tool_input") or {}
        base = lambda p: re.split(r"[/\\]", str(p).rstrip("/\\"))[-1]
        if tool == "Read":
            detail = base(tool_input.get("file_path") or "")
        elif tool == "Grep":
            detail = base(tool_input.get("path") or ".")
        elif tool in SHELL_TOOLS_LOG:
            detail = log_command_head(str(tool_input.get("command") or tool_input.get("cmd") or ""))
        else:
            detail = ""
        line = json.dumps({"ts": int(time.time()), "agent": "codex" if "turn_id" in data else "claude",
                           "tool": tool[:48], "action": action, "detail": detail[:64]}, separators=(",", ":")) + "\n"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))  # one write on an O_APPEND handle: concurrent hooks do not interleave
        finally:
            os.close(fd)
    except Exception:
        pass


def main() -> None:
    argv = sys.argv[1:]
    if argv[:1] == ["--scrub"]:  # `<search> | this script --scrub [--counts]`: mask secret files' lines in grep output
        sys.exit(scrub_stream(argv[1:] == ["--counts"]))
    if argv[:1] == ["--cat"]:  # `<this script> --cat FILE...`: like cat, secret files masked
        sys.exit(cat_files(argv[1:]))
    if len(argv) == 3 and argv[0] == "--mask" and argv[1] in set(GIT_DRIVERS.values()):  # git textconv driver
        try:
            with open(argv[2], "rb") as fh:
                sys.stdout.buffer.write(masked_bytes("x." + argv[1], fh.read()))
        except OSError:
            sys.exit(1)
        return
    if len(argv) == 1 and not argv[0].startswith("-"):  # `rg --pre`: this script FILE
        try:
            sys.stdout.buffer.write(masked_view(argv[0]))
        except OSError:
            sys.exit(1)  # no output: rg reports the error and searches nothing
        return
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return
    real_stdout, sys.stdout = sys.stdout, io.StringIO()
    try:
        hook_main(raw, data)
    finally:
        output, sys.stdout = sys.stdout.getvalue(), real_stdout
    if output:
        sys.stdout.write(output)
        sys.stdout.flush()
        record_event(raw, output)


def hook_main(raw: str, data: dict) -> None:
    try:
        targets, issues, cwd, rewritten = evaluate(data)
        if rewritten:
            command, kinds = rewritten
            hook = {"hookEventName": "PreToolUse"}
            if "turn_id" in data:  # Codex: updatedInput is only accepted together with an allow
                hook["permissionDecision"] = "allow"
            else:  # Claude: the normal permission flow still decides
                notices = {"rg": RG_NOTICE, "git": GIT_MASK_NOTICE, "scrub": SCRUB_NOTICE, "cat": CAT_NOTICE}
                hook["additionalContext"] = " ".join(notices[k] for k in ("rg", "git", "scrub", "cat") if k in kinds)
            hook["updatedInput"] = {**data["tool_input"], "command": command}
            json.dump({"hookSpecificOutput": hook}, sys.stdout)
        elif targets or issues:
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
