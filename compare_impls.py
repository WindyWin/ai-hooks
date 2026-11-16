#!/usr/bin/env python3
"""Differential test: feed the same PreToolUse payloads to the Python and the Rust hook and report
every difference in decision or reason text.

    cargo build --release --manifest-path rust/Cargo.toml
    python3 compare_impls.py                 # templated corpus + 3000 random mutations
    python3 compare_impls.py --mutations 20000 --seed 7
    python3 compare_impls.py --show 20       # print more mismatches

Exit status is 1 when any payload gets a different answer. Python runs in-process (fast); Rust is
spawned once per payload, exactly like the agents do.
"""
import argparse
import importlib.util
import io
import itertools
import json
import os
import random
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ["MASK_SECRETS_LOG"] = "off"  # comparing must not write to the real block / mask counters
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mask_secrets", HERE / "mask-secrets.py")
py = importlib.util.module_from_spec(spec)
spec.loader.exec_module(py)

READERS = ["cat", "head -n1", "tail", "less", "grep x", "sed -n p", "awk '{print}'", "cut -d= -f2", "sort", "strings",
           "xxd", "bash", "source", ".", "python3 -c 'print(1)'", "curl -F @", "cp", "ls", "wc -l", "stat", "echo",
           "diff -u", "rg x", "tee", "nl", "vim"]
FILES = [".env", "./.env", "sub/.env", "'.env'", '".env"', "$PWD/.env", "*.env", ".e?v", ".en[v]", "app.properties",
         "*.properties", "{a,b}.env", "{.env,notes.txt}", "link.txt", ".env.example", "notes.txt", "'my dir/.env'",
         "my\\ dir/.env", "**/.env", "sub/deep/config.properties", "~/.env", "$HOME/.env", "../.env", "sub/../.env",
         "src/main/resources/app.properties", "a.env", ".env.local", "/etc/passwd", "Main.java", ".git/.env", ""]
FORMS = ["{c} {f}", "cd sub && {c} {f}", "{c} < {f}", "echo hi | {c} {f}", "x=$({c} {f})", "x=`{c} {f}`",
         "for f in {f}; do {c} \"$f\"; done", "bash -c '{c} {f}'", "sudo {c} {f}", "env A=1 {c} {f}",
         "{c} {f} # comment", "{c} {f}; ls", "ls; {c} {f}", "ls && {c} {f}", "{c} {f} > out.txt", "{c} {f} 2>&1",
         "timeout 5 {c} {f}", "xargs {c} <<< {f}", "eval '{c} {f}'", "while read l; do echo $l; done < {f}",
         "f={f}; {c} $f", "cat <(echo) {f}", "(cd sub; {c} {f})", "{{ {c} {f}; }}", "! {c} {f}", "nohup {c} {f} &",
         "cd .. && cd sub && {c} {f}", "pushd sub >/dev/null; {c} {f}", "{c} \"{f}\"", "{c} '{f}'"]
GIT = ["git diff", "git show HEAD", "git log -p", "git log --stat", "git diff --stat", "git diff -- .env",
       "git diff -- notes.txt", "git grep x", "git grep -l x", "git blame notes.txt", "git blame .env",
       "git show HEAD:.env", "git cat-file -p HEAD:.env", "git -C sub diff", "git diff -- . ':(exclude)*.env'",
       "git diff -- . ':(exclude)*.properties' ':(exclude)*.env' ':(exclude).env*'", "git diff --name-only",
       "git stash show -p", "git log -c", "git diff -U5", "git show --stat", "git status", "git ls-files",
       "git log -p -3", "git reflog -p", "git diff-tree -p HEAD", "git diff-index -p HEAD", "git diff --no-textconv",
       "git diff --ext-diff", "git show --output=x", "git stash list -p", "git stash apply", "git annotate Main.java",
       "git blame -- .env", "git diff HEAD~1", "git show HEAD:Main.java", "git grep -n x HEAD", "git grep -O x",
       "git diff --no-index a b", "git -c core.pager=cat diff", "git --git-dir=.git diff", "git -C sub log -p",
       "git diff -- . && ls", "git diff | head", "cd sub && git diff HEAD", "git diff --binary", "git range-diff a b c",
       "git difftool", "git diff -O", "git log -p --attr-source=HEAD", "sudo git diff", "FOO=1 git log -p",
       "git diff ; git cat-file -p HEAD:.env", "git show HEAD~1:app.properties", "git diff 'x y'", "git diff \"x\""]
SEARCH = ["grep -r x .", "grep -rn TODO", "grep -R x sub", "grep -rn x --include='*.java' .", "grep -r x --exclude='*.env' .",
          "grep -r x --exclude='*.properties' --exclude='*.env' --exclude='.env*' .", "rg x", "rg x sub", "rg -t java x",
          "rg x -g '!*.env'", "rg x -g '!*.properties' -g '!*.env' -g '!.env*'", "rg -g '*.java' x", "ag x", "ack x",
          "grep -d recurse x .", "echo hi | grep x", "grep -r x notes.txt", "grep x notes.txt", "grep -rl x .",
          "find . -name '*.env'", "find . -name '*.env' -exec cat {} \\;", "find . -type f | xargs cat",
          "find . -name .env -print", "fd .env", "locate .env", "ls -R", "tree", "du -a", "grep -r x /tmp/nonexistent",
          "grep -rniw x .", "grep -rc x .", "grep -rq x .", "grep -rqn x .", "grep -rneq .", "grep -rho x .", "grep -rh x .",
          "grep -rn --color=always x .", "grep -rnA2 x .", "grep -rn -e a -e b .", "grep -rn x . | head", "grep -rn x . && ls",
          "grep -rn x . > o", "grep -rn x . || echo n", "egrep -rn 'a|b' .", "fgrep -rn x .", "grep -rnZ x .", "grep -rz x .",
          "grep -rnm1 x .", "grep -rn -5 x .", "grep -rn --include='*.java' -e x .", "ag -i x", "ack -w x", "ag -o x", "ack -h x",
          "ag --column x", "ack --group x", "ag --pager cat x", "rg x; grep -rn y", "cd sub && grep -rn x .",
          "grep -rn x sub other", "grep -rq x . && echo y", "grep --recursive --line-number x .", "grep -r --quiet x .",
          "grep -rn x . | grep -r y", "grep -rn x . | cat", "grep -rn x | head -1", "grep -rn x . 2>/dev/null",
          "(grep -rn x .)", "{ grep -rn x .; }", "if grep -rq x .; then echo y; fi", "for d in sub .; do grep -rn x $d; done",
          "grep -rn x .\ngrep -rn y .", "grep -rnI x .", "grep -rn --exclude-dir=sub x .", "grep -rn -m 1 x .", "grep -rn -d recurse x .",
          "grep -rnf pats .", "grep -rnE -- x .", "grep -rn x . src/main", "grep -rn -x x ."]
FIND = ["find . -name .env -exec cat {} \\;", "find . -type f -exec cat {} +", "find . -type f -exec cat {} \\; 2>/dev/null",
        "find . -type f -execdir cat {} \\;", "find . -name '*.properties' -exec cat {} +", "find sub -type f -exec cat {} +",
        "find . -type f -exec grep -H TOKEN {} +", "find . -type f -exec grep TOKEN {} +", "find . -type f -exec grep -c x {} \\;",
        "find . -type f -exec grep -i x {} \\; | sort", "find . -type f -exec grep -h x {} +", "find . -type f -exec grep -rn x {} +",
        "find . -type f -exec grep -o x {} +", "find . -type f -exec head -1 {} +", "find . -type f -ok head -1 {} \\;",
        "find . -type f -exec cat {}", "find . -type f -exec", "find . -type f -exec cp {} /tmp/x +", "find . -type f -exec ls -l {} \\;",
        "find . -name '*.txt' -exec head -1 {} +", "find . -name '*.txt' -exec cat {} +", "find . \\( -name '*.txt' -o -name .env \\) -exec cat {} +",
        "find . -name '*.txt' -o -name '*.env' -exec cat {} +", "find . ! -name '*.env' -exec head {} +", "find . -iname '.ENV' -exec cat {} +",
        "find . -type f -exec cat {} \\; -exec cat {} \\;", "find . -type f -exec ls {} \\; -exec cat {} \\;", "find . -type f -exec sh -c 'cat \"$0\"' {} \\;",
        "find . -type f -fprint out.txt", "find . -type f -exec cat {} + | head", "cd sub && find . -type f -exec cat {} +",
        "find . -type f -exec cat {} + && ls", "find . -type f -exec grep -H x {} + 2>&1", "find . -exec cat {} +", "find -exec cat {} +",
        "find / -exec cat {} +", "find . -type f -exec grep -Hn --color=always x {} +", "find . -type f -exec rtk cat {} +",
        "find . -type f -exec /usr/bin/cat {} +", "sudo find . -type f -exec cat {} +", "find . -name .env -ok cat {} \\;"]
# a secret file named as the operand of a reader: the operand moves into `<hook> --cat FILE |`
DIRECT = ["cat .env", "head -1 .env", "head -n 2 app.properties", "sed -n 1p .env", "sed -i s/a/b/ .env", "awk '{print $1}' .env",
          "awk -F= '{print $2}' .env", "awk -v x=1 '{print}' .env", "awk '{print}' x=1 .env", "cut -d= -f1 .env", "sort .env", "sort -o o .env",
          "nl .env", "tac .env", "uniq .env", "tail -f .env", "tail -n +2 .env", "grep K .env", "grep -n K app.properties", "grep -r K .env",
          "grep -e a -e b .env", "grep -f pats .env", "egrep 'a|b' .env", "fgrep -i k .env", "cat .env notes.txt", "cat notes.txt .env",
          "cat -n .env app.properties", "head .env notes.txt", "cat -- .env", "cat -- -x .env", "cat - .env", "cat .env -", "cat link.txt",
          "cat sub/.env", "cat ./sub/.env", "cat '.env'", "cat '.e'nv", "cat \".env\"", "cat .env.example", "cat .env 2>/dev/null", "cat .env 2>&1",
          "cat .env 2> err", "cat .env > o", "cat < .env", "cat .env | head", "cat .env | cat", "if cat .env; then echo y; fi",
          "while cat .env; do :; done", "! cat .env", "{ cat .env; }", "(cat .env)", "x=1 cat .env", "sudo cat .env", "command cat .env",
          "env cat .env", "cd sub && cat .env", "cd sub && cat ../.env", "cat ~/.env", "cat $HOME/.env", "cat *.env", "cat .e?v", "cat {.env,a.env}",
          "cat .env; cat app.properties", "cat .env && head app.properties", "cat .env &", "head -c 10 .env", "head -10 .env", "head -qn1 .env",
          "sed -e p .env", "sed -E -n '/K/p' .env", "sed --expression=p .env", "sed s/a/b/ .env", "sed -s -n 1p .env", "less .env", "tee .env",
          "cat .env\ncat app.properties", "head --lines=2 .env", "cat --number .env", "cat --bogus .env", "tail -n1 -f .env", "sort -k2 .env",
          "sort -t= -k2 .env", "cut -c1-3 .env", "uniq -c .env", "nl -ba .env", "cat 'my dir/.env'", "cat my\\ dir/.env", "cat -A .env", "gawk 1 .env"]
TOOLS = [("Read", {"file_path": f}) for f in [".env", "notes.txt", "link.txt", ".env.example", "sub/.env", "../.env",
                                              "app.properties", "~/.env", "$HOME/.env", "", "nonexistent.env"]]
TOOLS += [("Grep", {"pattern": "x", **extra}) for extra in [
    {}, {"path": ".env"}, {"path": "sub"}, {"path": ".", "output_mode": "content"}, {"glob": "*.env"},
    {"path": ".", "output_mode": "content", "glob": "*.java"}, {"path": ".", "output_mode": "content", "glob": "!*.env"},
    {"path": ".", "output_mode": "content", "type": "java"}, {"path": "sub", "output_mode": "files_with_matches"},
    {"path": "*.env"}, {"glob": "**/.env", "output_mode": "content"}, {"path": "nonexistent", "output_mode": "content"}]]
TOOLS += [("mcp__x__y", inp) for inp in [
    {"path": ".env"}, {"nested": {"deep": ["a", ".env"]}}, {"q": "select 1"}, {"path": "'.env'"}, {"p": "sub/.env",
     "q": "x"}, {"cmd": "cat .env"}, {"glob": "*.env"}, {"n": 5, "ok": True}, [".env"], "plain"]]
TOOLS += [("Write", {"file_path": ".env"}), ("Edit", {"file_path": "x"}), ("WebFetch", {"url": "http://a/.env"})]
TOOLS += [(t, {"command": ".env" if False else "cat .env", "workdir": "sub"}) for t in ["exec_command", "shell_command", "shell"]]
TOOLS += [("exec_command", {"cmd": "cat .env"}), ("Bash", {"cmd": "cat .env"}), ("Bash", {"command": ""}), ("Bash", {})]

# Codex payloads carry a turn_id; a rewrite is only offered (with an allow) for read-only rg pipelines
CODEX_RG = ["rg x | head -5", "rg -n x 2>&1 | sort -u | wc -l", "cd sub && rg x 2>/dev/null", "rg x && ls", "rg x > o", "rg x | xargs cat",
            "FOO=1 rg x", "rg -L x", "rg 'a$'", "rg $HOME", "(rg x)", "rg x &", "rg x | sort -o o", "rg x | uniq a b", "rg x | head -n 3 | tail -1",
            "rg --pre cat x", "rg x -g '*.env'", "rg x\nrg y", "rg x | tail -f", "sudo rg x", "rg x 2>&1 >/dev/null", "rg x 2> e",
            "rg x | head \"$f\"", "echo $(rg x)", "rg x; rg y | wc -l", "cd .. && rg x"]

MUTATION_CHARS = ["'", '"', "\\", " ", ";", "&&", "|", "$(", ")", "`", "#", "\n", "<", ">", "&", "{", "}", "$", "*", "?", "~"]


def make_tree(root: Path) -> None:
    (root / "sub" / "deep").mkdir(parents=True)
    (root / "my dir").mkdir()
    (root / "src" / "main" / "resources").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "node_modules" / "x").mkdir(parents=True)
    for rel, body in {
        ".env": "TOKEN=FAKE_A\nEMPTY=\n", "app.properties": "password=FAKE_B\n", ".env.example": "T=ex\n",
        "a.env": "X=FAKE_C\n", ".env.local": "L=FAKE_D\n", "sub/.env": "SUB=FAKE_E\n",
        "sub/deep/config.properties": "k=FAKE_F\n", "my dir/.env": "SP=FAKE_G\n", "notes.txt": "plain\n",
        "Main.java": "class Main {}\n", "src/main/resources/app.properties": "db.password=FAKE_H\n",
        ".git/.env": "G=FAKE_I\n", "node_modules/x/.env": "N=FAKE_J\n", "out.txt": "o\n",
    }.items():
        (root / rel).write_text(body)
    (root / "link.txt").symlink_to(root / ".env")


def describe(out: str, pre: str):
    """The deny reason, or `REWRITE <command>` when the hook rewrote the command instead. `pre` is the
    preprocessor path the implementation put in the command (the script or the binary); it differs per implementation."""
    if not out:
        return None
    hook = json.loads(out)["hookSpecificOutput"]
    if "updatedInput" in hook:
        if hook.get("permissionDecision") == "allow":  # Codex: the rewrite comes with an approval
            assert "additionalContext" not in hook
            tag = "REWRITE+ALLOW "
        else:  # Claude: the permission flow is not touched
            assert "permissionDecision" not in hook and hook.get("additionalContext")
            tag = "REWRITE "
        return tag + hook["updatedInput"]["command"].replace(shlex.quote(pre), "<PRE>")
    return hook["permissionDecisionReason"]


def run_python(payload: dict):
    stdin, stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        py.main()
        out = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = stdin, stdout
    return describe(out, os.path.abspath(py.__file__))


def run_rust(binary: str, payload: dict):
    r = subprocess.run([binary], input=json.dumps(payload), text=True, capture_output=True)
    if r.returncode != 0 or r.stderr:
        return f"<<RUST FAILURE rc={r.returncode} stderr={r.stderr[:200]}>>"
    return describe(r.stdout, os.path.realpath(binary))


def normalize(reason):
    """Order of files in 'such as: a, b' depends on directory listing order; compare as sets."""
    if reason is None:
        return None
    import re
    def fix(m):
        return m.group(1) + ", ".join(sorted(m.group(2).split(", "))) + m.group(3)
    return re.sub(r"(secret file\(s\) such as: )(.*?)(\)\.)", fix, reason)


EDGE_FILES = {"crlf.env": "A=FAKE_1\r\nB='x\r\ny'\r\n", "uni.properties": "a=FAKE_2\u2028b=FAKE_3\u0085c d\n",
              "cont.properties": "k=1\\\n  2\\\n  3\nz: 4\n", ".env.production": "export P=FAKE_4 # c\n\n# only comment\n",
              "bad.env": "T=FAKE_\udcff\n", "empty.env": "", "blank.env": "\n\n"}


def compare_masked_views(binary: str, root: Path) -> list:
    """`rg --pre` runs the hook as `hook FILE`: both implementations must print the same bytes."""
    for rel, body in EDGE_FILES.items():
        (root / rel).write_bytes(body.encode("utf-8", "surrogateescape"))
    bad = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        a = py.masked_view(str(path))
        r = subprocess.run([binary, str(path)], capture_output=True)
        if r.returncode != 0 or r.stderr or r.stdout != a:
            bad.append((str(path.relative_to(root)), a, r.stdout, r.returncode))
    return bad


def compare_filters(binary: str, root: Path) -> list:
    """git textconv (`--mask env|properties FILE`) and the grep filter (`--scrub`): same bytes from both implementations."""
    bad = []
    files = sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts[:1])
    for path in files:
        data = path.read_bytes()
        for kind in ("env", "properties"):
            a = py.masked_bytes("x." + kind, data)
            r = subprocess.run([binary, "--mask", kind, str(path)], capture_output=True)
            if r.returncode != 0 or r.stderr or r.stdout != a:
                bad.append((f"--mask {kind} {path.relative_to(root)}", a, r.stdout, r.returncode))
    lines = []
    for path in files:
        rel = str(path.relative_to(root))
        text = path.read_bytes().decode("utf-8", "replace")
        for n, line in enumerate(text.splitlines(), 1):
            for form in (f"./{rel}:{n}:{line}", f"./{rel}-{n}-{line}", f"{rel}:{line}", f"./{rel}\0{line}", f"./{rel}:{n}:3:{line}",
                         f"./{rel}:{n}:{line[:3]}", f"./{rel}:{n}", f"./{rel}-{line}", f"./{rel}:{n + 7}:{line}", f"./{rel}:{line}\r"):
                lines.append(form)
        lines += [f"./{rel}", f"./{rel}:3", f"{rel}:99999999999999999999999:x=y", f"{rel}:"]
    lines += ["--", "", "plain text", "src/Main.java:12:  // see app.properties: x=y", "Binary file ./a.env matches"]
    for counts in (False, True):
        py._FILE_LINES.clear()
        want = "".join(py.scrub_line(l + "\n", counts) for l in lines).encode("utf-8", "surrogateescape")
        got = subprocess.run([binary, "--scrub"] + (["--counts"] if counts else []), input="".join(l + "\n" for l in lines).encode("utf-8", "surrogateescape"),
                             capture_output=True, cwd=root)
        if got.stdout != want or got.stderr:
            bad.append((f"--scrub counts={counts}", want, got.stdout, got.returncode))
            for w, g, l in zip(want.split(b"\n"), got.stdout.split(b"\n"), lines):
                if w != g:
                    bad.append((f"  first difference for input {l!r}", w, g, 0))
                    break
    # `--cat FILE...`: the masked view of every operand (secret files and links to them masked, the rest raw), errors on stderr
    names = [str(p.relative_to(root)) for p in files] + ["missing.txt", "sub", "-"]
    for group in [[n] for n in names] + [[".env", "notes.txt"], ["notes.txt", "missing.txt", "app.properties"], ["link.txt", ".env.example"],
                                           ["-", ".env"], []]:
        runs = []
        for cmd in ([sys.executable, str(HERE / "mask-secrets.py")], [binary]):
            r = subprocess.run(cmd + ["--cat"] + group, input=b"FAKE_STDIN\n", capture_output=True, cwd=root)
            runs.append((r.stdout, r.stderr.replace(b"mask-secrets --cat", b"X"), r.returncode))
        if runs[0] != runs[1]:
            bad.append((f"--cat {' '.join(group)}", runs[0], runs[1], runs[1][2]))
    return bad


def corpus(seed: int, mutations: int):
    bash = [t.format(c=c, f=f) for t, c, f in itertools.product(FORMS, READERS, FILES)]
    bash += GIT + SEARCH + FIND + DIRECT + [f"cd sub && {g}" for g in GIT + SEARCH + FIND + DIRECT]
    rng = random.Random(seed)
    seeds = rng.sample(bash, min(len(bash), 400))
    for _ in range(mutations):
        s = list(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            pos = rng.randint(0, len(s))
            op = rng.random()
            if op < 0.6:
                s[pos:pos] = list(rng.choice(MUTATION_CHARS))
            elif op < 0.8 and s:
                del s[min(pos, len(s) - 1)]
            elif s:
                j = rng.randint(0, len(s) - 1)
                s[j], s[pos - 1 if pos else 0] = s[pos - 1 if pos else 0], s[j]
        bash.append("".join(s))
    payloads = [("Bash", {"command": c}) for c in dict.fromkeys(bash)] + TOOLS
    payloads += [("Bash", {"command": c}, {"turn_id": "turn-1"}) for c in dict.fromkeys(SEARCH + CODEX_RG + FIND[:6] + DIRECT[:12])]
    return payloads


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rust", default=str(HERE / "rust/target/release/mask-secrets"))
    ap.add_argument("--mutations", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--show", type=int, default=10, help="mismatches to print")
    args = ap.parse_args()
    if not Path(args.rust).exists():
        sys.exit(f"build the Rust binary first: cargo build --release --manifest-path rust/Cargo.toml ({args.rust})")

    payloads = corpus(args.seed, args.mutations)
    mismatches, decisions = [], {"deny": 0, "rewrite": 0, "allow": 0}
    with tempfile.TemporaryDirectory(prefix="mask-secrets-diff-") as tmp:
        root = Path(tmp) / "proj"
        root.mkdir()
        make_tree(root)
        os.chdir(root)
        os.environ["XDG_CACHE_HOME"] = str(Path(tmp) / "cache")  # both implementations write the git attributes file here
        subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
        for tool, inp, *extra in payloads:
            payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp, "cwd": str(root),
                       **(extra[0] if extra else {})}
            a, b = normalize(run_python(payload)), normalize(run_rust(args.rust, payload))
            decisions["allow" if not a else "rewrite" if a.startswith("REWRITE") else "deny"] += 1
            if a != b:
                mismatches.append((tool, inp, a, b))

        for attrs in ["*.properties diff=java\n", ".env -diff\n", "* diff=x\n", "*.java diff=java\n", "*.env binary\n", ""]:
            (root / ".gitattributes").write_text(attrs)
            for command in ["git diff", "git log -p", "git grep x", "git blame Main.java", "git show HEAD:.env", "cd sub && git diff"]:
                payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(root)}
                a, b = normalize(run_python(payload)), normalize(run_rust(args.rust, payload))
                decisions["allow" if not a else "rewrite" if a.startswith("REWRITE") else "deny"] += 1
                payloads.append(("Bash", {"command": command, "attributes": attrs}))
                if a != b:
                    mismatches.append(("Bash", {"command": command, "attributes": attrs}, a, b))
        (root / ".gitattributes").unlink()

        view_mismatches = compare_masked_views(args.rust, root) + compare_filters(args.rust, root)
    print(f"{len(payloads)} payloads (Python: {decisions['deny']} denied, {decisions['rewrite']} rewritten, {decisions['allow']} allowed), "
          f"{len(mismatches)} mismatches; masked views: {len(view_mismatches)} mismatches")
    for name, a, b, rc in view_mismatches[: args.show]:
        print(f"\n--- masked view of {name}\n  python: {a!r}\n  rust:   {b!r} (rc={rc})")
    kinds = {}
    for tool, inp, a, b in mismatches:
        k = ("python-deny/rust-allow" if a and not b else "python-allow/rust-deny" if b and not a else "different text")
        kinds[k] = kinds.get(k, 0) + 1
    for k, n in kinds.items():
        print(f"  {k}: {n}")
    for tool, inp, a, b in mismatches[: args.show]:
        print(f"\n--- {tool} {json.dumps(inp, ensure_ascii=False)}\n  python: {(a or 'ALLOW')[:300]!r}\n  rust:   {(b or 'ALLOW')[:300]!r}")
    return 1 if mismatches or view_mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
