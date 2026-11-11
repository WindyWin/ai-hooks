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
import subprocess
import sys
import tempfile
from pathlib import Path

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
       "git stash show -p", "git log -c", "git diff -U5", "git show --stat", "git status", "git ls-files"]
SEARCH = ["grep -r x .", "grep -rn TODO", "grep -R x sub", "grep -rn x --include='*.java' .", "grep -r x --exclude='*.env' .",
          "grep -r x --exclude='*.properties' --exclude='*.env' --exclude='.env*' .", "rg x", "rg x sub", "rg -t java x",
          "rg x -g '!*.env'", "rg x -g '!*.properties' -g '!*.env' -g '!.env*'", "rg -g '*.java' x", "ag x", "ack x",
          "grep -d recurse x .", "echo hi | grep x", "grep -r x notes.txt", "grep x notes.txt", "grep -rl x .",
          "find . -name '*.env'", "find . -name '*.env' -exec cat {} \\;", "find . -type f | xargs cat",
          "find . -name .env -print", "fd .env", "locate .env", "ls -R", "tree", "du -a", "grep -r x /tmp/nonexistent"]
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


def run_python(payload: dict):
    stdin, stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        py.main()
        out = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = stdin, stdout
    return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"] if out else None


def run_rust(binary: str, payload: dict):
    r = subprocess.run([binary], input=json.dumps(payload), text=True, capture_output=True)
    if r.returncode != 0 or r.stderr:
        return f"<<RUST FAILURE rc={r.returncode} stderr={r.stderr[:200]}>>"
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout else None


def normalize(reason):
    """Order of files in 'such as: a, b' depends on directory listing order; compare as sets."""
    if reason is None:
        return None
    import re
    def fix(m):
        return m.group(1) + ", ".join(sorted(m.group(2).split(", "))) + m.group(3)
    return re.sub(r"(secret file\(s\) such as: )(.*?)(\)\.)", fix, reason)


def corpus(seed: int, mutations: int):
    bash = [t.format(c=c, f=f) for t, c, f in itertools.product(FORMS, READERS, FILES)]
    bash += GIT + SEARCH + [f"cd sub && {g}" for g in GIT + SEARCH]
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
    mismatches, decisions = [], {"deny": 0, "allow": 0}
    with tempfile.TemporaryDirectory(prefix="mask-secrets-diff-") as tmp:
        root = Path(tmp) / "proj"
        root.mkdir()
        make_tree(root)
        os.chdir(root)
        for tool, inp in payloads:
            payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp, "cwd": str(root)}
            a, b = normalize(run_python(payload)), normalize(run_rust(args.rust, payload))
            decisions["deny" if a else "allow"] += 1
            if a != b:
                mismatches.append((tool, inp, a, b))

    print(f"{len(payloads)} payloads ({decisions['deny']} denied by Python, {decisions['allow']} allowed), "
          f"{len(mismatches)} mismatches")
    kinds = {}
    for tool, inp, a, b in mismatches:
        k = ("python-deny/rust-allow" if a and not b else "python-allow/rust-deny" if b and not a else "different text")
        kinds[k] = kinds.get(k, 0) + 1
    for k, n in kinds.items():
        print(f"  {k}: {n}")
    for tool, inp, a, b in mismatches[: args.show]:
        print(f"\n--- {tool} {json.dumps(inp, ensure_ascii=False)}\n  python: {(a or 'ALLOW')[:300]!r}\n  rust:   {(b or 'ALLOW')[:300]!r}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
