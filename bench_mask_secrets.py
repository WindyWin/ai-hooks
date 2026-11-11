#!/usr/bin/env python3
"""Latency benchmark for mask-secrets.py.

The hook runs as a fresh process before every Read/Grep/Bash/MCP call, so what matters is
wall-clock time per invocation (interpreter start + policy), not in-process speed. Each scenario
spawns the hook exactly as the agents do (`python -I mask-secrets.py`, JSON on stdin), checks it
made the expected decision, and reports min/median/p95/max.

    python3 bench_mask_secrets.py                # default: 30 runs per scenario
    python3 bench_mask_secrets.py -n 100         # more samples
    python3 bench_mask_secrets.py --huge         # also build a tree past the walk cap (~60k entries)
    python3 bench_mask_secrets.py --check        # exit 1 if a p95 exceeds its budget (CI-friendly)
    python3 bench_mask_secrets.py --json         # machine-readable output

Budgets are deliberately loose (shared CI boxes are noisy). The agents kill the hook after 5 s, so
anything near that is a real problem; the tree-walk scenarios are capped by the hook's own
WALK_BUDGET_SECONDS. Not named test_*.py, so `unittest` discovery skips it.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT = Path(__file__).with_name("mask-secrets.py")
CMD = [sys.executable, "-I", str(SCRIPT)]

FAST_BUDGET = 0.5   # seconds, p95: ordinary calls (hook timeout in the agents is 5 s)
WALK_BUDGET = 3.5   # seconds, p95: scenarios that walk a big tree (hook's own cap is 2 s + startup)


def build_tree(root: Path, files: int, secret: bool = True) -> None:
    """A project-shaped tree: nested dirs, source files, optionally one .env deep inside."""
    per_dir = 25
    for i in range(files):
        d = root / "src" / f"pkg{i // (per_dir * 20)}" / f"mod{(i // per_dir) % 20}"
        if i % per_dir == 0:
            d.mkdir(parents=True, exist_ok=True)
        (d / f"file{i}.txt").write_text("x\n")
    if secret:
        (root / "src" / "pkg0" / "mod0" / ".env").write_text("DEEP_TOKEN=FAKE_DEEP_123\n")


def scenarios(root: Path, big: Path, clean: Path, huge: Path | None):
    """(name, tool, tool_input, cwd, expect_deny, budget)"""
    cwd = str(root)
    s = [
        ("allow  Bash ls", "Bash", {"command": "ls -la"}, cwd, False, FAST_BUDGET),
        ("allow  Bash pipeline", "Bash",
         {"command": "git log --oneline | head -20 && find . -name '*.py' | xargs wc -l | sort -n | tail -5"},
         cwd, False, FAST_BUDGET),
        ("allow  Read plain", "Read", {"file_path": "regular.txt"}, cwd, False, FAST_BUDGET),
        ("allow  Read .env.example", "Read", {"file_path": ".env.example"}, cwd, False, FAST_BUDGET),
        ("allow  MCP big args", "mcp__x__query",
         {"query": "select * from t where a = 1 " * 200, "rows": [{"k": str(i)} for i in range(500)]},
         cwd, False, FAST_BUDGET),
        ("deny   Read .env", "Read", {"file_path": ".env"}, cwd, True, FAST_BUDGET),
        ("deny   Bash cat .env", "Bash", {"command": "cat .env"}, cwd, True, FAST_BUDGET),
        ("deny   Bash obfuscated loop", "Bash",
         {"command": 'for f in app.properties; do cat "$f"; done'}, cwd, True, FAST_BUDGET),
        ("deny   Read huge .env (2000 lines)", "Read", {"file_path": "huge.env"}, cwd, True, FAST_BUDGET),
        ("walk   Bash grep -r (big tree)", "Bash", {"command": "grep -rn TODO ."}, str(big), True, WALK_BUDGET),
        ("walk   Grep content (big tree)", "Grep", {"path": ".", "output_mode": "content", "pattern": "x"},
         str(big), True, WALK_BUDGET),
        ("allow  Bash grep -r (big tree, no secrets)", "Bash", {"command": "grep -rn TODO ."},
         str(clean), False, WALK_BUDGET),
        ("allow  Bash grep -r --include (big tree)", "Bash",
         {"command": "grep -rn TODO --include='*.py' ."}, str(big), False, FAST_BUDGET),
    ]
    if huge:
        s.append(("deny   Bash rg (huge tree, fails closed)", "Bash", {"command": "rg TODO"}, str(huge), True, WALK_BUDGET))
    return s


def run_once(tool, inp, cwd) -> tuple[float, bool]:
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp, "cwd": cwd})
    t0 = time.perf_counter()
    r = subprocess.run(CMD, input=payload, text=True, capture_output=True)
    dt = time.perf_counter() - t0
    if r.returncode != 0 or r.stderr:
        sys.exit(f"hook failed (rc={r.returncode}): {r.stderr.strip()[:300]}")
    out = json.loads(r.stdout) if r.stdout else None
    denied = bool(out and out["hookSpecificOutput"]["permissionDecision"] == "deny")
    return dt, denied


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p * (len(values) - 1))))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-n", "--runs", type=int, default=30, help="samples per scenario (default 30)")
    ap.add_argument("--files", type=int, default=5000, help="files in the 'big' tree (default 5000)")
    ap.add_argument("--huge", action="store_true", help="also benchmark a ~65k-entry tree (slow to build)")
    ap.add_argument("--check", action="store_true", help="exit 1 if any p95 exceeds its budget")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="mask-secrets-bench-") as tmp:
        root, big, clean = Path(tmp) / "small", Path(tmp) / "big", Path(tmp) / "clean"
        for d in (root, big, clean):
            d.mkdir()
        (root / ".env").write_text("TOKEN=FAKE_TOKEN_123\nHOST=fake.invalid\n")
        (root / "app.properties").write_text("password=FAKE_PASSWORD_123\n")
        (root / ".env.example").write_text("TOKEN=example\n")
        (root / "regular.txt").write_text("ordinary text\n")
        (root / "huge.env").write_text("".join(f"KEY_{i}=FAKE_VALUE_{i}\n" for i in range(2000)))
        build_tree(big, args.files)
        build_tree(clean, args.files, secret=False)
        huge = None
        if args.huge:
            huge = Path(tmp) / "huge"
            huge.mkdir()
            build_tree(huge, 65000, secret=False)

        # Floor: bare interpreter start with the same flags, so hook cost can be read as the delta.
        floor = []
        for _ in range(args.runs):
            t0 = time.perf_counter()
            subprocess.run([sys.executable, "-I", "-c", "pass"], check=True)
            floor.append(time.perf_counter() - t0)

        rows, failed = [], False
        for name, tool, inp, cwd, expect_deny, budget in scenarios(root, big, clean, huge):
            run_once(tool, inp, cwd)  # warm the page cache / .pyc
            times = []
            for _ in range(args.runs):
                dt, denied = run_once(tool, inp, cwd)
                if denied != expect_deny:
                    sys.exit(f"{name}: expected {'deny' if expect_deny else 'allow'}, got the opposite")
                times.append(dt)
            p95 = pct(times, 0.95)
            over = p95 > budget
            failed |= over
            rows.append({"scenario": name, "min": min(times), "median": statistics.median(times),
                         "p95": p95, "max": max(times), "budget": budget, "over_budget": over})

    floor_row = {"scenario": "floor  python -I -c pass", "min": min(floor), "median": statistics.median(floor),
                 "p95": pct(floor, 0.95), "max": max(floor), "budget": None, "over_budget": False}
    rows.insert(0, floor_row)

    if args.json:
        print(json.dumps({"runs": args.runs, "python": sys.version.split()[0], "results": rows}, indent=2))
    else:
        print(f"mask-secrets.py latency, {args.runs} runs each, Python {sys.version.split()[0]}, "
              f"{os.cpu_count()} CPUs (ms)\n")
        print(f"{'scenario':<42}{'min':>8}{'median':>8}{'p95':>8}{'max':>8}{'budget':>8}")
        for r in rows:
            budget = f"{r['budget'] * 1000:.0f}" if r["budget"] else "-"
            flag = "  OVER" if r["over_budget"] else ""
            print(f"{r['scenario']:<42}{r['min'] * 1000:>8.1f}{r['median'] * 1000:>8.1f}"
                  f"{r['p95'] * 1000:>8.1f}{r['max'] * 1000:>8.1f}{budget:>8}{flag}")
        print("\nhook cost above the interpreter floor = median - floor median.")
    return 1 if (args.check and failed) else 0


if __name__ == "__main__":
    sys.exit(main())
