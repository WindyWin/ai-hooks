# Shared secret masking hook

Claude and Codex both run one PreToolUse hook that keeps `.env` / `.properties` values out of the
conversation. There are two implementations of the same policy:

- **Rust** (`rust/`, the default): a single static binary, about 1-7 ms per call, no runtime needed.
- **Python** (`mask-secrets.py`): the original, kept as the fallback and as the reference the Rust
  port is checked against (`compare_impls.py`). Needs `python3`.

Edit the policy in both, or in neither: `compare_impls.py` fails when they disagree.
The old Claude script (`~/.claude/hooks/mask-secrets.py`) is a compatibility entry point to the Python hook
with no separate rules.

The policy blocks reads of `.env`, `.env.*`, `*.env`, and `*.properties`. When one
file is involved it returns a numbered preview with values replaced by `****`
(at most 5 files, 500 lines each). Template suffixes `.example`, `.sample`,
`.template`, `.dist`, and `.tpl` pass. Comments, keys, blank values, quoted multiline
dotenv values and properties continuation lines are handled.

## Install

One line (clones to `~/.local/share/ai-hooks`, or updates it, installs the hook binary, registers it):

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.sh | sh
```
```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.ps1 | iex
```

The script gets the Rust hook the first way that works: download the prebuilt binary from the latest
GitHub release, else `cargo build --release`, else fall back to the Python script. The first two need
no Python. From a checkout run `./install.sh` or `.\install.ps1`; pass flags after `sh -s --` when piping.
`AI_HOOKS_IMPL=python` forces the Python hook, `AI_HOOKS_DIR` changes the clone location.

The binary registers itself, so you can also do it by hand:

```bash
cargo build --release --manifest-path rust/Cargo.toml
rust/target/release/mask-secrets install            # --claude / --codex / --dry-run
rust/target/release/mask-secrets uninstall
```

It edits Claude's `~/.claude/settings.json` and Codex's `~/.codex/hooks.json` (plus
`features.hooks = true` in `config.toml`), only for agents whose config dir exists. It keeps your other
hooks, key order and indentation, backs up each file it changes, and is safe to re-run (an existing
entry is replaced in place, so switching from the Python hook to the binary is just re-running it).
Restart running sessions afterwards; Codex may ask you to trust the new hook (`/hooks`).
`python3 install.py` does the same for the Python hook.

### Releasing the binaries

Push a tag such as `v0.1.0`; `.github/workflows/release.yml` builds Linux (x86_64, aarch64, static musl),
macOS (Apple Silicon, Intel) and Windows binaries and attaches them to a GitHub release together with
`SHA256SUMS`. `install.sh` / `install.ps1` download `releases/latest/download/mask-secrets-<target>`.

## What it covers

- Claude `Read` / `Grep` tools pointing at a secret file, also through a symlink.
- `Grep` tool in `output_mode: content` over a directory that holds secret files, unless
  `glob` or `type` narrows it.
- Bash (and Codex shell aliases): a secret file named **anywhere** in a command that can print
  file content. That includes readers (`cat`, `grep`, `sed`, ...), unknown programs (`python`,
  `awk`, `curl`, ...), `for` lists and variables that feed a reader (`for f in a.properties; do cat "$f"`),
  `$(...)`, backticks, `bash -c`, `eval`, `< file`, `xargs`, `find -exec`, globs, `sudo`/`pkexec` wrappers,
  and relative names after `cd` / `git -C`.
  Commands that cannot print content (`ls`, `stat`, `wc`, `git add`, `git commit`, `find -name`,
  `cp`, `mv`, `rm`, ...) pass.
- git commands that print content (`diff`, `show`, `log -p`, `blame`, `grep`, `stash show -p`, ...). They pass
  with `--stat` / `--name-only` / `--name-status`, with explicit non-secret files, or when all secret file
  types are excluded: `-- . ':(exclude)*.properties' ':(exclude)*.env' ':(exclude).env*'`.
- Recursive searches (`grep -r`, `rg`, `ag`, `ack`) over a tree that holds secret files. They pass when
  `--exclude` / `-g '!...'` covers every secret file found, or `--include` / `-t` / `-g` narrows them.
- MCP tools (`mcp__*`): any string argument that names an existing secret file.
- Fail closed: if the hook itself errors on a request that mentions a secret file, the call is denied.

## Limitations

The hook reads command text; it cannot see what a program does with a filename it builds at run
time, copies of a secret file under another name, or a `git diff` style output that contains a secret
file the command never names beyond the cases above. For a hard guarantee also keep the
`permissions.deny` Read rules in `~/.claude/settings.json`, and use a sandbox filesystem deny for Bash.
Comments and template files are assumed not to contain real secret values.

Run tests with `python3 ~/.local/share/ai-hooks/test_mask_secrets.py`.
They create temporary fake files and do not read real secrets.

Registrations live in `~/.claude/settings.json` (matcher `Read|Grep|Bash|mcp__.*`) and `~/.codex/hooks.json`.
Codex hook definitions must be trusted; review new/changed definitions with `/hooks`.
Backups of earlier versions are under `backups/`.

Official Codex hook contract: https://learn.chatgpt.com/docs/hooks

## Tests and benchmark

```bash
cargo test --manifest-path rust/Cargo.toml          # Rust unit tests
python3 -m unittest test_mask_secrets               # black-box tests against the Python hook
HOOK_CMD=rust/target/release/mask-secrets python3 -m unittest test_mask_secrets   # same tests, Rust hook
python3 compare_impls.py                            # Python vs Rust on ~25k payloads; exit 1 on any difference
python3 bench_mask_secrets.py --cmd rust/target/release/mask-secrets --huge --check
```

`compare_impls.py` runs templated commands (readers x file names x shell forms, git, recursive searches,
the Read/Grep/MCP tools) plus random mutations of them through both implementations and reports any
difference in decision or reason. The benchmark spawns the hook like the agents do and compares against a
bare process-spawn floor; budgets are loose (0.5 s normal, 3.5 s for tree walks; the agents kill the hook
at 5 s). Options: `-n RUNS`, `--files N`, `--json`, `--cmd COMMAND`.

Typical latency per call on a 12-core Linux box: Rust 1.4-7 ms (19 ms for a 65k-file tree), Python 29-35 ms
(80 ms for the same tree).

Known difference from the Python hook: when a secret file is found but cannot be previewed (unreadable
or non-UTF-8 path) the Rust hook still blocks, with a generic message, where Python stays silent. The
Windows build is untested.
