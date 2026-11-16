# Shared secret masking hook

Claude and Codex both run one PreToolUse hook that keeps `.env` / `.properties` values out of the
conversation. There are two implementations of the same policy:

- **Rust** (`rust/`, the default): a single static binary, about 1-7 ms per call, no runtime needed.
- **Python** (`mask-secrets.py`): the original, kept as the fallback and as the reference the Rust
  port is checked against (`compare_impls.py`). Needs `python3`.

Edit the policy in both, or in neither: `compare_impls.py` fails when they disagree.
The old Claude script (`~/.claude/hooks/mask-secrets.py`) is a compatibility entry point to the Python hook
with no separate rules.

The policy keeps reads of `.env`, `.env.*`, `*.env`, and `*.properties` from showing values. The `Read` tool is
blocked and the block message carries a numbered preview with values replaced by `****`
(at most 5 files, 500 lines each). Shell commands that would reach those files are not blocked
any more where they can be made safe: the hook rewrites them so they run and print the files masked
(`cat .env`, `head -1 .env`, `grep K .env`, `find . -exec cat {} +`, searches, git; see "Masked instead of blocked").
What cannot be rewritten safely is still blocked, with the same masked preview. Template suffixes `.example`, `.sample`,
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

### Interactive installer and counters

```bash
mask-secrets tui      # install / remove per agent, and a live blocked / masked dashboard
mask-secrets stats    # the same counters as plain text
```

The **Install** tab lists Claude Code and Codex with their state (installed, installed with a different
command, not installed, config not found). `enter` installs or removes the hook for the selected agent,
`a` installs for every detected agent, `u` removes from all, `d` toggles a dry run. It uses the same code as
`mask-secrets install`, so other hooks, key order and backups behave the same.

The **Stats** tab shows how many calls the hook **blocked** (denied) and **masked** (rewritten so the command
prints masked output) for all time, the last 7 days and the last 24 hours, per agent and per tool, with an
hourly chart and the most recent events. `r` refreshes, `c` clears the counters, `tab` switches tabs.

Counting works by appending one JSON line per blocked or masked call to
`~/.local/state/mask-secrets/events.jsonl` (`$XDG_STATE_HOME`, `%LOCALAPPDATA%` on Windows, or the path in
`MASK_SECRETS_LOG`; `MASK_SECRETS_LOG=off` disables it). A line holds the time, agent, tool, action and a short
detail: the secret file's base name, or the command's first word. It never holds a value, file content or a full
command line, and calls that pass untouched are not logged. Both the Rust and the Python hook write it, so the
counters work with either. The test suites and `compare_impls.py` set `MASK_SECRETS_LOG=off`.

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
  types are excluded: `-- . ':(exclude)*.properties' ':(exclude)*.env' ':(exclude).env*'`. Otherwise, on the
  Claude Bash tool, they are rewritten to print the files masked, see below.
- Recursive searches (`grep -r`, `rg`, `ag`, `ack`) over a tree that holds secret files. They pass when
  `--exclude` / `-g '!...'` covers every secret file found, or `--include` / `-t` / `-g` narrows them, or
  with `-q`. Otherwise, on the Claude Bash tool, they are rewritten to print the files masked, see below.
  `rg`: the hook rewrites the command (`updatedInput`) to
  `rg --pre <hook> --pre-glob '*.[pP]...' ... ` so rg searches the secret files **masked**. The hook doubles as
  the preprocessor (`mask-secrets FILE` prints the masked file) and `--pre-glob` limits it to `*.properties`,
  `*.env`, `.env` and `.env.*`, written as character classes because `--pre-glob` is case-sensitive (`.ENV`).
  The search still reports path, line number and key and the value is `****`, so "where is `DB_PASSWORD`
  defined?" gets an answer, and a value cannot be probed (`rg hunter2` finds nothing). It works with `-o`, `-c`,
  `-l`, `-C` and `--json`; template files (`.env.example`) are searched as they are; dotfiles still need
  `--hidden`, as always with rg. The size of the tree does not matter (no "too large to verify" block), because
  nothing has to be listed. The Python hook needs `mask-secrets.py` to be executable for this (it is in git;
  `chmod +x` it after copying it elsewhere). The rewritten command is analysed again and the original block
  stands when it cannot be made safe: nested shells (`bash -c`), `$(...)`, backticks, heredocs, quoted or
  redirected command words, `-L` / `--follow`, a `--pre` of its own, another searcher or secret file in the same
  command.
  - **Claude**: the permission decision is not touched, so normal permission prompts still apply.
  - **Codex** only accepts `updatedInput` together with `permissionDecision: "allow"`, which approves the call.
    So it is only rewritten when the whole command cannot change anything: `rg` (optionally after `cd`) piped
    into `head`, `tail`, `wc`, `sort` or `uniq` with plain flags, with only `2>/dev/null` / `2>&1` redirections
    and no variables, substitutions, `&`, other commands or `sort -o`. Anything else keeps the block. Codex
    payloads are recognised by their `turn_id` field.
- MCP tools (`mcp__*`): any string argument that names an existing secret file.
- Fail closed: if the hook itself errors on a request that mentions a secret file, the call is denied.

### Masked instead of blocked

A `PreToolUse` hook cannot change a tool's output, but it can change the command. So where a command can be made to
print the secret files masked, it is rewritten (`updatedInput`) and runs, and the agent gets `KEY=****` instead of a
refusal. Claude sees a short notice saying the command was changed. Each command type uses what it has:

| command | how it is masked | what the agent sees |
| --- | --- | --- |
| `rg` | `--pre <hook> --pre-glob ...`, the search runs over masked files | path, line, key, `****`; values cannot be probed |
| `git diff`, `show`, `log -p`, `blame`, `annotate`, `grep`, `reflog -p`, `stash show -p`, `diff-tree` / `diff-index` / `diff-files -p` | `-c core.attributesFile=... -c diff.maskenv.textconv=...` plus `--textconv --no-ext-diff`: git's own textconv filter runs the hook on every secret-looking file | `KEY=****` in the diff / blame / grep output; values cannot be probed (`log -S` and `git grep` match masked text). Both sides of a diff are masked, so a change that only touches a value shows **no diff** |
| `grep -r` (`egrep`, `fgrep`), `ag`, `ack` | `<search> \| <hook> --scrub`: a filter that masks lines that start with a secret file's path (`path:12:KEY=value`, `path-13-...`, `-Z`, `-c` counts) | `./.env:1:KEY=****`; the filter reads the file to recognise continuation lines of a multi-line value. A value **can** be probed with a pattern (the line shows up, masked) |
| `cat`, `tac`, `nl`, `head`, `tail`, `sort`, `cut`, `uniq`, `sed`, `awk`, `gawk`, `grep` (`egrep`, `fgrep`) naming a secret file | the file operand moves in front of the command: `head -1 .env` becomes `<hook> --cat .env \| head -1`. `--cat` prints the masked file (symlinks to a secret file too) and the reader runs on that text, so options, `sed` / `awk` programs and patterns work as written | the real command output on masked text: `cat .env` shows `KEY=****`, `awk -F= '{print $1}' .env` lists the keys, `grep -c K .env` counts. The exit status is that of the reader at the end of the pipeline. `grep` / `sed` / `awk` see masked text, so a value cannot be probed |
| `find ... -exec cat {} \;` / `+` (also `-execdir`) | `cat` is replaced by `<hook> --cat` | every file printed, secret ones masked |
| `find ... -exec grep ... {} \;` / `+` | `-H` is added when missing and the whole `find` is piped through `<hook> --scrub` (`--counts` when every grep has `-c`) | `./.env:1:KEY=****`, other files raw |

In all of these the original block stands instead when:

- the agent is Codex. A rewrite needs an approval there, so it keeps the rg-only rule above and blocks everything else (git / grep / ag / ack / cat / find).
- the command is too complex to edit safely: nested shells (`bash -c`), `$(...)`, backticks, heredocs, quoted or
  redirected command words, or a secret file is named directly in a part the rewrite does not cover.
- git: `--no-textconv`, `--ext-diff`, `--no-index`, `--output`, `--binary`, `-O`, `--attr-source`; subcommands
  textconv does not reach (`cat-file -p`, `difftool`); or the repository's `.gitattributes` / `.git/info/attributes`
  give those file names another `diff` driver (the hook asks `git check-attr` first). The attributes file the
  masking needs is written on first use to `$XDG_CACHE_HOME/mask-secrets/` (`~/.cache/...`, `%LOCALAPPDATA%` on
  Windows); when that fails the block stands.
- grep / ag / ack: a flag whose output has a shape the filter does not understand. Understood: `-n -i -w -x -F -E
  -G -P -v -c -l -L -A/-B/-C/-NUM -H -s -I -a -U -Z -m -e -f -d -D`, `--include`, `--exclude`, `--exclude-dir` and the
  long forms of those. Not rewritten: `-o`, `-h` / `--no-filename`, `--color`, `-z`, `-b`, `-R`, `ag --column`,
  `ack --group` / `--output`, and unknown flags. `grep -q` prints nothing and passes. The filter exits 1 when
  nothing came out, like grep, but it does not carry grep's own exit status. `ag` and `ack` print the same
  `path:line:text` shape as grep when piped, but were not available to test against.

- a direct read (`cat`, `head`, `sed`, `awk`, `grep` ...) that cannot be fed through `--cat` without changing what it
  means: more than one operand for anything but `cat`; an operand that is not a plain literal path (`$VAR`, glob,
  brace, `~user`, a quoted word that does not stay one word); a redirect other than `2>/dev/null` / `2>&1`
  (`< .env`, `> out`); a wrapper or assignment before the command (`sudo`, `command`, `rtk`, `FOO=1`); a flag
  outside the grammar of that reader (`sed -i`, `sed -f`, `sort -o`, `tail -f`, `grep -r`, `awk var=x file`, unknown
  flags); unknown programs (`python`, `less`, `vim`, `curl`, `tee` ...); and anything inside `bash -c`, `$(...)`
  or a heredoc.
- find -exec: an `-exec` whose program is not `cat` / `grep` with the arguments above and that could print the file
  (`head`, `sed`, `sh -c ...`, `grep -h` / `-o` / `--color`, a `{}` that is not the last argument) over a tree that
  holds secret files (or too large to verify). `-exec` programs that never print content (`ls`, `stat`, `wc` ...)
  pass. `-name` / `-iname` in a plain conjunction narrow the files `find` can select, so `find . -name '*.txt' -exec head {} +`
  passes when no `.txt` file is a secret; with `-o`, `!` or `\( ... \)` the whole tree counts.

The hook binary has three more entry points for this: `mask-secrets --mask env|properties FILE` (the textconv driver),
`mask-secrets --scrub [--counts]` (the stdin filter) and `mask-secrets --cat FILE...` (`cat` that masks secret files;
`-` is stdin, other files are copied as they are).

## Limitations

The hook reads command text; it cannot see what a program does with a filename it builds at run
time, copies of a secret file under another name, or a `git diff` style output that contains a secret
file the command never names beyond the cases above (`git format-patch --stdout` and `git range-diff` print raw
content and are not covered). A symlink or copy under an innocent name that `find -name` selects, or that
`find | xargs cat` reads, is not seen; a direct `cat link-to-env` is. `cat .e?v` and `cat $PWD/.env` are not
recognised as secret files either (the hook reads text, not the shell's expansion; this predates `--cat`). `--cat` with several
operands exits with the status of the reader at the end of the pipeline, not of a missing file. For a hard guarantee also keep the
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
