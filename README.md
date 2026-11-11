# Shared secret masking hook

Claude and Codex both run `python3 -I ~/.local/share/ai-hooks/mask-secrets.py`
at PreToolUse. Edit this file to update the policy for both agents.
The old Claude script (`~/.claude/hooks/mask-secrets.py`) is a compatibility entry
point with no separate rules.

The policy blocks reads of `.env`, `.env.*`, `*.env`, and `*.properties`. When one
file is involved it returns a numbered preview with values replaced by `****`
(at most 5 files, 500 lines each). Template suffixes `.example`, `.sample`,
`.template`, `.dist`, and `.tpl` pass. Comments, keys, blank values, quoted multiline
dotenv values and properties continuation lines are handled.

## Install

```bash
git clone https://github.com/WindyWin/ai-hooks ~/.local/share/ai-hooks
python3 ~/.local/share/ai-hooks/install.py
```

`install.py` registers the hook for Claude (`~/.claude/settings.json`) and Codex
(`~/.codex/hooks.json`, plus `features.hooks = true` in `config.toml`). It only touches
agents whose config dir exists, backs up each file it changes, keeps your other hooks, and is
safe to re-run. Options: `--claude`, `--codex`, `--dry-run`, `--uninstall`. Restart running
sessions afterwards; Codex may ask you to trust the new hook (`/hooks`).

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
