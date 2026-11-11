#!/usr/bin/env python3
"""Installer for the Python hook (the fallback; the Rust binary installs itself: `mask-secrets install`).

Registers mask-secrets.py as a PreToolUse hook for Claude Code and Codex.

    python3 install.py                 # every agent whose config dir exists
    python3 install.py --claude        # Claude only
    python3 install.py --codex         # Codex only
    python3 install.py --uninstall     # remove the hook again
    python3 install.py --dry-run       # show what would change

Idempotent: re-running updates the existing entry instead of adding a second one.
Other hooks and settings are left untouched; each changed file is backed up first.
Honours CLAUDE_CONFIG_DIR and CODEX_HOME. Standard library only.
"""
import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

HOOK_SCRIPT = Path(__file__).resolve().with_name("mask-secrets.py")
MARKER = "mask-secrets"  # matches both the Python script and the Rust binary
PYTHON = "python" if os.name == "nt" else "python3"  # Windows installs ship python, not python3
EVENT = "PreToolUse"

AGENTS = {
    "claude": {
        "matcher": "Read|Grep|Bash|mcp__.*",
        "default_dir": "~/.claude",
        "env": "CLAUDE_CONFIG_DIR",
        "file": "settings.json",
    },
    "codex": {
        "matcher": "^(Bash|Read|Grep|exec_command|shell_command|shell)$",
        "default_dir": "~/.codex",
        "env": "CODEX_HOME",
        "file": "hooks.json",
    },
}


def config_dir(agent):
    spec = AGENTS[agent]
    return Path(os.environ.get(spec["env"]) or os.path.expanduser(spec["default_dir"]))


def hook_entry(agent):
    return {
        "matcher": AGENTS[agent]["matcher"],
        "hooks": [
            {
                "type": "command",
                "command": f'{PYTHON} -I "{HOOK_SCRIPT}"',
                "timeout": 5,
                "statusMessage": "Masking secrets...",
            }
        ],
    }


def is_ours(group):
    return any(MARKER in (h.get("command") or "") for h in group.get("hooks", []))


def detect_indent(text):
    match = re.search(r"^( +|\t)\"", text, re.M)
    return match.group(1) if match else "  "


def backup(path):
    if path.exists():
        dest = path.with_name(f"{path.name}.bak.{time.strftime('%Y%m%d%H%M%S')}")
        shutil.copy2(path, dest)
        return dest
    return None


def write_if_changed(path, new_text, old_text, dry_run, label):
    if new_text == old_text:
        print(f"  {label}: already up to date")
        return
    if dry_run:
        print(f"  {label}: would update {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    saved = backup(path)
    path.write_text(new_text)
    print(f"  {label}: updated {path}" + (f" (backup: {saved.name})" if saved else ""))


def update_hooks_json(agent, uninstall, dry_run):
    path = config_dir(agent) / AGENTS[agent]["file"]
    old_text = path.read_text() if path.exists() else ""
    try:
        data = json.loads(old_text) if old_text.strip() else {}
    except json.JSONDecodeError as exc:
        sys.exit(f"  {agent}: {path} is not valid JSON ({exc}); fix it and re-run")
    indent = detect_indent(old_text) if old_text else "  "

    hooks = data.setdefault("hooks", {})
    groups, placed = [], False
    for group in hooks.get(EVENT, []):
        if not is_ours(group):
            groups.append(group)
        elif not uninstall and not placed:
            groups.append(hook_entry(agent))  # replace in place, keep position
            placed = True
    if not uninstall and not placed:
        groups.append(hook_entry(agent))
    if groups:
        hooks[EVENT] = groups
    else:
        hooks.pop(EVENT, None)
    if not hooks:
        data.pop("hooks")

    new_text = json.dumps(data, indent=indent, ensure_ascii=False) + "\n"
    write_if_changed(path, new_text, old_text, dry_run, agent)


def enable_codex_hooks_feature(uninstall, dry_run):
    """Codex ignores hooks.json unless [features] hooks = true is set in config.toml."""
    if uninstall:
        return
    path = config_dir("codex") / "config.toml"
    old_text = path.read_text() if path.exists() else ""
    section = re.search(r"^\[features\][ \t]*\n", old_text, re.M)
    if section:
        nxt = re.search(r"^\[", old_text[section.end():], re.M)
        body_end = section.end() + (nxt.start() if nxt else len(old_text) - section.end())
        body = old_text[section.end():body_end]
        if re.search(r"^hooks[ \t]*=[ \t]*true\b", body, re.M):
            return print("  codex: config.toml already has features.hooks = true")
        if re.search(r"^hooks[ \t]*=", body, re.M):
            body = re.sub(r"^hooks[ \t]*=.*$", "hooks = true", body, count=1, flags=re.M)
        else:
            body = "hooks = true\n" + body
        new_text = old_text[:section.end()] + body + old_text[body_end:]
    else:
        sep = "" if not old_text or old_text.endswith("\n\n") else "\n"
        new_text = old_text + sep + "[features]\nhooks = true\n"
    write_if_changed(path, new_text, old_text, dry_run, "codex config.toml")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--claude", action="store_true", help="install for Claude Code only")
    parser.add_argument("--codex", action="store_true", help="install for Codex only")
    parser.add_argument("--uninstall", action="store_true", help="remove the hook")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    args = parser.parse_args()

    if not HOOK_SCRIPT.is_file():
        sys.exit(f"missing {HOOK_SCRIPT}")

    chosen = [a for a in AGENTS if getattr(args, a)]
    if not chosen:
        chosen = [a for a in AGENTS if config_dir(a).is_dir()]
        if not chosen:
            sys.exit("neither ~/.claude nor ~/.codex found; pass --claude or --codex to create one")

    verb = "Removing" if args.uninstall else "Installing"
    print(f"{verb} hook {HOOK_SCRIPT}")
    for agent in chosen:
        update_hooks_json(agent, args.uninstall, args.dry_run)
        if agent == "codex":
            enable_codex_hooks_feature(args.uninstall, args.dry_run)

    if not args.dry_run:
        print("Restart running sessions to load the hook.")
        if "codex" in chosen and not args.uninstall:
            print("Codex may ask you to review/trust the new hook (/hooks) on next start.")


if __name__ == "__main__":
    main()
