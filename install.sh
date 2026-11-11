#!/bin/sh
# Install the shared secret-masking hook for Claude Code and Codex (Linux/macOS).
#
#   ./install.sh [--claude] [--codex] [--dry-run] [--uninstall]
#   curl -fsSL https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.sh | sh -s -- --codex
#
# When run outside a checkout it clones the repo to $AI_HOOKS_DIR
# (default ~/.local/share/ai-hooks), or updates it if it is already there.
set -eu

REPO_URL=${AI_HOOKS_REPO:-https://github.com/WindyWin/ai-hooks}
DEST=${AI_HOOKS_DIR:-$HOME/.local/share/ai-hooks}

here=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || here=
if [ -n "$here" ] && [ -f "$here/install.py" ] && [ -f "$here/mask-secrets.py" ]; then
    dir=$here
else
    command -v git >/dev/null 2>&1 || { echo "git is required to download ai-hooks" >&2; exit 1; }
    if [ -d "$DEST/.git" ]; then
        echo "Updating $DEST"
        git -C "$DEST" pull --ff-only
    elif [ -e "$DEST" ]; then
        echo "$DEST exists and is not a git checkout; move it or set AI_HOOKS_DIR" >&2
        exit 1
    else
        echo "Cloning $REPO_URL to $DEST"
        git clone --depth 1 "$REPO_URL" "$DEST"
    fi
    dir=$DEST
fi

for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        exec "$py" "$dir/install.py" "$@"
    fi
done
echo "python3 is required (the hook itself is a Python script)" >&2
exit 1
