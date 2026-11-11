#!/bin/sh
# Install the shared secret-masking hook for Claude Code and Codex (Linux/macOS).
#
#   ./install.sh [--claude] [--codex] [--dry-run] [--uninstall]
#   curl -fsSL https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.sh | sh -s -- --codex
#
# It gets the hook as a prebuilt Rust binary (no Python needed), in this order:
#   1. download the release binary for this OS/CPU
#   2. build it with cargo from rust/
#   3. fall back to the Python script (needs python3)
# When run outside a checkout it clones the repo to $AI_HOOKS_DIR (default ~/.local/share/ai-hooks),
# or updates it if it is already there.
#
# Environment: AI_HOOKS_DIR, AI_HOOKS_REPO, AI_HOOKS_BIN_URL (override the download URL),
#              AI_HOOKS_IMPL=python (skip the binary and use the Python script).
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

bin="$dir/bin/mask-secrets"

detect_target() {
    case "$(uname -m)" in
        x86_64 | amd64) cpu=x86_64 ;;
        aarch64 | arm64) cpu=aarch64 ;;
        *) return 1 ;;
    esac
    case "$(uname -s)" in
        Linux) echo "$cpu-unknown-linux-musl" ;;
        Darwin) echo "$cpu-apple-darwin" ;;
        *) return 1 ;;
    esac
}

fetch() { # fetch URL FILE
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
    else return 1; fi
}

works() { [ -x "$1" ] && "$1" --version >/dev/null 2>&1; }

download_binary() {
    url=${AI_HOOKS_BIN_URL:-}
    if [ -z "$url" ]; then
        target=$(detect_target) || return 1
        url="$REPO_URL/releases/latest/download/mask-secrets-$target"
    fi
    tmp=$(mktemp) || return 1
    if fetch "$url" "$tmp" && chmod +x "$tmp" && works "$tmp"; then
        mkdir -p "$dir/bin" && mv "$tmp" "$bin" && return 0
    fi
    rm -f "$tmp"
    return 1
}

build_binary() {
    command -v cargo >/dev/null 2>&1 && [ -f "$dir/rust/Cargo.toml" ] || return 1
    echo "Building the Rust hook with cargo (first build takes a minute)"
    cargo build --release --quiet --manifest-path "$dir/rust/Cargo.toml" || return 1
    mkdir -p "$dir/bin" && cp "$dir/rust/target/release/mask-secrets" "$bin"
}

if [ "${AI_HOOKS_IMPL:-}" != python ]; then
    if download_binary; then
        echo "Installed the prebuilt Rust hook: $bin"
    elif build_binary; then
        echo "Built the Rust hook: $bin"
    elif works "$bin"; then
        echo "Could not download or build a new binary; keeping the existing $bin"
    else
        echo "Could not get a prebuilt binary or build one with cargo; falling back to the Python hook" >&2
    fi
    if works "$bin"; then
        exec "$bin" install "$@"
    fi
fi

for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        exec "$py" "$dir/install.py" "$@"
    fi
done
echo "Need either a Rust binary or python3 (the fallback hook is a Python script)" >&2
exit 1
