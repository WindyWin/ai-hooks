# Install the shared secret-masking hook for Claude Code and Codex (Windows PowerShell / pwsh).
#
#   .\install.ps1 [--claude] [--codex] [--dry-run] [--uninstall]
#   irm https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.ps1 | iex
#
# When run outside a checkout it clones the repo to $env:AI_HOOKS_DIR
# (default ~\.local\share\ai-hooks), or updates it if it is already there.
# Arguments are passed straight to install.py (use the same --flags as on Linux/macOS).
$ErrorActionPreference = 'Stop'

$repoUrl = if ($env:AI_HOOKS_REPO) { $env:AI_HOOKS_REPO } else { 'https://github.com/WindyWin/ai-hooks' }
$dest    = if ($env:AI_HOOKS_DIR)  { $env:AI_HOOKS_DIR }  else { Join-Path $HOME '.local\share\ai-hooks' }

$here = $PSScriptRoot
if ($here -and (Test-Path (Join-Path $here 'install.py')) -and (Test-Path (Join-Path $here 'mask-secrets.py'))) {
    $dir = $here
} else {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is required to download ai-hooks' }
    if (Test-Path (Join-Path $dest '.git')) {
        Write-Host "Updating $dest"
        git -C $dest pull --ff-only
    } elseif (Test-Path $dest) {
        throw "$dest exists and is not a git checkout; move it or set AI_HOOKS_DIR"
    } else {
        Write-Host "Cloning $repoUrl to $dest"
        git clone --depth 1 $repoUrl $dest
    }
    if ($LASTEXITCODE -ne 0) { throw 'git failed' }
    $dir = $dest
}

$script = Join-Path $dir 'install.py'
if (Get-Command python -ErrorAction SilentlyContinue)    { & python $script @args }
elseif (Get-Command py -ErrorAction SilentlyContinue)    { & py -3 $script @args }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { & python3 $script @args }
else { throw 'Python 3 is required (the hook itself is a Python script)' }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
