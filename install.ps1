# Install the shared secret-masking hook for Claude Code and Codex (Windows PowerShell / pwsh).
#
#   .\install.ps1 [--claude] [--codex] [--dry-run] [--uninstall]
#   irm https://raw.githubusercontent.com/WindyWin/ai-hooks/main/install.ps1 | iex
#
# It gets the hook as a prebuilt Rust binary (no Python needed), in this order:
#   1. download the release binary
#   2. build it with cargo from rust\
#   3. fall back to the Python script (needs python)
# When run outside a checkout it clones the repo to $env:AI_HOOKS_DIR (default ~\.local\share\ai-hooks),
# or updates it if it is already there. Arguments are passed straight to the installer.
#
# Environment: AI_HOOKS_DIR, AI_HOOKS_REPO, AI_HOOKS_BIN_URL (override the download URL),
#              AI_HOOKS_IMPL=python (skip the binary and use the Python script).
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

$bin = Join-Path $dir 'bin\mask-secrets.exe'

function Test-Binary($path) {
    if (-not (Test-Path $path)) { return $false }
    try { & $path --version *> $null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}

function Get-Binary {
    $url = if ($env:AI_HOOKS_BIN_URL) { $env:AI_HOOKS_BIN_URL }
           else { "$repoUrl/releases/latest/download/mask-secrets-x86_64-pc-windows-msvc.exe" }
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
        if (Test-Binary $tmp) {
            New-Item -ItemType Directory -Force (Split-Path $bin) | Out-Null
            Move-Item -Force $tmp $bin
            return $true
        }
    } catch { }
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
    return $false
}

function Build-Binary {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { return $false }
    $manifest = Join-Path $dir 'rust\Cargo.toml'
    if (-not (Test-Path $manifest)) { return $false }
    Write-Host 'Building the Rust hook with cargo (first build takes a minute)'
    cargo build --release --quiet --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) { return $false }
    New-Item -ItemType Directory -Force (Split-Path $bin) | Out-Null
    Copy-Item -Force (Join-Path $dir 'rust\target\release\mask-secrets.exe') $bin
    return $true
}

if ($env:AI_HOOKS_IMPL -ne 'python') {
    if (Get-Binary)        { Write-Host "Installed the prebuilt Rust hook: $bin" }
    elseif (Build-Binary)  { Write-Host "Built the Rust hook: $bin" }
    elseif (Test-Binary $bin) { Write-Host "Could not download or build a new binary; keeping the existing $bin" }
    else { Write-Warning 'Could not get a prebuilt binary or build one with cargo; falling back to the Python hook' }
    if (Test-Binary $bin) {
        & $bin install @args
        exit $LASTEXITCODE
    }
}

$script = Join-Path $dir 'install.py'
if (Get-Command python -ErrorAction SilentlyContinue)       { & python $script @args }
elseif (Get-Command py -ErrorAction SilentlyContinue)       { & py -3 $script @args }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { & python3 $script @args }
else { throw 'Need either a Rust binary or Python 3 (the fallback hook is a Python script)' }
exit $LASTEXITCODE
