# Assemble Zerofall-style portable folder with native launcher (no WebView).
# Does NOT bundle IDA. Optionally copies x64dbg headless Release trees.
param(
    [string]$OutDir = "artifacts/release/native-portable",
    [string]$Name = "headless-re-mcp-win.x64",
    [switch]$SkipZip,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$stage = Join-Path $OutDir $Name
Write-Host "stage = $stage"
if ($WhatIf) {
    Write-Host "WhatIf: would stage portable tree and write FIRST_RUN.txt / run_native.cmd"
    exit 0
}

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item -Recurse "src\headless_re_mcp" (Join-Path $stage "src\headless_re_mcp")
Copy-Item "pyproject.toml","README.md","LICENSE","THIRD_PARTY_NOTICES.md","upstream.lock.json","first_setup.py" $stage -ErrorAction SilentlyContinue
Copy-Item -Recurse "docs" (Join-Path $stage "docs") -ErrorAction SilentlyContinue
Copy-Item -Recurse "scripts" (Join-Path $stage "scripts") -ErrorAction SilentlyContinue

foreach ($arch in @("x86","x64")) {
    $candidates = @(
        "external\x64dbg-$arch",
        "artifacts\x64dbg-$arch\Release"
    )
    $src = $null
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "headless.exe")) { $src = $c; break }
    }
    if ($null -eq $src) { continue }
    $target = Join-Path $stage "runtime\x64dbg-$arch"
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item -Recurse "$src\*" $target
}

$nativeCmd = @(
    '@echo off',
    'setlocal',
    'cd /d "%~dp0"',
    'set PYTHONPATH=%~dp0src',
    'python -m headless_re_mcp.native_app',
    'if errorlevel 1 pause'
) -join "`r`n"
Set-Content -Path (Join-Path $stage "run_native.cmd") -Value $nativeCmd -Encoding ASCII

$setupCmd = @(
    '@echo off',
    'setlocal',
    'cd /d "%~dp0"',
    'set PYTHONPATH=%~dp0src',
    'python first_setup.py',
    'if errorlevel 1 pause'
) -join "`r`n"
Set-Content -Path (Join-Path $stage "run_first_setup.cmd") -Value $setupCmd -Encoding ASCII

$firstRun = @(
    'Headless RE-MCP native portable',
    '===============================',
    '',
    '1. Install Python 3.11+ on PATH (embeddable runtime is a follow-up checkpoint).',
    '2. Double-click run_native.cmd  -> Tk/Win32 native launcher',
    '   or run_first_setup.cmd       -> terminal wizard',
    '3. Point IDA to your licensed install (NOT bundled).',
    '4. x64dbg headless (if present) is under runtime/x64dbg-*',
    '5. No WebView2 / Electron shell is used.'
) -join "`r`n"
Set-Content -Path (Join-Path $stage "FIRST_RUN.txt") -Value $firstRun -Encoding ASCII

if (-not $SkipZip) {
    $zip = Join-Path $OutDir "$Name.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path $stage -DestinationPath $zip
    Write-Host "Wrote $zip"
}

Write-Host "Staged: $stage"
