# Build portable ZIP without IDA / unclear-license unpackers (M15.2).
param(
    [string]$OutDir = "artifacts/release",
    [string]$Name = "headless-re-mcp-portable"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$stage = Join-Path $OutDir "_portable_stage"
$dest = Join-Path $stage $Name
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# Application source (ASCII paths only).
Copy-Item -Recurse "src\headless_re_mcp" (Join-Path $dest "src\headless_re_mcp")
Copy-Item "pyproject.toml","README.md","LICENSE","upstream.lock.json","start_web.py","setup.py" $dest -ErrorAction SilentlyContinue
Copy-Item -Recurse "docs" (Join-Path $dest "docs") -ErrorAction SilentlyContinue
# external/ docs + placeholders (binaries filled below when present). Never copy IDA.
New-Item -ItemType Directory -Force -Path (Join-Path $dest "external") | Out-Null
if (Test-Path "external\README.md") {
    Copy-Item "external\README.md" (Join-Path $dest "external\README.md")
}
if (Test-Path "external\optional\README.md") {
    New-Item -ItemType Directory -Force -Path (Join-Path $dest "external\optional") | Out-Null
    Copy-Item "external\optional\README.md" (Join-Path $dest "external\optional\README.md")
}

# Release payloads never carry caches, user databases, configuration or dumps.
Get-ChildItem -LiteralPath $dest -Directory -Recurse -Force |
    Where-Object { $_.Name -in @("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules") } |
    Sort-Object FullName -Descending |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
Get-ChildItem -LiteralPath $dest -File -Recurse -Force |
    Where-Object { $_.Extension -in @(".pyc", ".pyo", ".dmp", ".idb", ".i64") -or $_.Name -in @("agent.db", "providers.json", "config.json") } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
if (-not (Test-Path -LiteralPath (Join-Path $dest "src\headless_re_mcp\web\spa\index.html"))) {
    throw "production SPA missing; run: cd webui; npm ci; npm run build"
}

# Packable x64dbg runtimes (GPL). Prefer external/, then artifacts/. Never IDA.
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
    $target = Join-Path $dest "runtime\x64dbg-$arch"
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item -Recurse "$src\*" $target
    # Also mirror under external/ inside the portable tree for docs + auto-discover.
    $extTarget = Join-Path $dest "external\x64dbg-$arch"
    New-Item -ItemType Directory -Force -Path $extTarget | Out-Null
    Copy-Item -Recurse "$src\*" $extTarget
}

@"
Headless RE-MCP Portable
========================

1. Install Python 3.11+ and: pip install -e ".[web,test]"
2. x64dbg headless (if included) lives under external/x64dbg-* and runtime/x64dbg-*
3. IDA is NEVER bundled — set HEADLESS_RE_IDA_HOME to your licensed install
4. Optional CLIs (diec/upx/de4dot/...) via env — see external/README.md
5. Run: python -m headless_re_mcp doctor --strict
6. Serve MCP: python -m headless_re_mcp serve
7. Browser workbench: python start_web.py

This archive may include GPL x64dbg headless Release trees.
It does NOT include IDA, idalib, Hex-Rays, DIE, de4dot, Exeinfo, or unclear-license unpackers.
"@ | Out-File -Encoding ascii (Join-Path $dest "FIRST_RUN.txt")

$zip = Join-Path $OutDir "$Name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $dest -DestinationPath $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $Name.zip" | Out-File -Encoding ascii (Join-Path $OutDir "$Name.sha256")
Write-Host "Wrote $zip"
Write-Host "SHA256 $hash"
