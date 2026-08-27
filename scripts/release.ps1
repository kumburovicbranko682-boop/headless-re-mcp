#Requires -Version 5.1
<#
.SYNOPSIS
  Single guarded release entry point for all distributable artifacts.

.EXAMPLE
  powershell -File scripts/release.ps1 -Target package
  powershell -File scripts/release.ps1 -Target portable,deps
  powershell -File scripts/release.ps1 -Target msi -WixDir "C:\Program Files (x86)\WiX Toolset v3.14\bin"
#>
[CmdletBinding()]
param(
    [string]$Target = "package",
    [string]$OutDir = "artifacts/release",
    [string]$WixDir = "",
    [switch]$SkipZip,
    [switch]$SkipSbom,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$ResolvedRoot = [IO.Path]::GetFullPath($Root)
$ResolvedOutput = [IO.Path]::GetFullPath((Join-Path $Root $OutDir))

function Assert-UnderOutput([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($Path)
    $prefix = $ResolvedOutput.TrimEnd("\") + "\"
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "unsafe release path outside output root: $resolved"
    }
    return $resolved
}

function Reset-Stage([string]$Path) {
    $resolved = Assert-UnderOutput $Path
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $resolved | Out-Null
    return $resolved
}

function Remove-ReleaseJunk([string]$Path) {
    $resolved = Assert-UnderOutput $Path
    Get-ChildItem -LiteralPath $resolved -Directory -Recurse -Force |
        Where-Object { $_.Name -in @(
            "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"
        ) } |
        Sort-Object FullName -Descending |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
    Get-ChildItem -LiteralPath $resolved -File -Recurse -Force |
        Where-Object {
            $_.Extension -in @(".pyc", ".pyo", ".dmp", ".idb", ".i64", ".log", ".tmp") -or
            $_.Name -in @("agent.db", "providers.json", "config.json")
        } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
}

function Write-ArtifactHash([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($item.Name)" | Set-Content -LiteralPath "$($item.FullName).sha256" -Encoding ASCII
    Write-Host "SHA256 $hash  $($item.Name)"
}

function Copy-AppTree([string]$Destination) {
    Copy-Item -Recurse "src\headless_re_mcp" (Join-Path $Destination "src\headless_re_mcp")
    # THIRD_PARTY_NOTICES.md and the docs/ tree were folded into README when the
    # public docs shrank; with $ErrorActionPreference = Stop, copying either
    # made every portable build throw on the missing path.
    Copy-Item @(
        "pyproject.toml", "setup.py", "start_web.py", "README.md", "LICENSE",
        "upstream.lock.json"
    ) $Destination
    Remove-ReleaseJunk $Destination
    $spa = Join-Path $Destination "src\headless_re_mcp\web\spa\index.html"
    if (-not (Test-Path -LiteralPath $spa)) {
        throw "production SPA missing; run: cd webui; npm ci; npm run build"
    }
}

function Find-XdbgRuntime([string]$Arch) {
    foreach ($candidate in @(
        "external\x64dbg-$Arch",
        "artifacts\x64dbg-$Arch\Release"
    )) {
        if (Test-Path -LiteralPath (Join-Path $candidate "headless.exe")) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Build-Package {
    New-Item -ItemType Directory -Force -Path $ResolvedOutput | Out-Null
    python -m pip install -U build hatchling
    if ($LASTEXITCODE -ne 0) { throw "failed to install build dependencies" }
    python -m build --sdist --wheel --outdir $ResolvedOutput
    if ($LASTEXITCODE -ne 0) { throw "python package build failed" }
    if (-not $SkipSbom) {
        python -m pip freeze | Out-File -Encoding UTF8 (Join-Path $ResolvedOutput "sbom-pip-freeze.txt")
    }
    Get-ChildItem -LiteralPath $ResolvedOutput -File |
        Where-Object { $_.Name -match '\.(whl|tar\.gz)$' } |
        ForEach-Object { Write-ArtifactHash $_.FullName }
}

function Build-Portable {
    $stageRoot = Reset-Stage (Join-Path $ResolvedOutput "_portable_stage")
    $name = "headless-re-mcp-portable"
    $destination = Join-Path $stageRoot $name
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-AppTree $destination

    foreach ($arch in @("x86", "x64")) {
        $source = Find-XdbgRuntime $arch
        if (-not $source) {
            Write-Warning "x64dbg $arch runtime missing; portable remains partially configured"
            continue
        }
        $runtime = Join-Path $destination "runtime\x64dbg-$arch"
        New-Item -ItemType Directory -Force -Path $runtime | Out-Null
        Copy-Item -Recurse -Force (Join-Path $source "*") $runtime
    }

    $setupCmd = @(
        '@echo off', 'setlocal', 'cd /d "%~dp0"',
        'python setup.py', 'if errorlevel 1 pause'
    ) -join "`r`n"
    Set-Content -LiteralPath (Join-Path $destination "setup.cmd") -Value $setupCmd -Encoding ASCII
    $webCmd = @(
        '@echo off', 'setlocal', 'cd /d "%~dp0"',
        'python start_web.py', 'if errorlevel 1 pause'
    ) -join "`r`n"
    Set-Content -LiteralPath (Join-Path $destination "start_web.cmd") -Value $webCmd -Encoding ASCII
    @"
Headless RE-MCP Portable
========================

Run one command: python setup.py
The installer adds Python dependencies, downloads and verifies the pinned Release
dependency bundle when needed, detects licensed IDA 9.x, writes MCP configuration,
and runs Doctor. IDA / idalib / Hex-Rays are never bundled.
"@ | Set-Content -LiteralPath (Join-Path $destination "FIRST_RUN.txt") -Encoding ASCII

    if (-not $SkipZip) {
        $zip = Join-Path $ResolvedOutput "$name.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path $destination -DestinationPath $zip -CompressionLevel Optimal
        Write-ArtifactHash $zip
    }
}

function Copy-DependencyTree([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source)) { return $false }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -Recurse -Force (Join-Path $Source "*") $Destination
    return $true
}

function Build-Deps {
    $depsRoot = Join-Path $ResolvedOutput "deps-bundle"
    New-Item -ItemType Directory -Force -Path $depsRoot | Out-Null
    $name = "headless-re-mcp-deps-win.x64"
    $stage = Reset-Stage (Join-Path $depsRoot $name)
    $included = @()
    $missing = @()

    foreach ($arch in @("x64", "x86")) {
        $source = Find-XdbgRuntime $arch
        if (-not $source) {
            $missing += "x64dbg-$arch"
            continue
        }
        $destination = Join-Path $stage "runtime\x64dbg-$arch"
        if (Copy-DependencyTree $source $destination) {
            $included += @{
                id = "x64dbg-$arch"; path = "runtime/x64dbg-$arch/headless.exe";
                license = "GPL-3.0"
            }
        }
    }

    $toolMap = @(
        @{ id="upx"; src="artifacts\tools\upx-5.2.0"; dst="tools\upx"; exe="upx.exe"; license="GPL-2.0-or-later"; env="HEADLESS_RE_UPX" },
        @{ id="die"; src="artifacts\tools\die_win64_portable_3.21_x64"; dst="tools\die"; exe="diec.exe"; license="MIT"; env="HEADLESS_RE_DIEC" },
        @{ id="cdb"; src="artifacts\tools\cdb-amd64"; dst="tools\cdb"; exe="cdb.exe"; license="Microsoft Debugging Tools"; env="HEADLESS_RE_CDB" },
        @{ id="de4dot"; src="artifacts\tools\de4dotEx-3.2.4-net48"; dst="tools\de4dot"; exe="de4dot.exe"; license="GPL-3.0"; env="HEADLESS_RE_DE4DOT" },
        @{ id="net_reactor_slayer"; src="artifacts\tools\NETReactorSlayer-v6.4.0.0"; dst="tools\net_reactor_slayer"; exe="NETReactorSlayer.CLI.exe"; license="GPL-3.0"; env="HEADLESS_RE_NET_REACTOR_SLAYER" }
    )
    foreach ($tool in $toolMap) {
        $destination = Join-Path $stage $tool.dst
        if (-not (Copy-DependencyTree $tool.src $destination)) {
            $missing += $tool.id
            continue
        }
        $found = Get-ChildItem -LiteralPath $destination -Recurse -File -Filter $tool.exe |
            Select-Object -First 1
        if (-not $found) {
            $missing += "$($tool.id):exe"
            continue
        }
        $relative = $found.FullName.Substring($stage.Length).TrimStart("\").Replace("\", "/")
        $included += @{
            id=$tool.id; path=$relative; license=$tool.license; env=$tool.env
        }
    }

    Copy-Item "upstream.lock.json", "LICENSE" $stage
    $manifest = [ordered]@{
        schema_version = 1
        name = $name
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        never_bundles_ida = $true
        excluded = @("IDA Professional", "idalib", "Hex-Rays", "ExeinfoPE")
        included = $included
        missing = $missing
    }
    $manifest | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $stage "MANIFEST.json") -Encoding UTF8
    @"
Headless RE-MCP dependency bundle (NO IDA)
================================================
Extracted and configured automatically by: python setup.py
Manual activation is unnecessary. See MANIFEST.json and upstream.lock.json.
"@ | Set-Content -LiteralPath (Join-Path $stage "FIRST_RUN.txt") -Encoding ASCII

    if (-not $SkipZip) {
        $zip = Join-Path $depsRoot "$name.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
        Write-ArtifactHash $zip
    }
    Write-Host "Included: $(($included | ForEach-Object { $_.id }) -join ', ')"
    if ($missing.Count) { Write-Warning "Missing: $($missing -join ', ')" }
}

function Build-Msi {
    # Delegated rather than reimplemented: the MSI has to carry the interpreter
    # and the full dependency closure, and build_msi.ps1 is the copy that does
    # that and is exercised by the release workflow and verify_msi.ps1.
    $builder = Join-Path $PSScriptRoot "build_msi.ps1"
    & $builder -OutDir $OutDir -WixDir $WixDir
    if ($LASTEXITCODE -eq 2) { throw "WiX candle/light/heat not found; pass -WixDir" }
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed: $LASTEXITCODE" }
}

$targets = @($Target.Split(",") | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
$allowedTargets = @("package", "portable", "deps", "msi")
$invalidTargets = @($targets | Where-Object { $_ -notin $allowedTargets })
if ($invalidTargets.Count) {
    throw "invalid release target(s): $($invalidTargets -join ', ')"
}
if (-not $targets.Count) { throw "at least one release target is required" }
Write-Host "Headless RE-MCP release targets: $($targets -join ', ')"
Write-Host "Output: $ResolvedOutput"
if ($WhatIf) {
    Write-Host "WhatIf: validation complete; no files changed."
    exit 0
}
foreach ($item in $targets) {
    switch ($item) {
        "package" { Build-Package }
        "portable" { Build-Portable }
        "deps" { Build-Deps }
        "msi" { Build-Msi }
    }
}
Write-Host "Release targets completed."
