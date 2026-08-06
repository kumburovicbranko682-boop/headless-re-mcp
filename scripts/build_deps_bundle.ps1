# Build a deps-only portable bundle (everything useful except IDA).
# Output: artifacts/release/deps-bundle/headless-re-mcp-deps-win.x64(.zip)
param(
    [string]$OutDir = "artifacts/release/deps-bundle",
    [string]$Name = "headless-re-mcp-deps-win.x64",
    [switch]$SkipZip,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$stage = Join-Path $OutDir $Name
Write-Host "stage = $stage"
if ($WhatIf) {
    Write-Host "WhatIf: would pack x64dbg/upx/die/cdb/de4dot/nrs (never IDA)"
    exit 0
}

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Copy-Tree([string]$Src, [string]$Dst) {
    if (-not (Test-Path $Src)) {
        Write-Warning "missing: $Src"
        return $false
    }
    New-Item -ItemType Directory -Force -Path $Dst | Out-Null
    Copy-Item -Recurse -Force (Join-Path $Src "*") $Dst
    return $true
}

function Find-HeadlessSrc([string]$Arch) {
    foreach ($c in @(
        "external\x64dbg-$Arch",
        "artifacts\x64dbg-$Arch\Release"
    )) {
        if (Test-Path (Join-Path $c "headless.exe")) { return $c }
    }
    return $null
}

$included = @()
$missing = @()

foreach ($arch in @("x64", "x86")) {
    $src = Find-HeadlessSrc $arch
    $dst = Join-Path $stage "runtime\x64dbg-$arch"
    if ($null -eq $src) {
        $missing += "x64dbg-$arch"
        continue
    }
    if (Copy-Tree $src $dst) {
        $included += @{
            id = "x64dbg-$arch"
            path = "runtime/x64dbg-$arch/headless.exe"
            license = "GPL-3.0"
        }
    }
}

$toolMap = @(
    @{ id = "upx"; src = "artifacts\tools\upx-5.2.0"; dst = "tools\upx"; exe = "upx.exe"; license = "GPL-2.0-or-later"; env = "HEADLESS_RE_UPX" },
    @{ id = "die"; src = "artifacts\tools\die_win64_portable_3.21_x64"; dst = "tools\die"; exe = "die\diec.exe"; license = "MIT"; env = "HEADLESS_RE_DIEC" },
    @{ id = "cdb"; src = "artifacts\tools\cdb-amd64"; dst = "tools\cdb"; exe = "cdb.exe"; license = "Microsoft Debugging Tools (redistribute per your MSDN terms)"; env = "HEADLESS_RE_CDB" },
    @{ id = "de4dot"; src = "artifacts\tools\de4dotEx-3.2.4-net48"; dst = "tools\de4dot"; exe = "de4dot.exe"; license = "GPL-3.0"; env = "HEADLESS_RE_DE4DOT" },
    @{ id = "net_reactor_slayer"; src = "artifacts\tools\NETReactorSlayer-v6.4.0.0"; dst = "tools\net_reactor_slayer"; exe = "NETReactorSlayer.CLI.exe"; license = "GPL-3.0"; env = "HEADLESS_RE_NET_REACTOR_SLAYER" }
)

foreach ($t in $toolMap) {
    $ok = Copy-Tree $t.src (Join-Path $stage $t.dst)
    if (-not $ok) {
        $missing += $t.id
        continue
    }
    $exeRel = Join-Path $t.dst $t.exe
    $exeFull = Join-Path $stage $exeRel
    if (-not (Test-Path $exeFull)) {
        $found = Get-ChildItem (Join-Path $stage $t.dst) -Recurse -Filter (Split-Path $t.exe -Leaf) -EA SilentlyContinue | Select-Object -First 1
        if ($found) {
            $exeRel = $found.FullName.Substring($stage.Length).TrimStart("\").Replace("\", "/")
        } else {
            Write-Warning "exe missing after copy: $($t.id)"
            $missing += "$($t.id):exe"
            continue
        }
    } else {
        $exeRel = $exeRel.Replace("\", "/")
    }
    $included += @{
        id = $t.id
        path = $exeRel
        license = $t.license
        env = $t.env
    }
}

Copy-Item "upstream.lock.json" (Join-Path $stage "upstream.lock.json") -ErrorAction SilentlyContinue
Copy-Item "LICENSE" (Join-Path $stage "LICENSE") -ErrorAction SilentlyContinue
Copy-Item "README.md" (Join-Path $stage "README.md") -ErrorAction SilentlyContinue

$manifest = [ordered]@{
    schema_version = 1
    name = $Name
    generated_at = (Get-Date).ToString("o")
    never_bundles_ida = $true
    excluded = @("IDA Professional", "idalib", "Hex-Rays", "ExeinfoPE")
    included = $included
    missing = $missing
    activate = "Run activate_deps.ps1 from this folder, or set HEADLESS_RE_* to paths under runtime/ and tools/."
}
$manifestPath = Join-Path $stage "MANIFEST.json"
($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path $manifestPath -Encoding UTF8

$activate = @'
# Point HEADLESS_RE_* at this deps bundle (IDA still required separately).
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
function P([string]$Rel) { Join-Path $Root $Rel }

$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = (P "runtime\x64dbg-x64\headless.exe")
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = (P "runtime\x64dbg-x86\headless.exe")

$upx = P "tools\upx\upx.exe"
if (Test-Path $upx) { $env:HEADLESS_RE_UPX = $upx }

$diec = Get-ChildItem (P "tools\die") -Recurse -Filter diec.exe -EA SilentlyContinue | Select-Object -First 1
if ($diec) { $env:HEADLESS_RE_DIEC = $diec.FullName }

$cdb = P "tools\cdb\cdb.exe"
if (Test-Path $cdb) { $env:HEADLESS_RE_CDB = $cdb }

$de4dot = Get-ChildItem (P "tools\de4dot") -Recurse -Filter de4dot.exe -EA SilentlyContinue | Select-Object -First 1
if ($de4dot) { $env:HEADLESS_RE_DE4DOT = $de4dot.FullName }

$nrs = Get-ChildItem (P "tools\net_reactor_slayer") -Recurse -Filter "NETReactorSlayer*.exe" -EA SilentlyContinue |
    Where-Object { $_.Name -match "CLI" } | Select-Object -First 1
if (-not $nrs) {
    $nrs = Get-ChildItem (P "tools\net_reactor_slayer") -Recurse -Filter "*.exe" -EA SilentlyContinue | Select-Object -First 1
}
if ($nrs) { $env:HEADLESS_RE_NET_REACTOR_SLAYER = $nrs.FullName }

Write-Host "Deps activated from $Root"
Write-Host "IDA is NOT included. Set HEADLESS_RE_IDA_HOME to your licensed install."
Get-ChildItem Env:HEADLESS_RE_* | Format-Table Name, Value -AutoSize
'@
Set-Content -Path (Join-Path $stage "activate_deps.ps1") -Value $activate -Encoding UTF8

$first = @(
    "Headless RE-MCP dependency bundle (NO IDA)",
    "=========================================",
    "",
    "Includes when present: x64dbg headless x86/x64, UPX, DIE diec, cdb,",
    "de4dotEx, NETReactorSlayer.",
    "",
    "Excluded forever: IDA / idalib / Hex-Rays / ExeinfoPE.",
    "",
    "Usage:",
    "  1. Unzip next to the app or anywhere",
    "  2. powershell -File activate_deps.ps1",
    "  3. Set HEADLESS_RE_IDA_HOME to your IDA 9.x install",
    "  4. python -m headless_re_mcp doctor --strict",
    "",
    "See MANIFEST.json and README.md."
) -join "`r`n"
Set-Content -Path (Join-Path $stage "FIRST_RUN.txt") -Value $first -Encoding ASCII

if (-not $SkipZip) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $zip = Join-Path $OutDir "$Name.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $Name.zip" | Set-Content -Path (Join-Path $OutDir "$Name.sha256") -Encoding ASCII
    $size = (Get-Item $zip).Length
    Write-Host ("Wrote {0} ({1:N1} MB)" -f $zip, ($size / 1MB))
    Write-Host "SHA256 $hash"
}

Write-Host "Included: $(($included | ForEach-Object { $_.id }) -join ', ')"
if ($missing.Count) { Write-Host "Missing: $($missing -join ', ')" }
Write-Host "Staged: $stage"
