# Fetch / update upstream source trees pinned by upstream.lock.json.
#
# Only entries with a "tree" field are cloned under upstream/<tree>.
# Release-asset-only tools stay outside the tree (see lock "use" notes).
#
# Usage:
#   powershell -File scripts/sync_upstream.ps1
#   powershell -File scripts/sync_upstream.ps1 -Name x64dbg
#   powershell -File scripts/sync_upstream.ps1 -WhatIf

[CmdletBinding()]
param(
    [string]$Name = "",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$lockPath = Join-Path $Root "upstream.lock.json"
if (-not (Test-Path -LiteralPath $lockPath)) {
    throw "missing upstream.lock.json"
}

$lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
$upstreamRoot = Join-Path $Root "upstream"
New-Item -ItemType Directory -Force -Path $upstreamRoot | Out-Null

$repos = @($lock.repositories | Where-Object {
    $_.PSObject.Properties.Name -contains "tree" -and -not [string]::IsNullOrWhiteSpace([string]$_.tree)
})
if ($Name) {
    $repos = @($repos | Where-Object { $_.name -eq $Name -or $_.tree -eq $Name })
    if ($repos.Count -eq 0) {
        throw "no lock entry with tree matching Name='$Name'"
    }
}

function Invoke-Git {
    param([string[]]$GitArgs, [string]$WorkDir)
    Push-Location $WorkDir
    try {
        & git @GitArgs
        if ($LASTEXITCODE -ne 0) {
            throw ("git {0} failed with exit {1}" -f ($GitArgs -join " "), $LASTEXITCODE)
        }
    } finally {
        Pop-Location
    }
}

foreach ($repo in $repos) {
    $tree = [string]$repo.tree
    $url = [string]$repo.url
    $commit = [string]$repo.commit
    if (-not $url -or -not $commit) {
        throw ("lock entry '{0}' needs url+commit" -f $repo.name)
    }

    $dest = Join-Path $upstreamRoot $tree
    Write-Host ("==> {0} -> upstream/{1} @ {2}" -f $repo.name, $tree, $commit)

    if ($WhatIf) { continue }

    if (-not (Test-Path -LiteralPath (Join-Path $dest ".git"))) {
        if (Test-Path -LiteralPath $dest) {
            throw ("{0} exists but is not a git checkout; move it aside and re-run" -f $dest)
        }
        New-Item -ItemType Directory -Force -Path $upstreamRoot | Out-Null
        & git clone --filter=blob:none $url $dest
        if ($LASTEXITCODE -ne 0) {
            throw ("git clone failed for {0}" -f $url)
        }
    } else {
        Invoke-Git -WorkDir $dest -GitArgs @("remote", "set-url", "origin", $url)
        Invoke-Git -WorkDir $dest -GitArgs @("fetch", "--all", "--tags", "--prune")
    }

    Invoke-Git -WorkDir $dest -GitArgs @("checkout", "--detach", $commit)
    $head = (& git -C $dest rev-parse HEAD).Trim()
    if ($head -ne $commit) {
        throw ("{0}: HEAD {1} != locked {2}" -f $tree, $head, $commit)
    }
    Write-Host ("OK upstream/{0} = {1}" -f $tree, $head)
}

Write-Host "done. Build headless with native/xdbg-headless-rpc/build.ps1 after syncing x64dbg."