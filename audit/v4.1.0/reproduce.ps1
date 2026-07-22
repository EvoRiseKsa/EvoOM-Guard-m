# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path (Get-Location) 'evoguard-v4.1.0-review'),

    [Parameter()]
    [string]$Python = 'python',

    [Parameter()]
    [switch]$Smoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'EvoRiseKsa/EvoOM-Guard-m'
$tag = 'v4.1.0'
$commit = '16029f3e34237ed07b97649c5c9be35d0a356bf7'
$tree = '7c749ed298050840fdd52577e6364a6e63cd36a6'
$pyzSha256 = 'd5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2'
$sumsSha256 = '2e9839e838d9384a2f7200f9caddb336ffe043cd971f8151c9d3efb090fa4c3b'
$pyzSize = 1388088L
$sumsSize = 80L

foreach ($command in @('gh', 'git')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $command"
    }
}
if ($Smoke -and -not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Required command not found for -Smoke: $Python"
}

if (Test-Path -LiteralPath $OutputDirectory) {
    $existing = Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1
    if ($null -ne $existing) { throw "Refusing to write into a non-empty path: $OutputDirectory" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$releaseDirectory = Join-Path $OutputDirectory 'release'
$sourceDirectory = Join-Path $OutputDirectory 'source'
New-Item -ItemType Directory -Force -Path $releaseDirectory | Out-Null

Write-Host '== GitHub release attestation =='
& gh release verify $tag --repo $repository
if ($LASTEXITCODE -ne 0) { throw 'GitHub release attestation verification failed.' }

Write-Host '== Download immutable assets =='
& gh release download $tag --repo $repository --dir $releaseDirectory --pattern evo-guard.pyz --pattern SHA256SUMS
if ($LASTEXITCODE -ne 0) { throw 'Release asset download failed.' }

$pyzPath = Join-Path $releaseDirectory 'evo-guard.pyz'
$sumsPath = Join-Path $releaseDirectory 'SHA256SUMS'
$actualPyz = (Get-FileHash -LiteralPath $pyzPath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualSums = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualPyz -ne $pyzSha256) { throw "evo-guard.pyz SHA-256 mismatch: $actualPyz" }
if ($actualSums -ne $sumsSha256) { throw "SHA256SUMS SHA-256 mismatch: $actualSums" }
if ((Get-Item -LiteralPath $pyzPath).Length -ne $pyzSize) { throw 'evo-guard.pyz size mismatch.' }
if ((Get-Item -LiteralPath $sumsPath).Length -ne $sumsSize) { throw 'SHA256SUMS size mismatch.' }

$expectedSumsText = "$pyzSha256  evo-guard.pyz" + [char]10
$actualSumsText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($sumsPath))
if ($actualSumsText -cne $expectedSumsText) { throw 'SHA256SUMS content mismatch.' }

Write-Host '== Resolve fixed source tag =='
& git clone --quiet --depth 1 --branch $tag "https://github.com/$repository.git" $sourceDirectory
if ($LASTEXITCODE -ne 0) { throw 'Fixed source tag clone failed.' }
$actualCommit = (& git -C $sourceDirectory rev-parse HEAD).Trim()
$actualTree = (& git -C $sourceDirectory rev-parse 'HEAD^{tree}').Trim()
if ($actualCommit -ne $commit) { throw "Tag resolved to unexpected commit: $actualCommit" }
if ($actualTree -ne $tree) { throw "Tag resolved to unexpected tree: $actualTree" }
$verification = (& gh api "repos/$repository/commits/$commit" --jq '{verified:.commit.verification.verified,reason:.commit.verification.reason}' | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or -not $verification.verified -or $verification.reason -ne 'valid') {
    throw 'GitHub commit signature verification failed.'
}

if ($Smoke) {
    Write-Host '== Optional released zipapp smoke check =='
    $version = (& $Python -I $pyzPath version).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -ne 'evo-guard 4.1.0') { throw "Unexpected zipapp version: $version" }
    & $Python -I $pyzPath doctor
    if ($LASTEXITCODE -ne 0) { throw 'Zipapp doctor failed.' }
}

Write-Host ''
Write-Host 'Verified target:'
Write-Host "  release: $tag"
Write-Host "  commit:  $commit"
Write-Host "  tree:    $tree"
Write-Host "  pyz:     $pyzSha256"
