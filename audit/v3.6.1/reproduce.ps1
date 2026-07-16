# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.

<#
Verify the immutable EvoOM Guard v3.6.1 review target without executing a
candidate repository or using signing material. This is an artifact and
source-identity check, not an independent security assessment.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path (Get-Location) 'evoguard-v3.6.1-review'),

    [Parameter()]
    [string]$Python = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'EvoRiseKsa/EvoOM-Guard-m'
$tag = 'v3.6.1'
$commit = '23c388773581e65501e733f88d158113e0095830'
$pyzSha256 = '4d3e074d707ffdae70e4b3d78e786245c77fd6bdc51782eb1b3f8c4ed0e12a34'
$sumsSha256 = 'da970e6e53b0fd9dd4ea5bfee8ee05037e74886aeb661b821223dcaf7b968372'
$pyzSize = 770287L
$sumsSize = 80L

foreach ($command in @('gh', 'git', $Python)) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $command"
    }
}

if (Test-Path -LiteralPath $OutputDirectory) {
    $existing = Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1
    if ($null -ne $existing) {
        throw "Refusing to write into a non-empty path: $OutputDirectory"
    }
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
$actualPyzSha256 = (Get-FileHash -LiteralPath $pyzPath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualSumsSha256 = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualPyzSha256 -ne $pyzSha256) { throw "evo-guard.pyz SHA-256 mismatch: $actualPyzSha256" }
if ($actualSumsSha256 -ne $sumsSha256) { throw "SHA256SUMS SHA-256 mismatch: $actualSumsSha256" }
if ((Get-Item -LiteralPath $pyzPath).Length -ne $pyzSize) { throw 'evo-guard.pyz size mismatch.' }
if ((Get-Item -LiteralPath $sumsPath).Length -ne $sumsSize) { throw 'SHA256SUMS size mismatch.' }

$expectedSumsText = "$pyzSha256  evo-guard.pyz`n"
$actualSumsText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($sumsPath))
if ($actualSumsText -cne $expectedSumsText) {
    throw 'SHA256SUMS content mismatch.'
}

Write-Host '== Resolve fixed source tag =='
& git clone --quiet --depth 1 --branch $tag "https://github.com/$repository.git" $sourceDirectory
if ($LASTEXITCODE -ne 0) { throw 'Fixed source tag clone failed.' }
$actualCommit = (& git -C $sourceDirectory rev-parse HEAD).Trim()
if ($actualCommit -ne $commit) { throw "Tag resolved to unexpected commit: $actualCommit" }

Write-Host '== Released zipapp smoke check =='
$version = (& $Python -I $pyzPath version).Trim()
if ($LASTEXITCODE -ne 0 -or $version -ne 'evo-guard 3.6.1') { throw "Unexpected zipapp version: $version" }
& $Python -I $pyzPath doctor
if ($LASTEXITCODE -ne 0) { throw 'Zipapp doctor failed.' }

Write-Host ''
Write-Host 'Verified target:'
Write-Host "  release: $tag"
Write-Host "  commit:  $commit"
Write-Host "  pyz:     $pyzSha256"
