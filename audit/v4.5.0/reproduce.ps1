# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Source-available - see LICENSE for permitted use.

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path (Get-Location) 'evoguard-v4.5.0-review'),

    [Parameter()]
    [string]$Python = 'python',

    [Parameter()]
    [switch]$Smoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'EvoRiseKsa/EvoOM-Guard-m'
$tag = 'v4.5.0'
$releaseId = 363544789L
$publishedAt = '2026-08-01T14:32:33Z'
$commit = '6bb4c328e56661b661e50532886802c6ba36a997'
$tree = 'bd81a595ca8608ad7da04390f31d5e489f5083ef'
$tagCiRun = 30703985270L
$pyzSha256 = '44bf036666bc7bb2903b647f33b63254771771887de4f170c91e8cdd8307c89d'
$spdxSha256 = 'd073198e6a3a7d565895b3cf885c95386768670a243e05e5b1471636a0f8da4b'
$sumsSha256 = '0172d35b903661328f16366517fe5a8f666aaf282cf26c5ec4e263da4abedd0f'
$pyzSize = 2356398L
$spdxSize = 99797L
$sumsSize = 166L

foreach ($command in @('gh', 'git')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $command"
    }
}
if ($Smoke -and -not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Required command not found for -Smoke: $Python"
}

if (Test-Path -LiteralPath $OutputDirectory) {
    $directory = Get-Item -LiteralPath $OutputDirectory -Force
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to write into a link or non-directory path: $OutputDirectory"
    }
    $existing = Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1
    if ($null -ne $existing) {
        throw "Refusing to write into a non-empty path: $OutputDirectory"
    }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$releaseDirectory = Join-Path $OutputDirectory 'release'
$sourceDirectory = Join-Path $OutputDirectory 'source'
New-Item -ItemType Directory -Force -Path $releaseDirectory | Out-Null

Write-Host '== GitHub Release attestation =='
& gh release verify $tag --repo $repository
if ($LASTEXITCODE -ne 0) {
    throw 'GitHub Release attestation verification failed.'
}

Write-Host '== Exact immutable Release metadata =='
$release = ((& gh api "repos/$repository/releases/tags/$tag") | Out-String) |
    ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Release metadata query failed.' }
if ([long]$release.id -ne $releaseId -or
    $release.tag_name -cne $tag -or
    $release.target_commitish -cne $commit -or
    $release.published_at -cne $publishedAt -or
    $release.immutable -ne $true) {
    throw 'Release metadata mismatch.'
}

$expectedAssets = @{
    'evo-guard.pyz' = @($pyzSize, "sha256:$pyzSha256", 497974096L)
    'evo-guard.spdx.json' = @($spdxSize, "sha256:$spdxSha256", 497974097L)
    'SHA256SUMS' = @($sumsSize, "sha256:$sumsSha256", 497974098L)
}
if (@($release.assets).Count -ne $expectedAssets.Count) {
    throw 'Release asset count mismatch.'
}
$expectedReleaseNames = @('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS') |
    Sort-Object
$actualReleaseNames = @($release.assets | ForEach-Object name) | Sort-Object
if (Compare-Object -CaseSensitive -ReferenceObject $expectedReleaseNames `
        -DifferenceObject $actualReleaseNames) {
    throw 'Release asset names mismatch.'
}
foreach ($asset in @($release.assets)) {
    if (-not $expectedAssets.ContainsKey($asset.name)) {
        throw "Unexpected Release asset: $($asset.name)"
    }
    $expected = $expectedAssets[$asset.name]
    if ([long]$asset.size -ne [long]$expected[0] -or
        $asset.digest -cne [string]$expected[1] -or
        [long]$asset.id -ne [long]$expected[2]) {
        throw "Release asset metadata mismatch: $($asset.name)"
    }
}

Write-Host '== Download and hash the exact asset set =='
& gh release download $tag --repo $repository --dir $releaseDirectory `
    --pattern evo-guard.pyz --pattern evo-guard.spdx.json --pattern SHA256SUMS
if ($LASTEXITCODE -ne 0) { throw 'Release asset download failed.' }

$actualNames = @(
    Get-ChildItem -LiteralPath $releaseDirectory -File |
        Sort-Object Name |
        ForEach-Object Name
)
$expectedNames = @('evo-guard.pyz', 'evo-guard.spdx.json', 'SHA256SUMS') |
    Sort-Object
if (Compare-Object -CaseSensitive -ReferenceObject $expectedNames -DifferenceObject $actualNames) {
    throw 'Downloaded asset set mismatch.'
}

$pyzPath = Join-Path $releaseDirectory 'evo-guard.pyz'
$spdxPath = Join-Path $releaseDirectory 'evo-guard.spdx.json'
$sumsPath = Join-Path $releaseDirectory 'SHA256SUMS'
$actualPyz = (Get-FileHash -LiteralPath $pyzPath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualSpdx = (Get-FileHash -LiteralPath $spdxPath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualSums = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualPyz -cne $pyzSha256) { throw "evo-guard.pyz SHA-256 mismatch: $actualPyz" }
if ($actualSpdx -cne $spdxSha256) { throw "SPDX SHA-256 mismatch: $actualSpdx" }
if ($actualSums -cne $sumsSha256) { throw "SHA256SUMS SHA-256 mismatch: $actualSums" }
if ((Get-Item -LiteralPath $pyzPath).Length -ne $pyzSize) { throw 'evo-guard.pyz size mismatch.' }
if ((Get-Item -LiteralPath $spdxPath).Length -ne $spdxSize) { throw 'SPDX size mismatch.' }
if ((Get-Item -LiteralPath $sumsPath).Length -ne $sumsSize) { throw 'SHA256SUMS size mismatch.' }

$expectedSumsText =
    "$pyzSha256  evo-guard.pyz" + [char]10 +
    "$spdxSha256  evo-guard.spdx.json" + [char]10
$actualSumsText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($sumsPath))
if ($actualSumsText -cne $expectedSumsText) { throw 'SHA256SUMS content mismatch.' }

Write-Host '== Resolve fixed source tag and tree =='
& git clone --quiet --depth 1 --branch $tag "https://github.com/$repository.git" $sourceDirectory
if ($LASTEXITCODE -ne 0) { throw 'Fixed source tag clone failed.' }
$actualCommit = (& git -C $sourceDirectory rev-parse HEAD).Trim()
$actualTree = (& git -C $sourceDirectory rev-parse 'HEAD^{tree}').Trim()
if ($actualCommit -cne $commit) { throw "Tag resolved to unexpected commit: $actualCommit" }
if ($actualTree -cne $tree) { throw "Tag resolved to unexpected tree: $actualTree" }

Write-Host '== Confirm expected unsigned commit observation =='
$verification = ((& gh api "repos/$repository/commits/$commit" `
    --jq '{verified:.commit.verification.verified,reason:.commit.verification.reason}') |
    Out-String) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    $verification.verified -ne $false -or
    $verification.reason -cne 'unsigned') {
    throw 'Unexpected GitHub commit verification state.'
}

Write-Host '== Pin successful tag CI observation =='
$tagCi = ((& gh run view $tagCiRun --repo $repository `
    --json databaseId,event,headBranch,headSha,status,conclusion) | Out-String) |
    ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    [long]$tagCi.databaseId -ne $tagCiRun -or
    $tagCi.event -cne 'push' -or
    $tagCi.headBranch -cne $tag -or
    $tagCi.headSha -cne $commit -or
    $tagCi.status -cne 'completed' -or
    $tagCi.conclusion -cne 'success') {
    throw 'Tag CI metadata mismatch.'
}

if ($Smoke) {
    Write-Host '== Optional released zipapp smoke check =='
    $version = (& $Python -I $pyzPath version).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne 'evo-guard 4.5.0') {
        throw "Unexpected zipapp version: $version"
    }
    & $Python -I $pyzPath doctor
    if ($LASTEXITCODE -ne 0) { throw 'Zipapp doctor failed.' }
}

Write-Host ''
Write-Host 'Verified frozen target identity:'
Write-Host "  release: $tag"
Write-Host "  commit:  $commit (GitHub: unsigned)"
Write-Host "  tree:    $tree"
Write-Host "  pyz:     $pyzSha256"
Write-Host "  SPDX:    $spdxSha256"
