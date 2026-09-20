<#
.SYNOPSIS
    Builds NoteVault in release mode and packages the output into a distributable .zip archive.

.DESCRIPTION
    This script performs a release build of all NoteVault binaries using Cargo,
    then collects the compiled executables and the default config.json into a
    versioned .zip file placed in the project root.

    The version is read from Cargo.toml. The archive is named:
        note_vault-<version>-windows-x86_64.zip

.EXAMPLE
    .\scripts\make_release.ps1

    Run from the project root directory.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Paths
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CargoToml   = Join-Path $ProjectRoot "Cargo.toml"
$TargetDir   = Join-Path $ProjectRoot "target\release"
$ConfigFile  = Join-Path $ProjectRoot "config.json"

# Read version from Cargo.toml
$VersionLine = Select-String -Path $CargoToml -Pattern '^version\s*=\s*"(.+)"' |
               Select-Object -First 1
if (-not $VersionLine) {
    Write-Error "Could not read version from Cargo.toml."
    exit 1
}
$Version = $VersionLine.Matches[0].Groups[1].Value
Write-Host "Building NoteVault v$Version ..." -ForegroundColor Cyan

# Build
Push-Location $ProjectRoot
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build --release failed (exit code $LASTEXITCODE)."
        exit 1
    }
} finally {
    Pop-Location
}

# Collect artifacts
$Binaries = @(
    (Join-Path $TargetDir "note_vault.exe"),
    (Join-Path $TargetDir "note_vault_cli.exe")
)

foreach ($Binary in $Binaries) {
    if (-not (Test-Path $Binary)) {
        Write-Error "Expected binary not found: $Binary"
        exit 1
    }
}

# Create archive
$ArchiveName = "note_vault-$Version-windows-x86_64.zip"
$ArchivePath = Join-Path $ProjectRoot $ArchiveName

if (Test-Path $ArchivePath) {
    Remove-Item $ArchivePath -Force
}

$FilesToZip = $Binaries

# Include config.json as a template if it exists
if (Test-Path $ConfigFile) {
    $FilesToZip += $ConfigFile
}

Compress-Archive -Path $FilesToZip -DestinationPath $ArchivePath -CompressionLevel Optimal

Write-Host ""
Write-Host "Release archive created:" -ForegroundColor Green
Write-Host "  $ArchivePath" -ForegroundColor White
Write-Host ""
Write-Host "Contents:" -ForegroundColor Cyan
foreach ($F in $FilesToZip) {
    $Size = (Get-Item $F).Length
    Write-Host ("  {0,-35} {1,8} KB" -f (Split-Path $F -Leaf), ([math]::Round($Size / 1KB, 1)))
}
