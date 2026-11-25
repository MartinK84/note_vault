# Generates a cryptographically random 1024-byte keyfile
$path = "notevault.key"
$bytes = New-Object byte[] 1024
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$fullPath = Join-Path (Get-Location).Path $path
[System.IO.File]::WriteAllBytes($fullPath, $bytes)
Write-Host "Keyfile generated successfully: $fullPath" -ForegroundColor Green
