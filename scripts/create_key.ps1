# Erzeugt ein 1024 Byte großes Keyfile mit kryptographischem Zufall
$path = "notevault.key"
$bytes = New-Object byte[] 1024
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($bytes)
[System.IO.File]::WriteAllBytes((Resolve-Path .\).Path + "\$path", $bytes)
Write-Host "Keyfile erfolgreich generiert: $(Resolve-Path $path)" -ForegroundColor Green