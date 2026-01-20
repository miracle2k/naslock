$ErrorActionPreference = "Stop"

$Repo = "miracle2k/naslock"
$BaseUrl = "https://github.com/$Repo/releases/latest/download"
$Target = "x86_64-pc-windows-msvc"
$Asset = "naslock-$Target.zip"
$Checksum = "$Asset.sha256"
$Bin = "naslock.exe"

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("naslock-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
  $zipPath = Join-Path $tempDir $Asset
  $checksumPath = Join-Path $tempDir $Checksum

  Invoke-WebRequest "$BaseUrl/$Asset" -OutFile $zipPath
  Invoke-WebRequest "$BaseUrl/$Checksum" -OutFile $checksumPath

  $expected = (Get-Content $checksumPath -Raw).Trim().Split()[0].ToLower()
  $actual = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()

  if ($expected -ne $actual) {
    throw "Checksum mismatch for $Asset"
  }

  Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

  $binPath = Join-Path $tempDir $Bin
  if (-not (Test-Path $binPath)) {
    throw "Binary not found in archive: $Bin"
  }

  $installDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "naslock\\bin" }
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  Copy-Item $binPath -Destination (Join-Path $installDir $Bin) -Force

  Write-Host "Installed $Bin to $installDir"

  $pathParts = $env:PATH -split ';'
  if (-not ($pathParts -contains $installDir)) {
    Write-Host "Note: $installDir is not on your PATH."
  }
} finally {
  Remove-Item -Recurse -Force $tempDir
}
