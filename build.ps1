# Builds AV with the compiler built into Windows (.NET Framework 4.8).
# Nothing to install: csc.exe is already present on the system.
$ErrorActionPreference = 'Stop'
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }

# Each argument is built as its own complete string and passed via an array
# (splat) rather than as one long backtick-continued line: PowerShell 7/pwsh
# (used by GitHub Actions) passes embedded quotes in mixed quoted/unquoted
# tokens (e.g. /resource:"$PSScriptRoot\logo.png",logo.png) through to the
# native exe literally instead of resolving them, unlike Windows PowerShell
# 5.1. Splatting a pre-built array sidesteps that native-argument-passing
# difference entirely and works identically on both.
$outExe = Join-Path $PSScriptRoot 'AV.exe'
# All sources live in src\ — csc stitches them into the same single portable exe
$sources = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter *.cs |
    Sort-Object Name | ForEach-Object { $_.FullName }
$cscArgs = @(
    '/nologo'
    '/target:winexe'
    '/platform:anycpu'
    '/codepage:65001'
    "/out:$outExe"
    "/win32icon:$(Join-Path $PSScriptRoot 'app.ico')"
    "/resource:$(Join-Path $PSScriptRoot 'logo.png'),logo.png"
    "/resource:$(Join-Path $PSScriptRoot 'app.ico'),app.ico"
    '/r:System.dll'
    '/r:System.Drawing.dll'
    '/r:System.Windows.Forms.dll'
    '/r:System.IO.Compression.dll'
    '/r:System.IO.Compression.FileSystem.dll'
) + $sources

& $csc @cscArgs

if ($LASTEXITCODE -eq 0) {
    $size = [math]::Round((Get-Item $outExe).Length / 1KB, 1)
    Write-Host "OK: AV.exe ($size KB)"
} else {
    Write-Host "Build FAILED" -ForegroundColor Red
    exit 1
}
