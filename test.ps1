# Builds and runs the unit tests with the compiler built into Windows — same
# zero-toolchain approach as build.ps1. The app sources and tests\*.cs are
# compiled together into a console AVUI.Tests.exe (the /main switch picks
# the test runner's entry point over the app's), then executed; a non-zero exit
# code means failures, which is what CI keys off.
$ErrorActionPreference = 'Stop'
$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }

$outExe = Join-Path $PSScriptRoot 'AVUI.Tests.exe'
$sources = @(Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter *.cs) +
           @(Get-ChildItem (Join-Path $PSScriptRoot 'tests') -Filter *.cs) |
    Sort-Object Name | ForEach-Object { $_.FullName }
$cscArgs = @(
    '/nologo'
    '/target:exe'
    '/platform:anycpu'
    '/codepage:65001'
    '/main:AVUI.Tests.Program'
    "/out:$outExe"
    '/r:System.dll'
    '/r:System.Drawing.dll'
    '/r:System.Windows.Forms.dll'
    '/r:System.IO.Compression.dll'
    '/r:System.IO.Compression.FileSystem.dll'
) + $sources

& $csc @cscArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Test build FAILED' -ForegroundColor Red
    exit 1
}

& $outExe
$code = $LASTEXITCODE
if ($code -eq 0) { Write-Host 'All tests passed' -ForegroundColor Green }
else { Write-Host 'Tests FAILED' -ForegroundColor Red }
exit $code
