param([Parameter(Mandatory=$true)][string]$ToolchainBin)
$ErrorActionPreference = 'Stop'
$sourceRoot = $PSScriptRoot
$buildRoot = Join-Path $sourceRoot 'build'
New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
$libraryPath = Join-Path $buildRoot 'kernel32-x86.a'
$outputPath = Join-Path (Split-Path $sourceRoot -Parent) 'wpcap.dll'
& (Join-Path $ToolchainBin 'dlltool.exe') -m i386 --as-flags --32 --kill-at -d (Join-Path $sourceRoot 'kernel32-x86.def') -l $libraryPath
if ($LASTEXITCODE -ne 0) { throw 'Import library build failed' }
& (Join-Path $ToolchainBin 'gcc.exe') -m32 -Os -fno-builtin -fno-stack-protector -nostdlib -shared '-Wl,--entry,_DllMain@12' -o $outputPath (Join-Path $sourceRoot 'wpcap-compat.c') (Join-Path $sourceRoot 'wpcap-compat.def') $libraryPath
if ($LASTEXITCODE -ne 0) { throw 'DLL build failed' }
Write-Output $outputPath
