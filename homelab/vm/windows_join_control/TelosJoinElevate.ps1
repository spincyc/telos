$ErrorActionPreference = 'Stop'
$root = Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
$script = Join-Path $root 'TelosJoin.ps1'
Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $script
)
