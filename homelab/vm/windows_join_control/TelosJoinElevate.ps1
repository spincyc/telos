$ErrorActionPreference = 'Stop'
$root = Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
$script = Join-Path $root 'TelosJoin.ps1'
$document = Get-Content -LiteralPath (Join-Path $root 'join.json') -Raw |
    ConvertFrom-Json
if ($document.schema_version -ne 2 -or
    $document.nonce -notmatch '^[a-f0-9]{32}$') {
    throw 'join elevation material is invalid'
}
$serial = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
$serial.NewLine = "`n"
try {
    $serial.Open()
    $serial.WriteLine(
        '{"schema_version":1,"event":"join-elevation-requested","nonce":"' +
        [string]$document.nonce + '"}'
    )
}
finally {
    if ($serial.IsOpen) {
        $serial.Close()
    }
    $serial.Dispose()
}
$document = $null
Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $script
)
