param()

$ErrorActionPreference = 'Stop'
$volume = Get-Volume -FileSystemLabel 'TELOS_JOIN' |
    Select-Object -First 1
if (-not $volume) {
    throw 'TELOS_JOIN volume missing'
}
$root = $volume.DriveLetter + ':\'
$document = Get-Content -LiteralPath ($root + 'join.json') -Raw |
    ConvertFrom-Json
if ($document.schema_version -ne 1 -or
    $document.nonce -notmatch '^[a-f0-9]{32}$' -or
    $document.domain -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
    [string]::IsNullOrWhiteSpace($document.username) -or
    [string]::IsNullOrWhiteSpace($document.password)) {
    throw 'join material is invalid'
}

# Convert the one-use password to a SecureString before announcing that the
# medium may be destroyed.  Nothing mutating occurs before the host replies.
$password = ConvertTo-SecureString ([string]$document.password) -AsPlainText -Force
$credential = [PSCredential]::new([string]$document.username, $password)
$domain = [string]$document.domain
$nonce = [string]$document.nonce
$document = $null

$serial = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
$serial.ReadTimeout = 120000
$serial.NewLine = "`n"
try {
    $serial.Open()
    $serial.WriteLine(
        '{"schema_version":1,"event":"join-material-loaded","nonce":"' +
        $nonce + '"}'
    )
    $release = $serial.ReadLine().Trim()
    if ($release -ne ('TELOS_JOIN_MEDIA_DESTROYED ' + $nonce)) {
        throw 'join mutation release was not authorized'
    }
}
finally {
    if ($serial.IsOpen) {
        $serial.Close()
    }
    $serial.Dispose()
}

Add-Computer -DomainName $domain -Credential $credential -ErrorAction Stop
Restart-Computer -Force
