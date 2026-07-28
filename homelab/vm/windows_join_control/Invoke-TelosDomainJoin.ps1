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
if ($document.schema_version -ne 2 -or
    $document.nonce -notmatch '^[a-f0-9]{32}$' -or
    $document.domain -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
    $document.realm -notmatch '^[A-Z0-9.-]{1,253}$' -or
    $document.realm -cne ([string]$document.domain).ToUpperInvariant() -or
    $document.operator -cne ('operator@' + [string]$document.realm) -or
    [string]::IsNullOrWhiteSpace($document.username) -or
    [string]::IsNullOrWhiteSpace($document.password)) {
    throw 'join material is invalid'
}

# Convert the one-use password to a SecureString before announcing that the
# medium may be destroyed.  Nothing mutating occurs before the host replies.
$password = ConvertTo-SecureString ([string]$document.password) -AsPlainText -Force
$credential = [PSCredential]::new([string]$document.username, $password)
$domain = [string]$document.domain
$operator = [string]$document.operator
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

# Resolve the fixed realm-qualified daily operator to a SID, assign only that
# SID to the built-in local Administrators group, and prove the assignment
# before reboot.  Any resolution, mutation, or verification failure stops the
# join path; this script never grants any domain-wide privileged group.
$operatorSid = ([Security.Principal.NTAccount]::new($operator)).Translate(
    [Security.Principal.SecurityIdentifier]
)
$administratorsSid = [Security.Principal.SecurityIdentifier]::new(
    'S-1-5-32-544'
)
$operatorAssigned = @(
    Get-LocalGroupMember -SID $administratorsSid |
        Where-Object { $_.SID.Value -ceq $operatorSid.Value }
)
if ($operatorAssigned.Count -eq 0) {
    Add-LocalGroupMember -SID $administratorsSid -Member $operatorSid `
        -ErrorAction Stop
}
$operatorAssigned = @(
    Get-LocalGroupMember -SID $administratorsSid |
        Where-Object { $_.SID.Value -ceq $operatorSid.Value }
)
if (@($operatorAssigned).Count -ne 1) {
    throw 'daily operator local Administrators assignment was not proved'
}
Restart-Computer -Force
