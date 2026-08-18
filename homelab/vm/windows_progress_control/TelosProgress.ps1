# Telos Windows guest progress reporter (v1 protocol, COM1 transport).
#
# Windows has no virtio-serial driver in this factory, so the named progress
# port cannot exist in the guest.  COM1 is the only channel available, and it
# is one-way host-inbound and shared with human-readable console output.  This
# script is therefore a DIAGNOSTIC reporter and nothing else:
#
#   * it never reads COM1, so no acknowledgment can ever reach it;
#   * it writes exactly one line shape and no other text, so console output
#     and progress frames stay separable;
#   * it reports phases and a percentage only.  No credential, identity value,
#     token, ticket, key, path, hostname, or log line is ever emitted.
#
# Nothing it reports is acceptance evidence and nothing it reports extends a
# host deadline.  Its material arrives on the one-use TELOS_PROGRESS medium;
# when that medium is absent the script exits 0 in silence.

param(
    [switch]$Register,
    [int]$IntervalSeconds = 10,
    [int]$MaxSeconds = 600
)

$ErrorActionPreference = 'Stop'

$TelosProgressMarker = 'TELOS-PROGRESS-V1'
$TelosProgressLabel = 'TELOS_PROGRESS'
$TelosProgressTaskName = 'TelosProgress'
$TelosProgressProducer = 'windows-com1-diagnostic'
$TelosProgressPhase = 'windows-firstboot'
$TelosProgressSpecVersion = '1.0'
$TelosProgressMacDomain = 'telos-guest-progress-v1'
$TelosProgressToken = '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z'
$TelosProgressMaxLine = 4096

# The exact scheduled-task argument. It resolves the medium by label at run
# time, so no drive letter is baked in. The host builds this same string in
# windows_progress_iso.progress_task_argument(); a test asserts they match.
$TelosProgressTaskArgument = @'
-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ((Get-Volume -FileSystemLabel 'TELOS_PROGRESS').DriveLetter + ':\TelosProgress.ps1')"
'@

function Get-TelosProgressRoot {
    # An absent medium is the ordinary unarmed case, not a fault, so this
    # lookup must not throw under $ErrorActionPreference = 'Stop'.
    $volumes = @(
        Get-Volume -FileSystemLabel $TelosProgressLabel `
            -ErrorAction SilentlyContinue |
            Where-Object DriveLetter
    )
    if ($volumes.Count -ne 1) {
        return $null
    }
    return ($volumes[0].DriveLetter + ':\')
}

function Get-TelosProgressMaterial {
    param([string]$Root)

    $document = Get-Content -LiteralPath ($Root + 'progress.json') -Raw |
        ConvertFrom-Json
    $attempt = [string]$document.attempt
    $nonce = [string]$document.nonce
    $keyHex = [string]$document.key_hex
    $producer = [string]$document.producer
    $phase = [string]$document.phase
    if ($document.schema_version -ne 1 -or
        $document.authoritative -ne $false -or
        $attempt -cnotmatch $TelosProgressToken -or
        $nonce -cnotmatch $TelosProgressToken -or
        $keyHex -cnotmatch '^(?:[0-9a-f]{2}){32,}\z' -or
        $producer -cne $TelosProgressProducer -or
        $phase -cne $TelosProgressPhase) {
        throw 'progress material is invalid'
    }
    $key = [byte[]]::new($keyHex.Length / 2)
    for ($index = 0; $index -lt $key.Length; $index++) {
        $key[$index] = [Convert]::ToByte(
            $keyHex.Substring($index * 2, 2), 16)
    }
    $keyHex = $null
    return @{
        attempt = $attempt
        nonce = $nonce
        key = $key
    }
}

function Get-TelosProgressMac {
    param([string]$Unsigned, [byte[]]$Key)

    # HMAC-SHA-256 over "telos-guest-progress-v1", one NUL byte, then the
    # canonical JSON of the envelope with `mac` omitted.
    $prefix = [Text.Encoding]::UTF8.GetBytes($TelosProgressMacDomain)
    $body = [Text.Encoding]::UTF8.GetBytes($Unsigned)
    $buffer = [byte[]]::new($prefix.Length + 1 + $body.Length)
    [Array]::Copy($prefix, 0, $buffer, 0, $prefix.Length)
    $buffer[$prefix.Length] = 0
    [Array]::Copy($body, 0, $buffer, $prefix.Length + 1, $body.Length)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $digest = $hmac.ComputeHash($buffer)
    }
    finally {
        $hmac.Dispose()
    }
    return [Convert]::ToBase64String($digest)
}

function New-TelosProgressLine {
    param(
        [string]$EventType,
        [string]$Status,
        [string]$Attempt,
        [string]$BootId,
        [int]$Sequence,
        [byte[]]$Key,
        [string]$Phase = $null,
        [string]$Nonce = $null,
        [object]$Progress = $null,
        [string]$EventId = $null,
        [string]$Moment = $null
    )

    if ([string]::IsNullOrEmpty($EventId)) {
        $EventId = ([guid]::NewGuid()).ToString()
    }
    if ([string]::IsNullOrEmpty($Moment)) {
        $Moment = [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ss',
            [Globalization.CultureInfo]::InvariantCulture) + 'Z'
    }
    # Every value below is a validated bounded token, a canonical UUID, a
    # fixed timestamp shape, base64, or an integer, so no JSON escaping can
    # ever apply. The fields are emitted in the protocol's sorted-key order
    # and `mac` is inserted at its own sorted position, which keeps the
    # rendering byte-identical to the host canonicaliser.
    $fields = [System.Collections.Generic.List[string]]::new()
    $fields.Add('"attempt":"' + $Attempt + '"')
    $fields.Add('"boot_id":"' + $BootId + '"')
    $fields.Add('"id":"' + $EventId + '"')
    if (-not [string]::IsNullOrEmpty($Nonce)) {
        $fields.Add('"nonce":"' + $Nonce + '"')
    }
    if ([string]::IsNullOrEmpty($Phase)) {
        $fields.Add('"phase":null')
    }
    else {
        $fields.Add('"phase":"' + $Phase + '"')
    }
    if ($null -ne $Progress) {
        $fields.Add('"progress":' + ([int]$Progress).ToString(
            [Globalization.CultureInfo]::InvariantCulture))
    }
    $fields.Add('"sequence":' + ([int]$Sequence).ToString(
        [Globalization.CultureInfo]::InvariantCulture))
    $fields.Add('"source":"' + $TelosProgressProducer + '"')
    $fields.Add('"specversion":"' + $TelosProgressSpecVersion + '"')
    $fields.Add('"status":"' + $Status + '"')
    $fields.Add('"time":"' + $Moment + '"')
    $fields.Add('"type":"' + $EventType + '"')
    $unsigned = '{' + [string]::Join(',', $fields.ToArray()) + '}'
    $mac = Get-TelosProgressMac -Unsigned $unsigned -Key $Key
    # attempt, boot_id, id are always the first three keys, and "mac" sorts
    # immediately after "id".
    $fields.Insert(3, '"mac":"' + $mac + '"')
    $signed = '{' + [string]::Join(',', $fields.ToArray()) + '}'
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($signed)
    ).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    $line = $TelosProgressMarker + ' ' + $encoded
    if ($line.Length -ge $TelosProgressMaxLine) {
        throw 'progress line exceeds the COM1 bound'
    }
    return $line
}

function Register-TelosProgressTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument $TelosProgressTaskArgument
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TelosProgressTaskName `
        -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null
    $registered = Get-ScheduledTask -TaskName $TelosProgressTaskName `
        -ErrorAction Stop
    if (@($registered.Actions).Count -ne 1 -or
        $registered.Actions[0].Execute -cne 'powershell.exe' -or
        $registered.Actions[0].Arguments -cne $TelosProgressTaskArgument -or
        @($registered.Triggers).Count -ne 1 -or
        $registered.Triggers[0].CimClass.CimClassName -cne `
            'MSFT_TaskBootTrigger' -or
        $registered.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
        throw 'progress scheduled task verification failed'
    }
}

function Invoke-TelosProgressReport {
    param([hashtable]$Material)

    if ($IntervalSeconds -lt 1 -or $IntervalSeconds -gt 60 -or
        $MaxSeconds -lt $IntervalSeconds -or $MaxSeconds -gt 3600) {
        throw 'progress bounds are invalid'
    }
    $bootId = 'boot-' + ([guid]::NewGuid()).ToString()
    $serial = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
    # One-way by construction: this reporter opens COM1 to write and never
    # reads it. There is no acknowledgment to wait for and none is honoured.
    $serial.NewLine = "`n"
    try {
        $serial.Open()
        $sequence = 0
        $serial.WriteLine((New-TelosProgressLine `
            -EventType 'sync' -Status 'starting' `
            -Attempt $Material.attempt -BootId $bootId -Sequence $sequence `
            -Key $Material.key -Nonce $Material.nonce))
        $sequence++
        $serial.WriteLine((New-TelosProgressLine `
            -EventType 'phase-started' -Status 'active' `
            -Attempt $Material.attempt -BootId $bootId -Sequence $sequence `
            -Key $Material.key -Phase $TelosProgressPhase))
        $sequence++
        $started = [Diagnostics.Stopwatch]::StartNew()
        while ($started.Elapsed.TotalSeconds -lt $MaxSeconds) {
            Start-Sleep -Seconds $IntervalSeconds
            $elapsed = $started.Elapsed.TotalSeconds
            if ($elapsed -ge $MaxSeconds) {
                break
            }
            $percent = [Math]::Min(
                99, [Math]::Floor(100.0 * $elapsed / $MaxSeconds))
            $serial.WriteLine((New-TelosProgressLine `
                -EventType 'heartbeat' -Status 'active' `
                -Attempt $Material.attempt -BootId $bootId `
                -Sequence $sequence -Key $Material.key `
                -Phase $TelosProgressPhase -Progress $percent))
            $sequence++
        }
        $serial.WriteLine((New-TelosProgressLine `
            -EventType 'phase-finished' -Status 'complete' `
            -Attempt $Material.attempt -BootId $bootId -Sequence $sequence `
            -Key $Material.key -Phase $TelosProgressPhase))
    }
    finally {
        if ($serial.IsOpen) {
            $serial.Close()
        }
        $serial.Dispose()
    }
}

$root = Get-TelosProgressRoot
if ($null -eq $root) {
    # Reporting is optional; an unarmed boot stays silent and succeeds.
    exit 0
}
if ($Register) {
    Register-TelosProgressTask
    exit 0
}
$material = $null
try {
    $material = Get-TelosProgressMaterial -Root $root
    Invoke-TelosProgressReport -Material $material
}
finally {
    if ($null -ne $material -and $null -ne $material.key) {
        [Array]::Clear($material.key, 0, $material.key.Length)
    }
    $material = $null
}
