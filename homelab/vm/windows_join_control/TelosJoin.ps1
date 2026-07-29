param()

$ErrorActionPreference = 'Stop'
$volumes = @(
    Get-Volume -FileSystemLabel 'TELOS_JOIN' |
        Where-Object DriveLetter
)
if ($volumes.Count -ne 1) {
    throw 'TELOS_JOIN volume count is invalid'
}
$volume = $volumes[0]
$root = $volume.DriveLetter + ':\'
$document = Get-Content -LiteralPath ($root + 'join.json') -Raw |
    ConvertFrom-Json
$usernameParts = @(([string]$document.username).Split('@'))
if ($document.schema_version -ne 2 -or
    $document.nonce -notmatch '^[a-f0-9]{32}$' -or
    $document.domain -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
    $document.realm -notmatch '^[A-Z0-9.-]{1,253}$' -or
    $document.realm -cne ([string]$document.domain).ToUpperInvariant() -or
    $document.operator -cne ('operator@' + [string]$document.realm) -or
    $usernameParts.Count -ne 2 -or
    $usernameParts[0] -cnotmatch '^tj-[a-f0-9]{16}$' -or
    $usernameParts[1] -cne [string]$document.realm -or
    [string]::IsNullOrWhiteSpace($document.password)) {
    throw 'join material is invalid'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $nonce = [string]$document.nonce
    $serial = [System.IO.Ports.SerialPort]::new(
        'COM1', 115200, 'None', 8, 'One')
    $serial.NewLine = "`n"
    try {
        $serial.Open()
        $serial.WriteLine(
            '{"schema_version":1,"event":"join-elevation-requested",' +
            '"nonce":"' + $nonce + '"}'
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
        $MyInvocation.MyCommand.Path
    )
    exit
}

# Copy the one-use join inputs into process memory before announcing that the
# medium may be destroyed. Nothing mutating occurs before the host replies.
$joinUsername = [string]$document.username
$joinPassword = [string]$document.password
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
    $failurePhase = 'add-computer'
    $computerSystems = @(Get-CimInstance -ClassName Win32_ComputerSystem `
        -ErrorAction Stop)
    if ($computerSystems.Count -ne 1) {
        throw 'computer-system instance count is invalid'
    }
    $joinResult = Invoke-CimMethod -InputObject $computerSystems[0] `
        -MethodName JoinDomainOrWorkgroup -Arguments @{
            Name = $domain
            Password = $joinPassword
            UserName = $joinUsername
            AccountOU = $null
            FJoinOptions = [uint32]3
        } -ErrorAction Stop
    $joinPassword = $null
    $joinStatus = [uint32]$joinResult.ReturnValue
    if ($joinStatus -ne 0) {
        $failurePhase = switch ($joinStatus) {
            5 { 'join-authorization' }
            1326 { 'join-authentication' }
            1355 { 'join-domain-discovery' }
            2224 { 'join-account-conflict' }
            default { 'join-unclassified' }
        }
        throw 'domain join returned a classified failure'
    }

# Resolve the fixed realm-qualified daily operator to a SID, assign only that
# SID to the built-in local Administrators group, and prove the assignment
# before reboot.  Any resolution, mutation, or verification failure stops the
# join path; this script never grants any domain-wide privileged group.
    $failurePhase = 'operator-resolution'
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
    $failurePhase = 'operator-mutation'
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class TelosLocalGroup {
    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_MEMBERS_INFO_0 {
        public IntPtr lgrmi0_sid;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint NetLocalGroupAddMembers(
        string servername,
        string groupname,
        uint level,
        ref LOCALGROUP_MEMBERS_INFO_0 buffer,
        uint totalentries);
}
'@
    $administratorGroups = @(Get-LocalGroup -SID $administratorsSid)
    if ($administratorGroups.Count -ne 1 -or
        $administratorGroups[0].SID.Value -cne $administratorsSid.Value) {
        throw 'built-in local Administrators group resolution failed'
    }
    $operatorSidBytes = [byte[]]::new($operatorSid.BinaryLength)
    $operatorSid.GetBinaryForm($operatorSidBytes, 0)
    $operatorSidPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal(
        $operatorSidBytes.Length)
    try {
        [Runtime.InteropServices.Marshal]::Copy(
            $operatorSidBytes, 0, $operatorSidPointer,
            $operatorSidBytes.Length)
        $member = [TelosLocalGroup+LOCALGROUP_MEMBERS_INFO_0]::new()
        $member.lgrmi0_sid = $operatorSidPointer
        $addStatus = [TelosLocalGroup]::NetLocalGroupAddMembers(
            $null, $administratorGroups[0].Name, 0, [ref]$member, 1)
        if ($addStatus -ne 0 -and $addStatus -ne 1378) {
            throw ('raw-SID local Administrators mutation failed: ' +
                $addStatus)
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($operatorSidPointer)
    }
}
$failurePhase = 'operator-verification'
$operatorAssigned = @(
    Get-LocalGroupMember -SID $administratorsSid |
        Where-Object { $_.SID.Value -ceq $operatorSid.Value }
)
if (@($operatorAssigned).Count -ne 1) {
    throw 'daily operator local Administrators assignment was not proved'
}

# Force the post-join sign-in surface to request an explicit qualified
# principal instead of exposing or selecting the last interactive user.
# Verify the exact DWORD before reboot and fail closed rather than attempting
# brittle account-tile navigation.
    $logonPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $logonPolicyName = 'DontDisplayLastUserName'
    $failurePhase = 'policy-mutation'
    try {
    New-ItemProperty -LiteralPath $logonPolicyPath -Name $logonPolicyName `
        -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
}
    catch {
        throw 'generic logon policy mutation failed'
    }
    $failurePhase = 'policy-readback'
    try {
    $logonPolicyValue = Get-ItemPropertyValue -LiteralPath $logonPolicyPath `
        -Name $logonPolicyName -ErrorAction Stop
}
catch {
    throw 'generic logon policy readback failed'
}
    if ($logonPolicyValue -ne 1) {
        $failurePhase = 'policy-verification'
        throw 'generic logon policy verification failed'
    }
    $serial.WriteLine(
        '{"schema_version":1,"event":"join-reboot-ready","nonce":"' +
        $nonce + '"}'
    )
    $failurePhase = 'reboot-ack'
    $rebootAck = $serial.ReadLine().Trim()
    if ($rebootAck -ne ('TELOS_JOIN_REBOOT_ACK ' + $nonce)) {
        throw 'join reboot acknowledgment was not authorized'
    }
    $serial.WriteLine(
        '{"schema_version":1,"event":"join-reboot-accepted","nonce":"' +
        $nonce + '"}'
    )
}
catch {
    $originalError = $_
    if ($serial.IsOpen -and $failurePhase) {
        try {
            $serial.WriteLine(
                '{"schema_version":1,"event":"join-reboot-failed","nonce":"' +
                $nonce + '","phase":"' + $failurePhase + '"}'
            )
        }
        catch {
            # The original typed failure remains authoritative when COM1 is
            # already broken; never replace it with a reporting failure.
        }
    }
    throw $originalError
}
finally {
    $joinPassword = $null
    if ($serial.IsOpen) {
        $serial.Close()
    }
    $serial.Dispose()
}
Restart-Computer -Force
