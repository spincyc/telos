[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$volume = Get-Volume -FileSystemLabel 'TELOS_CREDENTIAL_ACTION' |
    Select-Object -First 1
if (-not $volume) {
    throw 'TELOS_CREDENTIAL_ACTION volume missing'
}
$root = $volume.DriveLetter + ':\'
$document = Get-Content -LiteralPath ($root + 'action.json') -Raw |
    ConvertFrom-Json
$actions = @(
    'connected-domain-login',
    'cached-domain-login',
    'local-rescue-login',
    'operator-local-administrators-check',
    'uncached-domain-user-denied'
)
if ($document.schema_version -ne 1 -or
    $document.nonce -notmatch '^[a-f0-9]{32}$' -or
    $actions -notcontains [string]$document.action -or
    [string]::IsNullOrWhiteSpace($document.username) -or
    [string]::IsNullOrWhiteSpace($document.domain) -or
    [string]::IsNullOrWhiteSpace($document.password)) {
    throw 'credential-action material is invalid'
}

# Materialize the password and all fixed action inputs before telling the host
# that the private medium may be detached and destroyed.
$password = [string]$document.password
$username = [string]$document.username
$domain = [string]$document.domain
$action = [string]$document.action
$nonce = [string]$document.nonce
$document = $null

$serial = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
$serial.ReadTimeout = 120000
$serial.NewLine = "`n"
try {
    $serial.Open()
    $serial.WriteLine(
        '{"schema_version":1,"event":"credential-material-loaded","nonce":"' +
        $nonce + '"}'
    )
    $release = $serial.ReadLine().Trim()
    if ($release -ne (
            'TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED ' + $nonce)) {
        throw 'credential action release was not authorized'
    }

    $source = @'
using System;
using System.Runtime.InteropServices;
public static class TelosCredentialLogon {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public Int32 dwProcessId;
        public Int32 dwThreadId;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessWithLogonW(
        string user, string domain, string password, Int32 logonFlags,
        string application, string commandLine, Int32 creationFlags,
        IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInfo);
    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr handle, UInt32 exitCode);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
    Add-Type -TypeDefinition $source

    # This encoded program is the only child action: observe the authenticated
    # principal and write a public result. It never receives a credential.
    $resultPath = Join-Path $env:SystemRoot (
        'Temp\telos-credential-' + $nonce + '.json')
    if (Test-Path -LiteralPath $resultPath) {
        throw 'credential action result path already exists'
    }
    $child = @'
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$reachable=$false
if ('__DOMAIN__' -ne '.') {
 $client=[Net.Sockets.TcpClient]::new()
 try {
  $pending=$client.ConnectAsync('__DOMAIN__',389)
  $reachable=$pending.Wait(1500) -and $client.Connected
 } catch {
  $reachable=$false
 } finally {
  $client.Dispose()
 }
}
$administratorSid='S-1-5-32-544'
$member=$false
$localMembers=@(Get-LocalGroupMember -SID $administratorSid -ErrorAction Stop)
foreach ($localMember in $localMembers) {
 if ($null -ne $localMember.SID -and
     $localMember.SID.Value -eq $identity.User.Value) {
  $member=$true
  break
 }
}
$record=[ordered]@{
 schema_version=1
 event='credential-action-result'
 nonce='__NONCE__'
 action='__ACTION__'
 result='pass'
 principal=[string]$identity.Name
 authenticated=[bool]$identity.IsAuthenticated
 local_administrators_member=[bool]$member
 authentication_type=[string]$identity.AuthenticationType
 domain_reachable=[bool]$reachable
 failure_classification='none'
}
$record | ConvertTo-Json -Compress |
 Set-Content -LiteralPath '__OUTPUT__' -Encoding UTF8 -NoNewline
'@
    $child = $child.Replace('__NONCE__', $nonce).
        Replace('__ACTION__', $action).
        Replace('__DOMAIN__', $domain).
        Replace('__OUTPUT__', $resultPath)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($child))
    $commandLine = (
        'powershell.exe -NoLogo -NoProfile -NonInteractive ' +
        '-ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
    $startup = [TelosCredentialLogon+STARTUPINFO]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf($startup)
    $process = [TelosCredentialLogon+PROCESS_INFORMATION]::new()
    $controllerReachable = $false
    if ($domain -ne '.') {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $pending = $client.ConnectAsync($domain, 389)
            $controllerReachable = (
                $pending.Wait(1500) -and $client.Connected)
        }
        catch {
            $controllerReachable = $false
        }
        finally {
            $client.Dispose()
        }
    }
    $created = [TelosCredentialLogon]::CreateProcessWithLogonW(
        $username, $domain, $password, 1, $null, $commandLine, 0,
        [IntPtr]::Zero, $env:SystemRoot, [ref]$startup, [ref]$process)
    $password = $null
    if (-not $created) {
        $logonError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($action -eq 'uncached-domain-user-denied' -and
                -not $controllerReachable -and $logonError -eq 1326) {
            $denied = [ordered]@{
                schema_version = 1
                event = 'credential-action-result'
                nonce = $nonce
                action = $action
                result = 'pass'
                principal = $domain + '\' + $username
                authenticated = $false
                local_administrators_member = $false
                authentication_type = 'None'
                domain_reachable = $false
                failure_classification = 'windows-logon-failure'
            }
            $serial.WriteLine(($denied | ConvertTo-Json -Compress))
            return
        }
        throw ('credential action logon failed: ' +
            $logonError)
    }
    try {
        $wait = [TelosCredentialLogon]::WaitForSingleObject(
            $process.hProcess, 30000)
        if ($wait -ne 0) {
            if (-not [TelosCredentialLogon]::TerminateProcess(
                    $process.hProcess, 1)) {
                throw 'credential action timeout cleanup failed'
            }
            [void][TelosCredentialLogon]::WaitForSingleObject(
                $process.hProcess, 5000)
            throw 'credential action timed out'
        }
    }
    finally {
        [void][TelosCredentialLogon]::CloseHandle($process.hThread)
        [void][TelosCredentialLogon]::CloseHandle($process.hProcess)
    }
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw 'credential action emitted no result'
    }
    $result = Get-Content -LiteralPath $resultPath -Raw
    Remove-Item -LiteralPath $resultPath -Force
    $serial.WriteLine($result)
}
finally {
    $password = $null
    if ($serial.IsOpen) {
        $serial.Close()
    }
    $serial.Dispose()
}
