[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# COM1 first, and one fixed diagnostic line BEFORE any risky work, so a
# host timeout can split "script never reported" from "script died
# mid-way": attempt 37 (20260811T134831Z) timed out against a clean
# desktop and the two cases were indistinguishable. Neither this line nor
# the failed line below carries authority: the host discards them and
# still gates media destruction on the nonce-bound material marker alone.
$serial = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
$serial.ReadTimeout = 120000
$serial.NewLine = "`n"
$serial.Open()
$serial.WriteLine('{"schema_version":1,"event":"credential-script-started"}')
$password = $null
# Progressive, fixed-literal failure coordinates for the catch below:
# attempt 38 (20260811T142143Z) proved the guest died within one second of
# the material release, but the fixed failed line could not say WHERE. The
# stage is only ever assigned from these literals and the code only from
# the Win32 logon error -- bounded and credential-free.
$failureStage = 'material'
$failureCode = 0
try {
    $volumes = @(
        Get-Volume -FileSystemLabel 'TELOS_CRED' |
            Where-Object DriveLetter
    )
    if ($volumes.Count -ne 1) {
        throw 'TELOS_CRED volume count is invalid'
    }
    $volume = $volumes[0]
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

    # Materialize the password and all fixed action inputs before telling
    # the host that the private medium may be detached and destroyed.
    $password = [string]$document.password
    $username = [string]$document.username
    $domain = [string]$document.domain
    $action = [string]$document.action
    $nonce = [string]$document.nonce
    $document = $null

    $serial.WriteLine(
        '{"schema_version":1,"event":"credential-material-loaded","nonce":"' +
        $nonce + '"}'
    )
    $failureStage = 'release-wait'
    $release = $serial.ReadLine().Trim()
    if ($release -ne (
            'TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED ' + $nonce)) {
        throw 'credential action release was not authorized'
    }
    $failureStage = 'post-release-setup'

    $failureStage = 'logon-compile'
    # Token-based credential proof. Attempts 39-42 proved
    # CreateProcessWithLogonW is a dead end here: it returns FALSE with an
    # authoritative in-frame last error of 0 even after LogonUser(INTERACTIVE)
    # succeeded and the Secondary Logon service was started -- a mechanism
    # failure of the spawn primitive, not the credential. LogonUser is the
    # correct primitive for "prove these credentials obtain an
    # online/interactive logon": it validates the credential against the DC
    # (or the local cache when offline), and its token carries the
    # authenticated SID, the authentication package (Kerberos => connected,
    # NTLM => cached), and the resolved group memberships -- everything the
    # checks judge -- with no interactive-process dependency.
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class TelosCredentialLogon {
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public UInt32 LowPart;
        public Int32 HighPart;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public UInt32 Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_STATISTICS {
        public LUID TokenId;
        public LUID AuthenticationId;
        public Int64 ExpirationTime;
        public Int32 TokenType;
        public Int32 ImpersonationLevel;
        public UInt32 DynamicCharged;
        public UInt32 DynamicAvailable;
        public UInt32 GroupCount;
        public UInt32 PrivilegeCount;
        public LUID ModifiedId;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }
    // Only the leading fields are needed; the rest of
    // SECURITY_LOGON_SESSION_DATA is deliberately omitted -- we read
    // AuthenticationPackage and stop.
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA {
        public UInt32 Size;
        public LUID LogonId;
        public LSA_UNICODE_STRING UserName;
        public LSA_UNICODE_STRING LogonDomain;
        public LSA_UNICODE_STRING AuthenticationPackage;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUser(
        string user, string domain, string password,
        Int32 logonType, Int32 logonProvider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr token, Int32 tokenInformationClass,
        IntPtr tokenInformation, Int32 tokenInformationLength,
        out Int32 returnLength);
    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern Int32 LsaGetLogonSessionData(
        ref LUID logonId, out IntPtr ppLogonSessionData);
    [DllImport("Secur32.dll")]
    public static extern Int32 LsaFreeReturnBuffer(IntPtr buffer);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    // Membership by raw token groups. WindowsIdentity.Groups omits the
    // deny-only BUILTIN\Administrators SID that a UAC-filtered interactive
    // admin token carries (attempt 46 reported False for the provisioned
    // operator, who TelosJoin verifiably added to local Administrators).
    // Reading TokenGroups directly counts the SID's PRESENCE regardless of
    // SE_GROUP_USE_FOR_DENY_ONLY -- the correct "is a local admin" test.
    // Uses only Marshal primitives + SecurityIdentifier(IntPtr) and derives
    // the array offset/stride from IntPtr.Size, so it is x86/x64-correct
    // without hand-computed struct offsets. Returns false on any failure.
    public static bool TokenHasGroup(IntPtr token, string sid) {
        int needed = 0;
        // TokenGroups = 2.
        GetTokenInformation(token, 2, IntPtr.Zero, 0, out needed);
        if (needed <= 0) { return false; }
        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try {
            int returned = 0;
            if (!GetTokenInformation(token, 2, buffer, needed, out returned)) {
                return false;
            }
            int count = Marshal.ReadInt32(buffer, 0);
            // TOKEN_GROUPS: DWORD GroupCount, then a pointer-aligned array of
            // SID_AND_ATTRIBUTES (array offset == IntPtr.Size on both x86/x64).
            int arrayOffset = IntPtr.Size;
            int entrySize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (int i = 0; i < count; i++) {
                IntPtr sidPtr = Marshal.ReadIntPtr(
                    buffer, arrayOffset + i * entrySize);
                if (sidPtr == IntPtr.Zero) { continue; }
                try {
                    System.Security.Principal.SecurityIdentifier current =
                        new System.Security.Principal.SecurityIdentifier(
                            sidPtr);
                    if (current.Value == sid) { return true; }
                }
                catch { }
            }
            return false;
        }
        finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
    // Capture the Win32 error in the same interop frame as the call:
    // attempts 39/40 proved a script-side read even on the next statement
    // renders 0, because the PowerShell engine runs interop of its own
    // between statements.
    public static bool LogonUserAndError(
        string user, string domain, string password, Int32 logonType,
        out IntPtr token, out Int32 logonError) {
        bool ok = LogonUser(user, domain, password, logonType, 0, out token);
        logonError = ok ? 0 : Marshal.GetLastWin32Error();
        return ok;
    }
    // WindowsIdentity(token).AuthenticationType is empty for a bare
    // LogonUser token (attempt 44). The real package lives in the token's
    // logon session: TokenStatistics.AuthenticationId (a LUID) ->
    // LsaGetLogonSessionData -> AuthenticationPackage. Reading the caller's
    // OWN just-created session needs no SeTcbPrivilege. Returns "" on any
    // failure so the host fails closed rather than on fabricated data.
    public static string LogonPackage(IntPtr token) {
        int needed = 0;
        // TokenStatistics = 10.
        GetTokenInformation(token, 10, IntPtr.Zero, 0, out needed);
        if (needed <= 0) { return ""; }
        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try {
            int returned = 0;
            if (!GetTokenInformation(token, 10, buffer, needed, out returned)) {
                return "";
            }
            TOKEN_STATISTICS stats = (TOKEN_STATISTICS)Marshal.PtrToStructure(
                buffer, typeof(TOKEN_STATISTICS));
            LUID authId = stats.AuthenticationId;
            IntPtr sessionData = IntPtr.Zero;
            if (LsaGetLogonSessionData(ref authId, out sessionData) != 0
                    || sessionData == IntPtr.Zero) {
                return "";
            }
            try {
                SECURITY_LOGON_SESSION_DATA data =
                    (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                        sessionData, typeof(SECURITY_LOGON_SESSION_DATA));
                LSA_UNICODE_STRING package = data.AuthenticationPackage;
                if (package.Buffer == IntPtr.Zero || package.Length == 0) {
                    return "";
                }
                return Marshal.PtrToStringUni(
                    package.Buffer, package.Length / 2);
            }
            finally {
                LsaFreeReturnBuffer(sessionData);
            }
        }
        finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
    Add-Type -TypeDefinition $source
    $failureStage = 'logon-prepare'

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
    $gatewayReachable = $false
    # With $ErrorActionPreference = 'Stop', Get-NetRoute THROWS when no
    # default route matches (offline fault phases); tolerate it and record
    # gateway_reachable = false rather than failing the whole action.
    $gatewayRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if ($gatewayRoute) {
        $ping = [Net.NetworkInformation.Ping]::new()
        try {
            $reply = $ping.Send([string]$gatewayRoute.NextHop, 1500)
            $gatewayReachable = (
                $reply.Status -eq
                [Net.NetworkInformation.IPStatus]::Success)
        }
        catch {
            $gatewayReachable = $false
        }
        finally {
            $ping.Dispose()
        }
    }

    if ($domain -eq '.') {
        $authenticationSemantics = 'local-account'
        $cacheEvidence = 'not-applicable'
    }
    elseif ($controllerReachable) {
        $authenticationSemantics = 'connected-domain'
        $cacheEvidence = 'online-interactive-logon'
    }
    else {
        $authenticationSemantics = 'cached-domain'
        $cacheEvidence = 'offline-cache-proven'
    }

    # LOGON32_LOGON_INTERACTIVE (2) so an online logon exercises Kerberos
    # against the DC and an offline one exercises the cached-credential
    # path -- the same distinction the check judges, without an
    # interactive process. The Win32 error is captured in the interop
    # frame; the token carries the SID, package and groups.
    $failureStage = 'logon-call'
    $loginClock = [Diagnostics.Stopwatch]::StartNew()
    $token = [IntPtr]::Zero
    $logonError = 0
    $ok = [TelosCredentialLogon]::LogonUserAndError(
        $username, $domain, $password, 2, [ref]$token, [ref]$logonError)
    $loginClock.Stop()
    $loginElapsedSeconds = [Math]::Round(
        $loginClock.Elapsed.TotalSeconds, 3)
    $password = $null
    $failureStage = 'logon-result'
    if (-not $ok) {
        $failureCode = [int]$logonError
        # Denial is only a PASS for the action that expects it: a
        # directory account that is neither reachable at the DC nor cached
        # on this box. Any other failure names its real Win32 code.
        $deniedCodes = @(1326, 1311, 1355)
        if ($action -eq 'uncached-domain-user-denied' -and
                -not $controllerReachable -and
                $deniedCodes -contains [int]$logonError) {
            $denied = [ordered]@{
                schema_version = 1
                event = 'credential-action-result'
                nonce = $nonce
                action = $action
                result = 'pass'
                principal_sid = ''
                principal_matches_expected = $false
                authenticated = $false
                local_administrators_member = $false
                authentication_type = 'None'
                authentication_semantics = 'domain-logon-denied'
                cache_evidence = 'offline-cache-miss-proven'
                login_elapsed_seconds = $loginElapsedSeconds
                domain_reachable = $false
                controller_reachable = $false
                gateway_reachable = [bool]$gatewayReachable
                failure_classification = 'windows-logon-failure'
            }
            $serial.WriteLine(($denied | ConvertTo-Json -Compress))
            return
        }
        throw ('credential action logon failed: ' + $logonError)
    }

    $failureStage = 'identity-read'
    try {
        # The real authentication package from the token's logon session:
        # WindowsIdentity(token).AuthenticationType is empty for a bare
        # LogonUser token (attempt 44). This is the ground-truth package
        # ("Kerberos"/"NTLM"/"Negotiate") that also drives online-vs-cached.
        $authenticationPackage = [string](
            [TelosCredentialLogon]::LogonPackage($token))
        $identity = [Security.Principal.WindowsIdentity]::new($token)
        try {
            $principalSid = [string]$identity.User.Value
            $authenticated = [bool]$identity.IsAuthenticated
            # Prefer the identity's own type when the OS populated it; fall
            # back to the logon-session package (the LogonUser-token case).
            $authenticationType = [string]$identity.AuthenticationType
            if ([string]::IsNullOrEmpty($authenticationType)) {
                $authenticationType = $authenticationPackage
            }
            # The raw local-Administrators SID is present in the token
            # (deny-only when the logon is UAC-filtered) exactly when the
            # account is a member. WindowsIdentity.Groups omits the
            # deny-only SID (attempt 46 -> False for the provisioned
            # operator), so read the raw TokenGroups: presence with ANY
            # attributes is the correct membership test.
            $administratorsSid = '.S-1-5-32-544'.Substring(1)
            $isAdministrator = [TelosCredentialLogon]::TokenHasGroup(
                $token, $administratorsSid)
            # Prove the credential authenticated as the intended account.
            # Compare the token's own name -- offline-safe, no DC lookup --
            # by account and by domain scope. Kerberos logons can render the
            # name in UPN form (user@domain) and NTLM/down-level in
            # NetBIOS form (DOMAIN\user); accept both. A domain action must
            # not resolve to the local machine; the local-rescue action must.
            $identityName = [string]$identity.Name
            if ($identityName.Contains('\')) {
                $nameParts = $identityName -split '\\', 2
                $domainPart = $nameParts[0]
                $accountTail = $nameParts[1]
            }
            elseif ($identityName.Contains('@')) {
                $nameParts = $identityName -split '@', 2
                $accountTail = $nameParts[0]
                $domainPart = $nameParts[1]
            }
            else {
                $accountTail = $identityName
                $domainPart = ''
            }
            $accountMatches = ($accountTail -ieq $username)
            if ($domain -eq '.') {
                $scopeMatches = ($domainPart -ieq $env:COMPUTERNAME)
            }
            else {
                # Domain scope: a DNS-suffix UPN (student@ad.factory.test)
                # or a NetBIOS domain (FACTORY), never the local machine.
                $scopeMatches = (
                    $domainPart -ne '' -and
                    $domainPart -ine $env:COMPUTERNAME)
            }
            $principalMatches = ($accountMatches -and $scopeMatches)
        }
        finally {
            $identity.Dispose()
        }
    }
    finally {
        if ($token -ne [IntPtr]::Zero) {
            [void][TelosCredentialLogon]::CloseHandle($token)
        }
    }

    $result = [ordered]@{
        schema_version = 1
        event = 'credential-action-result'
        nonce = $nonce
        action = $action
        result = 'pass'
        principal_sid = $principalSid
        principal_matches_expected = [bool]$principalMatches
        authenticated = [bool]$authenticated
        local_administrators_member = [bool]$isAdministrator
        authentication_type = $authenticationType
        authentication_semantics = $authenticationSemantics
        cache_evidence = $cacheEvidence
        login_elapsed_seconds = $loginElapsedSeconds
        domain_reachable = [bool]$controllerReachable
        controller_reachable = [bool]$controllerReachable
        gateway_reachable = [bool]$gatewayReachable
        failure_classification = 'none'
    }
    $serial.WriteLine(($result | ConvertTo-Json -Compress))
}
catch {
    # Never serialize the exception: it may contain private guest state.
    # One fixed-form, credential-free breadcrumb turns a silent COM1 into
    # a typed mid-script failure on the host: the stage is a closed
    # literal set and the code is the bounded Win32 error. When no code
    # was captured at a call site, a Win32Exception anywhere in the chain
    # still yields its NativeErrorCode -- a bounded integer, nothing else.
    try {
        if ($failureCode -eq 0) {
            $failureException = $_.Exception
            while ($null -ne $failureException) {
                if ($failureException -is
                        [ComponentModel.Win32Exception]) {
                    $failureCode = [int]$failureException.NativeErrorCode
                    break
                }
                $failureException = $failureException.InnerException
            }
        }
        $serial.WriteLine(
            '{"schema_version":1,"event":"credential-script-failed"' +
            ',"stage":"' + $failureStage + '","code":' +
            ([string][int]$failureCode) + '}')
    }
    catch {
    }
    throw
}
finally {
    $password = $null
    if ($serial.IsOpen) {
        $serial.Close()
    }
    $serial.Dispose()
}
