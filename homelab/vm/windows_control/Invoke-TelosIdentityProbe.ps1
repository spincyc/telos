[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'current-principal',
        'current-session-state',
        'interactive-operator',
        'controller-readiness',
        'domain-state',
        'managed-identity-state',
        'cached-logon-policy',
        'gateway-reachability',
        'dependency-reachability',
        'service-reachability',
        'update-policy'
    )]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [System.IO.Ports.SerialPort]$S
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ControllerDomain = 'ad.factory.test'
$ControllerFqdn = 'bootstrap-dc.ad.factory.test'

function Test-TcpPort {
    param([string]$HostName, [int]$Port)
    if ([string]::IsNullOrWhiteSpace($HostName)) {
        return $false
    }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.ConnectAsync($HostName, $Port)
        return $pending.Wait(1500) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Resolve-AccountSid {
    param([string]$Account)
    try {
        return (
            [Security.Principal.NTAccount]::new($Account)
        ).Translate([Security.Principal.SecurityIdentifier])
    }
    catch {
        return $null
    }
}

function Test-ProfileForSid {
    param([Security.Principal.SecurityIdentifier]$Sid)
    if ($null -eq $Sid) {
        return $false
    }
    $path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\' +
        'CurrentVersion\ProfileList\' + $Sid.Value
    return Test-Path -LiteralPath $path -PathType Container
}

function Get-DomainAdministratorSid {
    param([string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $null
    }
    $domainAdmins = Resolve-AccountSid ($Domain + '\Domain Admins')
    if ($null -eq $domainAdmins -or
            -not $domainAdmins.Value.EndsWith('-512')) {
        return $null
    }
    return $domainAdmins
}

function Test-LocalAdministratorMember {
    param([Security.Principal.SecurityIdentifier]$Sid)
    if ($null -eq $Sid) {
        return $false
    }
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544')
    $matches = @(
        Get-LocalGroupMember -SID $administratorsSid |
            Where-Object { $_.SID.Value -ceq $Sid.Value }
    )
    return $matches.Count -eq 1
}

function Test-UdpRole {
    param(
        [System.Net.IPAddress]$Address,
        [int]$Port,
        [string]$ExpectedReply
    )
    $client = [System.Net.Sockets.UdpClient]::new()
    try {
        $client.Client.ReceiveTimeout = 1500
        $client.Connect($Address, $Port)
        $request = [Text.Encoding]::ASCII.GetBytes('health')
        [void]$client.Send($request, $request.Length)
        $remote = [System.Net.IPEndPoint]::new(
            [System.Net.IPAddress]::Any, 0)
        $reply = $client.Receive([ref]$remote)
        return (
            $remote.Address.Equals($Address) -and
            $remote.Port -eq $Port -and
            [Text.Encoding]::ASCII.GetString($reply) -ceq $ExpectedReply
        )
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-UdpAuthorizationDenied {
    param(
        [System.Net.IPAddress]$Address,
        [int]$Port,
        [string]$ExpectedReply
    )
    $client = [System.Net.Sockets.UdpClient]::new()
    try {
        $client.Client.ReceiveTimeout = 1500
        $client.Connect($Address, $Port)
        # The fixed public request contains no identity or credential.
        $request = [Text.Encoding]::ASCII.GetBytes('authorize')
        [void]$client.Send($request, $request.Length)
        $remote = [System.Net.IPEndPoint]::new(
            [System.Net.IPAddress]::Any, 0)
        $reply = $client.Receive([ref]$remote)
        return (
            $remote.Address.Equals($Address) -and
            $remote.Port -eq $Port -and
            [Text.Encoding]::ASCII.GetString($reply) -ceq $ExpectedReply
        )
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Get-Probe {
    param([string]$Name)
    switch ($Name) {
        'current-principal' {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            return [ordered]@{
                principal = $identity.Name
                authenticated = $identity.IsAuthenticated
                elevated = $principal.IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
                authentication_type = $identity.AuthenticationType
            }
        }
        'current-session-state' {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            $computer = Get-CimInstance Win32_ComputerSystem
            $resolved = Resolve-AccountSid $identity.Name
            $domainAdmins = if ($computer.PartOfDomain) {
                Get-DomainAdministratorSid ([string]$computer.Domain)
            } else {
                $null
            }
            $profile = [Environment]::GetFolderPath('UserProfile')
            return [ordered]@{
                authenticated = [bool]$identity.IsAuthenticated
                identity_resolved = (
                    $null -ne $resolved -and
                    $resolved.Value -ceq $identity.User.Value
                )
                profile_loaded = (
                    -not [string]::IsNullOrWhiteSpace($profile) -and
                    (Test-Path -LiteralPath $profile -PathType Container)
                )
                local_profile = (
                    -not [string]::IsNullOrWhiteSpace($profile) -and
                    -not $profile.StartsWith('\\') -and
                    [IO.Path]::IsPathRooted($profile)
                )
                local_administrator = $principal.IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
                domain_administrator = (
                    $null -ne $domainAdmins -and
                    $principal.IsInRole($domainAdmins)
                )
            }
        }
        'interactive-operator' {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $computer = Get-CimInstance Win32_ComputerSystem
            $operator = 'operator@' + $ControllerDomain.ToUpperInvariant()
            $operatorSid = Resolve-AccountSid $operator
            $consolePrincipal = [string]$computer.UserName
            $consoleSid = Resolve-AccountSid $consolePrincipal
            $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
            $profilePath = [Environment]::GetFolderPath('UserProfile')
            $profiles = @(
                Get-CimInstance Win32_UserProfile |
                    Where-Object {
                        $_.SID -ceq $identity.User.Value
                    }
            )
            $profileSid = if ($profiles.Count -eq 1) {
                [string]$profiles[0].SID
            } else {
                ''
            }
            $profileLoaded = (
                $profiles.Count -eq 1 -and
                [bool]$profiles[0].Loaded -and
                -not [bool]$profiles[0].Special -and
                ([uint32]$profiles[0].Status -band 15) -eq 0
            )
            $localProfile = $false
            if ($profileLoaded -and
                    -not [string]::IsNullOrWhiteSpace($profilePath) -and
                    -not $profilePath.StartsWith('\\') -and
                    [IO.Path]::IsPathRooted($profilePath) -and
                    (Test-Path -LiteralPath $profilePath -PathType Container)) {
                $environmentPath = [IO.Path]::GetFullPath(
                    $profilePath).TrimEnd('\')
                $registeredPath = [IO.Path]::GetFullPath(
                    [Environment]::ExpandEnvironmentVariables(
                        [string]$profiles[0].LocalPath
                    )
                ).TrimEnd('\')
                $localProfile = $environmentPath.Equals(
                    $registeredPath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
            return [ordered]@{
                principal = [string]$identity.Name
                principal_sid = [string]$identity.User.Value
                operator = [string]$operator
                operator_sid = [string]$operatorSid.Value
                console_principal = [string]$consolePrincipal
                console_sid = [string]$consoleSid.Value
                authenticated = [bool]$identity.IsAuthenticated
                authentication_type = [string]$identity.AuthenticationType
                session_id = [int]$sessionId
                profile_sid = [string]$profileSid
                profile_loaded = [bool]$profileLoaded
                local_profile = [bool]$localProfile
            }
        }
        'controller-readiness' {
            $dns = $null -ne (Resolve-DnsName -Type SRV `
                "_ldap._tcp.dc._msdcs.$ControllerDomain" `
                -ErrorAction SilentlyContinue)
            & w32tm.exe /stripchart /computer:$ControllerFqdn /samples:1 `
                /dataonly | Out-Null
            $time = $LASTEXITCODE -eq 0
            $synthetic = @(
                'student', 'operator', 'directory-admin' |
                    ForEach-Object {
                        $null -ne (
                            Resolve-AccountSid (
                                $ControllerDomain + '\' + $_
                            )
                        )
                    }
            ) -notcontains $false
            return [ordered]@{
                samba_ad = (
                    (Test-TcpPort $ControllerFqdn 389) -and
                    (Test-TcpPort $ControllerFqdn 445)
                )
                dns = [bool]$dns
                kerberos = Test-TcpPort $ControllerFqdn 88
                time = [bool]$time
                synthetic_directory = [bool]$synthetic
            }
        }
        'domain-state' {
            $computer = Get-CimInstance Win32_ComputerSystem
            $secure = $false
            $operator = ''
            $operatorLocalAdministrator = $false
            if ($computer.PartOfDomain) {
                $secure = Test-ComputerSecureChannel
                $operator = 'operator@' + (
                    [string]$computer.Domain
                ).ToUpperInvariant()
                $operatorSid = (
                    [Security.Principal.NTAccount]::new($operator)
                ).Translate([Security.Principal.SecurityIdentifier])
                $administratorsSid = (
                    [Security.Principal.SecurityIdentifier]::new(
                        'S-1-5-32-544'
                    )
                )
                $matches = @(
                    Get-LocalGroupMember -SID $administratorsSid |
                        Where-Object {
                            $_.SID.Value -ceq $operatorSid.Value
                        }
                )
                $operatorLocalAdministrator = $matches.Count -eq 1
            }
            return [ordered]@{
                part_of_domain = [bool]$computer.PartOfDomain
                domain = [string]$computer.Domain
                secure_channel = [bool]$secure
                operator = $operator
                operator_local_administrator = [bool](
                    $operatorLocalAdministrator
                )
            }
        }
        'managed-identity-state' {
            $computer = Get-CimInstance Win32_ComputerSystem
            $domain = if ($computer.PartOfDomain) {
                [string]$computer.Domain
            } else {
                ''
            }
            $standardSid = Resolve-AccountSid ($domain + '\student')
            $operatorSid = Resolve-AccountSid ($domain + '\operator')
            $directoryAdminSid = Resolve-AccountSid (
                $domain + '\directory-admin')
            $domainAdminsSid = Get-DomainAdministratorSid $domain
            $operatorDomainAdmin = (
                $null -ne $operatorSid -and
                $null -ne $domainAdminsSid -and
                (Get-CimInstance Win32_GroupUser | Where-Object {
                    $_.GroupComponent.Name -ceq 'Domain Admins' -and
                    $_.PartComponent.SID -ceq $operatorSid.Value
                }).Count -gt 0
            )
            $directoryDomainAdmin = (
                $null -ne $directoryAdminSid -and
                $null -ne $domainAdminsSid -and
                (Get-CimInstance Win32_GroupUser | Where-Object {
                    $_.GroupComponent.Name -ceq 'Domain Admins' -and
                    $_.PartComponent.SID -ceq $directoryAdminSid.Value
                }).Count -gt 0
            )
            return [ordered]@{
                standard_identity_resolved = $null -ne $standardSid
                standard_profile_present = Test-ProfileForSid $standardSid
                operator_identity_resolved = $null -ne $operatorSid
                operator_profile_present = Test-ProfileForSid $operatorSid
                operator_local_administrator = `
                    Test-LocalAdministratorMember $operatorSid
                operator_domain_administrator = [bool]$operatorDomainAdmin
                directory_admin_identity_resolved = `
                    $null -ne $directoryAdminSid
                directory_admin_domain_administrator = `
                    [bool]$directoryDomainAdmin
                operator_is_directory_admin = (
                    $null -ne $operatorSid -and
                    $null -ne $directoryAdminSid -and
                    $operatorSid.Value -ceq $directoryAdminSid.Value
                )
            }
        }
        'cached-logon-policy' {
            $value = Get-ItemPropertyValue `
                -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
                -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue
            return [ordered]@{
                configured = $null -ne $value
                cached_logon_count = if ($null -eq $value) {
                    $null
                } else {
                    [int]$value
                }
            }
        }
        'gateway-reachability' {
            return [ordered]@{
                gateway_reachable = Test-UdpRole `
                    ([System.Net.IPAddress]::Parse('10.1.31.1')) 31337 `
                    'sim-ok:health'
            }
        }
        'dependency-reachability' {
            return [ordered]@{
                update_source_reachable = Test-UdpRole `
                    ([System.Net.IPAddress]::Parse('10.1.31.3')) 31338 `
                    'update-source:available'
                optional_storage_reachable = Test-UdpRole `
                    ([System.Net.IPAddress]::Parse('10.1.31.4')) 31339 `
                    'optional-storage:available'
                optional_storage_authorization_denied = `
                    Test-UdpAuthorizationDenied `
                    ([System.Net.IPAddress]::Parse('10.1.31.4')) 31339 `
                    'optional-storage:authorization-denied'
            }
        }
        'service-reachability' {
            $computer = Get-CimInstance Win32_ComputerSystem
            $domain = if ($computer.PartOfDomain) {
                [string]$computer.Domain
            } else {
                ''
            }
            return [ordered]@{
                domain = $domain
                dns = if ($domain) {
                    $null -ne (Resolve-DnsName -Type SRV `
                        "_ldap._tcp.dc._msdcs.$domain" `
                        -ErrorAction SilentlyContinue)
                } else {
                    $false
                }
                kerberos = Test-TcpPort $domain 88
                ldap = Test-TcpPort $domain 389
                smb = Test-TcpPort $domain 445
            }
        }
        'update-policy' {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            $value = Get-ItemPropertyValue -Path $path -Name NoAutoUpdate `
                -ErrorAction SilentlyContinue
            return [ordered]@{
                policy_present = $null -ne $value
                automatic_updates_configured = $value -eq 0
            }
        }
    }
}

$serial = $S
try {
    $start = [ordered]@{
        schema_version = 1
        action = $Action
        result = 'start'
    }
    $serial.WriteLine(($start | ConvertTo-Json -Compress))
    try {
        $record = [ordered]@{
            schema_version = 1
            action = $Action
            result = 'pass'
            observed_at = [DateTime]::UtcNow.ToString(
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture)
            observation = Get-Probe $Action
        }
    }
    catch {
        # Never serialize the exception: it may contain private guest state.
        $record = [ordered]@{
            schema_version = 1
            action = $Action
            result = 'fail'
            observed_at = [DateTime]::UtcNow.ToString(
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture)
            failure = [ordered]@{
                phase = 'observation'
                code = 'guest-probe-error'
            }
        }
    }
    $line = $record | ConvertTo-Json -Compress -Depth 5
    $serial.WriteLine($line)
}
finally {
    $serial.Dispose()
}
