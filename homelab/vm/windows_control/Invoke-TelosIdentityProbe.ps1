[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'current-principal',
        'domain-state',
        'cached-logon-policy',
        'service-reachability',
        'update-policy'
    )]
    [string]$Action,

    [ValidatePattern('^COM[1-9][0-9]*$')]
    [string]$SerialPort = 'COM1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
        'domain-state' {
            $computer = Get-CimInstance Win32_ComputerSystem
            $secure = $false
            if ($computer.PartOfDomain) {
                $secure = Test-ComputerSecureChannel
            }
            return [ordered]@{
                part_of_domain = [bool]$computer.PartOfDomain
                domain = [string]$computer.Domain
                secure_channel = [bool]$secure
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

$record = [ordered]@{
    schema_version = 1
    action = $Action
    result = 'pass'
    observed_at = [DateTime]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
    observation = Get-Probe $Action
}
$line = $record | ConvertTo-Json -Compress -Depth 5
$serial = [System.IO.Ports.SerialPort]::new(
    $SerialPort, 115200, 'None', 8, 'One')
try {
    $serial.Open()
    $serial.WriteLine($line)
}
finally {
    $serial.Dispose()
}
