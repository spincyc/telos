param()

$ErrorActionPreference = 'Stop'
$taskName = 'TelosPostSubmitDiagnostic'
$root = Join-Path $env:ProgramData 'Telos\PostSubmitDiagnostic'
$configPath = Join-Path $root 'config.json'
$serial = $null
$resultSent = $false
$cleanupComplete = $false

function Write-DiagnosticEvent {
    param(
        [string]$Event,
        [string]$Nonce,
        [string]$Code,
        [switch]$CleanupComplete
    )
    if ($CleanupComplete -and $Code) {
        $line = '{"cleanup_complete":true,"code":"' + $Code +
            '","event":"' + $Event + '","nonce":"' + $Nonce +
            '","schema_version":1}'
    } elseif ($CleanupComplete) {
        $line = '{"cleanup_complete":true,"event":"' + $Event +
            '","nonce":"' + $Nonce + '","schema_version":1}'
    } else {
        $line = '{"event":"' + $Event + '","nonce":"' + $Nonce +
            '","schema_version":1}'
    }
    $serial.WriteLine($line)
}

function Read-ExactCommand {
    param([string[]]$Commands, [string]$Nonce, [string]$ExpectedPrincipal)
    try {
        $raw = $serial.ReadLine()
        $record = $raw | ConvertFrom-Json
    } catch {
        throw 'diagnostic command is invalid'
    }
    $properties = @($record.PSObject.Properties.Name)
    $expectedCount = if ($ExpectedPrincipal) { 4 } else { 3 }
    if ($properties.Count -ne $expectedCount -or
        'schema_version' -notin $properties -or
        'command' -notin $properties -or
        'nonce' -notin $properties -or
        $record.schema_version -ne 1 -or
        $record.command -cnotin $Commands -or
        $record.nonce -cne $Nonce -or
        ($ExpectedPrincipal -and (
            'principal' -notin $properties -or
            $record.principal -cne $ExpectedPrincipal))) {
        throw 'diagnostic command is invalid'
    }
    $canonical = if ($ExpectedPrincipal) {
        '{"command":"' + [string]$record.command + '","nonce":"' +
            $Nonce + '","principal":"' + $ExpectedPrincipal +
            '","schema_version":1}'
    } else {
        '{"command":"' + [string]$record.command + '","nonce":"' +
            $Nonce + '","schema_version":1}'
    }
    if ($raw -cne $canonical) {
        throw 'diagnostic command is not canonical'
    }
    return [string]$record.command
}

function Remove-Diagnostic {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $PSCommandPath -Force `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    $remainingTask = Get-ScheduledTask -TaskName $taskName `
        -ErrorAction SilentlyContinue
    if ($null -ne $remainingTask) {
        throw 'diagnostic task cleanup failed'
    }
    $remainingConfig = Test-Path -LiteralPath $configPath -PathType Leaf
    $remainingScript = Test-Path -LiteralPath $PSCommandPath -PathType Leaf
    $remainingRoot = Test-Path -LiteralPath $root
    if ($remainingConfig -or $remainingScript -or $remainingRoot) {
        throw 'diagnostic file cleanup failed'
    }
    $script:cleanupComplete = $true
}

function Complete-Diagnostic {
    param([string]$Event, [string]$Nonce, [string]$Code)
    Remove-Diagnostic
    Write-DiagnosticEvent -Event $Event -Nonce $Nonce -Code $Code `
        -CleanupComplete
    $script:resultSent = $true
}

function Get-EventData {
    param($EventRecord)
    $values = @{}
    $xml = [xml]$EventRecord.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($item.Name) {
            $values[[string]$item.Name] = [string]$item.'#text'
        }
    }
    return $values
}

function Get-FailureCode {
    param([hashtable]$Data)
    $status = ([string]$Data.Status).ToUpperInvariant()
    $subStatus = ([string]$Data.SubStatus).ToUpperInvariant()
    if ($status -eq '0XC000006A' -or $subStatus -eq '0XC000006A') {
        return 'bad-credential'
    }
    if ($status -eq '0XC0000064' -or $subStatus -eq '0XC0000064') {
        return 'bad-credential'
    }
    if ($status -eq '0XC0000072' -or $subStatus -eq '0XC0000072') {
        return 'account-disabled'
    }
    if ($status -eq '0XC0000234' -or $subStatus -eq '0XC0000234') {
        return 'account-locked'
    }
    if ($status -eq '0XC0000193' -or $subStatus -eq '0XC0000193') {
        return 'account-expired'
    }
    if ($status -in @('0XC0000071', '0XC0000224') -or
        $subStatus -in @('0XC0000071', '0XC0000224')) {
        return 'password-expired'
    }
    $restriction = @(
        '0XC000006E', '0XC0000070', '0XC000015B')
    if ($status -in $restriction -or $subStatus -in $restriction) {
        return 'logon-restriction'
    }
    return 'other-rejection'
}

function Test-OperatorMatch {
    param([int]$Id, [hashtable]$Data, $Config, [string]$OperatorPrincipal)
    if ($Id -eq 4624) {
        return [string]$Data.TargetUserSid -ceq [string]$Config.operator_sid
    }
    $domain = [string]$Data.TargetDomainName
    $targetName = [string]$Data.TargetUserName
    $realmDomain = (
        $domain -ceq [string]$Config.operator_realm -or
        $domain -ceq
            ([string]$Config.operator_realm).Split('.')[0])
    $splitIdentity = (
        $targetName -ceq [string]$Config.operator_name -and
        $realmDomain)
    # Windows may preserve an interactively typed UPN in TargetUserName and
    # leave TargetDomainName blank. Accept only the exact public UPN and finite
    # domain forms for that same identity.
    $upnIdentity = (
        $targetName -ceq $OperatorPrincipal -and
        (-not $domain -or $realmDomain))
    return ($splitIdentity -or $upnIdentity)
}

try {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class TelosAuditPolicy {
    [StructLayout(LayoutKind.Sequential)]
    public struct AUDIT_POLICY_INFORMATION {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AuditQuerySystemPolicy(
        [In] Guid[] pSubCategoryGuids,
        uint PolicyCount,
        out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll")]
    public static extern void AuditFree(IntPtr Buffer);
}
'@

    $config = Get-Content -LiteralPath $configPath -Raw |
        ConvertFrom-Json
    if ($config.schema_version -ne 1 -or
        $config.nonce -notmatch '^[a-f0-9]{32}$' -or
        $config.operator_sid -notmatch '^S-\d(?:-\d+)+$' -or
        $config.operator_name -cne 'operator' -or
        $config.operator_realm -notmatch '^[A-Z0-9.-]{1,253}$') {
        throw 'diagnostic configuration is invalid'
    }
    $nonce = [string]$config.nonce
    $operatorPrincipal = (
        [string]$config.operator_name + '@' +
        [string]$config.operator_realm)

    # COM1 can still be transitioning from the join process at startup.
    $connectDeadline = [DateTime]::UtcNow.AddSeconds(180)
    while ($null -eq $serial -and [DateTime]::UtcNow -lt $connectDeadline) {
        $candidate = [System.IO.Ports.SerialPort]::new(
            'COM1', 115200, 'None', 8, 'One')
        $candidate.NewLine = "`n"
        $candidate.ReadTimeout = 120000
        try {
            $candidate.Open()
            $serial = $candidate
        }
        catch {
            $candidate.Dispose()
            Start-Sleep -Milliseconds 500
        }
    }
    if ($null -eq $serial) {
        throw 'diagnostic serial deadline expired'
    }

    # QEMU's wait=off socket chardev does not retain output written before a
    # host client connects. Wait for the nonce- and principal-bound host
    # command first so startup ordering cannot discard a one-shot readiness
    # receipt and leave both peers waiting on each other.
    [void](Read-ExactCommand @('arm') $nonce $operatorPrincipal)
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $auditPointer = [IntPtr]::Zero
    $auditGuid = [Guid]'0CCE9215-69AE-11D9-BED3-505054503030'
    if ([TelosAuditPolicy]::AuditQuerySystemPolicy(
            @($auditGuid), 1, [ref]$auditPointer)) {
        try {
            $auditPolicy = [Runtime.InteropServices.Marshal]::PtrToStructure(
                $auditPointer,
                [type][TelosAuditPolicy+AUDIT_POLICY_INFORMATION])
            $auditBits = [uint32]$auditPolicy.AuditingInformation
        } finally {
            [TelosAuditPolicy]::AuditFree($auditPointer)
        }
    } else {
        $auditBits = [uint32]0
    }
    if (-not $securityLog.IsEnabled -or ($auditBits -band 3) -ne 3) {
        Complete-Diagnostic 'result' $nonce 'audit-disabled'
        return
    }
    $latest = @(Get-WinEvent -LogName Security -MaxEvents 1 `
        -ErrorAction SilentlyContinue)
    $baseline = if ($latest.Count -eq 1) {
        [long]$latest[0].RecordId
    } else { [long]0 }
    $baselineTime = [DateTime]::UtcNow
    Write-DiagnosticEvent 'armed' $nonce
    $nextCommand = Read-ExactCommand @('submitted', 'cancel') $nonce
    if ($nextCommand -ceq 'cancel') {
        Complete-Diagnostic 'cancelled' $nonce
        return
    }
    Write-DiagnosticEvent 'submitted' $nonce
    $serial.ReadTimeout = 500

    # The host grants this scan an independent 70-second phase. Keep ten
    # seconds for its terminal receipt, verified cleanup, and COM1 handoff.
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $sawInteractiveLogon = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($serial.BytesToRead -gt 0) {
            [void](Read-ExactCommand @('cancel') $nonce)
            Complete-Diagnostic 'cancelled' $nonce
            return
        }
        $log = Get-WinEvent -ListLog Security -ErrorAction Stop
        if (-not $log.IsEnabled) {
            $code = 'audit-disabled'
            break
        }
        $current = @(Get-WinEvent -LogName Security -MaxEvents 1 `
            -ErrorAction SilentlyContinue)
        if ($current.Count -eq 1 -and
            [long]$current[0].RecordId -lt $baseline) {
            $code = 'event-log-reset'
            break
        }
        if ($log.OldestRecordNumber -and
            $baseline -gt 0 -and
            [long]$log.OldestRecordNumber -gt ($baseline + 1)) {
            $code = 'event-gap'
            break
        }
        $events = @(Get-WinEvent -LogName Security -FilterXPath (
                '*[System[(EventID=4624 or EventID=4625 or EventID=1102) ' +
                'and EventRecordID > ' + $baseline + ']]'
            ) -MaxEvents 65 -ErrorAction SilentlyContinue)
        $cleared = @($events | Where-Object { $_.Id -eq 1102 })
        $systemCleared = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-Eventlog'
                Id = 104
                StartTime = $baselineTime
            } -MaxEvents 1 -ErrorAction SilentlyContinue)
        if ($cleared.Count -gt 0 -or $systemCleared.Count -gt 0) {
            $code = 'event-log-reset'
            break
        }
        if ($events.Count -eq 65) {
            $code = 'ambiguous'
            break
        }
        $events = @($events | Where-Object { $_.Id -in @(4624, 4625) })
        $matches = @()
        foreach ($eventRecord in $events) {
            $data = Get-EventData $eventRecord
            if ([string]$data.LogonType -cne '2') {
                continue
            }
            $sawInteractiveLogon = $true
            $isOperator = Test-OperatorMatch `
                $eventRecord.Id $data $config $operatorPrincipal
            if ($isOperator) {
                $matches += ,@($eventRecord, $data)
            }
        }
        if ($matches.Count -gt 1) {
            $code = 'ambiguous'
            break
        }
        if ($matches.Count -eq 1) {
            if ($matches[0][0].Id -eq 4624) {
                $code = 'interactive-logon-success'
            } else {
                $code = Get-FailureCode $matches[0][1]
            }
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $code) {
        # No correlated Type-2 logon closed the submission. Collect secondary
        # evidence, bounded and fail-closed, within the same baseline window so
        # a silently reset sign-in reports WHY instead of a bare no-logon-event.
        # An operator failure of any LogonType is the most direct rejection; a
        # missing logon server or broken secure channel explains a submission
        # that never reaches authentication; a Kerberos error is next; an
        # operator non-interactive success is the weakest correlate. Only a
        # genuine absence of any evidence remains no-logon-event.
        $operatorFailure = $false
        $operatorNonInteractive = $false
        $secondary = @(Get-WinEvent -LogName Security -FilterXPath (
                '*[System[(EventID=4624 or EventID=4625) ' +
                'and EventRecordID > ' + $baseline + ']]'
            ) -MaxEvents 65 -ErrorAction SilentlyContinue)
        foreach ($eventRecord in $secondary) {
            $data = Get-EventData $eventRecord
            if (-not (Test-OperatorMatch `
                    $eventRecord.Id $data $config $operatorPrincipal)) {
                continue
            }
            if ($eventRecord.Id -eq 4625) {
                $operatorFailure = $true
            } elseif ([string]$data.LogonType -cne '2') {
                $operatorNonInteractive = $true
            }
        }
        $netlogonNoDc = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'NETLOGON'
                Id = 5719
                StartTime = $baselineTime
            } -MaxEvents 1 -ErrorAction SilentlyContinue)
        $netlogonSecure = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'NETLOGON'
                Id = 3210, 5783
                StartTime = $baselineTime
            } -MaxEvents 1 -ErrorAction SilentlyContinue)
        $kerberosError = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-Security-Kerberos'
                StartTime = $baselineTime
                Level = 1, 2, 3
            } -MaxEvents 1 -ErrorAction SilentlyContinue)
        $code = if ($operatorFailure) {
            'non-interactive-logon-failure'
        } elseif ($netlogonNoDc.Count -gt 0) {
            'no-logon-servers'
        } elseif ($netlogonSecure.Count -gt 0) {
            'secure-channel-error'
        } elseif ($kerberosError.Count -gt 0) {
            'kerberos-error'
        } elseif ($operatorNonInteractive) {
            'non-interactive-logon'
        } elseif ($sawInteractiveLogon) {
            'uncorrelated-logon-event'
        } else {
            'no-logon-event'
        }
    }
    Complete-Diagnostic 'result' $nonce $code
}
catch {
    if ($serial -and $serial.IsOpen -and -not $resultSent -and $nonce) {
        try {
            if (-not $cleanupComplete) { Remove-Diagnostic }
            Write-DiagnosticEvent 'result' $nonce 'watcher-error' `
                -CleanupComplete
            $resultSent = $true
        } catch {
            # Cleanup remains mandatory when the bounded transport is gone.
        }
    }
}
finally {
    if ($serial) {
        if ($serial.IsOpen) { $serial.Close() }
        $serial.Dispose()
    }
    if (-not $cleanupComplete) {
        try { Remove-Diagnostic } catch {}
    }
}
