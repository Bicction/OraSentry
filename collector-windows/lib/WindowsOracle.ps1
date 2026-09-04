Set-StrictMode -Version 2.0

function Get-WindowsOracleRegistryKeys {
    # Bounded to Oracle roots and their immediate Home keys; never dump registry values.
    foreach ($root in @("HKLM:\SOFTWARE\ORACLE", "HKLM:\SOFTWARE\WOW6432Node\ORACLE")) {
        if (Test-Path -LiteralPath $root -ErrorAction Stop) {
            Get-Item -LiteralPath $root -ErrorAction Stop
            Get-ChildItem -LiteralPath $root -ErrorAction Stop
        }
    }
}

function ConvertTo-WindowsAccountSid {
    param([string]$Account)
    if ($Account -in @("LocalSystem", "NT AUTHORITY\SYSTEM")) { return "S-1-5-18" }
    if ($Account.StartsWith('.\')) { $Account = $env:COMPUTERNAME + $Account.Substring(1) }
    try { return (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return "" }
}

function ConvertFrom-LockPagesPolicy {
    param([string]$Text)
    $match = [regex]::Match($Text, '(?im)^\s*SeLockMemoryPrivilege\s*=([^\r\n]*)')
    if ($match.Success) {
        foreach ($principal in ($match.Groups[1].Value -split ',')) {
            $principal = $principal.Trim().TrimStart('*')
            if (-not $principal) { continue }
            if ($principal -match '^S-1-') { $principal } else { ConvertTo-WindowsAccountSid $principal }
        }
    }
}

function Get-LockPagesGrant {
    param([string]$AccountSid, [string[]]$GrantedSids, [object[]]$Memberships)
    if (-not $AccountSid) { return "UNRESOLVED_ACCOUNT" }
    if ($GrantedSids -contains $AccountSid) { return "DIRECT" }
    foreach ($membership in @($Memberships)) {
        if ($membership.MEMBER_SID -eq $AccountSid -and $GrantedSids -contains $membership.GROUP_SID) { return "LOCAL_GROUP" }
    }
    if ($AccountSid -eq "S-1-5-18") { return "SYSTEM_ACCOUNT" }
    # Absence from direct/local membership is not proof of denial: domain nesting and
    # the already-running service token are deliberately not inferred here.
    return "UNCONFIRMED"
}

function Collect-OracleWindowsMemory {
    param($Context, [string]$DomainDir)
    Invoke-CollectionAction $Context "oracle_memory_config.txt" {
        $services = @(Get-CimInstance Win32_Service -Filter "Name LIKE 'OracleService%'" -ErrorAction Stop)
        if ($Context.CheckType -eq "db") { $services = @($services | Where-Object { $_.Name -ieq ("OracleService" + $Context.OracleSid) }) }
        $rows = New-Object System.Collections.Generic.List[object]
        if (-not $services.Count) {
            $rows.Add(@("", "", "", "", "", "", "", "", "", "NO_LOCAL_SERVICE", ""))
        } else {
            $token = [guid]::NewGuid().ToString("N")
            $policyPath = Join-Path $Context.RawDir (".rights-" + $token + ".inf")
            $logPath = Join-Path $Context.RawDir (".rights-" + $token + ".log")
            try {
                & secedit.exe /export /mergedpolicy /areas USER_RIGHTS /cfg $policyPath /log $logPath /quiet | Out-Null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $policyPath)) { throw "User rights export failed" }
                $granted = @(ConvertFrom-LockPagesPolicy ([IO.File]::ReadAllText($policyPath)))
            } finally {
                # Exact files created by this action only. Do not package the full policy.
                foreach ($tempFile in @($policyPath, $logPath)) {
                    if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction Stop }
                }
            }
            $memberships = @()
            $membershipFile = Join-Path $Context.RawDir "host\privileged_groups.txt"
            if (Test-Path -LiteralPath $membershipFile) { $memberships = @(Import-Csv -LiteralPath $membershipFile -Delimiter '|') }
            $keys = @(Get-WindowsOracleRegistryKeys)
            foreach ($service in $services) {
                $sid = $service.Name.Substring("OracleService".Length)
                $serviceHome = ""
                if ($service.PathName -match '^\s*"?(.+?\\bin\\oracle\.exe)"?(?:\s|$)') { $serviceHome = Split-Path -Parent (Split-Path -Parent $matches[1]) }
                $matchedKeys = @($keys | Where-Object {
                    $registeredHome = [string](Get-BaselineRegistryValue $_.PSPath "ORACLE_HOME")
                    $serviceHome -and $registeredHome.TrimEnd('\') -ieq $serviceHome.TrimEnd('\')
                })
                $accountSid = ConvertTo-WindowsAccountSid $service.StartName
                $grant = Get-LockPagesGrant $accountSid $granted $memberships
                if (-not $matchedKeys.Count) {
                    $rows.Add(@($service.Name, $sid, $service.StartName, $accountSid, $serviceHome, "", "", "", $grant, "REGISTRY_UNMATCHED", ($granted -join ",")))
                }
                foreach ($key in $matchedKeys) {
                    $globalMode = Get-BaselineRegistryValue $key.PSPath "ORA_LPENABLE"
                    $instanceMode = Get-BaselineRegistryValue $key.PSPath ("ORA_" + $sid + "_LPENABLE")
                    $evidence = if ($matchedKeys.Count -eq 1) { "CONFIG_ONLY" } else { "MULTIPLE_HOME_KEYS" }
                    $rows.Add(@($service.Name, $sid, $service.StartName, $accountSid, $serviceHome, $key.Name,
                        $globalMode, $instanceMode, $grant, $evidence, ($granted -join ",")))
                }
            }
        }
        Write-PipeTable (Join-Path $DomainDir "oracle_memory_config.txt") @("SERVICE","SID","ACCOUNT","ACCOUNT_SID","ORACLE_HOME","REGISTRY_KEY","ORA_LPENABLE","ORA_SID_LPENABLE","LOCK_PAGES_GRANT","EVIDENCE","GRANTED_SIDS") $rows.ToArray()
    } -Optional
}

function Add-OracleConfigurationAclRows {
    param([string]$Path, [string]$Kind, $Rows)
    if ($Kind -ne "REGISTRY" -and ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[%$?*]')) {
        $Rows.Add(@($Kind, $Path, "", "", "", "", "", "", "", "UNRESOLVED_PATH"))
        return
    }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        $Rows.Add(@($Kind, $Path, "", "", "", "", "", "", "", "ABSENT"))
        return
    }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $modified = if ($item.PSObject.Properties['LastWriteTimeUtc']) { $item.LastWriteTimeUtc.ToString('o') } else { "" }
    foreach ($access in $acl.Access) {
        $identitySid = ""
        try { $identitySid = $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
        $rights = if ($access.PSObject.Properties['RegistryRights']) { $access.RegistryRights } else { $access.FileSystemRights }
        $Rows.Add(@($Kind, $Path, $acl.Owner, $access.IdentityReference, $identitySid, [string]$rights,
            [string]$access.AccessControlType, $access.IsInherited, $modified, "OBSERVED"))
    }
}

function Collect-OracleConfigurationAcls {
    param($Context, [string]$SecDir)
    Invoke-CollectionAction $Context "oracle_config_acl.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        $failures = New-Object System.Collections.Generic.List[string]
        $directories = New-Object System.Collections.Generic.List[string]
        $directories.Add((Join-Path $Context.OracleHome "network\admin"))
        if ($env:TNS_ADMIN) { $directories.Add($env:TNS_ADMIN) }
        foreach ($key in @(Get-WindowsOracleRegistryKeys)) {
            $registeredHome = [string](Get-BaselineRegistryValue $key.PSPath "ORACLE_HOME")
            if ($registeredHome.TrimEnd('\') -ine $Context.OracleHome.TrimEnd('\')) { continue }
            try {
                Add-OracleConfigurationAclRows $key.PSPath "REGISTRY" $rows
                $tnsAdmin = [string](Get-BaselineRegistryValue $key.PSPath "TNS_ADMIN")
                if ($tnsAdmin) { $directories.Add($tnsAdmin) }
            } catch { $failures.Add($_.Exception.Message) }
        }
        foreach ($directory in @($directories | Select-Object -Unique)) {
            if ($directory -notmatch '^[A-Za-z]:[\\/]' -or $directory -match '[%$?*]') {
                $rows.Add(@("NETWORK_FILE", $directory, "", "", "", "", "", "", "", "UNRESOLVED_PATH"))
                continue
            }
            foreach ($name in @("listener.ora", "sqlnet.ora", "tnsnames.ora")) {
                $path = Join-Path $directory $name
                try {
                    Add-OracleConfigurationAclRows $path "NETWORK_FILE" $rows
                } catch { $failures.Add($_.Exception.Message) }
            }
        }
        Write-PipeTable (Join-Path $SecDir "oracle_config_acl.txt") @("KIND","PATH","OWNER","IDENTITY","IDENTITY_SID","RIGHTS","TYPE","INHERITED","MODIFIED_UTC","EVIDENCE") $rows.ToArray()
        if ($failures.Count) { throw ($failures -join "; ") }
    } -Optional
}
