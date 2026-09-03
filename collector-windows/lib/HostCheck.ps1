Set-StrictMode -Version 2.0

function Get-WindowsCriticalEventClassification {
    param([Parameter(Mandatory=$true)]$Event)
    $provider = [string]$Event.ProviderName
    $message = [string]$Event.Message
    $id = [int]$Event.Id
    $category = ""
    $severity = ""
    if ($id -eq 55 -and $provider -match '(?i)ntfs|refs') {
        $category = "FILESYSTEM_CORRUPTION"; $severity = "CRIT"
    } elseif ($id -in @(7,11,15,51) -and $provider -match '(?i)disk|stor|scsi|ntfs') {
        $category = "STORAGE_ERROR"; $severity = "CRIT"
    } elseif ($id -in @(129,153) -and $provider -match '(?i)stor|disk|scsi') {
        $category = "STORAGE_RESET"; $severity = "WARN"
    } elseif (($id -eq 41 -and $provider -match '(?i)kernel-power') -or $id -eq 6008) {
        $category = "UNEXPECTED_SHUTDOWN"; $severity = "CRIT"
    } elseif ($provider -match '(?i)whea' -and $id -in @(1,18,20)) {
        $category = "HARDWARE_ERROR"; $severity = "CRIT"
    } elseif ($provider -match '(?i)whea' -and $id -in @(17,19)) {
        $category = "HARDWARE_WARNING"; $severity = "WARN"
    } elseif ($id -eq 2004 -and $provider -match '(?i)resource-exhaustion') {
        $category = "RESOURCE_EXHAUSTION"; $severity = "CRIT"
    } elseif ($id -in @(7031,7034) -and $provider -match '(?i)service control manager' -and $message -match '(?i)oracle|tns') {
        $category = "ORACLE_SERVICE_CRASH"; $severity = "CRIT"
    } elseif ($id -eq 1102) {
        $category = "AUDIT_LOG_CLEARED"; $severity = "CRIT"
    } elseif ($provider -match '(?i)time-service|w32time' -and $id -in @(29,34,36,47,50)) {
        $category = "TIME_SYNC"; $severity = "WARN"
    } elseif ($provider -match '(?i)volsnap' -and $id -in @(25,27,36)) {
        $category = "VOLUME_SNAPSHOT"; $severity = "WARN"
    } elseif (($provider -match '(?i)oracle' -or $message -match '(?i)OracleService|ORA-\d{5}|TNS-\d{5}') -and [int]$Event.Level -le 2) {
        $category = "ORACLE_APPLICATION"; $severity = "WARN"
    }
    if (-not $category) { return $null }
    return [pscustomobject]@{ Category=$category; Severity=$severity }
}

function Test-WindowsFirewallPortMatch {
    param([string]$PortSpec, [int]$Port)
    if (-not $PortSpec -or $PortSpec -in @("Any", "*")) { return $true }
    foreach ($part in ($PortSpec -split ',')) {
        $value = $part.Trim()
        if ($value -match '^\d+$' -and [int]$value -eq $Port) { return $true }
        if ($value -match '^(\d+)-(\d+)$' -and $Port -ge [int]$matches[1] -and $Port -le [int]$matches[2]) { return $true }
    }
    return $false
}

function Collect-WindowsHost {
    param([Parameter(Mandatory=$true)]$Context)
    $hostDir = Join-Path $Context.RawDir "host"
    New-Item -ItemType Directory -Force -Path $hostDir | Out-Null
    Write-CollectorLog -Context $Context -Message "开始采集 Windows 主机数据"

    Invoke-CollectionAction $Context "disk_usage.txt" {
        $rows = @()
        try {
            foreach ($disk in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop) {
                $total = [double]$disk.Size
                $free = [double]$disk.FreeSpace
                $used = [Math]::Max([double]0, [double]($total - $free))
                $pct = if ($total -gt 0) { [Math]::Round($used / $total * 100, 2) } else { 0 }
                $rows += ,@($disk.DeviceID, $disk.VolumeName, $disk.FileSystem,
                    [Math]::Round($total / 1GB, 2), [Math]::Round($used / 1GB, 2),
                    [Math]::Round($free / 1GB, 2), $pct)
            }
        } catch {
            foreach ($disk in [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady }) {
                $total = [double]$disk.TotalSize
                $free = [double]$disk.AvailableFreeSpace
                $used = [Math]::Max([double]0, [double]($total - $free))
                $pct = if ($total -gt 0) { [Math]::Round($used / $total * 100, 2) } else { 0 }
                $rows += ,@($disk.Name.TrimEnd('\'), $disk.VolumeLabel, $disk.DriveFormat,
                    [Math]::Round($total / 1GB, 2), [Math]::Round($used / 1GB, 2),
                    [Math]::Round($free / 1GB, 2), $pct)
            }
        }
        if (-not $rows) { throw "未发现可用的固定磁盘" }
        Write-PipeTable (Join-Path $hostDir "disk_usage.txt") @("VOLUME","LABEL","FILESYSTEM","TOTAL_GB","USED_GB","FREE_GB","USAGE_PCT") $rows
    }

    Invoke-CollectionAction $Context "cpu_metrics.txt" {
        $usage = ""
        $uptime = ""
        $count = [Environment]::ProcessorCount
        try {
            $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $usage = [Math]::Round([double]$cpu.PercentProcessorTime, 2)
            $uptime = [Math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
        } catch {
            try {
                $counter = Get-Counter '\Processor(_Total)\% Processor Time' -MaxSamples 1 -ErrorAction Stop
                $usage = [Math]::Round([double]$counter.CounterSamples[0].CookedValue, 2)
            } catch {}
        }
        Write-PipeTable (Join-Path $hostDir "cpu_metrics.txt") @("CPU_COUNT","CPU_USAGE_PCT","UPTIME_HOURS") @(
            ,@($count, $usage, $uptime)
        )
    }

    Invoke-CollectionAction $Context "memory_metrics.txt" {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $total = [Math]::Round([double]$os.TotalVisibleMemorySize / 1024, 0)
            $available = [Math]::Round([double]$os.FreePhysicalMemory / 1024, 0)
        } catch {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
            $info = New-Object Microsoft.VisualBasic.Devices.ComputerInfo
            $total = [Math]::Round([double]$info.TotalPhysicalMemory / 1MB, 0)
            $available = [Math]::Round([double]$info.AvailablePhysicalMemory / 1MB, 0)
        }
        $used = [Math]::Max([double]0, [double]($total - $available))
        $pct = if ($total -gt 0) { [Math]::Round($used / $total * 100, 2) } else { 0 }
        Write-PipeTable (Join-Path $hostDir "memory_metrics.txt") @("TOTAL_MB","AVAILABLE_MB","USED_MB","USAGE_PCT") @(
            ,@($total, $available, $used, $pct)
        )
    } -Optional

    Invoke-CollectionAction $Context "pagefile_metrics.txt" {
        $rows = @()
        foreach ($page in @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)) {
            $pct = if ([double]$page.AllocatedBaseSize -gt 0) {
                [Math]::Round([double]$page.CurrentUsage / [double]$page.AllocatedBaseSize * 100, 2)
            } else { 0 }
            $rows += ,@($page.Name, $page.AllocatedBaseSize, $page.CurrentUsage, $page.PeakUsage, $pct)
        }
        Write-PipeTable (Join-Path $hostDir "pagefile_metrics.txt") @("NAME","ALLOCATED_MB","USED_MB","PEAK_MB","USAGE_PCT") $rows
    } -Optional

    Invoke-CollectionAction $Context "disk_io.txt" {
        $rows = @()
        foreach ($disk in @(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop | Where-Object { $_.Name -ne "_Total" })) {
            $readMs = [Math]::Round([double]$disk.AvgDisksecPerRead * 1000, 2)
            $writeMs = [Math]::Round([double]$disk.AvgDisksecPerWrite * 1000, 2)
            $rows += ,@($disk.Name, $readMs, $writeMs, $disk.PercentDiskTime, $disk.DiskReadsPersec, $disk.DiskWritesPersec)
        }
        Write-PipeTable (Join-Path $hostDir "disk_io.txt") @("DISK","READ_LATENCY_MS","WRITE_LATENCY_MS","BUSY_PCT","READ_IOPS","WRITE_IOPS") $rows
    } -Optional

    Invoke-CollectionAction $Context "performance_samples.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        for ($sample = 1; $sample -le 10; $sample++) {
            $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            $system = Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop
            $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
            $paging = Get-CimInstance Win32_PerfFormattedData_PerfOS_PagingFile -Filter "Name='_Total'" -ErrorAction SilentlyContinue
            $disks = @(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "_Total" })
            if (-not $disks) { $disks = @($null) }
            foreach ($disk in $disks) {
                $rows.Add(@(
                    (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $sample,
                    [Math]::Round([double]$cpu.PercentProcessorTime, 2),
                    [Math]::Round([double]$cpu.PercentPrivilegedTime, 2),
                    [double]$system.ProcessorQueueLength,
                    [double]$memory.AvailableMBytes,
                    [double]$memory.PercentCommittedBytesInUse,
                    [double]$memory.PagesPersec,
                    $(if ($paging) { [double]$paging.PercentUsage } else { "" }),
                    $(if ($disk) { $disk.Name } else { "" }),
                    $(if ($disk) { [Math]::Round([double]$disk.AvgDisksecPerRead * 1000, 2) } else { "" }),
                    $(if ($disk) { [Math]::Round([double]$disk.AvgDisksecPerWrite * 1000, 2) } else { "" }),
                    $(if ($disk) { [double]$disk.CurrentDiskQueueLength } else { "" }),
                    $(if ($disk) { [double]$disk.PercentDiskTime } else { "" }),
                    $(if ($disk) { [double]$disk.DiskReadsPersec } else { "" }),
                    $(if ($disk) { [double]$disk.DiskWritesPersec } else { "" }),
                    $(if ($disk) { [Math]::Round([double]$disk.DiskReadBytesPersec / 1MB, 2) } else { "" }),
                    $(if ($disk) { [Math]::Round([double]$disk.DiskWriteBytesPersec / 1MB, 2) } else { "" })
                ))
            }
            if ($sample -lt 10) { Start-Sleep -Seconds 1 }
        }
        if ($rows.Count -eq 0) { throw "未获得 Windows 性能采样" }
        Write-PipeTable (Join-Path $hostDir "performance_samples.txt") @(
            "TIME","SAMPLE","CPU_TOTAL_PCT","CPU_PRIVILEGED_PCT","PROCESSOR_QUEUE_LENGTH",
            "AVAILABLE_MB","COMMITTED_PCT","PAGES_PER_SEC","PAGEFILE_PCT","DISK",
            "READ_LATENCY_MS","WRITE_LATENCY_MS","QUEUE_LENGTH","BUSY_PCT","READ_IOPS",
            "WRITE_IOPS","READ_MBPS","WRITE_MBPS"
        ) $rows
    } -Optional

    Invoke-CollectionAction $Context "login_metrics.txt" {
        $sessions = @(Get-CimInstance Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in @(2, 10, 11) })
        $since = (Get-Date).AddDays(-7)
        $failed = @()
        try { $failed = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$since} -MaxEvents 100 -ErrorAction Stop) } catch {
            if ($_.Exception.Message -notmatch '(?i)no events were found|找不到.*事件|没有.*事件') { throw }
        }
        Write-PipeTable (Join-Path $hostDir "login_metrics.txt") @("ACTIVE_SESSION_COUNT","FAILED_LOGIN_7D_SAMPLED") @(
            ,@($sessions.Count, $failed.Count)
        )
        $rows = foreach ($event in $failed) {
            ,@($event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $event.Id, $event.ProviderName, ($event.Message -replace "`r?`n", " "))
        }
        Write-PipeTable (Join-Path $hostDir "login_failed.txt") @("TIME","EVENT_ID","PROVIDER","MESSAGE") $rows
    } -Optional

    Invoke-CollectionAction $Context "firewall_profiles.txt" {
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { throw "Get-NetFirewallProfile 不可用" }
        $rows = foreach ($profile in Get-NetFirewallProfile -ErrorAction Stop) {
            ,@($profile.Name, $profile.Enabled, $profile.DefaultInboundAction, $profile.DefaultOutboundAction)
        }
        Write-PipeTable (Join-Path $hostDir "firewall_profiles.txt") @("PROFILE","ENABLED","INBOUND_ACTION","OUTBOUND_ACTION") $rows
    } -Optional

    Invoke-CollectionAction $Context "firewall_oracle_rules.txt" {
        if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { throw "Windows 防火墙命令不可用" }
        $processNames = @{}
        foreach ($process in Get-Process -ErrorAction SilentlyContinue) { $processNames[$process.Id] = $process.ProcessName }
        $endpoints = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
            [string]$processNames[$_.OwningProcess] -match '(?i)^(oracle|tnslsnr)'
        })
        $allowRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($endpoint in $endpoints) {
            $matched = $false
            foreach ($rule in $allowRules) {
                $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
                foreach ($portFilter in $portFilters) {
                    if ([string]$portFilter.Protocol -notin @("TCP", "6", "Any") -or
                        -not (Test-WindowsFirewallPortMatch ([string]$portFilter.LocalPort) ([int]$endpoint.LocalPort))) { continue }
                    $matched = $true
                    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | Select-Object -First 1
                    $remote = if ($addressFilter) { ([string[]]$addressFilter.RemoteAddress) -join "," } else { "Any" }
                    $exposure = if (-not $remote -or $remote -match '(?i)^(Any|\*|0\.0\.0\.0/0|::/0)(,|$)') { "ANY" } else { "SCOPED" }
                    $rows.Add(@($endpoint.LocalPort, $processNames[$endpoint.OwningProcess], $endpoint.LocalAddress,
                        $rule.DisplayName, $rule.Profile, $remote, $exposure))
                }
            }
            if (-not $matched) {
                $rows.Add(@($endpoint.LocalPort, $processNames[$endpoint.OwningProcess], $endpoint.LocalAddress,
                    "", "", "", "NO_EXPLICIT_ALLOW_RULE"))
            }
        }
        Write-PipeTable (Join-Path $hostDir "firewall_oracle_rules.txt") @(
            "PORT","PROCESS","LOCAL_ADDRESS","RULE_NAME","PROFILE","REMOTE_ADDRESS","EXPOSURE"
        ) $rows
    } -Optional

    Invoke-CollectionAction $Context "time_sync.txt" {
        $service = Get-Service W32Time -ErrorAction SilentlyContinue
        $source = "N/A"
        try { $source = (& w32tm.exe /query /source 2>&1 | Out-String).Trim() } catch {}
        $offsetMs = ""
        $statusText = ""
        try { $statusText = ((& w32tm.exe /query /status 2>&1 | Out-String) -replace "`r?`n", "; ").Trim() } catch {}
        if ($source -and $source -notmatch '(?i)N/A|local cmos|free-running|error|未同步') {
            try {
                $offsets = @()
                foreach ($line in @(& w32tm.exe /stripchart "/computer:$source" /samples:3 /dataonly 2>&1)) {
                    if ([string]$line -match '([+-]?\d+(?:[\.,]\d+)?)s') {
                        $offsets += [Math]::Abs([double]($matches[1] -replace ',', '.')) * 1000
                    }
                }
                if ($offsets.Count -gt 0) { $offsetMs = [Math]::Round(($offsets | Measure-Object -Average).Average, 2) }
            } catch {}
        }
        $zone = [System.TimeZoneInfo]::Local.Id
        Write-PipeTable (Join-Path $hostDir "time_sync.txt") @("LOCAL_TIME","TIMEZONE","SERVICE_STATUS","SOURCE","OFFSET_MS","STATUS_TEXT") @(
            ,@((Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"), $zone, $(if ($service) { $service.Status } else { "NotFound" }), $source, $offsetMs, $statusText)
        )
    }

    Invoke-CollectionAction $Context "network_listen.txt" {
        $processNames = @{}
        foreach ($process in Get-Process -ErrorAction SilentlyContinue) { $processNames[$process.Id] = $process.ProcessName }
        $rows = @()
        try {
            if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { throw "NetTCP cmdlet不可用" }
            foreach ($item in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
                $rows += ,@("TCP", $item.LocalAddress, $item.LocalPort, $item.State, $item.OwningProcess, $processNames[$item.OwningProcess])
            }
            foreach ($item in Get-NetUDPEndpoint -ErrorAction Stop) {
                $rows += ,@("UDP", $item.LocalAddress, $item.LocalPort, "LISTEN", $item.OwningProcess, $processNames[$item.OwningProcess])
            }
        } catch {
            foreach ($line in & netstat.exe -ano -p tcp) {
                if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)') {
                    $rows += ,@("TCP", $matches[1], $matches[2], "LISTEN", $matches[3], $processNames[[int]$matches[3]])
                }
            }
        }
        Write-PipeTable (Join-Path $hostDir "network_listen.txt") @("PROTOCOL","LOCAL_ADDRESS","LOCAL_PORT","STATE","PID","PROCESS") $rows
    } -Optional

    Invoke-CollectionAction $Context "event_log_errors.txt" {
        $since = (Get-Date).AddDays(-7)
        $events = @()
        try { $events = @(Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Level=@(1,2); StartTime=$since} -MaxEvents 100 -ErrorAction Stop) } catch {
            if ($_.Exception.Message -notmatch '(?i)no events were found|找不到.*事件|没有.*事件') { throw }
        }
        $rows = foreach ($event in $events) {
            ,@($event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $event.LogName, $event.Id, $event.LevelDisplayName,
                $event.ProviderName, ($event.Message -replace "`r?`n", " "))
        }
        Write-PipeTable (Join-Path $hostDir "event_log_errors.txt") @("TIME","LOG","EVENT_ID","LEVEL","PROVIDER","MESSAGE") $rows
    } -Optional

    Invoke-CollectionAction $Context "critical_events.txt" {
        $since = (Get-Date).AddDays(-7)
        $events = @()
        $queryErrors = New-Object System.Collections.Generic.List[string]
        try { $events += @(Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Level=@(1,2); StartTime=$since} -MaxEvents 500 -ErrorAction Stop) } catch {
            if ($_.Exception.Message -notmatch '(?i)no events were found|找不到.*事件|没有.*事件') { $queryErrors.Add("System/Application级别查询: $($_.Exception.Message)") }
        }
        try { $events += @(Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Id=@(7,11,15,25,27,29,34,36,41,47,50,51,55,129,153,2004,6008,7031,7034); StartTime=$since} -MaxEvents 500 -ErrorAction Stop) } catch {
            if ($_.Exception.Message -notmatch '(?i)no events were found|找不到.*事件|没有.*事件') { $queryErrors.Add("System/Application事件ID查询: $($_.Exception.Message)") }
        }
        try { $events += @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=1102; StartTime=$since} -MaxEvents 50 -ErrorAction Stop) } catch {
            if ($_.Exception.Message -notmatch '(?i)no events were found|找不到.*事件|没有.*事件') { $queryErrors.Add("Security审计清除查询: $($_.Exception.Message)") }
        }
        $seen = @{}
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($event in ($events | Sort-Object TimeCreated -Descending)) {
            $key = "{0}:{1}" -f $event.LogName, $event.RecordId
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $classification = Get-WindowsCriticalEventClassification $event
            if (-not $classification) { continue }
            $rows.Add(@($event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $classification.Category,
                $classification.Severity, $event.LogName, $event.ProviderName, $event.Id,
                ($event.Message -replace "`r?`n", " ")))
        }
        Write-PipeTable (Join-Path $hostDir "critical_events.txt") @(
            "TIME","CATEGORY","SEVERITY","LOG","PROVIDER","EVENT_ID","MESSAGE"
        ) $rows
        if ($queryErrors.Count -gt 0) { throw ($queryErrors -join "; ") }
    } -Optional

    Invoke-CollectionAction $Context "oracle_services.txt" {
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -like "Oracle*" -or $_.PathName -match "(?i)oracle" })
        $rows = foreach ($service in $services) {
            $recovery = ""
            try { $recovery = ((& sc.exe qfailure $service.Name 2>&1 | Out-String) -replace "`r?`n", "; ").Trim() } catch {}
            ,@($service.Name, $service.DisplayName, $service.State, $service.StartMode, $service.StartName,
                $service.ProcessId, $service.PathName, $service.ExitCode, $service.ServiceSpecificExitCode, $recovery)
        }
        Write-PipeTable (Join-Path $hostDir "oracle_services.txt") @(
            "NAME","DISPLAY_NAME","STATE","START_MODE","ACCOUNT","PID","PATH","EXIT_CODE","SERVICE_EXIT_CODE","RECOVERY_ACTIONS"
        ) $rows
    } -Optional

    Invoke-CollectionAction $Context "oracle_processes.txt" {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match '(?i)^(oracle|tnslsnr|asm|emagent)' })
        $perfById = @{}
        foreach ($perf in @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue)) {
            if ($perf.IDProcess) { $perfById[[int]$perf.IDProcess] = $perf }
        }
        $rows = foreach ($process in $processes) {
            $perf = $perfById[[int]$process.ProcessId]
            ,@($process.ProcessId, $process.Name, $process.ExecutablePath, $process.CommandLine,
                $(if ($perf) { [Math]::Round([double]$perf.PercentProcessorTime, 2) } else { "" }),
                $(if ($perf) { [Math]::Round([double]$perf.WorkingSet / 1MB, 2) } else { "" }),
                $(if ($perf) { [Math]::Round([double]$perf.WorkingSetPrivate / 1MB, 2) } else { "" }),
                $(if ($perf) { $perf.ThreadCount } else { "" }),
                $(if ($perf) { $perf.HandleCount } else { "" }),
                $(if ($perf) { [Math]::Round([double]$perf.ElapsedTime / 3600, 2) } else { "" }))
        }
        Write-PipeTable (Join-Path $hostDir "oracle_processes.txt") @(
            "PID","NAME","PATH","COMMAND_LINE","CPU_PCT","WORKING_SET_MB","PRIVATE_MB","THREADS","HANDLES","UPTIME_HOURS"
        ) $rows
    } -Optional

    Invoke-CollectionAction $Context "windows_maintenance.txt" {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ubr = ""
        try { $ubr = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop).UBR } catch {}
        $hotfix = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending | Select-Object -First 1
        $patchAge = ""
        if ($hotfix -and $hotfix.InstalledOn) { $patchAge = [Math]::Floor(((Get-Date) - [DateTime]$hotfix.InstalledOn).TotalDays) }
        $pendingReasons = New-Object System.Collections.Generic.List[string]
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReasons.Add('CBS') }
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReasons.Add('WINDOWS_UPDATE') }
        try {
            $rename = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
            if ($rename) { $pendingReasons.Add('PENDING_FILE_RENAME') }
        } catch {}
        Write-PipeTable (Join-Path $hostDir "windows_maintenance.txt") @(
            "CAPTION","VERSION","BUILD","UBR","LAST_HOTFIX","LAST_HOTFIX_DATE","PATCH_AGE_DAYS",
            "PENDING_REBOOT","PENDING_REASONS","LAST_BOOT_TIME"
        ) @(
            ,@($os.Caption, $os.Version, $os.BuildNumber, $ubr,
                $(if ($hotfix) { $hotfix.HotFixID } else { "" }),
                $(if ($hotfix) { ([DateTime]$hotfix.InstalledOn).ToString("yyyy-MM-dd") } else { "" }),
                $patchAge, ($pendingReasons.Count -gt 0), ($pendingReasons -join ","),
                ([DateTime]$os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss"))
        )
    } -Optional

    Write-CollectorLog -Context $Context -Message "Windows 主机数据采集完成"
}
