Set-StrictMode -Version 2.0

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

    Invoke-CollectionAction $Context "login_metrics.txt" {
        $sessions = @(Get-CimInstance Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in @(2, 10, 11) })
        $since = (Get-Date).AddDays(-7)
        $failed = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$since} -MaxEvents 100 -ErrorAction Stop)
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

    Invoke-CollectionAction $Context "time_sync.txt" {
        $service = Get-Service W32Time -ErrorAction SilentlyContinue
        $source = "N/A"
        try { $source = (& w32tm.exe /query /source 2>&1 | Out-String).Trim() } catch {}
        $zone = [System.TimeZoneInfo]::Local.Id
        Write-PipeTable (Join-Path $hostDir "time_sync.txt") @("LOCAL_TIME","TIMEZONE","SERVICE_STATUS","SOURCE") @(
            ,@((Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"), $zone, $(if ($service) { $service.Status } else { "NotFound" }), $source)
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
        $events = @(Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Level=@(1,2); StartTime=$since} -MaxEvents 100 -ErrorAction Stop)
        $rows = foreach ($event in $events) {
            ,@($event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $event.LogName, $event.Id, $event.LevelDisplayName,
                $event.ProviderName, ($event.Message -replace "`r?`n", " "))
        }
        Write-PipeTable (Join-Path $hostDir "event_log_errors.txt") @("TIME","LOG","EVENT_ID","LEVEL","PROVIDER","MESSAGE") $rows
    } -Optional

    Invoke-CollectionAction $Context "oracle_services.txt" {
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -like "Oracle*" -or $_.PathName -match "(?i)oracle" })
        $rows = foreach ($service in $services) {
            ,@($service.Name, $service.DisplayName, $service.State, $service.StartMode, $service.StartName, $service.ProcessId, $service.PathName)
        }
        Write-PipeTable (Join-Path $hostDir "oracle_services.txt") @("NAME","DISPLAY_NAME","STATE","START_MODE","ACCOUNT","PID","PATH") $rows
    } -Optional

    Invoke-CollectionAction $Context "oracle_processes.txt" {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match '(?i)^(oracle|tnslsnr|asm|emagent)' })
        $rows = foreach ($process in $processes) { ,@($process.ProcessId, $process.Name, $process.ExecutablePath, $process.CommandLine) }
        Write-PipeTable (Join-Path $hostDir "oracle_processes.txt") @("PID","NAME","PATH","COMMAND_LINE") $rows
    } -Optional

    Write-CollectorLog -Context $Context -Message "Windows 主机数据采集完成"
}
