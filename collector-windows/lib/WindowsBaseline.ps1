Set-StrictMode -Version 2.0

# Phase 2: read-only, optional collectors. No policy, service or cluster changes.
function Get-BaselineProperty {
    param($Object, [string]$Name, $Default = "")
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Get-BaselineRegistryValue {
    param([string]$Path, [string]$Name, $Default = "")
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $Default }
    return Get-BaselineProperty (Get-ItemProperty -LiteralPath $Path -ErrorAction Stop) $Name $Default
}

function Get-NetworkCounterDelta {
    param($Before, $After, [string[]]$Names)
    [decimal]$total = 0
    foreach ($name in $Names) {
        $left = Get-BaselineProperty $Before $name $null
        $right = Get-BaselineProperty $After $name $null
        if ($null -eq $left -or $null -eq $right -or [decimal]$right -lt [decimal]$left) { return $null }
        $total += [decimal]$right - [decimal]$left
    }
    return $total
}

function Collect-WindowsNetworkBaseline {
    param($Context)
    $hostDir = Join-Path $Context.RawDir "host"
    Invoke-CollectionAction $Context "network_config.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
        $ipConfig = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop)
        foreach ($adapter in $adapters) {
            $cfg = $ipConfig | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -First 1
            $rows.Add(@("ADAPTER", $adapter.ifIndex, $adapter.Name, [string]$adapter.Status,
                $adapter.LinkSpeed, ((Get-BaselineProperty $cfg "IPAddress" @()) -join ","), "", ""))
        }
        foreach ($dns in @(Get-DnsClientServerAddress -ErrorAction Stop)) {
            if (@($dns.ServerAddresses).Count -gt 0) {
                $rows.Add(@("DNS", $dns.InterfaceIndex, $dns.InterfaceAlias, "", "", ($dns.ServerAddresses -join ","), "", ""))
            }
        }
        foreach ($route in @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @("0.0.0.0/0", "::/0") })) {
            $routeState = [string](Get-BaselineProperty $route "State" "")
            $rows.Add(@("DEFAULT_ROUTE", $route.InterfaceIndex, $route.InterfaceAlias, $routeState,
                "", $route.DestinationPrefix, $route.NextHop, $route.RouteMetric))
        }
        Write-PipeTable (Join-Path $hostDir "network_config.txt") @("KIND","IF_INDEX","NAME","STATE","LINK_SPEED","ADDRESS","NEXT_HOP","METRIC") $rows.ToArray()
    } -Optional

    Invoke-CollectionAction $Context "network_quality.txt" {
        $first = @{}
        foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" })) {
            $first[[string]$adapter.InterfaceGuid] = @($adapter, ($adapter | Get-NetAdapterStatistics -ErrorAction Stop))
        }
        $tcpFirst = @{}
        foreach ($family in @("TCPv4", "TCPv6")) {
            $tcpFirst[$family] = Get-CimInstance ("Win32_PerfRawData_Tcpip_" + $family) -ErrorAction Stop
        }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Seconds 5
        $elapsed = $watch.Elapsed.TotalSeconds
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop)) {
            $key = [string]$adapter.InterfaceGuid
            if (-not $first.ContainsKey($key)) { continue }
            $before = $first[$key][1]
            $after = $adapter | Get-NetAdapterStatistics -ErrorAction Stop
            $packets = Get-NetworkCounterDelta $before $after @("ReceivedUnicastPackets","ReceivedMulticastPackets","ReceivedBroadcastPackets","SentUnicastPackets","SentMulticastPackets","SentBroadcastPackets")
            $errors = Get-NetworkCounterDelta $before $after @("ReceivedPacketErrors","OutboundPacketErrors")
            $drops = Get-NetworkCounterDelta $before $after @("ReceivedDiscardedPackets","OutboundDiscardedPackets")
            $received = Get-NetworkCounterDelta $before $after @("ReceivedBytes")
            $sent = Get-NetworkCounterDelta $before $after @("SentBytes")
            $valid = $null -ne $packets -and $null -ne $errors -and $null -ne $drops -and $null -ne $received -and $null -ne $sent
            $state = if ($valid -and $adapter.Status -eq "Up") { "VALID" } else { "RESET_OR_UNAVAILABLE" }
            $rows.Add(@("NIC", $adapter.Name, $elapsed.ToString("F3", [Globalization.CultureInfo]::InvariantCulture),
                $packets, $errors, $drops, $received, $sent, "", "", $state))
        }
        foreach ($family in @("TCPv4", "TCPv6")) {
            $after = Get-CimInstance ("Win32_PerfRawData_Tcpip_" + $family) -ErrorAction Stop
            $sent = Get-NetworkCounterDelta $tcpFirst[$family] $after @("SegmentsSentPersec")
            $retrans = Get-NetworkCounterDelta $tcpFirst[$family] $after @("SegmentsRetransmittedPersec")
            $state = if ($null -ne $sent -and $null -ne $retrans) { "VALID" } else { "RESET_OR_UNAVAILABLE" }
            $rows.Add(@("TCP", $family, $elapsed.ToString("F3", [Globalization.CultureInfo]::InvariantCulture), "", "", "", "", "", $sent, $retrans, $state))
        }
        Write-PipeTable (Join-Path $hostDir "network_quality.txt") @("KIND","NAME","SECONDS","PACKETS","ERRORS","DISCARDS","RX_BYTES","TX_BYTES","TCP_SENT","TCP_RETRANS","COUNTER_STATE") $rows.ToArray()
    } -Optional
}

function Collect-WindowsProtection {
    param($Context)
    $path = Join-Path $Context.RawDir "host\endpoint_protection.txt"
    Invoke-CollectionAction $Context "endpoint_protection.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        $failures = New-Object System.Collections.Generic.List[string]
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            try {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                if ($null -eq $mp) { throw "Defender returned no status" }
                $updated = Get-BaselineProperty $mp "AntivirusSignatureLastUpdated" $null
                $age = if ($updated -and ([datetime]$updated).Year -gt 2000) { [math]::Floor(((Get-Date) - [datetime]$updated).TotalDays) } else { "" }
                $rows.Add(@("DEFENDER", "Microsoft Defender", (Get-BaselineProperty $mp "AMRunningMode" "Unknown"),
                    $mp.AMServiceEnabled, $mp.AntivirusEnabled, $mp.RealTimeProtectionEnabled,
                    $mp.AntivirusSignatureVersion, $updated, $age, "OBSERVED"))
            } catch { $failures.Add($_.Exception.Message); $rows.Add(@("DEFENDER","Microsoft Defender","", "", "", "", "", "", "", "QUERY_FAILED")) }
        } else { $rows.Add(@("DEFENDER","Microsoft Defender","", "", "", "", "", "", "", "NOT_AVAILABLE")) }
        $sense = Get-CimInstance Win32_Service -Filter "Name='Sense'" -ErrorAction Stop
        $rows.Add(@("EDR_SERVICE", "Sense", $(if ($sense) { $sense.State } else { "NotInstalled" }), "", "", "", "", "", "", "INVENTORY_ONLY"))
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType -eq 1) {
            try {
                foreach ($av in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)) {
                    $rows.Add(@("REGISTERED_AV", $av.displayName, $av.productState, "", "", "", "", "", "", "INVENTORY_ONLY"))
                }
            } catch { $failures.Add($_.Exception.Message) }
        }
        Write-PipeTable $path @("KIND","PRODUCT","MODE","SERVICE_ENABLED","ANTIVIRUS_ENABLED","REALTIME_ENABLED","SIGNATURE_VERSION","SIGNATURE_UPDATED","SIGNATURE_AGE_DAYS","EVIDENCE") $rows.ToArray()
        if ($failures.Count) { throw ($failures -join "; ") }
    } -Optional
}

function Collect-WindowsPrivilegedGroups {
    param($Context)
    Invoke-CollectionAction $Context "privileged_groups.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        $failures = New-Object System.Collections.Generic.List[string]
        $groups = @(Get-CimInstance Win32_Group -Filter "LocalAccount=True" -ErrorAction Stop | Where-Object {
            $_.SID -eq "S-1-5-32-544" -or $_.Name -match '^ORA_(.*_)?(DBA|OPER)$'
        })
        foreach ($group in $groups) {
            try {
                $members = @(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser -ErrorAction Stop)
                if (-not $members.Count) { $rows.Add(@($group.Name, $group.SID, "", "", "", "EMPTY")) }
                foreach ($member in $members) {
                    $rows.Add(@($group.Name, $group.SID, ($member.Domain + "\" + $member.Name), $member.SID, $member.CimClass.CimClassName, "OBSERVED"))
                }
            } catch { $failures.Add($group.Name); $rows.Add(@($group.Name, $group.SID, "", "", "", "QUERY_FAILED")) }
        }
        Write-PipeTable (Join-Path $Context.RawDir "host\privileged_groups.txt") @("GROUP","GROUP_SID","MEMBER","MEMBER_SID","MEMBER_TYPE","EVIDENCE") $rows.ToArray()
        if ($failures.Count) { throw ("Group membership query failed: " + ($failures -join ",")) }
    } -Optional
}

function Initialize-AuditReader {
    if ("OraSentry.NativeAuditReader" -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace OraSentry {
  public static class NativeAuditReader {
    [StructLayout(LayoutKind.Sequential)]
    struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    struct Privileges { public uint Count; public Luid Id; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    public struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.U1)]
    static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr policies);
    [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool LookupPrivilegeValue(string system, string name, out Luid id);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref Privileges state,
      uint length, out Privileges previous, out uint returned);
    public static uint Read(string id) {
      // Enable an already-assigned privilege only in this process, restoring it
      // immediately. This cannot grant a privilege absent from the caller token.
      IntPtr token;
      if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      Privileges previous = new Privileges(); bool adjusted = false;
      try {
        Luid luid;
        if (LookupPrivilegeValue(null, "SeSecurityPrivilege", out luid)) {
          Privileges state = new Privileges { Count=1, Id=luid, Attributes=2 }; uint returned;
          adjusted = AdjustTokenPrivileges(token, false, ref state,
            (uint)Marshal.SizeOf(typeof(Privileges)), out previous, out returned);
        }
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(new Guid[] {new Guid(id)}, 1, out buffer))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return ((Policy)Marshal.PtrToStructure(buffer, typeof(Policy))).Flags; }
        finally { AuditFree(buffer); }
      } finally {
        if (adjusted) { Privileges ignored; uint returned;
          AdjustTokenPrivileges(token, false, ref previous,
            (uint)Marshal.SizeOf(typeof(Privileges)), out ignored, out returned); }
        CloseHandle(token);
      }
    }
  }
}
'@ -ErrorAction Stop
}

function Collect-WindowsAuditPolicy {
    param($Context)
    Invoke-CollectionAction $Context "windows_audit_policy.txt" {
        Initialize-AuditReader
        $categories = [ordered]@{
            "Logon" = "0cce9215-69ae-11d9-bed3-505054503030"
            "AuditPolicyChange" = "0cce922f-69ae-11d9-bed3-505054503030"
            "UserAccountManagement" = "0cce9235-69ae-11d9-bed3-505054503030"
            "SecurityGroupManagement" = "0cce9237-69ae-11d9-bed3-505054503030"
        }
        $rows = foreach ($entry in $categories.GetEnumerator()) {
            $flags = [OraSentry.NativeAuditReader]::Read($entry.Value)
            ,@($entry.Key, $entry.Value, (($flags -band 1) -ne 0), (($flags -band 2) -ne 0), $flags)
        }
        Write-PipeTable (Join-Path $Context.RawDir "host\windows_audit_policy.txt") @("SUBCATEGORY","GUID","SUCCESS","FAILURE","FLAGS") $rows
    } -Optional
}

function Collect-WindowsCluster {
    param($Context)
    Invoke-CollectionAction $Context "windows_cluster.txt" {
        $rows = New-Object System.Collections.Generic.List[object]
        try {
        $service = Get-CimInstance Win32_Service -Filter "Name='ClusSvc'" -ErrorAction Stop
        if (-not $service) {
            $rows.Add(@("CLUSTER", "", "NOT_INSTALLED", "", "Windows Failover Cluster service not installed"))
        } elseif (-not (Test-Path -LiteralPath "HKLM:\Cluster" -ErrorAction Stop)) {
            $rows.Add(@("CLUSTER", "", "NOT_CONFIGURED", "", "ClusSvc installed but no local cluster configuration"))
        } else {
            $rows.Add(@("SERVICE", "ClusSvc", $service.State, "", ""))
            # Persist service evidence before optional management module/API calls.
            Write-PipeTable (Join-Path $Context.RawDir "host\windows_cluster.txt") @("KIND","NAME","STATE","OWNER","DETAIL") $rows.ToArray()
            Import-Module FailoverClusters -ErrorAction Stop
            $cluster = Get-Cluster -ErrorAction Stop
            $rows.Add(@("CLUSTER", $cluster.Name, "CONFIGURED", "", ""))
            foreach ($node in @(Get-ClusterNode -Cluster $cluster.Name -ErrorAction Stop)) {
                $rows.Add(@("NODE", $node.Name, [string]$node.State, "", "NodeWeight=" + $node.NodeWeight))
            }
            foreach ($group in @(Get-ClusterGroup -Cluster $cluster.Name -ErrorAction Stop)) {
                $rows.Add(@("GROUP", $group.Name, [string]$group.State, [string]$group.OwnerNode, ""))
            }
            foreach ($resource in @(Get-ClusterResource -Cluster $cluster.Name -ErrorAction Stop)) {
                $rows.Add(@("RESOURCE", $resource.Name, [string]$resource.State, [string]$resource.OwnerGroup, [string]$resource.ResourceType))
            }
            foreach ($network in @(Get-ClusterNetwork -Cluster $cluster.Name -ErrorAction Stop)) {
                $rows.Add(@("NETWORK", $network.Name, [string]$network.State, "", [string]$network.Role))
            }
            $quorum = Get-ClusterQuorum -Cluster $cluster.Name -ErrorAction Stop
            $witness = Get-BaselineProperty $quorum "QuorumResource" $null
            $rows.Add(@("QUORUM", [string]$quorum.QuorumType, $(if ($witness) { [string]$witness.State } else { "NO_WITNESS" }), "", [string]$witness))
        }
        } finally {
            Write-PipeTable (Join-Path $Context.RawDir "host\windows_cluster.txt") @("KIND","NAME","STATE","OWNER","DETAIL") $rows.ToArray()
        }
    } -Optional
}

function Collect-WindowsBaseline {
    param($Context)
    Collect-WindowsNetworkBaseline $Context
    Collect-WindowsProtection $Context
    Collect-WindowsPrivilegedGroups $Context
    Collect-WindowsAuditPolicy $Context
    Collect-WindowsCluster $Context
}
