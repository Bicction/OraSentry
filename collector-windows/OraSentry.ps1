[CmdletBinding()]
param(
    [Alias("Host")][switch]$HostCheck,
    [Alias("Database")][switch]$DatabaseCheck,
    [switch]$All,
    [switch]$InteractiveLogin,
    [switch]$NoPack,
    [string]$ConfigFile = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$collectorRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $collectorRoot "lib\Common.ps1")
. (Join-Path $collectorRoot "lib\Package.ps1")
. (Join-Path $collectorRoot "lib\HostCheck.ps1")
. (Join-Path $collectorRoot "lib\Oracle.ps1")
. (Join-Path $collectorRoot "lib\DatabaseCheck.ps1")
. (Join-Path $collectorRoot "lib\SecurityCheck.ps1")

if (-not $ConfigFile) { $ConfigFile = Join-Path $collectorRoot "conf\check.psd1" }
if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { throw "配置文件不存在: $ConfigFile" }
$config = Import-PowerShellDataFile -LiteralPath $ConfigFile

if (-not $HostCheck -and -not $DatabaseCheck -and -not $All) { $All = $true }
$doHost = ($HostCheck -or $All) -and [bool]$config.CheckHost
$doDatabase = ($DatabaseCheck -or $All) -and [bool]$config.CheckDatabase
$overallExit = 0

Write-Host "============================================"
Write-Host "  OraSentry Windows Collector v4.3"
Write-Host "============================================"

if ($doHost) {
    $hostContext = Initialize-Collection -CheckType host -Config $config
    try {
        Collect-WindowsHost $hostContext
    } catch {
        Write-CollectorLog $hostContext "ERROR" $_.Exception.Message
        Add-CollectionManifest $hostContext "host_collection" "COLLECTOR" "FAILED" 1 $_.Exception.Message
    }
    if (-not (Complete-Collection $hostContext)) { $overallExit = 1 }
    if (-not $NoPack) {
        $safeHost = ([string]$env:COMPUTERNAME) -replace '[^A-Za-z0-9_.-]', '_'
        Pack-Collection $hostContext ("host_check_{0}_{1}.tar.gz" -f $safeHost, $hostContext.Timestamp) | Out-Null
    }
}

if ($doDatabase) {
    $sid = "UNKNOWN"
    try { $sid = Find-OracleSid $config } catch {
        # 仍创建可审计的失败采集包。
        $sid = if ($config.OracleSid) { [string]$config.OracleSid } else { "UNKNOWN" }
    }
    $dbContext = Initialize-Collection -CheckType db -Config $config -OracleSid $sid
    try {
        Initialize-OracleConnection $dbContext $config -InteractiveLogin:$InteractiveLogin
        Collect-WindowsDatabase $dbContext $config
        if ([bool]$config.CheckSecurity) { Collect-WindowsSecurity $dbContext $config }
    } catch {
        Write-CollectorLog $dbContext "ERROR" $_.Exception.Message
        Add-CollectionManifest $dbContext "database_environment" "COLLECTOR" "FAILED" 1 $_.Exception.Message
    }
    if (-not (Complete-Collection $dbContext)) { $overallExit = 1 }
    if (-not $NoPack) {
        $safeSid = ([string]$dbContext.OracleSid) -replace '[^A-Za-z0-9_.-]', '_'
        Pack-Collection $dbContext ("db_check_{0}_{1}.tar.gz" -f $safeSid, $dbContext.Timestamp) | Out-Null
    }
}

if (-not $doHost -and -not $doDatabase) {
    Write-Warning "配置中的主机和数据库采集均已关闭"
}

exit $overallExit
