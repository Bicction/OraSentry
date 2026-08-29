Set-StrictMode -Version 2.0

function Find-OracleSid {
    param([hashtable]$Config)
    if ($Config.OracleSid) { return [string]$Config.OracleSid }
    $fromEnvironment = [Environment]::GetEnvironmentVariable("ORACLE_SID", "Process")
    if ($fromEnvironment) { return $fromEnvironment }
    $sids = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^OracleService(.+)$' } |
        ForEach-Object { [regex]::Match($_.Name, '^OracleService(.+)$').Groups[1].Value } |
        Sort-Object -Unique)
    if ($sids.Count -eq 1) { return [string]$sids[0] }
    if ($sids.Count -gt 1) { throw "检测到多个 Oracle SID（$($sids -join ', ')），请在 conf/check.psd1 中指定 OracleSid" }
    throw "未检测到 Oracle SID，请在 conf/check.psd1 中指定 OracleSid"
}

function Find-OracleHome {
    param([hashtable]$Config, [string]$OracleSid)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Config.OracleHome) { $candidates.Add([string]$Config.OracleHome) }
    $fromEnvironment = [Environment]::GetEnvironmentVariable("ORACLE_HOME", "Process")
    if ($fromEnvironment) { $candidates.Add($fromEnvironment) }

    foreach ($root in @("HKLM:\SOFTWARE\Oracle", "HKLM:\SOFTWARE\WOW6432Node\Oracle")) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem $root -ErrorAction SilentlyContinue) {
            $home = (Get-ItemProperty $key.PSPath -Name ORACLE_HOME -ErrorAction SilentlyContinue).ORACLE_HOME
            if ($home) { $candidates.Add([string]$home) }
        }
    }

    $service = Get-CimInstance Win32_Service -Filter "Name='OracleService$OracleSid'" -ErrorAction SilentlyContinue
    if ($service -and $service.PathName) {
        $executable = [regex]::Match([string]$service.PathName, '^(?:"([^"]+)"|(\S+))').Groups |
            Select-Object -Skip 1 | Where-Object { $_.Value } | Select-Object -First 1
        if ($executable) {
            $path = [string]$executable.Value
            if ((Split-Path -Leaf $path) -ieq "oracle.exe") {
                $candidates.Add((Split-Path -Parent (Split-Path -Parent $path)))
            }
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate "bin\sqlplus.exe"))) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    throw "无法定位包含 bin\sqlplus.exe 的 Oracle Home，请在 conf/check.psd1 中指定 OracleHome"
}

function Initialize-OracleConnection {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][hashtable]$Config,
        [switch]$InteractiveLogin
    )
    $sid = if ($Context.OracleSid) { $Context.OracleSid } else { Find-OracleSid $Config }
    if ($sid -notmatch '^[A-Za-z0-9_.-]+$') { throw "OracleSid 包含不允许的字符" }
    $home = Find-OracleHome $Config $sid
    $Context.OracleSid = $sid
    $Context.OracleHome = $home
    $Context.SqlPlus = Join-Path $home "bin\sqlplus.exe"
    [Environment]::SetEnvironmentVariable("ORACLE_SID", $sid, "Process")
    [Environment]::SetEnvironmentVariable("ORACLE_HOME", $home, "Process")
    [Environment]::SetEnvironmentVariable("NLS_LANG", ".AL32UTF8", "Process")

    $mode = if ($InteractiveLogin) { "Interactive" } else { [string]$Config.AuthMode }
    switch ($mode.ToUpperInvariant()) {
        "OS" {
            $Context.AuthMode = "os"
        }
        "WALLET" {
            if (-not $Config.WalletAlias -or [string]$Config.WalletAlias -notmatch '^[A-Za-z0-9_.:-]+$') {
                throw "Wallet 模式需要有效的 WalletAlias"
            }
            $Context.AuthMode = "wallet"
            $Context.ConnectDescriptor = [string]$Config.WalletAlias
        }
        "INTERACTIVE" {
            $Context.AuthMode = "interactive_password"
            $Context.LoginUser = Read-Host "Oracle巡检账号"
            if ($Context.LoginUser -notmatch '^[A-Za-z][A-Za-z0-9_$#]*$') { throw "Oracle账号格式无效" }
            $hostName = Read-Host "数据库IP/主机名"
            $port = Read-Host "端口 [1521]"
            if (-not $port) { $port = "1521" }
            $connectType = Read-Host "连接类型 [SERVICE_NAME/SID，默认 SERVICE_NAME]"
            if (-not $connectType) { $connectType = "SERVICE_NAME" }
            $connectType = $connectType.ToUpperInvariant()
            $connectName = Read-Host "服务名/SID"
            $role = Read-Host "角色 [SYSDBA/SYSOPER/NORMAL，默认 SYSDBA]"
            if (-not $role) { $role = "SYSDBA" }
            $role = $role.ToUpperInvariant()
            if ($hostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]*$') { throw "数据库主机名格式无效" }
            if ($port -notmatch '^\d+$' -or [int]$port -lt 1 -or [int]$port -gt 65535) { throw "数据库端口无效" }
            if ($connectType -notin @("SERVICE_NAME","SID")) { throw "连接类型只支持 SERVICE_NAME 或 SID" }
            if ($connectName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw "服务名/SID格式无效" }
            if ($role -notin @("SYSDBA","SYSOPER","NORMAL")) { throw "数据库角色无效" }
            $Context.SecurePassword = Read-Host "密码" -AsSecureString
            $Context.ConnectDescriptor = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=$hostName)(PORT=$port))(CONNECT_DATA=($connectType=$connectName)))"
            $Context.LoginRole = $role
        }
        default { throw "AuthMode 只支持 OS、Wallet 或 Interactive" }
    }

    Add-EnvironmentInfo $Context @(
        "oracle_sid=$sid",
        "oracle_home=$home",
        "db_auth=$($Context.AuthMode)"
    )
    Write-CollectorLog -Context $Context -Message "Oracle环境已初始化: SID=$sid, Home=$home, Auth=$($Context.AuthMode)"
}

function Get-OracleConnectCommand {
    param([Parameter(Mandatory=$true)]$Context)
    switch ($Context.AuthMode) {
        "os" { return "CONNECT / AS SYSDBA" }
        "wallet" { return "CONNECT /@$($Context.ConnectDescriptor) AS SYSDBA" }
        "interactive_password" {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Context.SecurePassword)
            try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
            $quoted = $password.Replace('"', '""')
            $role = if ($Context.LoginRole -eq "NORMAL") { "" } else { " AS $($Context.LoginRole)" }
            return "CONNECT $($Context.LoginUser)/`"$quoted`"@$($Context.ConnectDescriptor)$role"
        }
        default { throw "Oracle认证模式尚未初始化" }
    }
}

function Invoke-OraSql {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][string]$OutputFile,
        [Parameter(Mandatory=$true)][string]$Sql
    )
    $connect = Get-OracleConnectCommand $Context
    $scriptText = @"
SET ECHO OFF
SET DEFINE OFF
WHENEVER OSERROR EXIT FAILURE ROLLBACK
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
$connect
SET LINESIZE 32767
SET PAGESIZE 50000
SET FEEDBACK OFF
SET HEADING ON
SET VERIFY OFF
SET TRIMSPOOL ON
SET COLSEP '|'
ALTER SESSION SET NLS_DATE_FORMAT='YYYY-MM-DD HH24:MI:SS';
$Sql
EXIT
"@
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Context.SqlPlus
    $info.Arguments = "-L -S /nolog"
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    try {
        $info.StandardInputEncoding = $script:Utf8NoBom
        $info.StandardOutputEncoding = $script:Utf8NoBom
        $info.StandardErrorEncoding = $script:Utf8NoBom
    } catch {
        # 旧版 .NET 缺少编码属性时退回系统控制台编码。
    }
    $info.EnvironmentVariables["ORACLE_SID"] = $Context.OracleSid
    $info.EnvironmentVariables["ORACLE_HOME"] = $Context.OracleHome
    $info.EnvironmentVariables["NLS_LANG"] = ".AL32UTF8"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw "无法启动 sqlplus.exe" }
    $process.StandardInput.Write($scriptText)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $combined = $stdout
    if ($stderr) { $combined += "`r`n" + $stderr }
    Write-CollectorText -Path $OutputFile -Text $combined
    if ($process.ExitCode -ne 0 -or $combined -match '(?m)^(ORA|SP2|TNS|LRM)-\d+') {
        $summary = (($combined -split "`r?`n" | Select-Object -Last 3) -join " ").Trim()
        throw "SQL*Plus执行失败(rc=$($process.ExitCode)): $summary"
    }
}

function Invoke-OraScalar {
    param([Parameter(Mandatory=$true)]$Context, [Parameter(Mandatory=$true)][string]$Sql)
    $temp = Join-Path $Context.RawDir ".oracle_probe_$PID.txt"
    try {
        Invoke-OraSql $Context $temp $Sql
        $lines = Get-Content -LiteralPath $temp -ErrorAction Stop |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -notmatch '^-' -and $_ -notmatch '^(Connected|Session altered)' }
        return [string]($lines | Select-Object -Last 1)
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Invoke-RegisteredSql {
    param($Context, [string]$Directory, [string]$Name, [string]$Sql, [switch]$Optional)
    $path = Join-Path $Directory $Name
    Invoke-CollectionAction -Context $Context -Item $Name -Type "SQL" -Optional:$Optional -Action {
        Invoke-OraSql $Context $path $Sql
    }
}

function Skip-SqlCollection {
    param($Context, [string]$Directory, [string]$Name, [string]$Header, [string]$Reason)
    Write-CollectorLines (Join-Path $Directory $Name) @($Header)
    Add-CollectionManifest $Context $Name "SQL" "SKIPPED" 0 $Reason
}
