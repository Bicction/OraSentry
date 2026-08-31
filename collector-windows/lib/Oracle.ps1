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
    if ($sids.Count -gt 1) { throw "检测到多个 Oracle SID（$($sids -join ', ')），请在 conf/check.psd1 中指定 ORACLE_SID" }
    throw "未检测到 Oracle SID，请在 conf/check.psd1 中指定 ORACLE_SID"
}

function Get-OracleHomeFromRegistryKey {
    param([Parameter(Mandatory=$true)][string]$Path)
    $values = Get-ItemProperty -LiteralPath $Path -Name ORACLE_HOME -ErrorAction SilentlyContinue
    if (-not $values) { return "" }
    $oracleHomeProperty = $values.PSObject.Properties["ORACLE_HOME"]
    if (-not $oracleHomeProperty -or -not $oracleHomeProperty.Value) { return "" }
    return [string]$oracleHomeProperty.Value
}

function Find-OracleHome {
    param([hashtable]$Config, [string]$OracleSid)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Config.OracleHome) { $candidates.Add([string]$Config.OracleHome) }
    $fromEnvironment = [Environment]::GetEnvironmentVariable("ORACLE_HOME", "Process")
    if ($fromEnvironment) { $candidates.Add($fromEnvironment) }

    # CMD 能直接运行 sqlplus 时，可能只配置了 PATH 而没有配置 ORACLE_HOME。
    $sqlPlusFromPath = Get-Command sqlplus.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($sqlPlusFromPath -and $sqlPlusFromPath.Source) {
        $sqlPlusPath = [string]$sqlPlusFromPath.Source
        $binDirectory = Split-Path -Parent $sqlPlusPath
        if ((Split-Path -Leaf $binDirectory) -ieq "bin") {
            $candidates.Add((Split-Path -Parent $binDirectory))
        }
    }

    foreach ($root in @("HKLM:\SOFTWARE\Oracle", "HKLM:\SOFTWARE\WOW6432Node\Oracle")) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem $root -ErrorAction SilentlyContinue) {
            $registryOracleHome = Get-OracleHomeFromRegistryKey $key.PSPath
            if ($registryOracleHome) { $candidates.Add($registryOracleHome) }
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
    throw "无法定位包含 bin\sqlplus.exe 的 Oracle Home，请在 conf/check.psd1 中指定 ORACLE_HOME"
}

function Initialize-OracleConnection {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][hashtable]$Config,
        [switch]$InteractiveLogin
    )
    $sid = if ($Context.OracleSid) { $Context.OracleSid } else { Find-OracleSid $Config }
    if ($sid -notmatch '^[A-Za-z0-9_.-]+$') { throw "OracleSid 包含不允许的字符" }
    $oracleHome = Find-OracleHome $Config $sid
    $Context.OracleSid = $sid
    $Context.OracleHome = $oracleHome
    $Context.SqlPlus = Join-Path $oracleHome "bin\sqlplus.exe"
    [Environment]::SetEnvironmentVariable("ORACLE_SID", $sid, "Process")
    [Environment]::SetEnvironmentVariable("ORACLE_HOME", $oracleHome, "Process")
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
        default { throw "数据库认证配置无效" }
    }

    Add-EnvironmentInfo $Context @(
        "oracle_sid=$sid",
        "oracle_home=$oracleHome",
        "db_auth=$($Context.AuthMode)"
    )
    Write-CollectorLog -Context $Context -Message "Oracle环境已初始化: SID=$sid, Home=$oracleHome, Auth=$($Context.AuthMode)"
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

function Get-SqlPlusErrorLines {
    param([AllowEmptyString()][string]$Text)
    return @(($Text -split "`r?`n") | Where-Object { $_ -match '^(ORA|SP2|TNS|LRM)-\d+' })
}

function Filter-SqlPlusStartupWarnings {
    param([AllowEmptyString()][string]$Text)
    $keptLines = New-Object System.Collections.Generic.List[string]
    $warningLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^(?i)SP2-0734:\s+unknown command beginning "[\uFEFF]?SET ECHO(?:\s|\.)') {
            $warningLines.Add($line)
        } else {
            $keptLines.Add($line)
        }
    }
    return [pscustomobject]@{
        Output = $keptLines -join "`r`n"
        Warnings = @($warningLines)
    }
}

function Register-SqlPlusStartupWarnings {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Warnings
    )
    if ($Warnings.Count -eq 0) { return }
    $warningPath = Join-Path $Context.RawDir "sqlplus_startup_warning.log"
    if (Test-Path -LiteralPath $warningPath) { return }
    Write-CollectorLines -Path $warningPath -Lines @(
        "SQL*Plus 启动脚本警告（已忽略，不影响 SQL 执行）：",
        $Warnings,
        "建议将 ORACLE_HOME\sqlplus\admin\glogin.sql 及用户 login.sql 保存为 UTF-8 无 BOM。"
    )
    $message = "SQL*Plus启动脚本的 SET ECHO 前含UTF-8 BOM，已忽略非致命SP2-0734；建议修复glogin.sql/login.sql编码"
    Write-CollectorLog -Context $Context -Level "WARN" -Message $message
    Add-CollectionManifest -Context $Context -Item "sqlplus_startup_profile" -Type "ENV" -Status "WARN" -ExitCode 0 -Message $message
}

function Write-SqlPlusDiagnostic {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][string]$OutputFile,
        [Parameter(Mandatory=$true)][string]$Sql,
        [Parameter(Mandatory=$true)][int]$ExitCode,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$ErrorLines,
        [AllowEmptyString()][string]$Output
    )
    $diagnosticPath = Join-Path $Context.RawDir "sqlplus_error.log"
    $safeSql = ($Sql -replace "`r?`n", " ").Trim()
    $lines = @(
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SQL*Plus failure",
        "output_file=$OutputFile",
        "exit_code=$ExitCode",
        "sql=$safeSql",
        "matched_errors=$(($ErrorLines -join ' | '))",
        "--- sqlplus output ---",
        $Output,
        "--- end sqlplus output ---",
        ""
    )
    [System.IO.File]::AppendAllText($diagnosticPath, ($lines -join "`r`n"), $script:Utf8NoBom)
}

function Write-Utf8NoBomProcessInput {
    param(
        [Parameter(Mandatory=$true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text
    )
    $cleanText = $Text.TrimStart([char]0xFEFF)
    $bytes = $script:Utf8NoBom.GetBytes($cleanText)
    $inputStream = $Process.StandardInput.BaseStream
    $inputStream.Write($bytes, 0, $bytes.Length)
    $inputStream.Flush()
    $inputStream.Close()
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
    Write-Utf8NoBomProcessInput -Process $process -Text $scriptText
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $combined = $stdout
    if ($stderr) { $combined += "`r`n" + $stderr }
    $filteredOutput = Filter-SqlPlusStartupWarnings $combined
    $startupWarnings = @($filteredOutput.Warnings)
    Register-SqlPlusStartupWarnings -Context $Context -Warnings $startupWarnings
    $combined = [string]$filteredOutput.Output
    Write-CollectorText -Path $OutputFile -Text $combined
    $errorLines = @(Get-SqlPlusErrorLines $combined)
    if ($process.ExitCode -ne 0 -or $errorLines.Count -gt 0) {
        Write-SqlPlusDiagnostic -Context $Context -OutputFile $OutputFile -Sql $Sql `
            -ExitCode $process.ExitCode -ErrorLines $errorLines -Output $combined
        $summary = if ($errorLines.Count -gt 0) {
            ($errorLines | Select-Object -First 5) -join " | "
        } else {
            (($combined -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) -join " ").Trim()
        }
        throw "SQL*Plus执行失败(rc=$($process.ExitCode)): $summary; 完整输出见 sqlplus_error.log"
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
