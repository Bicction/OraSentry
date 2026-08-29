Set-StrictMode -Version 2.0

$script:CollectorVersion = "4.3.0"
$script:SchemaVersion = "4.3"
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-CollectorText {
    param([Parameter(Mandatory=$true)][string]$Path, [AllowEmptyString()][string]$Text)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

function Write-CollectorLines {
    param([Parameter(Mandatory=$true)][string]$Path, [object[]]$Lines)
    $text = if ($Lines) { ($Lines | ForEach-Object { [string]$_ }) -join "`r`n" } else { "" }
    if ($text) { $text += "`r`n" }
    Write-CollectorText -Path $Path -Text $text
}

function ConvertTo-SafeField {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value).Replace("|", "/").Replace("`t", " ").Replace("`r", " ").Replace("`n", " ")
}

function Write-PipeTable {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$Headers,
        [object[]]$Rows
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((($Headers | ForEach-Object { ConvertTo-SafeField $_ }) -join "|"))
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $values = if ($row -is [System.Array]) { $row } else { @($row) }
        $lines.Add((($values | ForEach-Object { ConvertTo-SafeField $_ }) -join "|"))
    }
    Write-CollectorLines -Path $Path -Lines $lines
}

function Write-CollectorLog {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO",
        [Parameter(Mandatory=$true)][string]$Message
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    [System.IO.File]::AppendAllText($Context.LogFile, $line + "`r`n", $script:Utf8NoBom)
}

function Add-CollectionManifest {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][string]$Item,
        [Parameter(Mandatory=$true)][string]$Type,
        [Parameter(Mandatory=$true)][ValidateSet("OK","WARN","FAILED","SKIPPED")][string]$Status,
        [int]$ExitCode = 0,
        [string]$Message = ""
    )
    $safeMessage = ConvertTo-SafeField $Message
    $line = "{0}`t{1}`t{2}`t{3}`t{4}`r`n" -f (ConvertTo-SafeField $Item), $Type, $Status, $ExitCode, $safeMessage
    [System.IO.File]::AppendAllText($Context.ManifestFile, $line, $script:Utf8NoBom)
    if ($Status -eq "FAILED") { $Context.Failures++ }
    if ($Status -eq "WARN") { $Context.Warnings++ }
}

function Invoke-CollectionAction {
    param(
        [Parameter(Mandatory=$true)]$Context,
        [Parameter(Mandatory=$true)][string]$Item,
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [string]$Type = "COMMAND",
        [switch]$Optional
    )
    try {
        & $Action | Out-Null
        Add-CollectionManifest -Context $Context -Item $Item -Type $Type -Status "OK"
        return
    } catch {
        $message = $_.Exception.Message
        if ($Optional) {
            Write-CollectorLog -Context $Context -Level "WARN" -Message "$Item 不可用: $message"
            Add-CollectionManifest -Context $Context -Item $Item -Type $Type -Status "WARN" -ExitCode 1 -Message $message
            return
        }
        Write-CollectorLog -Context $Context -Level "ERROR" -Message "$Item 采集失败: $message"
        Add-CollectionManifest -Context $Context -Item $Item -Type $Type -Status "FAILED" -ExitCode 1 -Message $message
        return
    }
}

function Get-PrimaryIPv4 {
    try {
        $address = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -and $_.IPAddress } |
            ForEach-Object { $_.IPAddress } |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' } |
            Select-Object -First 1
        if ($address) { return [string]$address }
    } catch {}
    return "N/A"
}

function Initialize-Collection {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("host","db")][string]$CheckType,
        [Parameter(Mandatory=$true)][hashtable]$Config,
        [string]$OracleSid = ""
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $collectorRoot = Split-Path -Parent $PSScriptRoot
    $rawSetting = [string]$Config.RawDataDir
    if ([System.IO.Path]::IsPathRooted($rawSetting)) {
        $rawBase = [System.IO.Path]::GetFullPath($rawSetting)
    } else {
        $rawBase = [System.IO.Path]::GetFullPath((Join-Path $collectorRoot $rawSetting))
    }
    New-Item -ItemType Directory -Force -Path $rawBase | Out-Null
    $rawDir = Join-Path $rawBase $timestamp
    if (Test-Path -LiteralPath $rawDir) {
        $timestamp = "{0}_{1}" -f $timestamp, $PID
        $rawDir = Join-Path $rawBase $timestamp
    }
    New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

    $context = [pscustomobject]@{
        CheckType = $CheckType
        Timestamp = $timestamp
        CollectorRoot = $collectorRoot
        RawBase = $rawBase
        RawDir = $rawDir
        LogFile = Join-Path $rawDir "collect.log"
        ManifestFile = Join-Path $rawDir "collection_manifest.tsv"
        Failures = 0
        Warnings = 0
        OracleSid = $OracleSid
        OracleHome = ""
        AuthMode = ""
        SqlPlus = ""
        SecurePassword = $null
        LoginUser = ""
        ConnectDescriptor = ""
        LoginRole = "SYSDBA"
        PackageFile = ""
    }
    Write-CollectorText -Path $context.LogFile -Text ""
    Write-CollectorText -Path $context.ManifestFile -Text "item`ttype`tstatus`texit_code`tmessage`r`n"

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osCaption = if ($os) { "{0} {1}" -f $os.Caption, $os.Version } else { [Environment]::OSVersion.VersionString }
    $envLines = @(
        "schema_version=$script:SchemaVersion",
        "collector_version=$script:CollectorVersion",
        "data_classification=confidential",
        "platform=windows",
        "platform_family=windows",
        "hostname=$env:COMPUTERNAME",
        "server_ip=$(Get-PrimaryIPv4)",
        "os=$osCaption",
        "kernel=$([Environment]::OSVersion.Version)",
        "powershell_version=$($PSVersionTable.PSVersion)",
        "timestamp=$timestamp",
        "check_type=$CheckType",
        "debug=$($Config.Debug)",
        "report_footer=$($Config.ReportFooter)"
    )
    if ($OracleSid) { $envLines += "oracle_sid=$OracleSid" }
    Write-CollectorLines -Path (Join-Path $rawDir "env.info") -Lines $envLines
    Write-CollectorLog -Context $context -Message "初始化 Windows $CheckType 采集目录: $rawDir"
    return $context
}

function Add-EnvironmentInfo {
    param([Parameter(Mandatory=$true)]$Context, [Parameter(Mandatory=$true)][string[]]$Lines)
    $path = Join-Path $Context.RawDir "env.info"
    $text = ($Lines -join "`r`n") + "`r`n"
    [System.IO.File]::AppendAllText($path, $text, $script:Utf8NoBom)
}

function Complete-Collection {
    param([Parameter(Mandatory=$true)]$Context)
    Add-EnvironmentInfo -Context $Context -Lines @(
        "collection_failures=$($Context.Failures)",
        "collection_warnings=$($Context.Warnings)",
        "collection_completed_at=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    )
    if ($Context.Failures -gt 0) {
        Write-CollectorLog -Context $Context -Level "ERROR" -Message "采集存在 $($Context.Failures) 个失败项，详见 collection_manifest.tsv"
        return $false
    }
    Write-CollectorLog -Context $Context -Message "采集完整性校验通过"
    return $true
}
