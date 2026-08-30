[CmdletBinding()]
param(
    [switch]$Elevated,
    [switch]$NoPause
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$collectorRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Wait-OraSentryExit {
    if (-not $NoPause) {
        [void](Read-Host "按 Enter 键关闭窗口")
    }
}

try {
    if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
        throw "需要 Windows PowerShell 5.1 或更高版本"
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) {
        Write-Host "正在申请管理员权限，请在 UAC 窗口中选择“是”..."
        $escapedPath = $PSCommandPath.Replace('"', '""')
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated' -f $escapedPath
        if ($NoPause) { $arguments += ' -NoPause' }
        $process = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arguments -Wait -PassThru
        exit $process.ExitCode
    }

    $configFile = Join-Path $collectorRoot "conf\check.psd1"
    if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
        throw "配置文件不存在: $configFile"
    }
    . (Join-Path $collectorRoot "lib\Common.ps1")
    $config = ConvertTo-CollectorConfig (Import-PowerShellDataFile -LiteralPath $configFile)

    Write-Host "============================================"
    Write-Host "  OraSentry Windows 一键巡检"
    Write-Host "============================================"
    Write-Host "配置文件: $configFile"
    Write-Host ("采集范围: 主机={0}, 数据库={1}, 安全={2}" -f $config.CheckHost, $config.CheckDatabase, $config.CheckSecurity)
    Write-Host ("数据库认证: {0}" -f $config.AuthMode)
    Write-Host ""

    $outputRoot = if ([IO.Path]::IsPathRooted($config.RawDataDir)) {
        [IO.Path]::GetFullPath($config.RawDataDir)
    } else {
        [IO.Path]::GetFullPath((Join-Path $collectorRoot $config.RawDataDir))
    }
    $before = @()
    if (Test-Path -LiteralPath $outputRoot) {
        $before = @(Get-ChildItem -LiteralPath $outputRoot -Filter "*.tar.gz" -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName })
    }

    $powerShellExe = Join-Path $PSHOME "powershell.exe"
    & $powerShellExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $collectorRoot "OraSentry.ps1") -All -ConfigFile $configFile
    $collectorExitCode = $LASTEXITCODE

    $created = @()
    if (Test-Path -LiteralPath $outputRoot) {
        $created = @(Get-ChildItem -LiteralPath $outputRoot -Filter "*.tar.gz" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notin $before } |
            Sort-Object LastWriteTime)
    }

    Write-Host ""
    Write-Host "============================================"
    if ($collectorExitCode -eq 0) {
        Write-Host "巡检完成。" -ForegroundColor Green
    } else {
        Write-Host "巡检已结束，但存在失败项，请查看 collect.log 和 collection_manifest.tsv。" -ForegroundColor Yellow
    }
    if ($created.Count -gt 0) {
        Write-Host "新生成的采集包："
        foreach ($archive in $created) { Write-Host "  $($archive.FullName)" }
    } else {
        Write-Host "本次未发现新采集包。"
    }
    Write-Host "============================================"
    Wait-OraSentryExit
    exit $collectorExitCode
} catch {
    Write-Host ""
    Write-Host "启动巡检失败: $($_.Exception.Message)" -ForegroundColor Red
    Wait-OraSentryExit
    exit 1
}
