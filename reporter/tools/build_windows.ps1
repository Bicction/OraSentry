# Build the Windows one-file GUI exe.
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\build_windows.ps1

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$Python = $null
foreach ($candidate in @("python", "py")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) {
        $Python = $cmd.Source
        break
    }
}
if (-not $Python) {
    throw "Python not found. Install Python 3.8+ and add it to PATH."
}

Write-Host "Using Python: $Python"
& $Python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.8+ is required."
}

$Spec = Join-Path $ProjectRoot "tools\oracle_report.spec"
$Dist = Join-Path $ProjectRoot "dist"
$Work = Join-Path $ProjectRoot "build"
$StagedDist = Join-Path $Work ("dist-staging-" + [guid]::NewGuid().ToString("N"))

# 将 Tcl/Tk 脚本暂存到项目构建目录。部分受限环境可以加载 _tkinter，
# 但 Tcl 无法直接读取 Python 安装目录，PyInstaller 会静默排除 GUI。
$PythonPrefixOutput = & $Python -c 'import sys; print(sys.base_prefix)'
if ($LASTEXITCODE -eq 0 -and $PythonPrefixOutput) {
    $PythonPrefix = ([string]$PythonPrefixOutput).Trim()
} else {
    $PythonPrefix = Split-Path -Parent $Python
}
$TclSource = Join-Path $PythonPrefix "tcl"
$TclLibrary = Get-ChildItem -LiteralPath $TclSource -Directory -Filter "tcl8.*" -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName "init.tcl") } |
    Select-Object -First 1
$TkLibrary = Get-ChildItem -LiteralPath $TclSource -Directory -Filter "tk8.*" -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName "tk.tcl") } |
    Select-Object -First 1
if (-not $TclLibrary -or -not $TkLibrary) {
    throw "A complete Tcl/Tk runtime is required to build the OracleReport GUI."
}

$TclRuntime = Join-Path $Work "tcl-runtime"
New-Item -ItemType Directory -Path $TclRuntime -Force | Out-Null
Copy-Item -LiteralPath $TclLibrary.FullName -Destination $TclRuntime -Recurse -Force
Copy-Item -LiteralPath $TkLibrary.FullName -Destination $TclRuntime -Recurse -Force
$env:TCL_LIBRARY = Join-Path $TclRuntime $TclLibrary.Name
$env:TK_LIBRARY = Join-Path $TclRuntime $TkLibrary.Name

Write-Host "Checking Tcl/Tk runtime..."
& $Python -c 'import tkinter as tk; tk.Tcl()'
if ($LASTEXITCODE -ne 0) {
    throw "Tcl/Tk runtime check failed. Refusing to build an EXE without its GUI."
}
Write-Host "Tcl/Tk OK."

Write-Host "Installing pinned report and build dependencies..."
& $Python -m pip install -r (Join-Path $ProjectRoot "requirements.txt") -r (Join-Path $ProjectRoot "requirements-build.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

Write-Host "Building exe..."
try {
    # PyInstaller --noconfirm clears its dist path. Use a dedicated staging
    # directory so diagnostic packages placed in reporter/dist are preserved.
    & $Python -m PyInstaller --noconfirm --clean --distpath $StagedDist --workpath $Work $Spec
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed."
    }

    $BuiltExe = Join-Path $StagedDist "OracleReport.exe"
    if (-not (Test-Path $BuiltExe)) {
        throw "Output not found: $BuiltExe"
    }

    $WarningFile = Join-Path $Work "oracle_report\warn-oracle_report.txt"
    if ((Test-Path $WarningFile) -and
        (Select-String -LiteralPath $WarningFile -SimpleMatch "missing module named tkinter" -Quiet)) {
        throw "PyInstaller excluded tkinter; the generated EXE is not a usable GUI build."
    }

    New-Item -ItemType Directory -Path $Dist -Force | Out-Null
    $Exe = Join-Path $Dist "OracleReport.exe"
    Copy-Item -LiteralPath $BuiltExe -Destination $Exe -Force
} finally {
    if (Test-Path -LiteralPath $StagedDist) {
        $StagedFullPath = [IO.Path]::GetFullPath($StagedDist)
        $WorkFullPath = [IO.Path]::GetFullPath($Work).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $StagedFullPath.StartsWith($WorkFullPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean staging path outside build directory: $StagedFullPath"
        }
        Remove-Item -LiteralPath $StagedFullPath -Recurse -Force
    }
}

$HashFile = "${Exe}.sha256"
$Hash = Get-FileHash -LiteralPath $Exe -Algorithm SHA256
"$($Hash.Hash)  $([IO.Path]::GetFileName($Exe))" | Set-Content -LiteralPath $HashFile -Encoding ascii

Write-Host ""
Write-Host "Build OK: $Exe"
Write-Host "SHA256: $HashFile"
Write-Host "Copy this exe to any Windows PC. Python is not required on the target machine."
