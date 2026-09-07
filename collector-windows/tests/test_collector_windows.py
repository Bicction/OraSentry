# -*- coding: utf-8 -*-
"""Windows Collector 协议、安全与打包回归测试。"""
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell") or shutil.which("powershell.exe")


class WindowsCollectorTests(unittest.TestCase):
    def test_bundle_contains_required_files(self):
        required = (
            "OraSentry.ps1", "Start-OraSentry.ps1", "开始巡检.cmd",
            "main_host.ps1", "main_db.ps1", "conf/check.psd1",
            "lib/Common.ps1", "lib/Package.ps1", "lib/HostCheck.ps1",
            "lib/Oracle.ps1", "lib/DatabaseCheck.ps1", "lib/SecurityCheck.ps1",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_source_is_windows_powershell_utf8_bom_compatible(self):
        for path in list(ROOT.rglob("*.ps1")) + list(ROOT.rglob("*.psd1")):
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"), path)

    def test_security_queries_exclude_oracle_maintained_principals(self):
        security = (ROOT / "lib" / "SecurityCheck.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("dba_roles WHERE oracle_maintained='N'", security)
        self.assertIn("u.oracle_maintained='Y'", security)
        self.assertIn("p.owner NOT IN", security)
        self.assertIn("$oracleMaintainedExpr", security)

    def test_config_never_contains_plaintext_password_field(self):
        config = (ROOT / "conf" / "check.psd1").read_text(encoding="utf-8-sig")
        self.assertNotRegex(config, r"(?im)^\s*(DB_)?PASS(WORD)?\s*=")
        self.assertIn('DB_INTERACTIVE_LOGIN = "off"', config)
        self.assertIn('DB_WALLET_ALIAS = ""', config)
        self.assertNotIn('AuthMode =', config)

    def test_config_keys_match_linux_collector(self):
        windows_config = (ROOT / "conf" / "check.psd1").read_text(encoding="utf-8-sig")
        linux_config = (ROOT.parent / "collector-linux" / "conf" / "check.conf").read_text(encoding="utf-8")
        keys = (
            "DB_INTERACTIVE_LOGIN", "ORACLE_SID", "ORACLE_HOME", "DB_WALLET_ALIAS",
            "CHECK_HOST", "CHECK_DB", "CHECK_SECURITY", "CHECK_AWR", "COLLECT_SQL_TEXT",
            "RAW_DATA_DIR", "DEBUG", "REPORT_FOOTER",
        )
        for key in keys:
            self.assertIn(key, windows_config)
            self.assertIn(key, linux_config)

    def test_double_click_launcher_uses_powershell_and_keeps_password_off_command_line(self):
        launcher = (ROOT / "开始巡检.cmd").read_text(encoding="utf-8")
        starter = (ROOT / "Start-OraSentry.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("Start-OraSentry.ps1", launcher)
        self.assertIn("-Verb RunAs", starter)
        self.assertIn("ConvertTo-CollectorConfig", starter)
        self.assertNotRegex(launcher + starter, r"(?i)(DB_)?PASS(WORD)?\s*=")

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_config_normalization_selects_authentication_mode(self):
        common = str(ROOT / "lib" / "Common.ps1").replace("'", "''")
        command = (
            f". '{common}'; "
            "$os=ConvertTo-CollectorConfig @{DB_INTERACTIVE_LOGIN='off';DB_WALLET_ALIAS=''}; "
            "$wallet=ConvertTo-CollectorConfig @{DB_INTERACTIVE_LOGIN='off';DB_WALLET_ALIAS='orcl_wallet'}; "
            "$interactive=ConvertTo-CollectorConfig @{DB_INTERACTIVE_LOGIN='on';DB_WALLET_ALIAS=''}; "
            "$default=ConvertTo-CollectorConfig @{}; "
            "if($os.AuthMode-ne'OS'-or$wallet.AuthMode-ne'Wallet'-or$interactive.AuthMode-ne'Interactive'-or$default.AuthMode-ne'OS'){exit 2}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_oracle_initialization_does_not_overwrite_readonly_home(self):
        common = str(ROOT / "lib" / "Common.ps1").replace("'", "''")
        oracle = str(ROOT / "lib" / "Oracle.ps1").replace("'", "''")
        command = (
            f". '{common}'; . '{oracle}'; "
            "$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('orasentry-'+[guid]::NewGuid()); "
            "try { "
            "New-Item -ItemType Directory -Force -Path (Join-Path $testRoot 'bin')|Out-Null; "
            "New-Item -ItemType File -Force -Path (Join-Path $testRoot 'bin\\sqlplus.exe')|Out-Null; "
            "$logFile=Join-Path $testRoot 'collect.log'; "
            "New-Item -ItemType File -Force -Path $logFile|Out-Null; "
            "New-Item -ItemType File -Force -Path (Join-Path $testRoot 'env.info')|Out-Null; "
            "$context=[pscustomobject]@{OracleSid='TEST';OracleHome='';SqlPlus='';AuthMode='';"
            "ConnectDescriptor='';LoginUser='';SecurePassword=$null;LoginRole='SYSDBA';"
            "RawDir=$testRoot;LogFile=$logFile}; "
            "$config=@{OracleSid='TEST';OracleHome=$testRoot;AuthMode='OS';WalletAlias=''}; "
            "Initialize-OracleConnection $context $config; "
            "if($context.OracleHome-ne$testRoot-or$context.AuthMode-ne'os'){exit 2} "
            "} finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_oracle_home_falls_back_to_sqlplus_on_path(self):
        oracle = str(ROOT / "lib" / "Oracle.ps1").replace("'", "''")
        command = (
            f". '{oracle}'; "
            "$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('orasentry-path-'+[guid]::NewGuid()); "
            "try { "
            "$bin=Join-Path $testRoot 'bin'; "
            "New-Item -ItemType Directory -Force -Path $bin|Out-Null; "
            "New-Item -ItemType File -Force -Path (Join-Path $bin 'sqlplus.exe')|Out-Null; "
            "[Environment]::SetEnvironmentVariable('ORACLE_HOME',$null,'Process'); "
            "$env:PATH=$bin+[IO.Path]::PathSeparator+$env:PATH; "
            "$found=Find-OracleHome @{OracleHome=''} 'TEST_PATH_FALLBACK'; "
            "if($found-ne[IO.Path]::GetFullPath($testRoot)){exit 2} "
            "} finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_oracle_registry_key_without_oracle_home_is_ignored(self):
        oracle = str(ROOT / "lib" / "Oracle.ps1").replace("'", "''")
        command = (
            f". '{oracle}'; "
            "function Get-ItemProperty { [pscustomobject]@{PSPath='HKLM:\\SOFTWARE\\Oracle\\KEY_XE'} }; "
            "$missing=Get-OracleHomeFromRegistryKey 'HKLM:\\SOFTWARE\\Oracle\\KEY_XE'; "
            "if($missing){exit 2}; "
            "function Get-ItemProperty { [pscustomobject]@{ORACLE_HOME='C:\\Oracle\\dbhome_1'} }; "
            "$found=Get-OracleHomeFromRegistryKey 'HKLM:\\SOFTWARE\\Oracle\\KEY_ORCL'; "
            "if($found-ne'C:\\Oracle\\dbhome_1'){exit 3}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_error_log_contains_location_and_stack_trace(self):
        common = str(ROOT / "lib" / "Common.ps1").replace("'", "''")
        command = (
            f". '{common}'; "
            "$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('orasentry-error-'+[guid]::NewGuid()); "
            "try { "
            "New-Item -ItemType Directory -Force -Path $testRoot|Out-Null; "
            "$log=Join-Path $testRoot 'collect.log'; New-Item -ItemType File -Path $log|Out-Null; "
            "$context=[pscustomobject]@{LogFile=$log}; "
            "function Invoke-TestFailure { throw 'diagnostic-boom' }; "
            "try { Invoke-TestFailure } catch { Write-CollectorErrorRecord $context $_ }; "
            "$content=[IO.File]::ReadAllText($log,[Text.Encoding]::UTF8); "
            "if($content-notmatch'diagnostic-boom'-or$content-notmatch'错误位置'-or$content-notmatch'调用栈'-or$content-notmatch'Invoke-TestFailure'){exit 2} "
            "} finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_sqlplus_error_summary_uses_actual_error_lines(self):
        oracle = str(ROOT / "lib" / "Oracle.ps1").replace("'", "''")
        source = (ROOT / "lib" / "Oracle.ps1").read_text(encoding="utf-8-sig")
        self.assertRegex(source, r'Item "sqlplus_startup_profile"[^\r\n]+Status "OK"')
        command = (
            f". '{oracle}'; "
            "$output=\"SP2-0734: unknown command`r`nVERSION`r`n-----------------`r`n19.0.0.0.0`r`n\"; "
            "$errors=@(Get-SqlPlusErrorLines $output); "
            "if($errors.Count-ne1-or$errors[0]-ne'SP2-0734: unknown command'){exit 2}; "
            "$startup=\"SP2-0734: unknown command beginning `\"$([char]0xFEFF)SET ECHO ...`\" - rest of line ignored.`r`nVERSION`r`n19.0.0.0.0`r`n\"; "
            "$filtered=Filter-SqlPlusStartupWarnings $startup; "
            "if(@($filtered.Warnings).Count-ne1-or$filtered.Output-match'SP2-0734'-or@(Get-SqlPlusErrorLines $filtered.Output).Count-ne0){exit 3}; "
            "$realError=Filter-SqlPlusStartupWarnings \"SP2-0734: unknown command beginning `\"BAD COMMAND`\"`r`n\"; "
            "if(@(Get-SqlPlusErrorLines $realError.Output).Count-ne1){exit 4}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_sqlplus_standard_input_starts_without_utf8_bom(self):
        common = str(ROOT / "lib" / "Common.ps1").replace("'", "''")
        oracle = str(ROOT / "lib" / "Oracle.ps1").replace("'", "''")
        python_exe = str(Path(sys.executable)).replace("'", "''")
        command = (
            f". '{common}'; . '{oracle}'; "
            "$info=New-Object Diagnostics.ProcessStartInfo; "
            f"$info.FileName='{python_exe}'; "
            "$info.Arguments='-c \"import sys;print(sys.stdin.buffer.read().hex())\"'; "
            "$info.UseShellExecute=$false; $info.RedirectStandardInput=$true; "
            "$info.RedirectStandardOutput=$true; "
            "$process=New-Object Diagnostics.Process; $process.StartInfo=$info; "
            "if(-not$process.Start()){exit 2}; "
            "$text=([char]0xFEFF)+'SET ECHO OFF'; "
            "Write-Utf8NoBomProcessInput -Process $process -Text $text; "
            "$hex=$process.StandardOutput.ReadToEnd().Trim(); $process.WaitForExit(); "
            "if($hex-ne'534554204543484f204f4646'){exit 3}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_protocol_and_platform_are_explicit(self):
        common = (ROOT / "lib" / "Common.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('$script:SchemaVersion = "4.3"', common)
        self.assertIn('"platform=windows"', common)
        self.assertIn('"check_type=$CheckType"', common)

    def test_archive_names_include_host_or_sid(self):
        entry = (ROOT / "OraSentry.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('"host_check_{0}_{1}.tar.gz"', entry)
        self.assertIn('"db_check_{0}_{1}.tar.gz"', entry)

    def test_independent_entries_forward_named_switches(self):
        host_entry = (ROOT / "main_host.ps1").read_text(encoding="utf-8-sig")
        db_entry = (ROOT / "main_db.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("-HostCheck -NoPack:$NoPack -ConfigFile $ConfigFile", host_entry)
        self.assertIn("-DatabaseCheck -NoPack:$NoPack -InteractiveLogin:$InteractiveLogin", db_entry)
        self.assertNotIn("@arguments", host_entry + db_entry)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_database_query_catalog_loads_without_oracle(self):
        scripts = [ROOT / "lib" / name for name in ("Common.ps1", "Oracle.ps1", "DatabaseCheck.ps1")]
        prefix = "; ".join(". '" + str(path).replace("'", "''") + "'" for path in scripts)
        command = prefix + "; $q=Get-DatabaseQueries $false; if($q.Count -lt 50 -or -not $q.Contains('instance_status.txt') -or -not $q.Contains('tablespaces.txt') -or -not $q.Contains('storage_paths.txt')){exit 2}"
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_windows_critical_event_and_firewall_classifiers(self):
        host_check = str(ROOT / "lib" / "HostCheck.ps1").replace("'", "''")
        command = (
            f". '{host_check}'; "
            "$storage=[pscustomobject]@{ProviderName='storport';Message='Reset to device';Id=129;Level=3}; "
            "$classified=Get-WindowsCriticalEventClassification $storage; "
            "if($classified.Category-ne'STORAGE_RESET'-or$classified.Severity-ne'WARN'){exit 2}; "
            "$timeSuccess=[pscustomobject]@{ProviderName='Microsoft-Windows-Time-Service';Message='synchronized';Id=35;Level=4}; "
            "if(Get-WindowsCriticalEventClassification $timeSuccess){exit 6}; "
            "if(-not(Test-WindowsFirewallPortMatch '1521,5500-5510' 1521)){exit 3}; "
            "if(-not(Test-WindowsFirewallPortMatch '1521,5500-5510' 5505)){exit 4}; "
            "if(Test-WindowsFirewallPortMatch '1521,5500-5510' 8080){exit 5}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_first_phase_windows_metrics_are_registered(self):
        host_check = (ROOT / "lib" / "HostCheck.ps1").read_text(encoding="utf-8-sig")
        database_check = (ROOT / "lib" / "DatabaseCheck.ps1").read_text(encoding="utf-8-sig")
        for filename in (
            "performance_samples.txt", "firewall_oracle_rules.txt", "critical_events.txt",
            "oracle_processes.txt", "windows_maintenance.txt",
        ):
            self.assertIn(filename, host_check)
        self.assertIn("storage_path_capacity.txt", database_check)
        self.assertIn("Collect-WindowsStoragePathCapacity", database_check)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_storage_path_capacity_ignores_sqlplus_separator_rows(self):
        common = str(ROOT / "lib" / "Common.ps1").replace("'", "''")
        database = str(ROOT / "lib" / "DatabaseCheck.ps1").replace("'", "''")
        command = (
            f". '{common}'; . '{database}'; "
            "$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('orasentry-storage-'+[guid]::NewGuid()); "
            "try { "
            "$dbDir=Join-Path $testRoot 'db'; New-Item -ItemType Directory -Force -Path $dbDir|Out-Null; "
            "$source=\"STORAGE_TYPE|STORAGE_PATH`r`n------------|------------`r`nDATAFILE|C:\\oradata\\system01.dbf`r`nASM|+DATA/ORCL/DATAFILE/system.1`r`n\"; "
            "[IO.File]::WriteAllText((Join-Path $dbDir 'storage_paths.txt'),$source,(New-Object Text.UTF8Encoding($false))); "
            "$ctx=[pscustomobject]@{RawDir=$testRoot;ManifestFile=(Join-Path $testRoot 'manifest.tsv');"
            "LogFile=(Join-Path $testRoot 'collect.log');Failures=0;Warnings=0;OracleHome='C:\\Oracle'}; "
            "Collect-WindowsStoragePathCapacity $ctx $dbDir; "
            "$result=[IO.File]::ReadAllText((Join-Path $dbDir 'storage_path_capacity.txt')); "
            "if($result-match'------------'-or$result-notmatch'DATAFILE\\|FILESYSTEM\\|C:'-or$result-notmatch'ASM\\|ASM\\|\\+DATA'){exit 2} "
            "} finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_all_powershell_files_parse(self):
        command = (
            "$failed=$false; Get-ChildItem -LiteralPath '" + str(ROOT).replace("'", "''") +
            "' -Recurse -Filter *.ps1 | % {$t=$null;$e=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e)|Out-Null;"
            "if($e){$e|%{Write-Error $_};$failed=$true}}; if($failed){exit 1}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_native_tar_gz_is_readable_without_checksum_sidecar(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            work = Path(td)
            raw = work / "raw"
            raw.mkdir()
            (raw / "env.info").write_text("schema_version=4.3\nplatform=windows\n", encoding="utf-8")
            archive = work / "host_check_WINTEST_20260830_120000.tar.gz"
            package = str(ROOT / "lib" / "Package.ps1").replace("'", "''")
            source = str(raw).replace("'", "''")
            target = str(archive).replace("'", "''")
            command = f". '{package}'; New-TarGzArchive -SourceDirectory '{source}' -DestinationPath '{target}'"
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with tarfile.open(archive, "r:gz") as bundle:
                self.assertEqual(bundle.getnames(), ["env.info"])
                self.assertIn(b"platform=windows", bundle.extractfile("env.info").read())
            self.assertFalse(Path(str(archive) + ".sha256").exists())


if __name__ == "__main__":
    unittest.main()
