# -*- coding: utf-8 -*-
"""Windows Collector 协议、安全与打包回归测试。"""
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell") or shutil.which("powershell.exe")


class WindowsCollectorTests(unittest.TestCase):
    def test_bundle_contains_required_files(self):
        required = (
            "OraSentry.ps1", "main_host.ps1", "main_db.ps1", "conf/check.psd1",
            "lib/Common.ps1", "lib/Package.ps1", "lib/HostCheck.ps1",
            "lib/Oracle.ps1", "lib/DatabaseCheck.ps1", "lib/SecurityCheck.ps1",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_source_is_windows_powershell_utf8_bom_compatible(self):
        for path in list(ROOT.rglob("*.ps1")) + list(ROOT.rglob("*.psd1")):
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"), path)

    def test_config_never_contains_plaintext_password_field(self):
        config = (ROOT / "conf" / "check.psd1").read_text(encoding="utf-8-sig")
        self.assertNotRegex(config, r"(?im)^\s*(DB_)?PASS(WORD)?\s*=")
        self.assertIn('AuthMode = "OS"', config)

    def test_protocol_and_platform_are_explicit(self):
        common = (ROOT / "lib" / "Common.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('$script:SchemaVersion = "4.3"', common)
        self.assertIn('"platform=windows"', common)
        self.assertIn('"check_type=$CheckType"', common)

    def test_archive_names_include_host_or_sid(self):
        entry = (ROOT / "OraSentry.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('"host_check_{0}_{1}.tar.gz"', entry)
        self.assertIn('"db_check_{0}_{1}.tar.gz"', entry)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
    def test_database_query_catalog_loads_without_oracle(self):
        scripts = [ROOT / "lib" / name for name in ("Common.ps1", "Oracle.ps1", "DatabaseCheck.ps1")]
        prefix = "; ".join(". '" + str(path).replace("'", "''") + "'" for path in scripts)
        command = prefix + "; $q=Get-DatabaseQueries $false; if($q.Count -lt 50 -or -not $q.Contains('instance_status.txt') -or -not $q.Contains('tablespaces.txt')){exit 2}"
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
