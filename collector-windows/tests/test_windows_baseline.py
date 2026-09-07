# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(POWERSHELL, "Windows PowerShell is not available")
class WindowsBaselineCollectorTests(unittest.TestCase):
    def run_ps(self, body):
        prefix = "$ErrorActionPreference='Stop'; " + "; ".join(
            ". '" + str(ROOT / "lib" / file).replace("'", "''") + "'"
            for file in ("Common.ps1", "WindowsBaseline.ps1", "WindowsOracle.ps1")) + "; "
        # A Python child does not get PowerShell's PSModulePath version cleanup.
        # Do not load PowerShell 7 type data into the Windows PowerShell 5.1 test.
        env = os.environ.copy()
        env["PSMODULEPATH"] = str(Path(env["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/Modules")
        result = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", prefix + body],
                                capture_output=True, encoding="utf-8", errors="replace", timeout=30, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_counter_delta_rejects_reset_and_missing_values(self):
        self.run_ps("$before=[pscustomobject]@{A=100;B=200}; $after=[pscustomobject]@{A=105;B=220}; "
                    "if((Get-NetworkCounterDelta $before $after @('A','B')) -ne 25){throw 'delta'}; "
                    "if($null -ne (Get-NetworkCounterDelta $after $before @('A'))){throw 'reset'}; "
                    "if($null -ne (Get-NetworkCounterDelta $before $after @('MISSING'))){throw 'missing'}")

    def test_lock_pages_policy_and_direct_local_group_membership(self):
        self.run_ps("$sids=@(ConvertFrom-LockPagesPolicy \"[Privilege Rights]`nSeLockMemoryPrivilege = *S-1-5-18,*S-1-5-32-544`nOther=ignored\"); "
                    "if($sids.Count -ne 2){throw 'parse'}; "
                    "if((Get-LockPagesGrant 'S-1-5-18' $sids @()) -ne 'DIRECT'){throw 'direct'}; "
                    "$membership=[pscustomobject]@{MEMBER_SID='S-1-5-21-1';GROUP_SID='S-1-5-32-544'}; "
                    "if((Get-LockPagesGrant 'S-1-5-21-1' $sids @($membership)) -ne 'LOCAL_GROUP'){throw 'group'}; "
                    "if((Get-LockPagesGrant 'S-1-5-21-2' $sids @()) -ne 'UNCONFIRMED'){throw 'domain absence'}")

    def test_audit_native_reader_compiles_without_changing_policy(self):
        self.run_ps("Initialize-AuditReader; if(-not ('OraSentry.NativeAuditReader' -as [type])){throw 'native reader missing'}")

    def test_collector_read_only_hooks_and_acl_scope(self):
        baseline = (ROOT / "lib/WindowsBaseline.ps1").read_text(encoding="utf-8-sig")
        oracle = (ROOT / "lib/WindowsOracle.ps1").read_text(encoding="utf-8-sig")
        entry = (ROOT / "OraSentry.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("Collect-WindowsBaseline $hostContext", entry)
        self.assertIn("Collect-OracleWindowsMemory $hostContext", entry)
        self.assertNotRegex(baseline + oracle, r"(?i)\b(?:Set-MpPreference|Set-SmbServerConfiguration|Set-ItemProperty|Move-ClusterGroup|Start-Cluster|Stop-Cluster|AuditSetSystemPolicy)\b")
        self.assertIn("/export /mergedpolicy /areas USER_RIGHTS", oracle)
        self.assertNotIn("Copy-Item", oracle)
        security = (ROOT / "lib/SecurityCheck.ps1").read_text(encoding="utf-8-sig")
        self.assertNotIn("Collect-OracleConfigurationAcls", security + oracle)
        self.assertNotIn("oracle_config_acl.txt", security + oracle)
        self.assertNotIn("Get-OracleWalletDirectories", oracle)
        self.assertNotIn("wallet_root", oracle.lower())
        self.assertNotIn("cwallet.sso", oracle.lower())
        self.assertNotIn('"WALLET"', oracle)
        self.assertNotIn("Collect-WindowsRemoteAccess", baseline)
        self.assertNotIn("remote_access.txt", baseline)

    def context_script(self, tmp):
        escaped = str(tmp).replace("'", "''")
        return (f"$raw='{escaped}'; "
                "$ctx=[pscustomobject]@{RawDir=$raw;CheckType='host';OracleSid='ORCL';OracleHome=$raw;"
                "ManifestFile=(Join-Path $raw 'collection_manifest.tsv');LogFile=(Join-Path $raw 'collect.log');Failures=0;Warnings=0}; "
                "New-Item -ItemType Directory -Path (Join-Path $raw 'host') -Force | Out-Null; ")

    def test_oracle_memory_pipeline_maps_quoted_service_path_and_removes_export(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            self.run_ps(self.context_script(tmp) +
                        "function Get-CimInstance { [pscustomobject]@{Name='OracleServiceORCL';StartName='LocalSystem';PathName='\"D:\\Oracle Home\\bin\\oracle.exe\" ORCL'} }; "
                        "function Get-WindowsOracleRegistryKeys { [pscustomobject]@{PSPath='HKLM:\\Fake';Name='HKLM\\Fake'} }; "
                        "function Get-BaselineRegistryValue { param($Path,$Name,$Default); switch($Name) {'ORACLE_HOME' {'D:\\Oracle Home'} 'ORA_LPENABLE' {'1'} 'ORA_ORCL_LPENABLE' {'2'} default {''}} }; "
                        "function secedit.exe { $cfg=$args[[array]::IndexOf($args,'/cfg')+1]; Write-CollectorText $cfg 'SeLockMemoryPrivilege = *S-1-5-18'; $global:LASTEXITCODE=0 }; "
                        "Collect-OracleWindowsMemory $ctx (Join-Path $raw 'host'); "
                        "if($ctx.Warnings -ne 0){throw 'memory collection warning'}; "
                        "$items=@(Import-Csv -LiteralPath (Join-Path $raw 'host\\oracle_memory_config.txt') -Delimiter '|'); "
                        "if($items.Count -ne 1 -or $items[0].ORA_SID_LPENABLE -ne '2' -or $items[0].LOCK_PAGES_GRANT -ne 'DIRECT'){throw ('bad mapping: ' + ($items | ConvertTo-Json -Compress))}; "
                        "if(@(Get-ChildItem -LiteralPath $raw -Filter '.rights-*').Count){throw 'policy leaked'}")

    def test_cluster_failure_preserves_already_observed_node_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            self.run_ps(self.context_script(tmp) +
                        "function Get-CimInstance { [pscustomobject]@{State='Running'} }; "
                        "function Test-Path { param($LiteralPath); return $true }; "
                        "function Import-Module {}; function Get-Cluster { [pscustomobject]@{Name='TEST'} }; "
                        "function Get-ClusterNode { [pscustomobject]@{Name='NODE1';State='Down';NodeWeight=1} }; "
                        "function Get-ClusterGroup { throw 'test group query failure' }; "
                        "Collect-WindowsCluster $ctx; "
                        "if($ctx.Warnings -ne 1){throw 'missing manifest failure'}; "
                        "$content=[IO.File]::ReadAllText((Join-Path $raw 'host\\windows_cluster.txt')); "
                        "if($content -notmatch 'NODE\\|NODE1\\|Down'){throw 'lost observed node'}")

    def test_network_config_multivalue_fields_remain_separate_columns(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            self.run_ps(self.context_script(tmp) +
                        "function Invoke-CollectionAction { param($Context,$Item,$Action,[switch]$Optional); if($Item -eq 'network_config.txt'){& $Action} }; "
                        "function Get-NetAdapter { [pscustomobject]@{ifIndex=2;Name='LAN';Status='Up';LinkSpeed='1 Gbps'} }; "
                        "function Get-CimInstance { [pscustomobject]@{InterfaceIndex=2;IPAddress=@('10.0.0.1','::1')} }; "
                        "function Get-DnsClientServerAddress { [pscustomobject]@{InterfaceIndex=2;InterfaceAlias='LAN';ServerAddresses=@('10.0.0.53','10.0.0.54')} }; "
                        "function Get-NetRoute { [pscustomobject]@{InterfaceIndex=2;InterfaceAlias='LAN';DestinationPrefix='0.0.0.0/0';NextHop='10.0.0.254';RouteMetric=10} }; "
                        "Collect-WindowsNetworkBaseline $ctx; "
                        "$items=@(Import-Csv -LiteralPath (Join-Path $raw 'host\\network_config.txt') -Delimiter '|'); "
                        "if($items.Count -ne 3 -or $items[0].KIND -ne 'ADAPTER' -or $items[0].ADDRESS -ne '10.0.0.1,::1' -or $items[1].ADDRESS -ne '10.0.0.53,10.0.0.54' -or $items[2].STATE -ne ''){throw 'network columns or missing-State compatibility'}")

    def test_optional_warning_returns_incomplete_without_losing_package_flow(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            self.run_ps(self.context_script(tmp) +
                        "$ctx.Warnings=1; if(Complete-Collection $ctx){throw 'warning claimed complete'}; "
                        "if(-not (Test-Path -LiteralPath (Join-Path $raw 'env.info'))){throw 'completion metadata absent'}")


if __name__ == "__main__":
    unittest.main()
