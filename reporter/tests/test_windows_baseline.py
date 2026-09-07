# -*- coding: utf-8 -*-
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from parser import windows_baseline_parser as baseline
from parser.host_parser import parse_host
from parser.db_parser import parse_db
from parser.security_parser import parse_security
from parser.base import parse_collection_integrity
from report_gen import build_report


NETWORK = "KIND|NAME|SECONDS|PACKETS|ERRORS|DISCARDS|RX_BYTES|TX_BYTES|TCP_SENT|TCP_RETRANS|COUNTER_STATE\n"
PROTECTION = "KIND|PRODUCT|MODE|SERVICE_ENABLED|ANTIVIRUS_ENABLED|REALTIME_ENABLED|SIGNATURE_VERSION|SIGNATURE_UPDATED|SIGNATURE_AGE_DAYS|EVIDENCE\n"
MEMORY = "SERVICE|SID|ACCOUNT|ACCOUNT_SID|ORACLE_HOME|REGISTRY_KEY|ORA_LPENABLE|ORA_SID_LPENABLE|LOCK_PAGES_GRANT|EVIDENCE|GRANTED_SIDS\n"
AUDIT = "SUBCATEGORY|GUID|SUCCESS|FAILURE|FLAGS\n"
CLUSTER = "KIND|NAME|STATE|OWNER|DETAIL\n"


class WindowsBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.raw = Path(self.temp.name) / "raw"
        self.host = self.raw / "host"
        self.host.mkdir(parents=True)
        self.write("env.info", "platform=windows\nschema_version=4.3\nhostname=WIN-ORA01\ncheck_type=host\ntimestamp=20260903_120000\n")

    def write(self, relative, text):
        path = self.raw / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def memory(self, global_mode="1", instance_mode="", grant="DIRECT", domain="host"):
        self.write(domain + "/oracle_memory_config.txt", MEMORY +
                   f"OracleServiceORCL|ORCL|LAB\\oracle|S-1-5-21-1-2-3-1001|D:\\Oracle|HKLM\\Oracle|{global_mode}|{instance_mode}|{grant}|CONFIG_ONLY|S-1-5-21-1-2-3-1001\n")

    def protection(self, mode="Normal", age="2", realtime="True"):
        self.write("host/endpoint_protection.txt", PROTECTION +
                   f"DEFENDER|Defender|{mode}|True|True|{realtime}|1.2.3|2026-09-01|{age}|OBSERVED\n"
                   "EDR_SERVICE|Sense|Running|||||||INVENTORY_ONLY\n")

    def audit(self, success="True", failure="True"):
        self.write("host/windows_audit_policy.txt", AUDIT + "".join(
            f"{name}|guid|{success}|{failure}|3\n" for name in
            ("Logon", "AuditPolicyChange", "UserAccountManagement", "SecurityGroupManagement")))

    def test_old_packages_have_only_informational_phase2_items(self):
        self.assertEqual({r.status for r in baseline.parse_windows_baseline(str(self.raw))}, {"INFO"})

    def test_registered_missing_file_is_unknown_even_if_manifest_says_ok(self):
        for status in ("WARN", "FAILED", "OK"):
            with self.subTest(status=status):
                self.write("collection_manifest.tsv", f"item\ttype\tstatus\texit_code\tmessage\nnetwork_quality.txt\tCOMMAND\t{status}\t0\t\n")
                self.assertEqual(baseline.parse_network_quality(self.host).status, "UNKNOWN")

    def test_optional_failure_without_output_lowers_single_host_integrity(self):
        self.write("collection_manifest.tsv", "item\ttype\tstatus\texit_code\tmessage\nnetwork_quality.txt\tCOMMAND\tWARN\t1\tdenied\n")
        result = parse_collection_integrity(str(self.raw), scopes=["host"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(result.value, "1项不完整")
        self.assertIn("仅获得部分数据", result.detail)
        self.assertNotIn("命令/SQL 错误", result.detail)

    def test_malformed_and_empty_data_are_not_zero_healthy(self):
        for text in ("", "BAD|HEADER\n", NETWORK, NETWORK + "NIC|short\n"):
            with self.subTest(text=text):
                self.write("host/network_quality.txt", text)
                self.assertEqual(baseline.parse_network_quality(self.host).status, "UNKNOWN")

    def test_network_counts_are_interval_values_with_activity_floor(self):
        self.write("host/network_quality.txt", NETWORK + "TCP|TCPv4|5||||||10|2|VALID\n")
        self.assertEqual(baseline.parse_network_quality(self.host).status, "INFO")
        self.write("host/network_quality.txt", NETWORK + "TCP|TCPv4|5||||||1000|60|VALID\n")
        self.assertEqual(baseline.parse_network_quality(self.host).status, "CRIT")
        self.write("host/network_quality.txt", NETWORK + "TCP|TCPv4|5||||||1000|20|VALID\n")
        self.assertEqual(baseline.parse_network_quality(self.host).status, "WARN")

    def test_nic_error_ratio_and_throughput(self):
        self.write("host/network_quality.txt", NETWORK + "NIC|LAN|5|10000|200|0|5242880|0|||VALID\n")
        result = baseline.parse_network_quality(self.host)
        self.assertEqual(result.status, "CRIT")
        self.assertIn("1.00/0.00 MiB/s", result.extra_html)

    def test_network_invalid_or_reset_counters_are_unknown(self):
        for row in ("TCP|TCPv4|5||||||100|0|RESET_OR_UNAVAILABLE", "TCP|TCPv4|5||||||NaN|1|VALID",
                    "TCP|TCPv4|0||||||100|0|VALID", "TCP|TCPv4|5||||||10|20|VALID"):
            self.write("host/network_quality.txt", NETWORK + row + "\n")
            self.assertEqual(baseline.parse_network_quality(self.host).status, "UNKNOWN")

    def test_default_route_on_down_interface_warns_not_any_unused_nic(self):
        header = "KIND|IF_INDEX|NAME|STATE|LINK_SPEED|ADDRESS|NEXT_HOP|METRIC\n"
        nic = "ADAPTER|2|LAN|Disconnected|1 Gbps|10.0.0.2||\n"
        self.write("host/network_config.txt", header + nic)
        self.assertEqual(baseline.parse_network_config(self.host).status, "INFO")
        self.write("host/network_config.txt", header + nic + "DEFAULT_ROUTE|2|LAN|Alive||0.0.0.0/0|10.0.0.1|20\n")
        self.assertEqual(baseline.parse_network_config(self.host).status, "WARN")

    def test_defender_modes_and_signature_age(self):
        for mode, age, realtime, status in (("Normal", "2", "True", "OK"), ("Normal", "14", "True", "CRIT"),
                                           ("Normal", "2", "False", "WARN"), ("Normal", "", "True", "UNKNOWN"),
                                           ("Passive", "2", "False", "UNKNOWN"), ("EDR Block Mode", "2", "False", "UNKNOWN")):
            with self.subTest(mode=mode, age=age, realtime=realtime):
                self.protection(mode, age, realtime)
                self.assertEqual(baseline.parse_protection(self.host).status, status)

    def test_third_party_edr_inventory_does_not_claim_health(self):
        self.write("host/endpoint_protection.txt", PROTECTION + "REGISTERED_AV|Product|266240|||||||INVENTORY_ONLY\n")
        self.assertEqual(baseline.parse_protection(self.host).status, "UNKNOWN")

    def test_partial_collection_does_not_claim_complete_protection(self):
        self.protection()
        self.write("collection_manifest.tsv", "item\ttype\tstatus\texit_code\tmessage\nendpoint_protection.txt\tCOMMAND\tWARN\t1\tdenied\n")
        self.assertEqual(baseline.parse_protection(self.host).status, "UNKNOWN")

    def test_groups_use_sid_not_localized_name_or_headcount(self):
        header = "GROUP|GROUP_SID|MEMBER|MEMBER_SID|MEMBER_TYPE|EVIDENCE\n"
        self.write("host/privileged_groups.txt", header + "管理员|S-1-5-32-544|任意名称|S-1-5-11|Win32_Group|OBSERVED\n")
        self.assertEqual(baseline.parse_groups(self.host).status, "WARN")
        self.write("host/privileged_groups.txt", header + "ORA_DBA|S-1-5-21-1-2-3-1000|svc|S-1-5-21-1-2-3-1001|Win32_UserAccount|OBSERVED\n")
        self.assertEqual(baseline.parse_groups(self.host).status, "INFO")

    def test_remote_access_baseline_is_not_reported_from_legacy_packages(self):
        self.write("host/remote_access.txt", "SETTING|VALUE|SOURCE\nRDP_ENABLED|True|registry\nRDP_NLA|False|registry\nSMB1_SERVER|True|cmdlet\n")
        results = baseline.parse_windows_baseline(str(self.raw))
        self.assertNotIn("Windows远程访问基线", {result.name for result in results})
        self.assertFalse(hasattr(baseline, "parse_remote_access"))

    def test_audit_login_requires_success_and_failure(self):
        self.audit()
        self.assertEqual(baseline.parse_audit_policy(self.host).status, "OK")
        self.audit(failure="False")
        self.assertEqual(baseline.parse_audit_policy(self.host).status, "WARN")
        self.write("host/windows_audit_policy.txt", AUDIT + "Logon|guid|True|True|3\n")
        self.assertEqual(baseline.parse_audit_policy(self.host).status, "UNKNOWN")

    def test_cluster_optional_and_state_classification(self):
        for row, expected in (("CLUSTER||NOT_INSTALLED||", "INFO"), ("CLUSTER||NOT_CONFIGURED||", "INFO"),
                              ("NODE|node1|Down||", "CRIT"), ("RESOURCE|DBDisk|Failed|DB|Physical Disk", "CRIT"),
                              ("RESOURCE|Spare|Offline|DB|Physical Disk", "WARN"), ("QUORUM|NodeMajority|NO_WITNESS||", "INFO")):
            self.write("host/windows_cluster.txt", CLUSTER + row + "\n")
            self.assertEqual(baseline.parse_cluster(self.host).status, expected)

    def test_cluster_query_failure_preserves_stopped_service_evidence(self):
        self.write("host/windows_cluster.txt", CLUSTER + "SERVICE|ClusSvc|Stopped||\n")
        self.write("collection_manifest.tsv", "item\ttype\tstatus\texit_code\tmessage\nwindows_cluster.txt\tCOMMAND\tWARN\t1\tmodule unavailable\n")
        result = baseline.parse_cluster(self.host)
        self.assertEqual(result.status, "CRIT")
        self.assertIn("不完整", result.detail)

    def test_memory_instance_override_and_unconfirmed_grant(self):
        self.memory(grant="UNCONFIRMED")
        self.assertEqual(baseline.parse_oracle_memory(self.host).status, "UNKNOWN")
        self.memory(instance_mode="0", grant="UNCONFIRMED")
        self.assertEqual(baseline.parse_oracle_memory(self.host).status, "INFO")
        self.memory(grant="DIRECT")
        result = baseline.parse_oracle_memory(self.host)
        self.assertEqual(result.status, "INFO")
        self.assertIn("非实际使用量", result.value)

    def test_database_large_pages_identity_and_platform_specific_rules(self):
        self.memory(domain="db")
        header = "INSTANCE_NAME|HOST_NAME|NAME|VALUE\n"
        self.write("db/windows_large_pages.txt", header + "ORCL|WIN-ORA01|use_large_pages|FALSE\nORCL|WIN-ORA01|lock_sga|FALSE\n")
        self.assertEqual(baseline.parse_windows_large_pages(str(self.raw)).status, "INFO")
        self.write("db/windows_large_pages.txt", header + "ORCL|WIN-ORA01|lock_sga|TRUE\n")
        self.assertEqual(baseline.parse_windows_large_pages(str(self.raw)).status, "WARN")
        self.write("db/windows_large_pages.txt", header + "ORCL|OTHER-HOST|lock_sga|FALSE\n")
        self.assertEqual(baseline.parse_windows_large_pages(str(self.raw)).status, "UNKNOWN")

    def test_database_without_matching_local_service_is_unknown(self):
        self.write("db/windows_large_pages.txt", "INSTANCE_NAME|HOST_NAME|NAME|VALUE\nORCL|WIN-ORA01|lock_sga|FALSE\n")
        self.write("db/oracle_memory_config.txt", MEMORY + "|||||||||NO_LOCAL_SERVICE|\n")
        self.assertEqual(baseline.parse_windows_large_pages(str(self.raw)).status, "UNKNOWN")

    def test_retired_configuration_acl_is_ignored_without_hiding_other_failures(self):
        self.write("env.info", "platform=windows\ncheck_type=db\ncollector_version=4.4\n")
        self.write("security/oracle_config_acl.txt", "ORA-00942: old collection failure\n")
        for status in ("WARN", "FAILED", "SKIPPED", "OK"):
            with self.subTest(status=status):
                manifest = ("item\ttype\tstatus\texit_code\tmessage\n"
                            f"oracle_config_acl.txt\tCOMMAND\t{status}\t1\tCannot find registry path\n")
                self.write("collection_manifest.tsv", manifest)
                for scopes in (None, ("db", "security")):
                    result = parse_collection_integrity(str(self.raw), scopes=scopes)
                    self.assertEqual(result.status, "INFO")
                    self.assertEqual(result.value, "完整")
                    self.assertNotIn("oracle_config_acl", result.extra_html)
                self.write("collection_manifest.tsv", manifest + "db_version.txt\tSQL\tFAILED\t1\tORA-00942\n")
                result = parse_collection_integrity(str(self.raw), scopes=("db", "security"))
                self.assertEqual(result.status, "UNKNOWN")
                self.assertEqual(result.value, "1项失败")
                self.assertIn("db_version.txt", result.extra_html)
        self.assertNotIn("Oracle配置ACL", {r.name for r in parse_security(str(self.raw))})

    def test_phase2_items_reach_dispatch_html_and_docx(self):
        self.write("host/network_quality.txt", NETWORK + "TCP|TCPv4|5||||||1000|60|VALID\n")
        self.protection()
        self.audit()
        self.memory()
        self.write("host/windows_cluster.txt", CLUSTER + "CLUSTER||NOT_INSTALLED||\n")
        names = {r.name for r in parse_host(str(self.raw))}
        self.assertIn("Windows网络质量", names)
        self.assertIn("Oracle Windows大页", {r.name for r in parse_db(str(self.raw))["db"]})
        security_names = {r.name for r in parse_security(str(self.raw))}
        self.assertNotIn("Oracle配置ACL", security_names)
        self.assertNotIn("Oracle配置与Wallet ACL", security_names)
        report = build_report([str(self.raw)], str(Path(self.temp.name) / "report.html"), write_html=True, write_docx=True)
        html = Path(report.html).read_text(encoding="utf-8")
        with ZipFile(report.docx) as archive:
            xml = archive.read("word/document.xml").decode("utf-8")
        for name in ("Windows网络质量", "Windows终端防护", "Windows审计策略", "Oracle锁页权限与大页配置"):
            self.assertIn(name, html)
            self.assertIn(name, xml)


if __name__ == "__main__":
    unittest.main()
