# -*- coding: utf-8 -*-
"""Windows 采集包解析与报告端到端回归测试。"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from parser.host_parser import parse_host
from parser.db_parser import parse_db
from parser.security_parser import parse_security
from report_gen import build_report


class WindowsReporterTests(unittest.TestCase):
    @staticmethod
    def _write(root: Path, relative: str, text: str):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def _make_host(self, root: Path):
        self._write(root, "env.info", "schema_version=4.3\nplatform=windows\nhostname=WIN-ORA01\nserver_ip=10.0.0.8\ntimestamp=20260830_120000\ncheck_type=host\n")
        self._write(root, "collection_manifest.tsv", "item\ttype\tstatus\texit_code\tmessage\n")
        self._write(root, "host/disk_usage.txt", "VOLUME|LABEL|FILESYSTEM|TOTAL_GB|USED_GB|FREE_GB|USAGE_PCT\nC:|System|NTFS|200|100|100|50\nD:|Oracle|NTFS|500|450|50|90\n")
        self._write(root, "host/cpu_metrics.txt", "CPU_COUNT|CPU_USAGE_PCT|UPTIME_HOURS\n8|32.5|120\n")
        self._write(root, "host/memory_metrics.txt", "TOTAL_MB|AVAILABLE_MB|USED_MB|USAGE_PCT\n32768|12288|20480|62.5\n")
        self._write(root, "host/pagefile_metrics.txt", "NAME|ALLOCATED_MB|USED_MB|PEAK_MB|USAGE_PCT\nC:\\pagefile.sys|8192|1024|2048|12.5\n")
        self._write(root, "host/login_metrics.txt", "ACTIVE_SESSION_COUNT|FAILED_LOGIN_7D_SAMPLED\n2|3\n")
        self._write(root, "host/firewall_profiles.txt", "PROFILE|ENABLED|INBOUND_ACTION|OUTBOUND_ACTION\nDomain|True|Block|Allow\n")
        self._write(root, "host/time_sync.txt", "LOCAL_TIME|TIMEZONE|SERVICE_STATUS|SOURCE|OFFSET_MS|STATUS_TEXT\n2026-08-30 12:00:00 +08:00|China Standard Time|Running|dc01|10|同步正常\n")
        self._write(root, "host/network_listen.txt", "PROTOCOL|LOCAL_ADDRESS|LOCAL_PORT|STATE|PID|PROCESS\nTCP|0.0.0.0|1521|Listen|100|tnslsnr\n")
        self._write(root, "host/event_log_errors.txt", "TIME|LOG|EVENT_ID|LEVEL|PROVIDER|MESSAGE\n")
        self._write(root, "host/oracle_services.txt", "NAME|DISPLAY_NAME|STATE|START_MODE|ACCOUNT|PID|PATH|EXIT_CODE|SERVICE_EXIT_CODE|RECOVERY_ACTIONS\nOracleServiceORCL|OracleServiceORCL|Running|Auto|LocalSystem|123|D:\\oracle\\bin\\oracle.exe|0|0|RESTART\nOracleOraDB19Home1TNSListener|Oracle Listener|Running|Auto|LocalSystem|124|D:\\oracle\\bin\\tnslsnr.exe|0|0|RESTART\n")
        self._write(root, "host/oracle_processes.txt", "PID|NAME|PATH|COMMAND_LINE|CPU_PCT|WORKING_SET_MB|PRIVATE_MB|THREADS|HANDLES|UPTIME_HOURS\n123|oracle.exe|D:\\oracle\\bin\\oracle.exe||20|4096|3072|40|300|120\n124|tnslsnr.exe|D:\\oracle\\bin\\tnslsnr.exe||2|100|80|5|60|120\n")
        self._write(root, "host/disk_io.txt", "DISK|READ_LATENCY_MS|WRITE_LATENCY_MS|BUSY_PCT|READ_IOPS|WRITE_IOPS\n0 C:|2.5|3.0|20|50|25\n")
        samples = ["TIME|SAMPLE|CPU_TOTAL_PCT|CPU_PRIVILEGED_PCT|PROCESSOR_QUEUE_LENGTH|AVAILABLE_MB|COMMITTED_PCT|PAGES_PER_SEC|PAGEFILE_PCT|DISK|READ_LATENCY_MS|WRITE_LATENCY_MS|QUEUE_LENGTH|BUSY_PCT|READ_IOPS|WRITE_IOPS|READ_MBPS|WRITE_MBPS"]
        for sample in range(1, 11):
            samples.append(f"2026-08-30 12:00:{sample:02d}|{sample}|32.5|10|1|12288|65|2|12|0 C:|2.5|3|0|20|50|25|10|5")
        self._write(root, "host/performance_samples.txt", "\n".join(samples) + "\n")
        self._write(root, "host/firewall_oracle_rules.txt", "PORT|PROCESS|LOCAL_ADDRESS|RULE_NAME|PROFILE|REMOTE_ADDRESS|EXPOSURE\n1521|tnslsnr|0.0.0.0|Oracle App Network|Domain|10.0.0.0/24|SCOPED\n")
        self._write(root, "host/critical_events.txt", "TIME|CATEGORY|SEVERITY|LOG|PROVIDER|EVENT_ID|MESSAGE\n")
        self._write(root, "host/windows_maintenance.txt", "CAPTION|VERSION|BUILD|UBR|LAST_HOTFIX|LAST_HOTFIX_DATE|PATCH_AGE_DAYS|PENDING_REBOOT|PENDING_REASONS|LAST_BOOT_TIME\nWindows Server 2022|10.0|20348|3207|KB5000000|2026-08-01|29|False||2026-08-01 08:00:00\n")

    def test_windows_host_parser_dispatches_and_marks_not_applicable_items_info(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            results = parse_host(str(raw))
            by_name = {item.name: item for item in results}
            self.assertEqual(by_name["磁盘使用率-D:"].status, "CRIT")
            self.assertEqual(by_name["inode使用率"].status, "INFO")
            self.assertEqual(by_name["CPU使用率"].value, "P95 32.5%")
            self.assertEqual(by_name["Oracle服务"].status, "OK")
            self.assertEqual(by_name["Oracle进程健康"].status, "OK")
            self.assertEqual(by_name["网络监听端口"].status, "INFO")

    def test_windows_first_phase_risk_rules_are_actionable(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            self._write(raw, "host/firewall_profiles.txt", "PROFILE|ENABLED|INBOUND_ACTION|OUTBOUND_ACTION\nDomain|False|Allow|Allow\n")
            self._write(raw, "host/firewall_oracle_rules.txt", "PORT|PROCESS|LOCAL_ADDRESS|RULE_NAME|PROFILE|REMOTE_ADDRESS|EXPOSURE\n1521|tnslsnr|0.0.0.0|Oracle Any|Any|Any|ANY\n")
            self._write(raw, "host/time_sync.txt", "LOCAL_TIME|TIMEZONE|SERVICE_STATUS|SOURCE|OFFSET_MS|STATUS_TEXT\n2026-08-30 12:00:00 +08:00|China Standard Time|Running|dc01|6000|\n")
            self._write(raw, "host/critical_events.txt", "TIME|CATEGORY|SEVERITY|LOG|PROVIDER|EVENT_ID|MESSAGE\n2026-08-30 01:00:00|STORAGE_RESET|WARN|System|storport|129|reset 1\n2026-08-30 02:00:00|STORAGE_RESET|WARN|System|storport|129|reset 2\n2026-08-30 03:00:00|STORAGE_RESET|WARN|System|storport|129|reset 3\n")
            self._write(raw, "host/windows_maintenance.txt", "CAPTION|VERSION|BUILD|UBR|LAST_HOTFIX|LAST_HOTFIX_DATE|PATCH_AGE_DAYS|PENDING_REBOOT|PENDING_REASONS|LAST_BOOT_TIME\nWindows Server|10.0|20348|1|KB1|2026-01-01|200|True|CBS|2026-08-01 08:00:00\n")
            results = {item.name: item for item in parse_host(str(raw))}
            self.assertEqual(results["防火墙状态"].status, "WARN")
            self.assertEqual(results["Oracle端口暴露"].status, "WARN")
            self.assertEqual(results["时间同步"].status, "CRIT")
            self.assertEqual(results["Windows关键事件"].status, "CRIT")
            self.assertEqual(results["Windows补丁与重启"].status, "CRIT")

    def test_sustained_performance_samples_replace_single_point_values(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            header = "TIME|SAMPLE|CPU_TOTAL_PCT|CPU_PRIVILEGED_PCT|PROCESSOR_QUEUE_LENGTH|AVAILABLE_MB|COMMITTED_PCT|PAGES_PER_SEC|PAGEFILE_PCT|DISK|READ_LATENCY_MS|WRITE_LATENCY_MS|QUEUE_LENGTH|BUSY_PCT|READ_IOPS|WRITE_IOPS|READ_MBPS|WRITE_MBPS"
            lines = [header] + [f"2026-08-30 12:00:{sample:02d}|{sample}|96|85|24|500|98|800|90|0 C:|60|70|8|95|100|100|10|10" for sample in range(1, 11)]
            self._write(raw, "host/performance_samples.txt", "\n".join(lines) + "\n")
            results = {item.name: item for item in parse_host(str(raw))}
            self.assertEqual(results["CPU使用率"].status, "CRIT")
            self.assertEqual(results["内存使用率"].status, "CRIT")
            self.assertEqual(results["磁盘IO延迟"].status, "CRIT")

    def test_running_service_without_process_is_critical(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            self._write(raw, "host/oracle_processes.txt", "PID|NAME|PATH|COMMAND_LINE|CPU_PCT|WORKING_SET_MB|PRIVATE_MB|THREADS|HANDLES|UPTIME_HOURS\n")
            result = {item.name: item for item in parse_host(str(raw))}
            self.assertEqual(result["Oracle进程健康"].status, "CRIT")
            self.assertIn("oracle.exe", result["Oracle进程健康"].detail)

    def test_optional_collection_failure_is_not_reported_as_zero_events(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            self._write(raw, "collection_manifest.tsv", "item\ttype\tstatus\texit_code\tmessage\ncritical_events.txt\tCOMMAND\tWARN\t1\tSecurity access denied\n")
            result = {item.name: item for item in parse_host(str(raw))}
            self.assertEqual(result["Windows关键事件"].status, "UNKNOWN")
            self.assertIn("失败", result["Windows关键事件"].value)

    def test_windows_database_storage_volume_capacity_is_scored(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._write(raw, "env.info", "platform=windows\ncheck_type=db\n")
            self._write(raw, "db/storage_path_capacity.txt", "TYPE|STORAGE_KIND|VOLUME|PATH_COUNT|EXAMPLE_PATH|TOTAL_GB|FREE_GB|USAGE_PCT\nDATAFILE|FILESYSTEM|D:|12|D:\\oradata\\orcl\\system01.dbf|500|9|98.2\nREDO|FILESYSTEM|E:|3|E:\\redo\\redo01.log|200|100|50\nASM|ASM|+DATA|5|+DATA/ORCL/DATAFILE/system.1|||\n")
            result = {item.name: item for item in parse_db(str(raw))["db"]}
            self.assertEqual(result["Oracle存储卷容量"].status, "CRIT")
            self.assertIn("98.2%", result["Oracle存储卷容量"].value)

    def test_windows_acl_parser_replaces_unix_permission_logic(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._write(raw, "env.info", "platform=windows\n")
            self._write(raw, "security/oracle_home_acl.txt", "PATH|OWNER|IDENTITY|RIGHTS|TYPE|INHERITED\nD:\\Oracle|Administrators|Everyone|Modify|Allow|True\n")
            # 数据库安全解析器所需的其余文件允许为空表头。
            for name, header in {
                "password_policy.txt": "PROFILE|RESOURCE_NAME|RESOURCE_TYPE|LIMIT",
                "db_users.txt": "USERNAME|ACCOUNT_STATUS",
                "dba_role_users.txt": "GRANTEE|GRANTED_ROLE",
                "audit_settings.txt": "NAME|VALUE",
                "unified_audit_policies.txt": "POLICY_NAME",
                "traditional_audit_options.txt": "USER_NAME",
                "public_risky_grants.txt": "OWNER",
                "sys_privs.txt": "GRANTEE",
                "security_parameters.txt": "NAME|VALUE|ISDEFAULT",
                "listener_status.txt": "The command completed successfully\nstatus READY\nSecurity ON: Local OS Authentication",
                "listener_ora.txt": "ADMIN_RESTRICTIONS_LISTENER=ON",
                "sqlnet_ora.txt": "SQLNET.ENCRYPTION_SERVER=REQUIRED",
            }.items():
                self._write(raw, f"security/{name}", header + "\n")
            result = {item.name: item for item in parse_security(str(raw))}
            self.assertEqual(result["操作系统安全性"].status, "WARN")
            self.assertIn("宽泛写权限", result["操作系统安全性"].value)

    def test_windows_host_collection_builds_html_and_docx_contract(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td, "raw")
            raw.mkdir()
            self._make_host(raw)
            output = Path(td, "reports")
            result = build_report([str(raw)], str(output), write_html=True, write_docx=False)
            self.assertTrue(Path(result.html).is_file())
            html = Path(result.html).read_text(encoding="utf-8")
            self.assertIn("WIN-ORA01", html)
            self.assertIn("Windows事件日志", html)
            self.assertIn("Oracle服务", html)


if __name__ == "__main__":
    unittest.main()
