# -*- coding: utf-8 -*-
"""Windows 采集包解析与报告端到端回归测试。"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from parser.host_parser import parse_host
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
        self._write(root, "host/time_sync.txt", "LOCAL_TIME|TIMEZONE|SERVICE_STATUS|SOURCE\n2026-08-30 12:00:00 +08:00|China Standard Time|Running|dc01\n")
        self._write(root, "host/network_listen.txt", "PROTOCOL|LOCAL_ADDRESS|LOCAL_PORT|STATE|PID|PROCESS\nTCP|0.0.0.0|1521|Listen|100|tnslsnr\n")
        self._write(root, "host/event_log_errors.txt", "TIME|LOG|EVENT_ID|LEVEL|PROVIDER|MESSAGE\n")
        self._write(root, "host/oracle_services.txt", "NAME|DISPLAY_NAME|STATE|START_MODE|ACCOUNT|PID|PATH\nOracleServiceORCL|OracleServiceORCL|Running|Auto|LocalSystem|123|D:\\oracle\\bin\\oracle.exe\n")
        self._write(root, "host/disk_io.txt", "DISK|READ_LATENCY_MS|WRITE_LATENCY_MS|BUSY_PCT|READ_IOPS|WRITE_IOPS\n0 C:|2.5|3.0|20|50|25\n")

    def test_windows_host_parser_dispatches_and_marks_not_applicable_items_info(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td)
            self._make_host(raw)
            results = parse_host(str(raw))
            by_name = {item.name: item for item in results}
            self.assertEqual(by_name["磁盘使用率-D:"].status, "CRIT")
            self.assertEqual(by_name["inode使用率"].status, "INFO")
            self.assertEqual(by_name["CPU使用率"].value, "32.5%")
            self.assertEqual(by_name["Oracle服务"].status, "OK")

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
