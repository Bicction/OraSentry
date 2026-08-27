# -*- coding: utf-8 -*-
"""Collector 独立性与 Oracle 兼容性静态回归测试。"""
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CollectorTests(unittest.TestCase):
    def test_bundle_contains_required_files(self):
        required = (
            "main.sh",
            "main_host.sh",
            "main_db.sh",
            "conf/check.conf",
            "lib/common.sh",
            "lib/host_check.sh",
            "lib/db_check.sh",
            "lib/security_check.sh",
        )
        for relative_path in required:
            self.assertTrue((ROOT / relative_path).is_file(), relative_path)

    def test_output_is_relative_to_collector_root(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        self.assertIn('raw_base="${COLLECT_DIR}/${RAW_DATA_DIR}"', common)
        self.assertNotIn("PROJECT_DIR", common)

    def test_collector_does_not_reference_reporter_code(self):
        scripts = [ROOT / "main.sh", ROOT / "main_host.sh", ROOT / "main_db.sh"]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in scripts)
        self.assertNotIn("report/report_gen.py", combined)
        self.assertNotIn("reporter/report_gen.py", combined)

    def test_oracle_11g_queries_do_not_use_fetch_first(self):
        db_script = (ROOT / "lib" / "db_check.sh").read_text(encoding="utf-8")
        self.assertNotIn("FETCH FIRST", db_script.upper())
        self.assertIn("WHERE ROWNUM <= 20", db_script.upper())

    def test_database_archive_name_includes_sid_before_timestamp(self):
        main_script = (ROOT / "main_db.sh").read_text(encoding="utf-8")
        self.assertIn(
            'pack_collection "db_check_${safe_sid}_${CHECK_TIMESTAMP}.tar.gz"',
            main_script,
        )
        self.assertNotIn("db_check_${CHECK_TIMESTAMP}.tar.gz", main_script)

    def test_v42_schema_and_version_are_recorded(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        self.assertIn('COLLECTOR_VERSION="4.2.0"', common)
        self.assertIn('SCHEMA_VERSION="4.2"', common)
        self.assertIn('echo "schema_version=${SCHEMA_VERSION}"', common)

    def test_plaintext_database_password_is_rejected_and_never_debugged(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        config = (ROOT / "conf" / "check.conf").read_text(encoding="utf-8")
        self.assertIn("不再支持 DB_USER/DB_PASS", common)
        self.assertNotIn('log_debug "DB_CONNECT=', common)
        self.assertNotIn("#DB_PASS=", config)
        self.assertIn("DB_WALLET_ALIAS", config)

    def test_sensitive_features_are_opt_in(self):
        config = (ROOT / "conf" / "check.conf").read_text(encoding="utf-8")
        self.assertIn("CHECK_AWR=off", config)
        self.assertIn("COLLECT_SQL_TEXT=off", config)

    def test_top_process_commands_support_legacy_procps(self):
        host_script = (ROOT / "lib" / "host_check.sh").read_text(encoding="utf-8")
        command_lines = [
            line for line in host_script.splitlines()
            if "top_cpu_processes.txt" in line or "top_mem_processes.txt" in line
        ]
        commands = "\n".join(command_lines)
        self.assertIn("pcpu,pmem", commands)
        self.assertNotIn("%cpu", commands)
        self.assertNotIn("%mem", commands)
        self.assertIn("etime", commands)
        self.assertNotIn("etimes", commands)
        self.assertNotIn("| head", commands)
        self.assertIn("| sed -n '1,21p'", commands)
        self.assertNotIn('collect_cmd "${d}/top_', commands)
        self.assertIn('collect_optional_cmd "${d}/top_', commands)

    def test_alert_log_uses_instance_physical_file_for_thirty_days(self):
        db_script = (ROOT / "lib" / "db_check.sh").read_text(encoding="utf-8")
        self.assertIn('alert_log_summary.txt', db_script)
        self.assertIn("name='Diag Trace'", db_script)
        self.assertIn('alert_file="${diag_dir}/alert_${ORACLE_SID}.log"', db_script)
        self.assertIn("date -d '30 days ago'", db_script)
        self.assertIn('alert_log_30days.txt', db_script)
        self.assertIn('tail -n 100001 "${alert_file}"', db_script)
        self.assertIn('tail -n 100000 "${sample_candidate}"', db_script)
        self.assertIn('alert_log_last_100000.txt', db_script)
        self.assertIn("stat -c '%s'", db_script)
        self.assertIn('ALERT_FILE_SIZE_BYTES', db_script)
        self.assertIn('ANALYSIS_START_TIME|ANALYSIS_END_TIME', db_script)
        self.assertNotIn('v\\$diag_alert_ext', db_script)

    def test_instance_status_uses_gv_instance_for_all_instances(self):
        db_script = (ROOT / "lib" / "db_check.sh").read_text(encoding="utf-8")
        self.assertIn(
            "SELECT inst_id, instance_name, host_name, status, database_status, version, startup_time FROM gv\\$instance ORDER BY inst_id;",
            db_script,
        )

    def test_alert_log_does_not_fall_back_to_background_dump_dest(self):
        db_script = (ROOT / "lib" / "db_check.sh").read_text(encoding="utf-8")
        alert_section = db_script[db_script.index("collect_alert_log()") : db_script.index("# 跟踪文件")]
        self.assertNotIn("background_dump_dest", alert_section)
        self.assertNotIn("legacy_alert_file", alert_section)

    @unittest.skipUnless(shutil.which("bash"), "bash is not available")
    def test_shell_scripts_pass_bash_syntax_check(self):
        scripts = [
            ROOT / "main.sh",
            ROOT / "main_host.sh",
            ROOT / "main_db.sh",
            *sorted((ROOT / "lib").glob("*.sh")),
        ]
        subprocess.run(
            ["bash", "-n", *map(str, scripts)],
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
