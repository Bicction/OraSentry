# -*- coding: utf-8 -*-
"""Collector 独立性与 Oracle 兼容性静态回归测试。"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def find_bash():
    discovered = shutil.which("bash")
    if discovered:
        return discovered
    for variable in ("ProgramFiles", "ProgramW6432"):
        base = os.environ.get(variable)
        if not base:
            continue
        candidate = Path(base, "Git", "bin", "bash.exe")
        if candidate.is_file():
            return str(candidate)
    return None


BASH = find_bash()


class CollectorTests(unittest.TestCase):
    def test_bundle_contains_required_files(self):
        required = (
            "OraSentry.sh",
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

    def test_linux_scripts_and_config_use_lf_line_endings(self):
        files = [
            ROOT / "OraSentry.sh",
            ROOT / "main_host.sh",
            ROOT / "main_db.sh",
            *sorted((ROOT / "lib").glob("*.sh")),
            *sorted((ROOT / "conf").glob("*.conf")),
        ]
        for path in files:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotIn(b"\r", path.read_bytes())

    def test_output_is_relative_to_collector_root(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        self.assertIn('raw_base="${COLLECT_DIR}/${RAW_DATA_DIR}"', common)
        self.assertNotIn("PROJECT_DIR", common)

    def test_collector_does_not_reference_reporter_code(self):
        scripts = [ROOT / "OraSentry.sh", ROOT / "main_host.sh", ROOT / "main_db.sh"]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in scripts)
        self.assertNotIn("report/report_gen.py", combined)
        self.assertNotIn("reporter/report_gen.py", combined)

    def test_oracle_11g_queries_do_not_use_fetch_first(self):
        db_script = (ROOT / "lib" / "db_check.sh").read_text(encoding="utf-8")
        self.assertNotIn("FETCH FIRST", db_script.upper())
        self.assertIn("WHERE ROWNUM <= 20", db_script.upper())

    def test_security_queries_exclude_oracle_maintained_principals(self):
        security = (ROOT / "lib" / "security_check.sh").read_text(encoding="utf-8")
        self.assertIn("dba_roles WHERE oracle_maintained='N'", security)
        self.assertIn("u.oracle_maintained='Y'", security)
        self.assertIn("p.owner NOT IN", security)

    def test_database_archive_name_includes_sid_before_timestamp(self):
        main_script = (ROOT / "main_db.sh").read_text(encoding="utf-8")
        self.assertIn(
            'pack_collection "db_check_${safe_sid}_${CHECK_TIMESTAMP}.tar.gz"',
            main_script,
        )
        self.assertNotIn("db_check_${CHECK_TIMESTAMP}.tar.gz", main_script)

    def test_host_archive_name_includes_hostname_before_timestamp(self):
        main_script = (ROOT / "main_host.sh").read_text(encoding="utf-8")
        self.assertIn(
            'pack_collection "host_check_${safe_hostname}_${CHECK_TIMESTAMP}.tar.gz"',
            main_script,
        )
        self.assertNotIn('pack_collection "host_check_${CHECK_TIMESTAMP}.tar.gz"', main_script)

    def test_collection_packaging_has_no_checksum_sidecar_logic(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        start = common.index("pack_collection()")
        end = common.index("\nprint_collect_summary()", start)
        pack_function = common[start:end]
        self.assertNotIn("sha256sum", pack_function)
        self.assertNotIn(".sha256", pack_function)

    @unittest.skipUnless(BASH, "bash is not available")
    def test_collection_packaging_creates_no_checksum_sidecar(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            work = Path(td)
            raw = work / "raw"
            raw.mkdir()
            (raw / "env.info").write_text(
                "schema_version=4.2\ncollection_type=db\n",
                encoding="utf-8",
                newline="\n",
            )
            relative = work.relative_to(ROOT).as_posix()
            archive_name = "db_check_ORCL_20260829_120000.tar.gz"
            command = f"""
source lib/common.sh
RAW_BASE='{relative}'
RAW_DIR='{relative}/raw'
LOG_FILE='{relative}/raw/collect.log'
NO_PACK=false
pack_collection '{archive_name}'
"""
            result = subprocess.run(
                [BASH, "-c", command],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((work / archive_name).is_file())
            self.assertFalse((work / f"{archive_name}.sha256").exists())
            self.assertEqual(
                sorted(path.name for path in work.iterdir()),
                [archive_name, "raw"],
            )

    def test_v43_schema_platform_and_version_are_recorded(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        self.assertIn('COLLECTOR_VERSION="4.3.0"', common)
        self.assertIn('SCHEMA_VERSION="4.3"', common)
        self.assertIn('echo "platform=linux"', common)
        self.assertIn('echo "schema_version=${SCHEMA_VERSION}"', common)

    def test_database_password_is_prompted_and_never_configured_or_debugged(self):
        common = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
        config = (ROOT / "conf" / "check.conf").read_text(encoding="utf-8")
        self.assertIn("不支持通过 DB_USER/DB_PASS", common)
        self.assertNotIn('log_debug "DB_CONNECT=', common)
        self.assertNotIn("#DB_PASS=", config)
        self.assertIn("DB_INTERACTIVE_LOGIN=off", config)
        self.assertIn("prompt_database_login", common)
        self.assertIn("默认 SERVICE_NAME", common)
        self.assertIn("SERVICE_NAME|SID", common)
        self.assertIn('IFS= read -r -s -p "  密码: " DB_LOGIN_PASSWORD', common)
        self.assertIn('set +x', common)
        self.assertIn("DB_WALLET_ALIAS", config)

    def test_all_database_sqlplus_calls_use_secure_wrapper(self):
        scripts = [ROOT / "lib" / "common.sh", ROOT / "lib" / "db_check.sh"]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in scripts)
        self.assertIn("db_sqlplus()", combined)
        raw_calls = [
            line for line in combined.splitlines()
            if "sqlplus -" in line and "db_sqlplus" not in line
        ]
        self.assertEqual(raw_calls, [])
        self.assertNotIn("${DB_LOGIN_PASSWORD}@", combined)

    @unittest.skipUnless(BASH, "bash is not available")
    def test_interactive_password_is_stdin_only_and_hidden_from_xtrace(self):
        secret = 'Fake-P@ss/with "spaces"!'
        quoted_secret = secret.replace('"', '""')
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            work = Path(td)
            oracle_home = work / "oracle"
            bin_dir = oracle_home / "bin"
            bin_dir.mkdir(parents=True)
            fake_sqlplus = bin_dir / "sqlplus"
            fake_sqlplus.write_text(
                "#!/bin/bash\n"
                "printf '%s\\n' \"$@\" > \"${FAKE_SQLPLUS_ARGS}\"\n"
                "cat > \"${FAKE_SQLPLUS_STDIN}\"\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_sqlplus.chmod(0o755)

            relative = work.relative_to(ROOT).as_posix()
            command = f"""
export PATH="/usr/bin:/bin:$PATH"
source lib/common.sh
ORACLE_HOME='{relative}/oracle'
DB_AUTH_MODE='interactive_password'
export FAKE_SQLPLUS_ARGS='{relative}/args.txt'
export FAKE_SQLPLUS_STDIN='{relative}/stdin.txt'
set -x
prompt_database_login <<'PROMPT_INPUT'
192.0.2.10


ORCL
sys
{secret}
sysdba
PROMPT_INPUT
DB_CONNECT_DESCRIPTOR="(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${{DB_LOGIN_HOST}})(PORT=${{DB_LOGIN_PORT}}))(CONNECT_DATA=(${{DB_LOGIN_CONNECT_TYPE}}=${{DB_LOGIN_CONNECT_NAME}})))"
printf 'SELECT 1 FROM dual;\nEXIT\n' | db_sqlplus -L -S
"""
            result = subprocess.run(
                [BASH, "-c", command],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            args = (work / "args.txt").read_text(encoding="utf-8")
            stdin = (work / "stdin.txt").read_text(encoding="utf-8")
            trace = result.stdout + result.stderr
            self.assertNotIn(secret, args)
            self.assertNotIn(secret, trace)
            self.assertIn("/nolog", args)
            self.assertNotIn("sys@", args)
            self.assertNotIn(secret, stdin.splitlines())
            self.assertIn(f'CONNECT sys/"{quoted_secret}"@', stdin)
            self.assertIn("SERVICE_NAME=ORCL", stdin)
            self.assertNotIn("SID=ORCL", stdin)
            self.assertIn("AS SYSDBA", stdin)
            self.assertIn("SET ECHO OFF", stdin)
            self.assertIn("SET DEFINE OFF", stdin)

    def test_sensitive_feature_switches_are_explicit(self):
        config = (ROOT / "conf" / "check.conf").read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^CHECK_AWR=(?:on|off)$")
        self.assertRegex(config, r"(?m)^COLLECT_SQL_TEXT=(?:on|off)$")

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

    @unittest.skipUnless(BASH, "bash is not available")
    def test_shell_scripts_pass_bash_syntax_check(self):
        scripts = [
            ROOT / "OraSentry.sh",
            ROOT / "main_host.sh",
            ROOT / "main_db.sh",
            *sorted((ROOT / "lib").glob("*.sh")),
        ]
        subprocess.run(
            [BASH, "-n", *map(str, scripts)],
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
