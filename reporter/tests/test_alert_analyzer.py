import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from alert_analyzer import analyze_alert_directory, build_alert_check, _read_text
from docx_gen import parse_extra_html


class AlertAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "db"
        self.db.mkdir()

    def write(self, name, text, encoding="utf-8"):
        (self.db / name).write_text(text, encoding=encoding)

    def raw(self, text):
        self.write("alert_log_30days.txt", text)

    def summary(self, count, severe=0, **fields):
        values = dict(DATABASE_NAME="ORCL", INSTANCE_NAME="ORCL", HOST_NAME="db1",
                      ALERT_FILE="/diag/alert_ORCL.log", ALERT_COUNT=str(count), SEVERE_COUNT=str(severe),
                      FIRST_TIME="2026-08-01 00:00:00", LAST_TIME="2026-08-02 00:00:00",
                      WINDOW_DAYS="30", WINDOW_TRUNCATED="NO")
        values.update(fields)
        self.write("alert_log_summary.txt", "|".join(values) + "\n" + "|".join(values.values()) + "\n")

    def test_redo_chain_is_one_event_with_action_and_os_evidence(self):
        self.raw("2026-08-01T12:00:00.123456+08:00\nErrors in file /diag/example.trc:\n"
                 "ORA-00313: open failed for members of log group 1 of thread 1\n"
                 "ORA-00312: online log 1 thread 1: '+DATA/ORCL/ONLINELOG/group_1.257.123'\n"
                 "ORA-27041: unable to open file\nLinux-x86_64 Error: 2: No such file or directory\n")
        self.summary(4)
        analysis = analyze_alert_directory(self.db)
        self.assertEqual(analysis.event_count, 1)
        self.assertEqual(analysis.findings[0].severity, "CRIT")
        result = build_alert_check(self.db)
        self.assertIn("1个已观测告警事件", result.value)
        self.assertIn("OS 2", result.extra_html)
        self.assertIn("ORA-00312", result.extra_html)
        self.assertIn("处理建议", result.extra_html)
        self.assertIn("RESETLOGS", result.extra_html)
        self.assertIn("关键词命中 4 行", result.detail)

    def test_raw_noise_does_not_inherit_legacy_count_severity(self):
        self.raw("2026-08-01T12:00:00+08:00\nVKTM started at elevated (Time Critical) priority\n"
                 "If any errors are encountered before the pdb is marked as NEW,\nERROR(s)\n")
        self.summary(200)
        result = build_alert_check(self.db)
        self.assertEqual(result.status, "OK")
        self.assertIn("0个已观测", result.value)

    def test_catalog_is_not_loaded_when_log_has_no_diagnostic_codes(self):
        self.raw("2026-08-01T12:00:00+08:00\nDatabase mounted in Exclusive Mode\n")
        self.summary(0)
        with patch("alert_analyzer.catalog_metadata", side_effect=AssertionError("catalog should stay lazy")):
            analysis = analyze_alert_directory(self.db)
        self.assertEqual(analysis.event_count, 0)
        self.assertIn("按需未加载", analysis.catalog_version)

    def test_same_code_distinct_internal_arguments_stay_separate(self):
        self.raw("2026-08-01T12:00:00+08:00\nORA-00600: internal error [alpha], [1]\n"
                 "2026-08-01T12:00:01+08:00\nORA-00600: internal error [beta], [1]\n"
                 "2026-08-01T12:00:02+08:00\nORA-00600: internal error [alpha], [2]\n")
        analysis = analyze_alert_directory(self.db)
        self.assertEqual(analysis.event_count, 3)
        self.assertEqual(len(analysis.findings), 2)
        self.assertIn("[alpha]", analysis.findings[0].title)
        self.assertEqual(analysis.findings[0].count, 2)

    def test_qopatch_chain_explains_root_and_stack(self):
        self.raw("2026-08-01T12:00:00+08:00\n"
                 "ORA-06502: PL/SQL: 数字或值错误\nORA-06512: 在 SYS.DBMS_QOPATCH line 2327\n"
                 "ORA-29913: 执行 ODCIEXTTABLEFETCH 调出时出错\n"
                 "ORA-29400: 数据插件错误 KUP-04020: record exceeds buffer size\n"
                 "ORA-06512: 在 SYS.DBMS_QOPATCH line 927\n")
        analysis = analyze_alert_directory(self.db)
        self.assertEqual(analysis.event_count, 1)
        self.assertEqual(analysis.findings[0].title, "QOPatch 补丁清单读取失败")
        result = build_alert_check(self.db)
        self.assertIn("ORA-06512", result.extra_html)
        self.assertIn("调用栈", result.extra_html)
        self.assertEqual(result.status, "WARN")

    def test_single_critical_event_does_not_need_count_threshold(self):
        self.raw("2026-08-01T12:00:00Z\nORA-01578: ORACLE data block corrupted\n")
        self.assertEqual(build_alert_check(self.db).status, "CRIT")

    def test_success_code_is_information_and_wrapper_keeps_known_impact(self):
        self.raw("2026-08-01T12:00:00Z\nORA-00000: normal successful completion\n")
        result = build_alert_check(self.db)
        self.assertEqual(result.status, "OK")
        self.assertIn("0个已观测", result.value)
        self.raw("2026-08-01T12:00:00Z\nORA-00257: archiver error\n")
        self.assertEqual(build_alert_check(self.db).status, "CRIT")
        self.raw("2026-08-01T12:00:00Z\nORA-16038: cannot archive\nORA-27041: unable to open file\n")
        self.assertEqual(build_alert_check(self.db).status, "CRIT")

    def test_missing_and_untrusted_empty_are_unknown(self):
        self.assertEqual(build_alert_check(self.db).status, "UNKNOWN")
        self.raw("")  # e.g. collector timestamp extraction failed
        self.assertEqual(build_alert_check(self.db).status, "UNKNOWN")
        self.write("alert_log_recent.txt", "EVENT_TIME|MESSAGE_TEXT\n")
        self.assertEqual(build_alert_check(self.db).status, "UNKNOWN")
        self.summary(0)
        self.assertEqual(build_alert_check(self.db).status, "OK")

    def test_unknown_and_custom_errors_are_visible_not_guessed(self):
        self.raw("2026-08-01T12:00:00Z\nORA-999999: <script>alert('sample')</script>\n"
                 "2026-08-01T12:00:01Z\nORA-20001: customer rule failed\n")
        result = build_alert_check(self.db)
        self.assertNotEqual(result.status, "OK")
        self.assertIn("ORA-999999", result.extra_html)
        self.assertIn("ORA-20001", result.extra_html)
        self.assertNotIn("<script>", result.extra_html)
        self.assertIn("&lt;script&gt;", result.extra_html)

    def test_filtered_legacy_three_formats_preserve_scope_and_pipes(self):
        headers_rows = [
            ("EVENT_TIME|MESSAGE_TEXT", "2026-08-01T12:00:00Z|ORA-01653: unable to extend T|extra"),
            ("EVENT_TIME|MESSAGE_TYPE|MESSAGE_LEVEL|PROBLEM_KEY|MESSAGE_TEXT", "2026-08-01T12:00:00Z|1|16||ORA-01653: unable to extend T|extra"),
            ("DATABASE_NAME|INSTANCE_NAME|HOST_NAME|CON_ID|EVENT_TIME|MESSAGE_TYPE|MESSAGE_LEVEL|PROBLEM_KEY|MESSAGE_TEXT", "DB|inst1|host1|0|2026-08-01T12:00:00Z|1|16||ORA-01653: unable to extend T|extra"),
        ]
        for header, row in headers_rows:
            with self.subTest(header=header):
                self.write("alert_log_recent.txt", header + "\n" + row + "\n")
                self.summary(1440)
                analysis = analyze_alert_directory(self.db)
                self.assertEqual(analysis.event_count, 1)
                self.assertTrue(analysis.incomplete)
                self.assertIn("2026-08-01", analysis.findings[0].time)
                self.assertIn("T|extra", analysis.findings[0].evidence)
                result = build_alert_check(self.db)
                self.assertIn("关键词命中 1440 行", result.detail)
                self.assertNotIn("1440个", result.value)

    def test_truncation_and_existing_replacement_character_are_disclosed(self):
        self.raw("2026-08-01T12:00:00Z\nORA-04031: 无法分配\ufffd\n")
        self.summary(1, WINDOW_TRUNCATED="YES")
        analysis = analyze_alert_directory(self.db)
        self.assertTrue(analysis.incomplete)
        self.assertIn("乱码", "".join(analysis.notes))
        self.assertIn("上限", "".join(analysis.notes))

    def test_utf16_and_gb18030_do_not_drop_error_evidence(self):
        for encoding in ("utf-16", "gb18030", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                self.write("alert_log_30days.txt", "2026-08-01T12:00:00Z\nORA-04031: 无法分配内存\n", encoding)
                analysis = analyze_alert_directory(self.db)
                self.assertEqual(analysis.event_count, 1)
                self.assertIn("无法分配内存", analysis.findings[0].evidence)

    def test_bounded_utf16_tail_keeps_alignment(self):
        self.write("large.txt", "old line\n" * 20 + "2026-08-01T12:00:00Z\nORA-01578: data block corrupted\n", "utf-16")
        text, partial = _read_text(self.db / "large.txt", [], limit=130)
        self.assertTrue(partial)
        self.assertIn("ORA-01578", text)
        self.assertNotIn("\x00", text)

    def test_asm_and_unquoted_tablespace_objects_stay_separate(self):
        self.raw("2026-08-01T12:00:00Z\nORA-01653: unable to extend table A.T by 8 in tablespace TS1\n"
                 "2026-08-01T12:00:01Z\nORA-01653: unable to extend table B.T by 8 in tablespace TS2\n")
        self.assertEqual(len(analyze_alert_directory(self.db).findings), 2)

    def test_missing_catalog_does_not_make_log_disappear(self):
        self.raw("2026-08-01T12:00:00Z\nORA-01578: data block corrupted\n")
        with patch("alert_analyzer.catalog_metadata", side_effect=ValueError("invalid schema")):
            result = build_alert_check(self.db)
        self.assertNotEqual(result.status, "OK")
        self.assertIn("词典不可用", result.extra_html)
        self.assertIn("ORA-01578", result.extra_html)

    def test_word_block_conversion_preserves_explanations_and_evidence(self):
        self.raw("2026-08-01T12:00:00Z\nORA-01578: data block corrupted\n")
        blocks = parse_extra_html(build_alert_check(self.db).extra_html)
        text = str(blocks)
        for expected in ("ORA-01578", "处理建议", "建议排查", "置信度", "官方消息", "官方参考", "data block corrupted"):
            self.assertIn(expected, text)

    def test_catalog_version_hides_entry_count_and_phase_label(self):
        self.raw("2026-08-01T12:00:00Z\nORA-01578: data block corrupted\n")
        rendered = build_alert_check(self.db).extra_html
        self.assertIn("2026.09.07-v3", rendered)
        self.assertNotIn("个词条", rendered)
        self.assertNotIn("首版常见错误", rendered)

    def test_noncode_hang_and_instance_termination_cannot_turn_ok(self):
        self.raw("2026-08-01T12:00:00Z\nHang detected: chain 1\n")
        self.assertNotEqual(build_alert_check(self.db).status, "OK")
        self.raw("2026-08-01T12:00:00Z\nORA-00700: soft internal error [pga physmem limit]\nInstance terminated by LGWR\n")
        self.assertEqual(build_alert_check(self.db).status, "CRIT")


if __name__ == "__main__":
    unittest.main()
