# -*- coding: utf-8 -*-
"""Message-stack parsing: event counts, evidence retention and input bounds."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from parser.alert_event_parser import (
    MAX_EVENT_CODES, MAX_EVENT_LINES, MAX_LINE_CHARS, TRUNCATION_MARKER, INTERLEAVING_MARKER,
    extract_codes, parse_alert_rows, parse_alert_text,
)


REDO_STACK = """Errors in file /u01/diag/rdbms/orcl/orcl/trace/orcl_lgwr_123.trc:
ORA-00313: open failed for members of log group 3 of thread 1
ORA-00312: online log 3 thread 1: '/oradata/redo03.log'
ORA-27041: unable to open file
Linux-x86_64 Error: 2: No such file or directory
Additional information: 3"""

QOPATCH_STACK = """Errors in file /u01/diag/rdbms/orcl/orcl/trace/orcl_j000_456.trc:
ORA-06502: PL/SQL: numeric or value error
ORA-06512: at "SYS.DBMS_QOPATCH", line 101
ORA-29913: error in executing ODCIEXTTABLEFETCH callout
ORA-29400: data cartridge error
KUP-04020: found record longer than buffer size supported
ORA-06512: at "SYS.DBMS_QOPATCH", line 202
ORA-06512: at line 1"""


class AlertEventParserTests(unittest.TestCase):
    def test_redo_stack_is_one_event_with_os_context(self):
        events = parse_alert_text("2026-09-07T08:01:02.123456+08:00\n" + REDO_STACK)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.codes, ["ORA-00313", "ORA-00312", "ORA-27041"])
        self.assertEqual(event.time, "2026-09-07T08:01:02.123456+08:00")
        self.assertIn("Linux-x86_64 Error: 2: No such file or directory", event.lines)
        self.assertEqual((event.line_start, event.line_end), (1, 7))

    def test_qopatch_repeated_call_stack_does_not_inflate_occurrences(self):
        events = parse_alert_text(QOPATCH_STACK)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].codes, ["ORA-06502", "ORA-06512", "ORA-29913", "ORA-29400", "KUP-04020"])
        self.assertEqual(len(events[0].lines), 8)

    def test_same_timestamp_can_contain_two_trace_stacks(self):
        events = parse_alert_text("2026-09-07T08:01:02Z\n" + REDO_STACK + "\n" + QOPATCH_STACK)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].time, events[1].time)
        self.assertEqual(events[1].line_start, 8)

    def test_repeated_primary_splits_occurrences_without_dates(self):
        text = "\n".join(["ORA-00313: failed", "ORA-00312: log a", "ORA-00312: log b", "ORA-27041: open error"] * 3)
        events = parse_alert_text(text)
        self.assertEqual(len(events), 3)
        self.assertEqual([e.line_start for e in events], [1, 5, 9])
        self.assertTrue(all(e.codes == ["ORA-00313", "ORA-00312", "ORA-27041"] for e in events))

    def test_internal_incident_does_not_consume_unrelated_adjacent_stack(self):
        events = parse_alert_text("ORA-00700: soft internal error [pga physmem limit]\nORA-06512: at line 1\nORA-01652: unable to extend temp\nORA-00700: soft internal error [other]")
        self.assertEqual([e.codes for e in events], [["ORA-00700", "ORA-06512"], ["ORA-01652"], ["ORA-00700"]])

    def test_unknown_consecutive_codes_are_conservatively_grouped(self):
        events = parse_alert_text("ORA-99998: 中文未知错误\nORA-100000: follow-up\nWindows Error: 5: 拒绝访问")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].codes, ["ORA-99998", "ORA-100000"])
        self.assertIn("拒绝访问", "\n".join(events[0].lines))

    def test_code_boundaries_and_short_code_normalization(self):
        codes = extract_codes("ora-600 ORA-00600 TNS-12541 rman-600 kup-4020 PLS-00103 CRS-4535 ORA-100000 ORA-1000000 XORA-12345 ORA-12345extra ORA-１２３４５")
        self.assertEqual(codes, ["ORA-00600", "TNS-12541", "RMAN-00600", "KUP-04020", "PLS-00103", "CRS-04535", "ORA-100000"])

    def test_11g_english_date_and_crlf(self):
        text = "Mon Sep  7 08:01:02 2026\r\nORA-01578: ORACLE data block corrupted\r\nORA-01110: data file 7: 'users.dbf'\r\nMon Sep  7 08:01:03 2026\r\nORA-04031: unable to allocate"
        events = parse_alert_text(text)
        self.assertEqual([e.time for e in events], ["Mon Sep  7 08:01:02 2026", "Mon Sep  7 08:01:03 2026"])
        self.assertEqual(events[0].codes, ["ORA-01578", "ORA-01110"])

    def test_inline_timestamp_and_z_offset_preserved(self):
        events = parse_alert_text("\ufeff2026-09-07 08:01:02.123Z ORA-00600: internal error")
        self.assertEqual(events[0].time, "2026-09-07 08:01:02.123Z")
        self.assertEqual(events[0].codes, ["ORA-00600"])

    def test_physical_repeated_timestamp_is_a_boundary(self):
        events = parse_alert_text("2026-09-07T08:01:02+0800\nORA-01652: failed\n2026-09-07T08:01:02+0800\nORA-04031: failed")
        self.assertEqual(len(events), 2)

    def test_noise_words_and_zero_corruption_are_not_candidates(self):
        text = "2026-09-07T08:01:02+08:00\nTime Critical priority\nIf any errors are encountered, contact support\nNo errors in file were detected\nCorrupt blocks found: 0\nNo corrupt blocks found\nStarting automatic hang analysis\nSystem altered."
        self.assertEqual(parse_alert_text(text), [])
        self.assertEqual(parse_alert_text("\n\r\n" * 10000), [])
        self.assertEqual(parse_alert_text(""), [])

    def test_reliable_noncode_diagnostics_are_retained(self):
        for message in ["Fatal NI connect error 12170.", "Instance terminated by LGWR", "Hang detected: chain 1", "Block corruption detected", "Errors in file /u01/a.trc:"]:
            with self.subTest(message=message):
                events = parse_alert_text(message)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].codes, [])

    def test_interleaved_ni_roots_count_once_and_mark_ambiguous_context(self):
        text = ("Mon Sep  7 08:01:02 2026\nFatal NI connect error 12170.\n"
                "Fatal NI connect error 12170.\nMon Sep  7 08:01:02 2026\n"
                "TNS-12535: timed out\nTNS-12535: timed out\n" +
                "    ns secondary err code: 12560\n" * 10 +
                "TNS-00505: timed out\nTNS-00505: timed out\nnt OS err code: 0")
        events = parse_alert_text(text)
        self.assertEqual(len(events), 2)
        self.assertTrue(all("TNS-12535" in event.codes for event in events))
        self.assertTrue(all(INTERLEAVING_MARKER in event.lines for event in events))

    def test_two_column_rows_merge_same_time_and_preserve_pipe_message(self):
        rows = [["EVENT_TIME", "MESSAGE_TEXT"]] + [["2026-09-07 08:00:00", line] for line in REDO_STACK.splitlines()]
        events = parse_alert_rows(rows)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0].line_start, events[0].line_end), (2, 7))
        self.assertEqual(events[0].codes, ["ORA-00313", "ORA-00312", "ORA-27041"])
        self.assertIn("left|right", parse_alert_rows([["now", "ORA-99999: left", "right"]])[0].lines[0])

    def test_five_column_rows_ignore_metadata_codes_and_level_alone(self):
        rows = [
            ["now", "2", "1", "ORA-00600", "Time Critical priority"],
            ["now", "2", "1", "ORA-00700", "ORA-01652: unable to extend"],
            ["now", "2", "1", "", "ORA-06512: at line 1"],
        ]
        events = parse_alert_rows(rows)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].codes, ["ORA-01652", "ORA-06512"])

    def test_nine_column_rows_keep_instances_and_hosts_separate(self):
        def row(instance, host, message):
            return ["orcl", instance, host, "source", "2026-09-07T08:00:00Z", "2", "1", "", message]
        rows = [row("orcl1", "host-a", "ORA-00313: failed"), row("orcl1", "host-a", "ORA-00312: log a"), row("orcl2", "host-a", "ORA-27041: failed"), row("orcl2", "host-b", "ORA-04031: failed")]
        events = parse_alert_rows(rows)
        self.assertEqual([(e.instance, e.host) for e in events], [("orcl1", "host-a"), ("orcl2", "host-a"), ("orcl2", "host-b")])
        self.assertEqual(events[0].codes, ["ORA-00313", "ORA-00312"])

    def test_multiline_rows_and_one_column_legacy(self):
        events = parse_alert_rows([["now", REDO_STACK], ["now", QOPATCH_STACK]])
        self.assertEqual(len(events), 2)
        self.assertEqual([(e.line_start, e.line_end) for e in events], [(1, 1), (2, 2)])
        self.assertEqual(parse_alert_rows([["ORA-00600: internal error"]])[0].codes, ["ORA-00600"])
        self.assertEqual(parse_alert_rows([[], ["", ""], ["----", "----"]]), [])
        legacy = parse_alert_rows([["2026-09-07T08:00:00Z"], ["ORA-01652: failed"], ["2026-09-07T08:00:01Z"], ["ORA-04031: failed"]])
        self.assertEqual([e.time for e in legacy], ["2026-09-07T08:00:00Z", "2026-09-07T08:00:01Z"])

    def test_oversized_context_is_bounded_and_retains_diagnostic_evidence(self):
        text = "ORA-00313: open failed\n" + "neutral context\n" * 3000 + "ORA-00312: log a\nLinux Error: 2: missing\n" + "tail context\n" * 3000
        events = parse_alert_text(text)
        self.assertEqual(len(events), 1)
        self.assertLessEqual(len(events[0].lines), MAX_EVENT_LINES + 1)
        self.assertEqual(events[0].codes, ["ORA-00313", "ORA-00312"])
        self.assertIn("Linux Error: 2: missing", events[0].lines)
        self.assertTrue(events[0].lines[-1].startswith(TRUNCATION_MARKER))
        self.assertEqual(events[0].line_end, 6003)

    def test_very_long_line_is_clipped_without_hiding_terminal_code(self):
        events = parse_alert_text("ORA-99999: " + "x" * 40000 + " ORA-100000: 尾部")
        self.assertEqual(events[0].codes, ["ORA-99999", "ORA-100000"])
        self.assertLessEqual(len(events[0].lines[0]), MAX_LINE_CHARS)
        self.assertIn("ORA-100000", events[0].lines[0])
        self.assertTrue(events[0].lines[-1].startswith(TRUNCATION_MARKER))

    def test_distinct_code_limit_is_explicit_and_later_incident_still_found(self):
        text = " ".join(f"ORA-{90000 + index}: unknown" for index in range(300)) + "\nORA-00700: [pga physmem limit]"
        events = parse_alert_text(text)
        self.assertEqual(len(events), 2)
        self.assertEqual(len(events[0].codes), MAX_EVENT_CODES)
        self.assertIn("code limit reached yes", events[0].lines[-1])
        self.assertEqual(events[1].codes, ["ORA-00700"])


if __name__ == "__main__":
    unittest.main()
