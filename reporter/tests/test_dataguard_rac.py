import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from parser.db_parser import _parse_dataguard


class RacDataGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put('dataguard_identity', 'ORCL|orcl_stby|PHYSICAL STANDBY|READ ONLY WITH APPLY|ARCHIVELOG|YES|NO|MAXIMUM PERFORMANCE|MAXIMUM PERFORMANCE|NOT ALLOWED\n')
        self.put('dataguard_process', 'PROCESS_R|THREAD#|SEQUENCE#|PROCESS_ACTI|CLIENT_P\nARCH|0|0|CONNECTED|ARCH\n')
        self.put('dataguard_stats', 'apply lag|+00 00:00:00||09/15/2026 17:00:00|09/15/2026 16:59:59\n')
        self.put('rac_nodes', '1|1|ORCL1|db0|OPEN|ACTIVE\n2|2|ORCL2|db1|OPEN|ACTIVE\n')
        self.put('archive_gap', '')

    def put(self, name, text):
        (self.root / (name + '.txt')).write_text(text, encoding='utf-8')

    def result(self):
        return next(r for r in _parse_dataguard(str(self.root)) if r.name == 'DG Redo应用')

    def cluster(self, owner='1', action='APPLYING_LOG', role='MRP0', lag='+00 00:00:00'):
        self.put('dataguard_context', '2|ORCL2|db1|TRUE|2026-09-15 17:00:00\n')
        rows = []
        for i, host in [('1', 'db0'), ('2', 'db1')]:
            process = f'{role}|1|100|{action}|N/A' if i == owner else '||||'
            rows.append(f'{i}|ORCL{i}|{host}|{process}|2026-09-15 17:00:00')
        self.put('dataguard_cluster_process', '\n'.join(rows) + '\nDG_CLUSTER_OK\n')
        self.put('dataguard_cluster_stats', f'{owner or "1"}|apply lag|{lag}||09/15/2026 17:00:00|09/15/2026 16:59:59|2026-09-15 17:00:00\nDG_STATS_OK\n')

    def test_legacy_non_apply_rac_is_information_not_healthy_or_critical(self):
        r = self.result()
        self.assertEqual(r.status, 'INFO')
        self.assertIn('待确认', r.value)
        self.assertNotIn('未发现Redo Apply/MRP进程', r.suggestion)

    def test_legacy_read_only_rac_is_unknown(self):
        p = self.root / 'dataguard_identity.txt'
        p.write_text(p.read_text().replace('READ ONLY WITH APPLY', 'READ ONLY'))
        self.assertEqual(self.result().status, 'UNKNOWN')

    def test_legacy_local_apply_stays_healthy(self):
        self.put('dataguard_process', 'MRP0|1|100|WAIT_FOR_LOG|N/A\n')
        self.assertEqual(self.result().status, 'OK')

    def test_single_instance_missing_mrp_remains_critical(self):
        self.put('rac_nodes', '1|1|ORCL1|db0|OPEN|ACTIVE\n')
        self.assertEqual(self.result().status, 'CRIT')

    def test_remote_apply_is_healthy_and_names_owner(self):
        self.cluster()
        r = self.result()
        self.assertEqual(r.status, 'OK')
        self.assertIn('db0 / ORCL1', r.value)
        self.assertIn('本实例未承担', r.detail)

    def test_apply_relocation_is_detected_without_host_whitelist(self):
        self.cluster(owner='2')
        r = self.result()
        self.assertEqual(r.status, 'OK')
        self.assertIn('db1 / ORCL2', r.value)
        self.assertIn('本实例承担', r.detail)

    def test_modern_managed_recovery_and_logmerger_are_supported(self):
        for role in ['managed recovery', 'recovery logmerger']:
            with self.subTest(role=role):
                self.cluster(role=role)
                self.assertEqual(self.result().status, 'OK')

    def test_cluster_without_apply_is_critical_even_with_zero_lag(self):
        self.cluster(owner=None)
        self.assertEqual(self.result().status, 'CRIT')
        self.assertIn('集群未发现', self.result().value)

    def test_partial_failed_or_truncated_cluster_cannot_claim_stopped_or_healthy(self):
        for mode in ['partial', 'error', 'marker', 'context', 'old']:
            with self.subTest(mode=mode):
                self.cluster(owner=None)
                p = self.root / 'dataguard_cluster_process.txt'
                s = p.read_text()
                if mode == 'partial':
                    s = '\n'.join(s.splitlines()[1:])
                elif mode == 'error':
                    s += 'ORA-00942: table or view does not exist\n'
                elif mode == 'marker':
                    s = s.replace('DG_CLUSTER_OK', '')
                elif mode == 'context':
                    self.put('dataguard_context', 'SP2-0734: error\n')
                else:
                    s = s.replace('17:00:00', '16:00:00')
                p.write_text(s)
                self.assertEqual(self.result().status, 'UNKNOWN')

    def test_local_query_failure_and_empty_file_are_unknown(self):
        for text in ['', 'ORA-00942: table or view does not exist\n']:
            self.put('dataguard_process', text)
            self.assertEqual(self.result().status, 'UNKNOWN')

    def test_owner_lag_overrides_nonowner_zero_and_keeps_thresholds(self):
        for lag, status in [('+00 00:06:00', 'WARN'), ('+00 00:31:00', 'CRIT')]:
            self.cluster(lag=lag)
            self.assertEqual(self.result().status, status)

    def test_stale_and_frozen_metrics_are_not_healthy(self):
        for computed, datum in [('17:00:00', '16:00:00'), ('16:00:00', '16:00:00')]:
            self.cluster()
            self.put('dataguard_cluster_stats', f'1|apply lag|+00 00:00:00||09/15/2026 {computed}|09/15/2026 {datum}|2026-09-15 17:00:00\nDG_STATS_OK\n')
            self.assertEqual(self.result().status, 'CRIT')

    def test_entire_old_stats_snapshot_is_compared_with_process_collection_time(self):
        self.cluster()
        self.put('dataguard_cluster_stats', '1|apply lag|+00 00:00:00||09/15/2026 16:00:00|09/15/2026 16:00:00|2026-09-15 16:00:00\nDG_STATS_OK\n')
        self.assertEqual(self.result().status, 'CRIT')

    def test_missing_owner_lag_does_not_use_nonowner_zero(self):
        self.cluster()
        self.put('dataguard_cluster_stats', '2|apply lag|+00 00:00:00||09/15/2026 17:00:00|09/15/2026 16:59:59|2026-09-15 17:00:00\nDG_STATS_OK\n')
        self.assertEqual(self.result().status, 'UNKNOWN')

    def test_apply_gap_and_errors_remain_critical(self):
        for action in ['WAIT_FOR_GAP', 'ERROR', 'STOPPED']:
            self.cluster(action=action)
            self.assertEqual(self.result().status, 'CRIT')
        self.cluster()
        self.put('archive_gap', '1|101|103\n')
        self.assertEqual(self.result().status, 'CRIT')

    def test_legacy_rac_preserves_lag_risk(self):
        self.put('dataguard_stats', 'apply lag|+00 00:31:00||09/15/2026 17:00:00|09/15/2026 16:59:59\n')
        self.assertEqual(self.result().status, 'CRIT')

    def test_rfs_client_text_does_not_count_as_apply(self):
        self.cluster(role='RFS', action='RECEIVING')
        self.assertEqual(self.result().status, 'CRIT')

    def test_primary_does_not_require_redo_apply(self):
        self.put('dataguard_identity', 'ORCL|orcl|PRIMARY|READ WRITE|ARCHIVELOG|YES|NO|MAXIMUM PERFORMANCE|MAXIMUM PERFORMANCE|NOT ALLOWED\n')
        self.assertNotIn('DG Redo应用', [r.name for r in _parse_dataguard(str(self.root))])


if __name__ == '__main__':
    unittest.main()
