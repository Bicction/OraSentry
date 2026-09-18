import unittest
from pathlib import Path

class ClusterDataGuardCollectionTests(unittest.TestCase):
    def test_cluster_queries_preserve_instance_coverage_and_local_evidence(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'lib/DatabaseCheck.ps1').read_text(encoding='utf-8-sig')
        for name in ('dataguard_context.txt', 'dataguard_cluster_process.txt',
                     'dataguard_cluster_stats.txt', 'dataguard_process.txt'):
            self.assertIn(name, source)
        for fragment in ('LEFT JOIN gv`$managed_standby', 'LEFT JOIN gv`$dataguard_process',
                         'FROM gv`$dataguard_stats', 'DG_CLUSTER_OK', 'DG_STATS_OK',
                         'cluster_database', 'collected_at'):
            self.assertIn(fragment, source)
