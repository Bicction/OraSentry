from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from parser.disk_capacity import assess_disk_capacity
from parser.host_parser import _parse_disk_usage
from parser.windows_host_parser import _parse_disks
from parser.grid_parser import parse_grid_status


class HostCapacityGridTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_small_volume_with_four_gb_free_is_healthy_on_both_platforms(self):
        (self.root/'disk_usage.txt').write_text('Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 5G 1.1G 4G 22% /data\n', encoding='utf-8')
        self.assertEqual(_parse_disk_usage(str(self.root))[1].status, 'OK')
        (self.root/'disk_usage.txt').write_text('VOLUME|TOTAL_GB|USED_GB|FREE_GB|USAGE_PCT\nD:|5|1.1|4|22\n', encoding='utf-8')
        self.assertEqual(_parse_disks(str(self.root))[1].status, 'OK')

    def test_small_and_large_volumes_still_alert_when_full(self):
        for usage, total, free, expected in [(80,5,1,'WARN'),(90,5,.5,'CRIT'),
                                             (100,5,0,'CRIT'),(99,500,5,'CRIT'),
                                             (85,1000,150,'WARN'),(22,5,4,'OK')]:
            with self.subTest(usage=usage,total=total):
                self.assertEqual(assess_disk_capacity(usage,total,free)[0], expected)
        self.assertEqual(assess_disk_capacity(20,0,0)[0], 'UNKNOWN')

    def grid(self, resources='ONLINE ONLINE node1\nOFFLINE OFFLINE', rc=0, cluster=None):
        online='\n'.join(f'CRS-{n}: Service is online' for n in ('4638','4537','4529','4533'))
        outputs={'crs_check': online,'cluster_check': cluster or online,
                 'resources':resources,'nodes':'node1 1 Active\nnode2 2 Active'}
        text='GRID_USER=grid\nGRID_HOME=/u01/grid\nGRID_COLLECTION=OK\n'
        for name,output in outputs.items():
            text+=f'@@BEGIN {name}\n{output}\n@@END {name} {rc}\n'
        (self.root/'grid_rac.txt').write_text(text,encoding='utf-8')
        return parse_grid_status(str(self.root))

    def test_healthy_grid_and_intentionally_offline_resources(self):
        self.assertEqual(self.grid().status,'OK')

    def test_online_target_with_offline_resource_is_critical(self):
        self.assertEqual(self.grid(resources='1 ONLINE OFFLINE node1').status,'CRIT')

    def test_component_offline_is_critical(self):
        self.assertEqual(self.grid(cluster='CRS-4535: Cannot communicate with Cluster Ready Services').status,'CRIT')

    def test_timeout_or_incomplete_collection_is_unknown(self):
        self.assertEqual(self.grid(rc=124).status,'UNKNOWN')
        (self.root/'grid_rac.txt').write_text('GRID_USER=grid\n@@BEGIN crs_check\n',encoding='utf-8')
        self.assertEqual(parse_grid_status(str(self.root)).status,'UNKNOWN')

    def test_no_grid_is_not_applicable_and_no_file_is_not_healthy(self):
        self.assertEqual(parse_grid_status(str(self.root)).status,'UNKNOWN')
        (self.root/'grid_rac.txt').write_text('GRID_COLLECTION=SKIPPED\nGRID_REASON=本机未发现grid用户\n',encoding='utf-8')
        self.assertEqual(parse_grid_status(str(self.root)).status,'INFO')


if __name__=='__main__': unittest.main()
