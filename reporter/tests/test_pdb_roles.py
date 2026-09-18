from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from parser.db_parser import _parse_cdb_info
from scoring import check_weight
from report_gen import generate_action_panel, generate_category_section


class PdbRoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)
        self.put('cdb_info', 'CDB\nYES\n')
        self.role('PHYSICAL STANDBY')
        self.pdb('READ ONLY')

    def put(self, name, text):
        (self.db / (name + '.txt')).write_text(text, encoding='utf-8')

    def role(self, role):
        self.put('dataguard_identity', f'NAME|DB_UNIQUE_NAME|DATABASE_ROLE|OPEN_MODE|LOG_MODE|FORCE_LOGGING|FLASHBACK_ON|PROTECTION_MODE|PROTECTION_LEVEL|SWITCHOVER_STATUS\nCDB|cdb_stby|{role}|READ ONLY WITH APPLY|ARCHIVELOG|YES|NO|MAXIMUM PERFORMANCE|MAXIMUM PERFORMANCE|NOT ALLOWED\n')

    def pdb(self, mode, name='APPDB'):
        self.put('pdb_info', f'PDB_NAME|PDB_ID|STATUS|OPEN_MODE|RESTRICTED|OPEN_TIME|TOTAL_SIZE_GB\nPDB$SEED|2|NORMAL|READ ONLY|NO||1\n{name}|3|NORMAL|{mode}|NO||10\n')

    def result(self):
        return _parse_cdb_info(str(self.db))[0]

    def test_all_datafiles_are_listed_for_each_pdb(self):
        from lxml import html
        rows = ['PDB_ID|PDB_NAME|FILE_ID|TABLESPACE_NAME|FILE_NAME|MAX_SIZE_MB|TOTAL_SIZE_MB|USED_SIZE_MB|AUTOEXTENSIBLE|ONLINE_STATUS']
        expected = []
        for cid, name, count in [(3, 'APPDB', 24), (4, 'OTHERDB', 13)]:
            for n in range(count):
                filename = f'{name}_{n}.dbf'
                expected.append(filename)
                rows.append(f'{cid}|{name}|{n}|USERS|/data/{filename}|2048|1024|1000|YES|ONLINE')
        self.put('pdb_datafiles', '\n'.join(rows))
        item = next(r for r in _parse_cdb_info(str(self.db)) if r.name == 'PDB数据文件')
        doc = html.fromstring(item.extra_html)
        self.assertEqual(item.value, '37个')
        self.assertEqual(doc.xpath('//tbody/tr/td[2]/text()'), expected)
        self.assertNotIn('更多', item.extra_html)

    def test_physical_standby_readonly_is_normal(self):
        item = self.result()
        self.assertEqual(item.status, 'OK')
        self.assertEqual(item.suggestion, '')
        self.assertIn('物理备库PDB的READ ONLY为正常', item.detail)
        self.assertNotIn('未打开', item.detail)

    def test_physical_standby_readwrite_warns_with_role_evidence(self):
        self.pdb('READ WRITE')
        item = self.result()
        self.assertEqual(item.status, 'WARN')
        self.assertIn('APPDB', item.suggestion)
        self.assertIn('与预期READ ONLY不符', item.suggestion)
        self.assertNotIn('未正常打开', item.suggestion)

    def test_role_switch_changes_expectation(self):
        self.pdb('READ WRITE')
        self.assertEqual(self.result().status, 'WARN')
        self.role('PRIMARY')
        self.assertEqual(self.result().status, 'OK')

    def test_primary_readonly_is_business_information(self):
        self.role('PRIMARY')
        item = self.result()
        self.assertEqual(item.status, 'INFO')
        self.assertIn('业务用途', item.suggestion)
        self.assertEqual(check_weight(item), 0)

    def test_snapshot_and_logical_standby_can_be_readwrite(self):
        for role in ('SNAPSHOT STANDBY', 'LOGICAL STANDBY'):
            with self.subTest(role=role):
                self.role(role)
                self.pdb('READ WRITE')
                self.assertEqual(self.result().status, 'OK')

    def test_seed_readonly_is_normal_on_primary(self):
        self.role('PRIMARY')
        self.pdb('READ WRITE')
        self.assertEqual(self.result().status, 'OK')

    def test_seed_readwrite_warns_independently_of_database_role(self):
        for role in ('PRIMARY', 'PHYSICAL STANDBY', 'SNAPSHOT STANDBY'):
            self.role(role)
            self.put('pdb_info', 'PDB$SEED|2|NORMAL|READ WRITE|NO||1\n')
            self.assertEqual(self.result().status, 'WARN')
            self.assertIn('种子容器', self.result().suggestion)

    def test_mounted_pdb_retains_existing_acceptance_policy(self):
        for role in ('PRIMARY', 'PHYSICAL STANDBY'):
            self.role(role)
            self.pdb('MOUNTED')
            self.assertEqual(self.result().status, 'OK')

    def test_old_package_uses_database_status_role(self):
        (self.db / 'dataguard_identity.txt').unlink()
        self.put('database_status', 'NAME|OPEN_MODE|DATABASE_ROLE|CREATED|LOG_MODE\nCDB|READ ONLY WITH APPLY|PHYSICAL STANDBY||ARCHIVELOG\n')
        self.assertEqual(self.result().status, 'OK')

    def test_missing_failed_or_unrecognized_role_is_unknown(self):
        for text in ('', 'ORA-00942: table or view does not exist\n', 'CDB|cdb|UNRECOGNIZED\n'):
            self.put('dataguard_identity', text)
            self.assertEqual(self.result().status, 'UNKNOWN')

    def test_conflicting_role_snapshots_do_not_claim_healthy(self):
        self.put('database_status', 'CDB|READ WRITE|PRIMARY||ARCHIVELOG\n')
        self.assertEqual(self.result().status, 'UNKNOWN')

    def test_missing_open_mode_is_unknown(self):
        self.pdb('')
        self.assertEqual(self.result().status, 'UNKNOWN')

    def test_pdb_does_not_require_cdb_readonly_with_apply_mode(self):
        self.assertEqual(self.result().status, 'OK')
        self.pdb('READ ONLY WITH APPLY')
        self.assertEqual(self.result().status, 'WARN')

    def test_report_detail_and_actions_use_role_aware_result(self):
        item = self.result()
        html = generate_category_section('cdb', [item])
        self.assertIn('物理备库PDB只读', html)
        self.assertIn('模式判定', html)
        self.assertNotIn('APPDB', generate_action_panel({'cdb': [item]}))
        self.pdb('READ WRITE')
        actions = generate_action_panel({'cdb': [self.result()]})
        self.assertIn('APPDB', actions)
        self.assertIn('READ ONLY', actions)

    def test_non_cdb_remains_unaffected(self):
        self.put('cdb_info', 'CDB\nNO\n')
        self.assertEqual(self.result().value, '非CDB')
        self.assertEqual(self.result().status, 'OK')


if __name__ == '__main__':
    unittest.main()
