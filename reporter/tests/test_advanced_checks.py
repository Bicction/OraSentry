from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from parser.advanced_checks import parse_awr,parse_pdb,records,cache_assessment
from parser.db_parser import _parse_buffer_cache_hit

class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)
    def put(self,name,header,rows,marker=True):
        text='|'.join(header)+'\n'+'\n'.join('|'.join(map(str,r)) for r in rows)+'\n'
        if marker:text+=name.upper()+'_OK\n'
        (self.db/(name+'.txt')).write_text(text,encoding='utf-8')
    def fixture(self):
        self.put('awr_context_v2',['dbid','database_role','instance_number','instance_name','host_name','startup_time','collected_at'],[['1','PRIMARY','1','DB1','host','2026-01-01 00:00:00','2026-09-16 13:00:00']])
        self.snaps=[['1','1','99','2026-01-01 00:00:00','2026-09-16 11:00:00'],['1','1','100','2026-01-01 00:00:00','2026-09-16 12:00:00']]
        self.snapwrite()
        self.counts={'physical reads cache':100,'consistent gets from cache':9000,'db block gets from cache':1000,'parse count (total)':500,'parse count (hard)':10,'execute count':1000,'parse time elapsed':100,'CPU used by this session':1000,'physical reads':200,'physical reads direct':100,'physical writes':10,'redo size':100000,'user commits':1000,'user rollbacks':1}
        self.statwrite()
        self.put('awr_sqlstat_v2',['dbid','instance_number','snap_id','sql_id','plan_hash_value','executions_delta','parse_calls_delta','loads_delta','invalidations_delta','elapsed_time_delta','cpu_time_delta','buffer_gets_delta','disk_reads_delta','version_count'],[['1','1','100','sql_good','9',100,500,1,0,2000000,100000,1000,100,1],['1','2','100','wrong_instance','9',100,500,1,0,2000000,100000,1000,100,1]])
        self.put('awr_events_v2',['dbid','instance_number','snap_id','event_name','wait_class','total_waits','time_waited_micro'],[['1','1','99','db file sequential read','User I/O',1000,10000000],['1','1','100','db file sequential read','User I/O',1010,12000000]])
    def snapwrite(self):
        self.put('awr_snapshot_v2',['dbid','instance_number','snap_id','startup_time','end_time'],self.snaps)
    def statwrite(self,extra=None):
        self.stats=[]
        for n,d in self.counts.items():
            self.stats += [['1','1','99',n,100000000000],['1','1','100',n,100000000000+d]]
        self.put('awr_sysstat_v2',['dbid','instance_number','snap_id','stat_name','stat_value'],self.stats+(extra or []))
    def awr(self):return parse_awr(str(self.db))
    def test_exact_numeric_snapshot_order_and_scope(self):
        self.fixture();self.statwrite([['1','2','100','physical reads cache','999999999999999']])
        result=self.awr();self.assertIn('99.0%',result[0].extra_html)
        self.assertIn('快照 #100',result[0].value)
        self.assertIn('sql_good',result[0].suggestion)
        self.assertNotIn('wrong_instance',str(result))
    def test_hard_parse_not_inferred_from_total(self):
        self.fixture();r=self.awr()[0]
        self.assertIn('重复 prepare',r.suggestion)
        self.assertNotIn('硬解析占比：',r.suggestion)
    def test_hard_parse_specific_diagnosis(self):
        self.fixture();self.counts['parse count (hard)']=200;self.statwrite()
        self.assertIn('硬解析占比：',self.awr()[0].suggestion)
    def test_old_precision_loss_is_not_database_critical(self):
        (self.db/'awr_snapshot.txt').write_text('SNAP_ID\n77391\n',encoding='utf-8')
        self.assertEqual(self.awr()[0].status,'UNKNOWN')
    def test_scientific_counter_rejected(self):
        self.fixture();self.stats[0][-1]='1.2383E+11'
        self.put('awr_sysstat_v2',['dbid','instance_number','snap_id','stat_name','stat_value'],self.stats)
        self.assertEqual(self.awr()[0].status,'UNKNOWN')
    def test_restart_rejected(self):
        self.fixture();self.snaps[1][3]='2026-09-16 11:30:00';self.snapwrite()
        self.assertEqual(self.awr()[0].status,'UNKNOWN')
    def test_rollback_counter_not_clamped(self):
        self.fixture();self.counts['physical reads cache']=-10;self.statwrite()
        self.assertIn('计数回退',self.awr()[0].suggestion)
    def test_missing_metric_not_zero(self):
        self.fixture();del self.counts['physical reads cache'];self.statwrite()
        self.assertIn('缺少 physical reads cache',self.awr()[0].suggestion)
        self.assertIn('快照 #99、#100',self.awr()[0].suggestion)
    def scoped_stats(self, scopes):
        rows = [row+[cid] for cid in scopes for row in self.stats]
        self.put('awr_sysstat_v2',['dbid','instance_number','snap_id','stat_name','stat_value','con_id'],rows)
    def test_empty_stats_explain_collection_gap_and_keep_sql(self):
        self.fixture()
        (self.db/'awr_sysstat_v2.txt').write_text("'AWR_SYSSTAT_V2_O\n-----------------\nAWR_SYSSTAT_V2_OK\n",encoding='utf-8')
        result=self.awr();r=result[0]
        self.assertEqual(r.status,'UNKNOWN')
        self.assertIn('awr_sysstat_v2.txt 未返回',r.suggestion)
        self.assertIn('不代表数据库性能异常',r.detail)
        self.assertNotIn('候选 SQL',r.suggestion)
        self.assertNotIn('缺少 physical reads cache',r.suggestion)
        self.assertIn('sql_good',next(r for r in result if r.name=='AWR耗时SQL').extra_html)
    def test_prefers_whole_database_without_mixing_containers(self):
        self.fixture();self.scoped_stats(['3','1','0'])
        r=self.awr()[0]
        self.assertIn('CON_ID=0',r.detail)
        self.assertIn('99.0%',r.extra_html)
        self.assertNotIn('重复计数',r.suggestion)
    def test_root_only_statistics_are_explicitly_limited(self):
        self.fixture();self.scoped_stats(['1','3'])
        r=self.awr()[0]
        self.assertIn('仅 CDB$ROOT',r.detail)
        self.assertIn('不能代表整个 CDB',r.detail)
        self.assertIn('99.0%',r.extra_html)
        # SQL without container evidence must not explain root-only metrics.
        self.assertNotIn('候选 SQL',r.suggestion)
    def test_snapshot_scopes_must_match(self):
        self.fixture()
        self.put('awr_sysstat_v2',['dbid','instance_number','snap_id','stat_name','stat_value','con_id'],
                 [row+['0' if row[2]=='99' else '1'] for row in self.stats])
        r=self.awr()[0]
        self.assertEqual(r.status,'UNKNOWN')
        self.assertIn('不能跨容器求差',r.suggestion)
    def test_partial_whole_database_metrics_not_filled_from_root(self):
        self.fixture()
        self.put('awr_sysstat_v2',['dbid','instance_number','snap_id','stat_name','stat_value','con_id'],
                 [row+['0'] for row in self.stats if row[3]!='physical reads cache']+
                 [row+['1'] for row in self.stats])
        r=self.awr()[0]
        self.assertIn('CON_ID=0',r.detail)
        self.assertIn('缺少 physical reads cache',r.suggestion)
    def test_empty_events_are_unknown_not_zero_waits(self):
        self.fixture()
        self.put('awr_events_v2',['dbid','instance_number','snap_id','event_name','wait_class','total_waits','time_waited_micro'],[])
        r=next(r for r in self.awr() if r.name=='AWR等待事件')
        self.assertEqual(r.status,'UNKNOWN')
        self.assertIn('awr_events_v2.txt 未返回',r.detail)
    def test_wait_events_keep_their_own_container_scope(self):
        self.fixture()
        self.put('awr_events_v2',['dbid','instance_number','snap_id','event_name','wait_class','total_waits','time_waited_micro','con_id'],
                 [[1,1,99,'read','User I/O',100,1000000,1],
                  [1,1,100,'read','User I/O',110,3000000,1],
                  [1,1,99,'read','User I/O',100,100000000,3],
                  [1,1,100,'read','User I/O',900,900000000,3]])
        r=next(r for r in self.awr() if r.name=='AWR等待事件')
        self.assertEqual(r.status,'INFO')
        self.assertIn('CON_ID=1',r.detail)
        self.assertIn('2.0',r.extra_html)
        self.assertNotIn('800.0',r.extra_html)
    def test_duplicate_scope_rejected(self):
        self.fixture();self.statwrite([['1','1','100','physical reads cache','10']])
        self.assertEqual(self.awr()[0].status,'UNKNOWN')
    def test_low_sample_not_warn(self):
        self.assertEqual(cache_assessment(900,950)[0],'INFO')
    def test_out_of_range_not_clamped(self):
        self.assertEqual(cache_assessment(20000,10000)[:2],('UNKNOWN',None))
    def test_low_cache_only_warn_and_no_resize_command(self):
        self.assertEqual(cache_assessment(9000,10000)[0],'WARN')
    def test_standby_history_not_local_performance(self):
        self.fixture();p=self.db/'awr_context_v2.txt';p.write_text(p.read_text().replace('PRIMARY','PHYSICAL STANDBY'))
        self.assertEqual(self.awr()[0].value,'历史来源待确认')
    def test_waits_are_interval(self):
        self.fixture();r=next(r for r in self.awr() if r.name=='AWR等待事件')
        self.assertIn('2.0',r.extra_html);self.assertNotIn('12000000',r.extra_html)
    def test_no_completion_marker_rejected(self):
        self.put('pdb_temp_v2',['con_id','name'],[],False)
        with self.assertRaises(ValueError):records(str(self.db),'pdb_temp_v2')
    def test_oracle_error_even_with_marker_rejected(self):
        self.put('pdb_temp_v2',['con_id','name'],[])
        with (self.db/'pdb_temp_v2.txt').open('a') as f:f.write('ORA-00942: missing view')
        with self.assertRaises(ValueError):records(str(self.db),'pdb_temp_v2')
    def pdbfixture(self):
        (self.db/'pdb_info.txt').write_text('PDB_NAME|PDB_ID|STATUS|OPEN_MODE\nAPP_A|3|NORMAL|READ ONLY\nAPP_B|4|NORMAL|READ ONLY\n',encoding='utf-8')
        self.put('pdb_tablespaces_v2',['con_id','pdb_name','tablespace_name','contents','status','alloc_mb','used_mb','free_mb','max_mb','autoextensible'],[['1','CDB$ROOT','SYSTEM','PERMANENT','ONLINE',100,40,60,100,'NO'],['3','APP_A','USERS','PERMANENT','ONLINE',100,96,4,100,'NO'],['4','APP_B','USERS','PERMANENT','ONLINE',100,40,60,100,'NO']])
    def test_same_tablespace_different_pdb(self):
        self.pdbfixture();r=parse_pdb(str(self.db),'PHYSICAL STANDBY')[0]
        self.assertEqual(r.status,'CRIT');self.assertIn('APP_A/USERS',r.suggestion)
        self.assertNotIn('APP_B/USERS',r.suggestion);self.assertIn('在主库',r.suggestion)
    def test_missing_container_not_healthy(self):
        self.pdbfixture();p=self.db/'pdb_tablespaces_v2.txt'
        p.write_text('\n'.join(x for x in p.read_text().splitlines() if not x.startswith(('3|','4|'))),encoding='utf-8')
        self.assertEqual(parse_pdb(str(self.db),'PRIMARY')[0].status,'UNKNOWN')
    def test_undo_allocation_not_full_alarm(self):
        self.pdbfixture();p=self.db/'pdb_tablespaces_v2.txt';p.write_text(p.read_text().replace('PERMANENT','UNDO'),encoding='utf-8')
        self.assertEqual(parse_pdb(str(self.db),'PRIMARY')[0].status,'INFO')
    def test_autoextend_headroom_explained(self):
        self.pdbfixture();p=self.db/'pdb_tablespaces_v2.txt';p.write_text(p.read_text().replace('96|4|100|NO','96|4|200|YES'),encoding='utf-8')
        r=parse_pdb(str(self.db),'PRIMARY')[0]
        self.assertEqual(r.status,'INFO');self.assertIn('核实底层空间',r.detail)
    def test_sqlplus_aut_header_and_gb_overview(self):
        from lxml import html
        self.pdbfixture()
        self.put('pdb_tablespaces_v2',
                 ['con_id','pdb_name','tablespace_name','contents','status','alloc_mb','used_mb','free_mb','max_mb','AUT'],
                 [[1,'CDB$ROOT','USERS','PERMANENT','ONLINE',1024,512,512,1024,'NO'],
                  [3,'APP_A','USERS','PERMANENT','ONLINE',1024,1000,24,2048,'YES'],
                  [4,'APP_B','USERS','PERMANENT','ONLINE',1024,768,256,1024,'NO']])
        r=parse_pdb(str(self.db),'PRIMARY')[0]
        doc=html.fromstring(r.extra_html)
        self.assertEqual(r.status,'INFO')
        self.assertEqual(doc.xpath('//th/text()'),
                         ['容器','表空间','类型','已分配(GB)','已用(GB)','当前空闲(GB)',
                          '分配使用率','最大(GB)','最大使用率','自动扩展','状态'])
        self.assertEqual(doc.xpath('//tbody/tr/td[1]/text()'),['APP_B','CDB$ROOT','APP_A'])
        self.assertEqual(doc.xpath('//tbody/tr[last()]/td/text()'),
                         ['APP_A','USERS','PERMANENT','1.00','0.98','0.02','97.66%','2.00','48.83%','YES','ONLINE'])
        self.assertEqual(doc.xpath('//div[@class="bar-label"]/text()'),
                         ['APP_B/USERS','CDB$ROOT/USERS','APP_A/USERS'])
        self.assertEqual(doc.xpath('//div[@class="bar-value"]/text()'),['75.0%','50.0%','48.8%'])
    def test_temp_uses_same_overview(self):
        self.pdbfixture()
        content=(self.db/'pdb_tablespaces_v2.txt').read_text(encoding='utf-8')
        (self.db/'pdb_temp_v2.txt').write_text(
            content.replace('PDB_TABLESPACES_V2_OK','PDB_TEMP_V2_OK').replace('PERMANENT','TEMPORARY'),
            encoding='utf-8')
        permanent,temp=parse_pdb(str(self.db),'PRIMARY')[:2]
        self.assertEqual(temp.extra_html,permanent.extra_html.replace('PERMANENT','TEMPORARY'))
    def test_invalid_capacity_does_not_become_zero_bar(self):
        from lxml import html
        self.pdbfixture()
        p=self.db/'pdb_tablespaces_v2.txt'
        p.write_text(p.read_text().replace('96|4|100|NO','bad|4|100|NO'),encoding='utf-8')
        r=parse_pdb(str(self.db),'PRIMARY')[0]
        doc=html.fromstring(r.extra_html)
        self.assertEqual(r.status,'UNKNOWN')
        self.assertNotIn('APP_A/USERS',doc.xpath('//div[@class="bar-label"]/text()'))
        self.assertEqual(doc.xpath('//tbody/tr[last()]/td[4]/text()'),['N/A'])
        self.assertIn('APP_A/USERS',r.detail)
    def test_shared_storage_note_is_not_repeated_per_tablespace(self):
        self.pdbfixture()
        self.put('pdb_storage_v2',['con_id','tablespace_name','storage_name','usable_file_mb'],
                 [[1,'SYSTEM','DATA',1000],[3,'USERS','DATA',1000],[4,'USERS','DATA',1000]])
        r=parse_pdb(str(self.db),'PRIMARY')[0]
        self.assertEqual(r.detail.count('ASM DATA 共享可用'),1)
    def test_long_transaction(self):
        self.put('pdb_transactions_v2',['inst_id','con_id','sid','serial#','username','start_time','age_seconds','used_ublk','used_urec'],[[1,3,55,5,'APP','09/16/26 10:00:00',7200,10,100]])
        r=next(r for r in parse_pdb(str(self.db),'PRIMARY') if r.name=='PDB事务')
        self.assertEqual(r.status,'WARN');self.assertIn('7200',r.suggestion)
    def test_asm_reserve_exhausted_uses_allocated_capacity(self):
        self.pdbfixture();p=self.db/'pdb_tablespaces_v2.txt';p.write_text(p.read_text().replace('96|4|100|NO','96|4|200|YES'),encoding='utf-8')
        self.put('pdb_storage_v2',['con_id','tablespace_name','storage_name','usable_file_mb'],[[3,'USERS','DATA',-100]])
        r=parse_pdb(str(self.db),'PRIMARY')[0]
        self.assertEqual(r.status,'CRIT');self.assertIn('共享可用 -100',r.detail)
        self.assertIn('96.0%</div>',r.extra_html)
    def test_missing_health_coverage_is_unknown(self):
        self.pdbfixture();self.put('pdb_health_v2',['con_id','pdb_name','metric','metric_value'],[])
        r=next(r for r in parse_pdb(str(self.db),'PRIMARY') if r.name=='PDB对象与维护')
        self.assertEqual(r.status,'UNKNOWN')
    def test_buffer_missing_unknown(self):
        self.assertEqual(_parse_buffer_cache_hit(str(self.db)).status,'UNKNOWN')
    def test_buffer_negative_not_zero(self):
        self.put('buffer_cache_hit',['NAME','PHYSICAL_READS','DB_BLOCK_GETS','CONSISTENT_GETS','HIT_RATIO'],[['DEFAULT',20000,0,10000,-100]],False)
        self.assertEqual(_parse_buffer_cache_hit(str(self.db)).status,'UNKNOWN')

if __name__=='__main__':unittest.main()
