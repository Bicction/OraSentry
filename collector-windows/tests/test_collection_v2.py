"""SQL protocol parity prevents platform-specific scope or precision regressions."""
from pathlib import Path
from contextlib import closing
import re
import unittest

class CollectionV2Tests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[2]
        linux=(root/'collector-linux/lib/db_check.sh').read_text(encoding='utf-8')
        windows=(root/'collector-windows/lib/DatabaseCheck.ps1').read_text(encoding='utf-8-sig')
        self.linux=dict(re.findall(r'exec_sql "\$\{d\}/(\w+_v2)\.txt" "(.*?)"',linux,re.S))
        self.windows=dict(re.findall(r'Invoke-RegisteredSql \$Context \$dbDir "(\w+_v2)\.txt" "(.*?)" -Optional',windows,re.S))
    def normalized(self,sql):
        sql=sql.replace('\\$','$').replace('`$','$')
        for left,right in [('${awr_sysstat_con}','$awrSysstatCon'),('${awr_event_con}','$awrEventCon'),('${awr_sql_con}','$awrSqlCon')]:sql=sql.replace(left,right)
        return sql
    def test_windows_linux_protocol_equivalent(self):
        self.assertGreaterEqual(len(self.linux),17)
        self.assertEqual(set(self.linux),set(self.windows))
        for name in self.linux:self.assertEqual(self.normalized(self.linux[name]),self.normalized(self.windows[name]),name)
    def test_interval_counters_not_arbitrary_top_n(self):
        for queries in (self.linux,self.windows):
            sql=queries['awr_sysstat_v2']
            self.assertNotIn('ROWNUM',sql)
            self.assertRegex(sql,r'(?:ss.instance_number=s.instance_number|s.instance_number=ss.instance_number)')
            self.assertRegex(sql,r'(?:ss.dbid=s.dbid|s.dbid=ss.dbid)')
            self.assertIn('TO_CHAR(ss.value',sql)
            self.assertIn('physical reads cache',sql)
    def test_completion_marker_separate_sql_statement(self):
        for queries in (self.linux,self.windows):
            for name,sql in queries.items():self.assertTrue(sql.endswith(";\nSELECT '"+name.upper()+"_OK' FROM dual;"),name)
    def test_capacity_and_business_metrics_preserve_container_scope(self):
        for queries in (self.linux,self.windows):
            self.assertIn('fs.con_id=t.con_id',queries['pdb_tablespaces_v2'])
            self.assertIn('b.con_id=o.con_id',queries['pdb_health_v2'])
            self.assertIn('s.inst_id=t.inst_id',queries['pdb_transactions_v2'])
            self.assertIn('usable_file_mb',queries['pdb_storage_v2'])

    def test_awr_counters_collect_scopes_instead_of_filtering_them_out(self):
        # Execute the SELECT against both pre-12c and multitenant schemas.
        # This catches empty results caused by an unconditional CON_ID=0 filter.
        import sqlite3
        for queries in (self.linux, self.windows):
            for has_con_id in (False, True):
                for name, view, alias, variable, metric_columns, metric in [
                    ('awr_sysstat_v2','dba_hist_sysstat','ss','$awrSysstatCon',
                     'stat_name TEXT,value INTEGER', "'physical reads cache',123456789012345"),
                    ('awr_events_v2','dba_hist_system_event','e','$awrEventCon',
                     'event_name TEXT,wait_class TEXT,total_waits INTEGER,time_waited_micro INTEGER',
                     "'db file sequential read','User I/O',123456789012345,234567890123456"),
                ]:
                    with self.subTest(name=name, has_con_id=has_con_id):
                        query = self.normalized(queries[name]).replace(
                            variable, alias+'.con_id' if has_con_id else '0').split(';')[0]
                        with closing(sqlite3.connect(':memory:')) as db:
                            db.create_function('TO_CHAR',2,lambda value,fmt: str(value))
                            db.executescript('''
                                CREATE TABLE v$database (dbid INTEGER);
                                INSERT INTO v$database VALUES (1);
                                CREATE TABLE v$instance (instance_number INTEGER);
                                INSERT INTO v$instance VALUES (1);
                                CREATE TABLE dba_hist_snapshot (
                                    dbid INTEGER,instance_number INTEGER,snap_id INTEGER,
                                    startup_time TEXT,end_interval_time TEXT);
                                INSERT INTO dba_hist_snapshot VALUES
                                    (1,1,99,'2026-09-01','2026-09-17 08:00:00'),
                                    (1,1,100,'2026-09-01','2026-09-17 09:00:00'),
                                    (1,2,101,'2026-09-01','2026-09-17 09:00:00'),
                                    (2,1,102,'2026-09-01','2026-09-17 09:00:00');
                            ''')
                            db.execute(f'CREATE TABLE {view} (dbid INTEGER,instance_number INTEGER,snap_id INTEGER,'+
                                       metric_columns+(',con_id INTEGER' if has_con_id else '')+')')
                            scopes = [1,3] if has_con_id else [0]
                            for cid in scopes:
                                for dbid,inst,snap in [(1,1,99),(1,1,100),(1,2,101),(2,1,102)]:
                                    db.execute(f'INSERT INTO {view} VALUES ({dbid},{inst},{snap},{metric}'+
                                               (f',{cid}' if has_con_id else '')+')')
                            cursor=db.execute(query)
                            output=[dict(zip([c[0].lower() for c in cursor.description],r)) for r in cursor.fetchall()]
                            self.assertEqual(len(output),2*len(scopes))
                            self.assertEqual({r['con_id'] for r in output},set(scopes))
                            self.assertEqual({(r['dbid'],r['instance_number'],r['snap_id']) for r in output},
                                             {(1,1,99),(1,1,100)})
                            count='stat_value' if name=='awr_sysstat_v2' else 'total_waits'
                            self.assertEqual({r[count] for r in output},{'123456789012345'})

    def test_awr_sqlstat_query_executes_for_both_container_capabilities(self):
        # SQLite executes the shared SELECT/window syntax. This is not an
        # Oracle integration test; TO_CHAR is supplied as a formatting shim.
        import sqlite3
        for platform, queries in [('linux', self.linux), ('windows', self.windows)]:
            for has_con_id in (False, True):
                with self.subTest(platform=platform, has_con_id=has_con_id):
                    sql = self.normalized(queries['awr_sqlstat_v2']).replace(
                        '$awrSqlCon', 'q.con_id' if has_con_id else '0')
                    query, marker, trailing = sql.split(';')
                    self.assertFalse(trailing.strip())
                    with closing(sqlite3.connect(':memory:')) as db:
                        db.create_function('TO_CHAR', 2, lambda value, fmt: str(value))
                        db.executescript('''
                            CREATE TABLE v$database (dbid INTEGER);
                            INSERT INTO v$database VALUES (1);
                            CREATE TABLE v$instance (instance_number INTEGER);
                            INSERT INTO v$instance VALUES (1);
                            CREATE TABLE dual (dummy TEXT);
                            INSERT INTO dual VALUES ('X');
                            CREATE TABLE dba_hist_snapshot (
                                dbid INTEGER, instance_number INTEGER, snap_id INTEGER,
                                startup_time TEXT, end_interval_time TEXT);
                            INSERT INTO dba_hist_snapshot VALUES
                                (1,1,98,'2026-09-01','2026-09-17 07:00:00'),
                                (1,1,99,'2026-09-01','2026-09-17 08:00:00'),
                                (1,1,100,'2026-09-01','2026-09-17 09:00:00'),
                                (1,2,101,'2026-09-01','2026-09-17 09:00:00'),
                                (2,1,102,'2026-09-01','2026-09-17 09:00:00');
                        ''')
                        columns = ['dbid', 'instance_number', 'snap_id', 'sql_id',
                                   'plan_hash_value', 'executions_delta', 'parse_calls_delta',
                                   'loads_delta', 'invalidations_delta', 'elapsed_time_delta',
                                   'cpu_time_delta', 'buffer_gets_delta', 'disk_reads_delta',
                                   'version_count']
                        if has_con_id:
                            columns.append('con_id')
                        db.execute('CREATE TABLE dba_hist_sqlstat (' + ','.join(columns) + ')')
                        rows = [[1, 1, 100, 'sql_%02d' % n, 9, 100, 50, 1, 0,
                                 1000000 + n, 100000, 1000, 100, 1] for n in range(35)]
                        rows += [[dbid, inst, snap, 'excluded', 9, 100, 50, 1, 0,
                                  999999999, 100000, 1000, 100, 1]
                                 for dbid, inst, snap in [(1,1,99), (1,2,101), (2,1,102)]]
                        if has_con_id:
                            rows = [row + [3] for row in rows]
                        db.executemany('INSERT INTO dba_hist_sqlstat VALUES (' +
                                       ','.join('?' for _ in columns) + ')', rows)
                        cursor = db.execute(query)
                        output = [dict(zip([c[0].lower() for c in cursor.description], row))
                                  for row in cursor.fetchall()]
                        self.assertEqual(len(output), 30)
                        self.assertEqual({r['sql_id'] for r in output},
                                         {'sql_%02d' % n for n in range(5, 35)})
                        self.assertEqual({r['rn'] for r in output}, set(range(1, 31)))
                        self.assertEqual({r['con_id'] for r in output},
                                         {3 if has_con_id else 0})
                        self.assertEqual(db.execute(marker).fetchone(), ('AWR_SQLSTAT_V2_OK',))


if __name__=='__main__':unittest.main()
