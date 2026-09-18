"""Container-scoped checks and validated interval metrics.

V2 files are complete only when their trailing completion marker is present.
Unavailable evidence is never converted to a zero counter or a healthy result.
"""
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re

from config import DB_THRESHOLDS
from parser.base import CheckResult, read_file, generate_data_table, check_threshold
from parser.tablespace_view import effective_usage, render_tablespace_overview


def records(db, name):
    text = read_file(str(Path(db) / (name + '.txt')))
    if not text or re.search(r'ORA-\d|SP2-\d|ERROR at line', text):
        raise ValueError('未采集或查询失败')
    if name.upper() + '_OK' not in text:
        raise ValueError('缺少完整采集标记；请重新采集')
    lines = [x.strip() for x in text.splitlines() if '|' in x and not x.lstrip().startswith('-')]
    if not lines:
        return []
    header = [x.strip().lower() for x in lines[0].split('|')]
    result = []
    for line in lines[1:]:
        cells = [x.strip() for x in line.split('|')]
        if [x.lower() for x in cells] == header:
            continue
        if len(cells) != len(header):
            raise ValueError('列数不完整')
        result.append(dict(zip(header, cells)))
    return result


def number(value, exact=False):
    if not str(value).strip() or (exact and 'E' in str(value).upper()):
        raise ValueError('计数缺失或精度不足')
    try:
        n = Decimal(str(value))
    except InvalidOperation:
        raise ValueError('计数格式无效')
    if not n.is_finite() or n < 0:
        raise ValueError('计数无效')
    return n


def worst(statuses):
    return next((s for s in ('CRIT', 'WARN', 'UNKNOWN', 'INFO') if s in statuses), 'OK')


def cache_assessment(physical, logical):
    if logical <= 0:
        return 'INFO', None, '无有效逻辑读，不能评价缓存效率'
    value = float((1 - physical / logical) * 100)
    if not 0 <= value <= 100:
        return 'UNKNOWN', None, '计数口径或精度异常，命中率越界'
    reference = DB_THRESHOLDS['buffer_hit_ratio_warn']
    if logical < DB_THRESHOLDS.get('performance_min_logical_reads', 1000):
        return 'INFO', value, '逻辑读样本不足，仅供参考'
    if value < reference:
        focus = '重点关注；' if value < DB_THRESHOLDS['buffer_hit_ratio_crit'] else ''
        return 'WARN', value, f'{focus}低于参考线 {reference:g}%；检查高物理读 SQL、I/O 等待及缓存建议，勿仅凭命中率扩容'
    return 'OK', value, f'达到参考线 {reference:g}%；不代表全部 SQL 性能正常'


def awr_scope_rows(data, key, snap_ids, filename):
    """Select one container scope present in both snapshots, never sum scopes."""
    rows = [r for r in data if (r['dbid'], r['instance_number']) == key
            and r['snap_id'] in snap_ids]
    if not rows:
        raise ValueError(f'{filename}.txt 未返回所选实例和快照的数据行；'
                         '完成标记仅表示 SQL 执行结束，不代表已取得统计数据')
    by_snap = {snap: set() for snap in snap_ids}
    for r in rows:
        # Old collectors filtered CON_ID=0 in SQL and did not export the column.
        cid = r.get('con_id', 'legacy')
        by_snap[r['snap_id']].add(cid)
    common = set.intersection(*by_snap.values())
    selected = next((cid for cid in ('0', '1', 'legacy') if cid in common), None)
    if selected is None:
        observed = ', '.join(f"#{snap}: {','.join(sorted(ids)) or '无数据'}"
                             for snap, ids in by_snap.items())
        raise ValueError('两个快照缺少同一统计范围的完整数据（'+observed+'）；不能跨容器求差')
    scope = {
        '0': 'CON_ID=0（全库/非CDB范围）',
        '1': 'CON_ID=1（仅 CDB$ROOT，不能代表整个 CDB 或业务 PDB）',
        'legacy': '旧版采集范围（未输出 CON_ID）',
    }[selected]
    return [r for r in rows if r.get('con_id', 'legacy') == selected], selected, scope


def parse_awr(db):
    legacy = read_file(str(Path(db) / 'awr_snapshot.txt'))
    context_path = Path(db) / 'awr_context_v2.txt'
    if not context_path.exists():
        if 'SKIPPED|' in legacy:
            return [CheckResult('AWR分析', 'INFO', '未启用', '按配置未启用 AWR 采集')]
        return [CheckResult('AWR关键指标', 'UNKNOWN', '无法可靠计算',
            '旧采集包缺少完整精度、快照身份及缓存专用计数；历史比例不用于性能告警',
            '使用新版采集器重新采集；本地缓冲池累计统计不能代替 AWR 区间统计')]
    try:
        contexts = records(db, 'awr_context_v2')
        if len(contexts) != 1:
            raise ValueError('数据库身份不唯一')
        ctx = contexts[0]
        if ctx['database_role'] != 'PRIMARY':
            return [CheckResult('AWR关键指标', 'UNKNOWN', '历史来源待确认',
                f"当前角色 {ctx['database_role']}；备库中的 AWR 历史可能来自主库，不能据此评价当前备库负载",
                '当前节点参考本地统计；需确认 AWR 来源与采样实例后再分析历史性能')]
        key = (ctx['dbid'], ctx['instance_number'])
        snaps = [r for r in records(db, 'awr_snapshot_v2') if (r['dbid'], r['instance_number']) == key]
        snaps.sort(key=lambda r: int(r['snap_id']))
        if len(snaps) != 2 or snaps[0]['snap_id'] == snaps[1]['snap_id']:
            raise ValueError('需要两个完整且不同的本实例快照')
        a, b = snaps
        if a['startup_time'] != b['startup_time']:
            raise ValueError('快照跨越实例重启')
        start, end = (datetime.fromisoformat(r['end_time']) for r in snaps)
        seconds = (end-start).total_seconds()
        if seconds <= 0 or end > datetime.fromisoformat(ctx['collected_at']):
            raise ValueError('快照时间无效')
    except (ValueError, KeyError, TypeError) as exc:
        return [CheckResult('AWR关键指标', 'UNKNOWN', '无法可靠计算', str(exc), '重新采集完整的同实例快照；不将缺失计数作为 0')]

    values = {a['snap_id']: {}, b['snap_id']: {}}
    stat_error, stat_con, stat_scope = '', None, ''
    try:
        stat_rows, stat_con, stat_scope = awr_scope_rows(
            records(db, 'awr_sysstat_v2'), key, values, 'awr_sysstat_v2')
        for r in stat_rows:
            dst = values[r['snap_id']]
            if r['stat_name'] in dst:
                raise ValueError('相同实例快照存在重复计数，容器范围不明确')
            dst[r['stat_name']] = number(r['stat_value'], exact=True)
    except (ValueError, KeyError, TypeError) as exc:
        stat_error = str(exc)

    def delta(name):
        if name not in values[a['snap_id']] or name not in values[b['snap_id']]:
            missing = '、'.join('#'+snap for snap in values if name not in values[snap])
            raise ValueError('缺少 '+name+'（快照 '+missing+'）')
        d = values[b['snap_id']][name] - values[a['snap_id']][name]
        if d < 0:
            raise ValueError(name+' 计数回退')
        return d

    scope = f"实例 {ctx['instance_number']} / {ctx['instance_name']}，DBID {key[0]}；{start} 至 {end}；快照 #{a['snap_id']} → #{b['snap_id']}"
    table, statuses, advice = [], [], []
    def add(label, val, status, meaning, suggestion=''):
        table.append((label, val, status, meaning))
        statuses.append(status)
        if status in ('WARN','CRIT','UNKNOWN'):
            advice.append(label+'：'+(suggestion or meaning))
    if stat_error:
        add('AWR系统统计', 'N/A', 'UNKNOWN', stat_error,
            stat_error+'；使用修复后的采集器重新采集，核对 DBA_HIST_SYSSTAT 的 CON_ID 范围；旧包缺失或已舍入的计数不能从报告端恢复')
    else:
        try:
            physical = delta('physical reads cache')
            logical = delta('consistent gets from cache') + delta('db block gets from cache')
            status, ratio, meaning = cache_assessment(physical, logical)
            add('缓冲区命中率', f'{ratio:.1f}%' if ratio is not None else 'N/A', status, meaning)
        except ValueError as exc:
            add('缓冲区命中率', 'N/A', 'UNKNOWN', str(exc))
        min_exec = DB_THRESHOLDS.get('performance_min_executions', 100)
        try:
            parses, executes, hard = delta('parse count (total)'), delta('execute count'), delta('parse count (hard)')
            if hard > parses:
                raise ValueError('硬解析次数大于总解析次数')
            ratio = float(parses / executes * 100) if executes else None
            hard_ratio = float(hard / parses * 100) if parses else None
            enough = executes >= min_exec
            parse_warn = DB_THRESHOLDS.get('awr_parse_ratio_warn', 10)
            hard_warn = DB_THRESHOLDS.get('awr_hard_parse_ratio_warn', 10)
            hard_high = enough and hard_ratio is not None and hard_ratio > hard_warn
            parse_high = enough and ratio is not None and ratio > parse_warn
            add('解析/执行比例', f'{ratio:.1f}%' if ratio is not None else 'N/A', 'WARN' if parse_high else 'OK' if enough else 'INFO',
                f'总解析 {parses} / 执行 {executes}；参考 ≤{parse_warn}%，总解析包括软解析',
                '检查 Top SQL 解析/执行次数；硬解析不高时优先检查重复 prepare、语句缓存与游标复用')
            add('硬解析占比', f'{hard_ratio:.1f}%' if hard_ratio is not None else 'N/A', 'WARN' if hard_high else 'OK' if enough and hard_ratio is not None else 'INFO',
                f'硬解析 {hard} / 总解析 {parses}，{float(hard)/seconds:.2f} 次/秒；参考 ≤{hard_warn}%',
                '核对 SQL 文本差异、绑定变量、游标失效与子游标原因；占比不能证明未使用绑定变量')
        except ValueError as exc:
            add('解析效率', 'N/A', 'UNKNOWN', str(exc))
        for name, label, divisor, unit in [('parse time elapsed','解析耗时',100,'秒'),('CPU used by this session','会话 CPU',100,'秒'),('physical reads','物理读',1,'块'),('physical reads direct','直接路径读',1,'块'),('physical writes','物理写',1,'块'),('redo size','Redo',1048576,'MB')]:
            try:
                add(label, f'{delta(name)/divisor:.2f} {unit}', 'INFO', '区间增量；不以绝对量单独判异常')
            except ValueError as exc:
                add(label, 'N/A', 'UNKNOWN', str(exc))
        try:
            commits, rollbacks = delta('user commits'), delta('user rollbacks')
            total = commits+rollbacks
            pct = float(rollbacks/total*100) if total else None
            threshold = DB_THRESHOLDS.get('awr_rollback_ratio_warn',10)
            high = total >= min_exec and pct is not None and pct > threshold
            add('事务回滚占比', f'{pct:.1f}%' if pct is not None else 'N/A', 'WARN' if high else 'OK' if total >= min_exec else 'INFO',
                f'提交 {commits}，回滚 {rollbacks}；参考 ≤{threshold}%', '检查应用主动回滚、事务报错及重试；回滚不必然等于数据库故障')
        except ValueError as exc:
            add('事务回滚占比','N/A','UNKNOWN',str(exc))

    results = []
    try:
        sql = [r for r in records(db,'awr_sqlstat_v2') if (r['dbid'],r['instance_number'],r['snap_id']) == (*key,b['snap_id'])]
        rows = []
        for r in sql:
            vals = [number(r[n],exact=True) for n in ('executions_delta','parse_calls_delta','loads_delta','invalidations_delta','elapsed_time_delta','disk_reads_delta')]
            ex, pa, loads, inval, elapsed, reads = vals
            hint = []
            if pa > ex: hint.append('解析多于执行，检查重复 prepare')
            if inval: hint.append('存在失效，核对 DDL/统计信息变更')
            if number(r['version_count']) > 20: hint.append('子游标较多，检查共享失败原因')
            rows.append((r['sql_id'],r['plan_hash_value'],str(ex),str(pa),str(loads),str(inval),r['version_count'],f'{elapsed/1000000:.3f}',str(reads),'；'.join(hint) or '按负载分析',r.get('con_id','N/A')))
        results.append(CheckResult('AWR耗时SQL','INFO',f'{len(rows)} 条',scope+'；Top SQL 为采样子集，不能反推完整硬解析来源或绑定变量使用情况',extra_html=generate_data_table(['SQL ID','计划','执行','解析','加载','失效','子游标','耗时(秒)','物理读(块)','检查方向','CON_ID'],rows)))
        candidate_rows = [r for r in rows if stat_con != '1' or r[10] == '1']
        if any(status in ('WARN', 'CRIT') for status in statuses) and candidate_rows:
            for label,index in [('高物理读',8),('高解析次数',3),('游标失效',5)]:
                candidates=sorted(candidate_rows,key=lambda r:Decimal(r[index]),reverse=True)
                ids=list(dict.fromkeys(r[0] for r in candidates if Decimal(r[index])>0))[:3]
                if ids: advice.append(label+'候选 SQL：'+'、'.join(ids))
            advice.append('详见 AWR耗时SQL；候选仅来自已采集 Top SQL，不等于已确定根因')
    except (ValueError,KeyError) as exc:
        results.append(CheckResult('AWR耗时SQL','UNKNOWN','证据不足',str(exc),'无法关联 SQL，需补采同实例、同快照 SQL 统计'))
    try:
        events = {}
        event_rows, event_con, event_scope = awr_scope_rows(
            records(db,'awr_events_v2'), key, values, 'awr_events_v2')
        for r in event_rows:
            if (r['dbid'],r['instance_number']) == key and r['snap_id'] in values:
                ek = (r['event_name'],r['wait_class'])
                bucket = events.setdefault(ek,{})
                if r['snap_id'] in bucket: raise ValueError('等待事件范围重复')
                bucket[r['snap_id']] = (number(r['total_waits'],True),number(r['time_waited_micro'],True))
        rows=[]
        for (event,cls), pair in events.items():
            if len(pair)!=2: continue
            count=pair[b['snap_id']][0]-pair[a['snap_id']][0]
            elapsed=pair[b['snap_id']][1]-pair[a['snap_id']][1]
            if count<0 or elapsed<0: raise ValueError('等待计数回退')
            rows.append((event,cls,str(count),float(elapsed/1000000),f'{elapsed/count/1000:.2f}' if count else 'N/A'))
        rows.sort(key=lambda r:r[3],reverse=True)
        if not rows:
            raise ValueError('两个快照没有可配对的等待事件，无法计算区间增量')
        results.append(CheckResult('AWR等待事件','INFO',f'{len(rows)} 项',scope+'；'+event_scope+'；累计计数已按同实例快照求差',extra_html=generate_data_table(['事件','类别','区间等待次数','区间等待秒','平均毫秒'],rows[:20])))
    except (ValueError,KeyError) as exc:
        results.append(CheckResult('AWR等待事件','UNKNOWN','无法可靠计算',str(exc),
                                   '使用修复后的采集器重新采集；核对 DBA_HIST_SYSTEM_EVENT 的容器范围和快照覆盖'))
    if 'UNKNOWN' in statuses and not stat_error:
        advice.append('缺少的是计算所需的 AWR 原始计数，不等于数据库性能异常；使用修复后的采集器补采同一容器范围的两个快照')
    detail = scope + ('；系统统计范围：'+stat_scope if stat_scope else '')
    if stat_error:
        detail += '；AWR 系统统计数据缺失，无法计算性能指标，不代表数据库性能异常'
    return [CheckResult('AWR关键指标',worst(statuses),f"快照 #{b['snap_id']}",detail,'；'.join(advice),generate_data_table(['指标','值','状态','判断依据'],table))]+results


def parse_pdb(db, role):
    results=[]
    # This function is called only for CDBs, including legacy packages.
    info=read_file(str(Path(db)/'pdb_info.txt'))
    containers={'1':('CDB$ROOT','READ WRITE')}
    for line in info.splitlines():
        cells=[x.strip() for x in line.split('|')]
        if len(cells)>=4 and cells[1].isdigit(): containers[cells[1]]=(cells[0],cells[3])
    standby=role=='PHYSICAL STANDBY'
    maintenance='在主库评估并实施维护，确认结果经 DG 同步；不要在只读备库直接执行维护' if standby else '结合业务窗口确认后处理'
    storage={}
    try:
        for r in records(db,'pdb_storage_v2'):
            storage.setdefault((r['con_id'],r['tablespace_name']),[]).append(r)
    except (ValueError,KeyError):
        pass
    for file,title in [('pdb_tablespaces_v2','CDB/PDB表空间'),('pdb_temp_v2','CDB/PDB临时表空间')]:
        try:
            data=records(db,file)
            rows=[]; states=[]; suggestions=[]; notes=[]; seen=set()
            for r in data:
                seen.add(r['con_id']); label=r['pdb_name']+'/'+r['tablespace_name']
                ts = dict(container=r['pdb_name'], con_id=r['con_id'],
                          name=r['tablespace_name'], contents=r.get('contents', 'N/A'),
                          auto=r.get('autoextensible', r.get('aut', 'N/A')).upper(),
                          status=r.get('status', 'N/A'))
                try:
                    alloc,used,free,maximum=(number(r[k]) for k in ('alloc_mb','used_mb','free_mb','max_mb'))
                    if alloc<=0 or maximum<alloc or used>alloc: raise ValueError('空间数据不完整或口径不一致')
                    pct=float(used/alloc*100); maxpct=float(used/maximum*100)
                    ts.update(alloc=alloc/1024, used=used/1024, free=free/1024,
                              max=maximum/1024, alloc_pct=pct, max_pct=maxpct)
                    if r['contents']=='UNDO':
                        state='INFO'; note='已分配区不等于活跃事务占用；结合 UNDO 状态与错误计数'
                    else:
                        state=check_threshold(effective_usage(ts),DB_THRESHOLDS['tablespace_usage_warn'],DB_THRESHOLDS['tablespace_usage_crit'])
                        note='使用率偏高，建议检查容量并评估扩容' if state in ('WARN','CRIT') else ''
                        if pct>=DB_THRESHOLDS['tablespace_usage_warn'] and state=='OK':
                            state='INFO'; note='当前分配空间较满，文件仍有扩展额度；核实底层空间'
                    if r['status'] not in ('ONLINE','READ ONLY'):
                        state='WARN'; note='表空间状态异常，检查文件和容器状态'
                    groups=storage.get((r['con_id'],r['tablespace_name']),[])
                    for group in groups:
                        if not group.get('usable_file_mb'):
                            notes.append('底层余量未获取，不能保证自动扩展')
                            continue
                        try:
                            # ASM usable_file_mb may be negative when redundancy reserve is exhausted.
                            usable=Decimal(group['usable_file_mb'])
                            if not usable.is_finite(): raise InvalidOperation
                        except InvalidOperation:
                            notes.append('ASM 余量格式异常'); continue
                        notes.append(f"ASM {group['storage_name']} 共享可用 {usable} MB（不能按每个 PDB 重复计入）")
                        if usable<=0 and pct>=DB_THRESHOLDS['tablespace_usage_warn'] and maximum>alloc and r['contents']!='UNDO':
                            state=check_threshold(pct,DB_THRESHOLDS['tablespace_usage_warn'],DB_THRESHOLDS['tablespace_usage_crit'])
                            ts['chart_pct']=pct
                            note+='；底层无扩容余量，按当前分配容量判断'
                    if r['con_id']=='2': state='INFO'; note='种子容器，仅展示'
                    if state in ('WARN','CRIT'): suggestions.append(label+'：'+note.lstrip('；')+'；'+maintenance)
                    elif note and r['contents']!='UNDO' and r['con_id']!='2':
                        notes.append(note.lstrip('；'))
                except (ValueError,KeyError) as exc:
                    state='UNKNOWN'; notes.append(label+'：'+str(exc))
                    for key in ('alloc','used','free','max','alloc_pct','max_pct','chart_pct'):
                        ts.pop(key, None)
                rows.append(ts)
                states.append(state)
            for cid,(name,mode) in containers.items():
                if cid=='2' or cid in seen: continue
                status='INFO' if mode=='MOUNTED' else 'UNKNOWN'
                states.append(status)
                reason='PDB 未打开' if mode=='MOUNTED' else '字典可见性或采集覆盖不足'
                notes.append(name+'：'+reason)
                rows.append(dict(container=name, con_id=cid, name='未获取明细',
                                 contents='N/A', auto='N/A', status=reason))
            detail=(f'共 {len(data)} 个表空间；自动扩展=YES 时按最大使用率判定，否则按分配使用率判定。'
                    '容量单位为 GB，按最大使用率降序展示；文件上限不等于可用磁盘空间。')
            if any(r.get('contents')=='UNDO' for r in data):
                detail+=' UNDO 已分配区不等于活跃事务占用，结合 UNDO 状态与错误计数。'
            if any(r.get('con_id')=='2' for r in data):
                detail+=' 种子容器仅展示。'
            if notes: detail+='\n'+'\n'.join(dict.fromkeys(notes))
            results.append(CheckResult(title,worst(states),f'{len(data)} 个表空间',detail,
                                       '；'.join(suggestions),render_tablespace_overview(rows, containers=True)))
        except (ValueError,KeyError) as exc:
            results.append(CheckResult(title,'UNKNOWN','未完整采集',str(exc),'使用新版采集器补采；确认各已打开 PDB 的字典可见性'))
    specs=[('pdb_health_v2','PDB对象与维护'),('pdb_sessions_v2','PDB会话与阻塞'),('pdb_transactions_v2','PDB事务'),('pdb_temp_users_v2','PDB临时空间占用'),('pdb_open_instances_v2','PDB实例打开状态'),('pdb_services_v2','PDB活动服务'),('pdb_undo_v2','CDB/PDB UNDO状态'),('pdb_undo_errors_v2','CDB/PDB UNDO错误')]
    names={'INVALID_OBJECTS':'无效业务对象','UNUSABLE_INDEXES':'不可用业务索引','UNUSABLE_INDEX_PARTS':'不可用索引分区','UNUSABLE_INDEX_SUBPARTS':'不可用索引子分区','STALE_STATS':'过期统计信息','MISSING_STATS':'缺失统计信息','FAILED_JOBS_7D':'7天失败作业','LOCKED_EXPIRED_USERS':'锁定/过期业务账号'}
    for file,title in specs:
        try:
            data=records(db,file); states=[]; notes=[]
            for r in data:
                state='INFO'
                cid=r.get('con_id',''); label=containers.get(cid,('CON_ID='+cid,''))[0]
                if file=='pdb_health_v2':
                    n=number(r['metric_value']); metric=r['metric']; r['metric']=names.get(metric,metric)
                    state='WARN' if n>0 and metric not in ('LOCKED_EXPIRED_USERS','MISSING_STATS','STALE_STATS') else 'INFO' if n>0 else 'OK'
                    if metric=='STALE_STATS' and n>=DB_THRESHOLDS.get('stale_stats_warn',20): state='WARN'
                    if n>0: notes.append(f"{label} {r['metric']} {n}；"+maintenance)
                elif file=='pdb_sessions_v2':
                    if r.get('blocking_session'):
                        state='WARN'; notes.append(f"{label} 实例 {r['inst_id']} 会话 {r['sid']} 被 {r.get('blocking_instance')}/{r['blocking_session']} 阻塞；先核实阻塞事务及业务影响")
                elif file=='pdb_open_instances_v2':
                    if r.get('restricted')=='YES': state='WARN'; notes.append(label+' 为受限模式，核对维护安排')
                    if standby and r.get('open_mode')=='READ WRITE': state='WARN'; notes.append(label+' 打开模式与物理备库角色不符')
                elif file=='pdb_undo_errors_v2':
                    if number(r['snapshot_old'])+number(r['no_space'])>0:
                        state='WARN'; notes.append(label+' 最近24小时有 UNDO 错误；结合长查询、活跃事务及容量分析')
                elif file=='pdb_transactions_v2':
                    age=number(r['age_seconds'])
                    limit=DB_THRESHOLDS.get('pdb_long_transaction_warn_seconds',3600)
                    if age>=limit:
                        state='WARN'; notes.append(f"{label} 实例 {r['inst_id']} 会话 {r['sid']} 事务持续 {age} 秒（参考 {limit} 秒）；核对未提交事务及业务影响，勿直接终止会话")
                states.append(state); r['判定']=state
            if file=='pdb_health_v2':
                seen={r['con_id'] for r in data}
                for cid,(name,mode) in containers.items():
                    if cid in ('1','2') or cid in seen: continue
                    states.append('INFO' if mode=='MOUNTED' else 'UNKNOWN')
                    notes.append(name+'：未打开或未获取完整业务指标，不能判为健康')
            detail='按 CON_ID 和适用的 INST_ID 展示；无异常记录不代表未采集项目正常'
            if file.startswith('pdb_undo'): detail+='；12.1 共享 UNDO 以 CDB 范围展示，不虚构每个 PDB 的独立 UNDO；区状态以所属活动实例查询为准'
            headers=list(data[0]) if data else []
            results.append(CheckResult(title,worst(states) if states else 'INFO',f'{len(data)} 条',detail,'；'.join(notes),generate_data_table(headers,[[r.get(k,'') for k in headers] for r in data]) if headers else ''))
        except (ValueError,KeyError) as exc:
            results.append(CheckResult(title,'UNKNOWN','不可用',str(exc),'确认版本能力、容器打开状态及采集权限；旧包需补采'))
    return results
