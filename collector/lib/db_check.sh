#!/bin/bash
#==============================================================
# 数据库巡检 - 纯数据采集
# 仅收集数据库相关 SQL 查询输出，不做任何判定
# 由 collect/main_db.sh 加载 common.sh 后 source 本文件
#==============================================================

db_collect() {
    log_info "========== 开始数据库数据采集 =========="

    local d="${RAW_DIR}/db"
    mkdir -p "${d}"

    # 2.1 基础信息
    collect_db_version "${d}"
    collect_init_params "${d}"
    collect_instance_status "${d}"
    collect_database_resilience "${d}"
    collect_cdb_pdb "${d}"
    collect_rac_info "${d}"
    collect_db_language "${d}"

    # 2.2 备份与恢复
    collect_backup_status "${d}"
    collect_archive_log "${d}"

    # 2.3 存储结构
    collect_control_files "${d}"
    collect_redo_logs "${d}"
    collect_data_files "${d}"
    collect_tablespaces "${d}"
    collect_rollback_segments "${d}"
    collect_asm_diskgroups "${d}"

    # 2.4 性能与等待
    collect_sessions "${d}"
    collect_operational_risks "${d}"
    collect_buffer_cache_hit "${d}"
    collect_library_cache_hit "${d}"
    collect_sga_info "${d}"
    collect_wait_events "${d}"
    collect_top_disk_read_sql "${d}"
    collect_long_running_sql "${d}"
    collect_table_fragmentation "${d}"
    collect_dead_processes "${d}"

    # 2.5 对象有效性
    collect_system_tablespace "${d}"
    collect_invalid_objects "${d}"
    collect_invalid_indexes "${d}"
    collect_invalid_triggers "${d}"

    # 2.6 AWR分析（默认关闭，启用前需确认 Oracle 授权范围）
    if [[ "${CHECK_AWR:-off}" == "on" ]]; then
        collect_awr_metrics "${d}"
    else
        skip_awr_metrics "${d}"
    fi
    collect_failed_jobs "${d}"

    # 2.6 日志与诊断
    collect_alert_log "${d}"
    collect_trace_files "${d}"

    log_info "========== 数据库数据采集完成 =========="
}

# 数据库版本和补丁
collect_db_version() {
    local d="$1"
    log_info "[采集] 数据库版本和补丁"
    exec_sql "${d}/db_version.txt" "SELECT * FROM v\$version;"
    ${ORACLE_HOME}/OPatch/opatch lsinventory > "${d}/opatch.txt" 2>&1 || echo "opatch不可用" > "${d}/opatch.txt"
}

# 初始化参数文件
collect_init_params() {
    local d="$1"
    log_info "[采集] 初始化参数"
    exec_sql "${d}/spfile.txt" "SELECT name, value, isspecified FROM v\$spparameter WHERE isspecified='TRUE' ORDER BY name;"
    exec_sql "${d}/parameters.txt" "SHOW PARAMETER;"
}

# 实例状态
collect_instance_status() {
    local d="$1"
    log_info "[采集] 实例状态"
    exec_sql "${d}/instance_status.txt" "SELECT inst_id, instance_name, host_name, status, database_status, version, startup_time FROM gv\$instance ORDER BY inst_id;"
    exec_sql "${d}/database_status.txt" "SELECT name, open_mode, database_role, created, log_mode FROM v\$database;"
    if [[ "${HAS_VDATABASE_CDB:-NO}" == "YES" ]]; then
        exec_sql "${d}/cdb_info.txt" "SELECT CDB FROM v\$database;"
    else
        exec_sql "${d}/cdb_info.txt" "SELECT 'NO' CDB FROM dual;"
    fi
}

collect_database_resilience() {
    local d="$1"
    log_info "[采集] 数据库韧性与组件状态"
    exec_sql "${d}/db_resilience.txt" "SELECT force_logging, flashback_on, supplemental_log_data_min, database_role, protection_mode, protection_level, switchover_status FROM v\$database;"
    exec_sql "${d}/registry_components.txt" "SELECT comp_id, comp_name, version, status, modified FROM dba_registry ORDER BY comp_id;"
    exec_sql "${d}/datafile_recovery.txt" "SELECT r.file#, d.name, r.error, r.online_status, r.change#, r.time FROM v\$recover_file r JOIN v\$datafile d ON d.file#=r.file# ORDER BY r.file#;"
    exec_sql "${d}/block_corruption.txt" "SELECT file#, block#, blocks, corruption_change#, corruption_type FROM v\$database_block_corruption ORDER BY file#, block#;"
    exec_sql "${d}/dataguard_dest_status.txt" "SELECT dest_id, status, type, database_mode, recovery_mode, destination, error, archived_thread#, archived_seq# FROM v\$archive_dest_status WHERE status <> 'INACTIVE' ORDER BY dest_id;"
    exec_sql "${d}/archive_gap.txt" "SELECT thread#, low_sequence#, high_sequence# FROM v\$archive_gap ORDER BY thread#, low_sequence#;"
}

# CDB/PDB 信息
collect_cdb_pdb() {
    local d="$1"
    log_info "[采集] CDB/PDB信息"
    if [[ "${DB_IS_CDB:-NO}" == "YES" && "${HAS_DBA_PDBS:-NO}" == "YES" ]]; then
        exec_sql "${d}/pdb_info.txt" "SELECT p.pdb_name, p.pdb_id, p.status, v.open_mode, v.restricted, v.open_time, v.total_size/1024/1024/1024 total_size_gb FROM dba_pdbs p JOIN v\$pdbs v ON p.pdb_id = v.con_id ORDER BY p.pdb_id;"
        exec_sql "${d}/pdb_datafiles.txt" "SELECT p.pdb_id, p.pdb_name, d.file_id, d.tablespace_name, d.file_name, ROUND(d.maxbytes/1024/1024,2) max_size_mb, ROUND(d.bytes/1024/1024,2) total_size_mb, ROUND(d.user_bytes/1024/1024,2) used_size_mb, d.autoextensible, d.online_status FROM dba_pdbs p JOIN cdb_data_files d ON p.pdb_id = d.con_id ORDER BY p.pdb_id;"
        exec_sql "${d}/pdb_users.txt" "SELECT u.con_id, u.username, u.account_status, u.created, u.default_tablespace, u.profile FROM cdb_users u WHERE u.username NOT IN ('SYS','SYSTEM') ORDER BY u.con_id, u.username;"
    else
        skip_sql_collection "${d}/pdb_info.txt" "PDB_NAME|PDB_ID|STATUS|OPEN_MODE|RESTRICTED|OPEN_TIME|TOTAL_SIZE_GB" "当前数据库不是CDB或版本不支持多租户"
        skip_sql_collection "${d}/pdb_datafiles.txt" "PDB_ID|PDB_NAME|FILE_ID|TABLESPACE_NAME|FILE_NAME|MAX_SIZE_MB|TOTAL_SIZE_MB|USED_SIZE_MB|AUTOEXTENSIBLE|ONLINE_STATUS" "当前数据库不是CDB或版本不支持多租户"
        skip_sql_collection "${d}/pdb_users.txt" "CON_ID|USERNAME|ACCOUNT_STATUS|CREATED|DEFAULT_TABLESPACE|PROFILE" "当前数据库不是CDB或版本不支持多租户"
    fi
}

# RAC 信息
collect_rac_info() {
    local d="$1"
    log_info "[采集] RAC信息"
    exec_sql "${d}/rac_nodes.txt" "SELECT inst_id, instance_number, instance_name, host_name, status, database_status, instance_role, startup_time, version FROM gv\$instance ORDER BY inst_id;"
    local pdb_expr="CAST(NULL AS VARCHAR2(128)) pdb"
    local global_expr="CAST(NULL AS VARCHAR2(3)) global_service"
    [[ "${HAS_SERVICES_PDB:-NO}" == "YES" ]] && pdb_expr="pdb"
    [[ "${HAS_SERVICES_GLOBAL:-NO}" == "YES" ]] && global_expr="global_service"
    exec_sql "${d}/rac_services.txt" "SELECT name, network_name, creation_date, enabled, goal, failover_method, failover_type, ${pdb_expr}, ${global_expr} FROM dba_services ORDER BY name;"
}

# 数据库语言设置
collect_db_language() {
    local d="$1"
    log_info "[采集] 数据库语言设置"
    exec_sql "${d}/nls_params.txt" "SELECT parameter, value FROM nls_database_parameters ORDER BY parameter;"
}

# 第三方备份检查
collect_backup_status() {
    local d="$1"
    log_info "[采集] 备份状态"
    exec_sql "${d}/rman_backup.txt" "SELECT session_key, start_time, end_time, status, input_type, output_device_type, ROUND(output_bytes/1024/1024/1024,2) output_gb FROM v\$rman_backup_job_details WHERE start_time > SYSDATE - 7 ORDER BY start_time DESC;"
    exec_sql "${d}/rman_status.txt" "SELECT * FROM (SELECT operation, object_type, status, start_time, end_time FROM v\$rman_status WHERE start_time > SYSDATE - 7 ORDER BY start_time DESC) WHERE ROWNUM <= 50;"
}

# 归档日志目录使用情况
collect_archive_log() {
    local d="$1"
    log_info "[采集] 归档日志目录"
    exec_sql "${d}/recovery_file_dest.txt" "SELECT name, space_limit/1024/1024/1024 limit_gb, space_used/1024/1024/1024 used_gb, space_reclaimable/1024/1024/1024 reclaimable_gb, ROUND(space_used/space_limit*100,2) usage_pct FROM v\$recovery_file_dest;"
    exec_sql "${d}/archive_log.txt" "SELECT thread#, sequence#, name, archived, completion_time FROM v\$archived_log WHERE completion_time > SYSDATE - 7 ORDER BY completion_time DESC;"
}

# 控制文件
collect_control_files() {
    local d="$1"
    log_info "[采集] 控制文件"
    exec_sql "${d}/control_files.txt" "SELECT name, status, is_recovery_dest_file, block_size, file_size_blks FROM v\$controlfile;"
}

# Redo Log 文件
collect_redo_logs() {
    local d="$1"
    log_info "[采集] Redo Log"
    exec_sql "${d}/redo_logs.txt" "SELECT a.group#, a.thread#, a.sequence#, a.members, a.archived, a.status, a.bytes/1024/1024 size_mb, b.member FROM v\$log a, v\$logfile b WHERE a.group# = b.group#(+) ORDER BY a.group#, b.member;"
    exec_sql "${d}/redo_switch_freq.txt" "SELECT TO_CHAR(first_time, 'YYYY-MM-DD HH24') AS hour_slot, COUNT(*) AS switch_count FROM v\$log_history WHERE first_time > SYSDATE - 30 GROUP BY TO_CHAR(first_time, 'YYYY-MM-DD HH24') ORDER BY hour_slot;"
}

# 数据文件
collect_data_files() {
    local d="$1"
    log_info "[采集] 数据文件"
    exec_sql "${d}/data_files.txt" "SELECT file_name, tablespace_name, bytes/1024/1024 size_mb, autoextensible, maxbytes/1024/1024 maxsize_mb, status, online_status FROM dba_data_files ORDER BY tablespace_name, file_name;"
}

# 表空间
collect_tablespaces() {
    local d="$1"
    log_info "[采集] 表空间"
    exec_sql "${d}/tablespaces.txt" "WITH df AS (SELECT tablespace_name, SUM(bytes) alloc_bytes, SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes, MAX(autoextensible) autoextensible FROM dba_data_files GROUP BY tablespace_name), fs AS (SELECT tablespace_name, SUM(bytes) free_bytes FROM dba_free_space GROUP BY tablespace_name) SELECT df.tablespace_name, t.contents, ROUND(df.alloc_bytes/POWER(1024,3),2) alloc_gb, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/POWER(1024,3),2) used_gb, ROUND(NVL(fs.free_bytes,0)/POWER(1024,3),2) free_gb, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/NULLIF(df.alloc_bytes,0)*100,2) alloc_usage_pct, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/NULLIF(df.max_bytes,0)*100,2) max_usage_pct, ROUND(df.max_bytes/POWER(1024,3),2) max_gb, df.autoextensible, t.status FROM df JOIN dba_tablespaces t ON t.tablespace_name=df.tablespace_name LEFT JOIN fs ON fs.tablespace_name=df.tablespace_name ORDER BY alloc_usage_pct DESC;"
    local temp_container_filter=""
    [[ "${HAS_TEMPSEG_CON_ID:-NO}" == "YES" ]] && temp_container_filter="WHERE u.con_id=SYS_CONTEXT('USERENV','CON_ID')"
    exec_sql "${d}/temp_tablespaces.txt" "WITH tf AS (SELECT tablespace_name, SUM(bytes) alloc_bytes, SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes, MAX(autoextensible) autoextensible FROM dba_temp_files GROUP BY tablespace_name), tu AS (SELECT u.tablespace tablespace_name, SUM(u.blocks*t.block_size) used_bytes FROM v\$tempseg_usage u JOIN dba_tablespaces t ON t.tablespace_name=u.tablespace ${temp_container_filter} GROUP BY u.tablespace) SELECT tf.tablespace_name, 'TEMPORARY' contents, ROUND(tf.alloc_bytes/POWER(1024,3),2) alloc_gb, ROUND(NVL(tu.used_bytes,0)/POWER(1024,3),2) used_gb, ROUND((tf.alloc_bytes-NVL(tu.used_bytes,0))/POWER(1024,3),2) free_gb, ROUND(NVL(tu.used_bytes,0)/NULLIF(tf.alloc_bytes,0)*100,2) alloc_usage_pct, ROUND(NVL(tu.used_bytes,0)/NULLIF(tf.max_bytes,0)*100,2) max_usage_pct, ROUND(tf.max_bytes/POWER(1024,3),2) max_gb, tf.autoextensible, t.status FROM tf JOIN dba_tablespaces t ON t.tablespace_name=tf.tablespace_name LEFT JOIN tu ON tu.tablespace_name=tf.tablespace_name ORDER BY alloc_usage_pct DESC;"
    exec_sql "${d}/tablespaces_ext.txt" "SELECT tablespace_name, file_name, bytes/1024/1024 size_mb, autoextensible, maxbytes/1024/1024 maxsize_mb, increment_by FROM dba_data_files ORDER BY tablespace_name, file_name;"
}

# 回滚段管理
collect_rollback_segments() {
    local d="$1"
    log_info "[采集] 回滚段"
    exec_sql "${d}/undo_tablespace.txt" "SELECT tablespace_name, status, ROUND(sum(bytes)/1024/1024,2) size_mb FROM dba_undo_extents GROUP BY tablespace_name, status ORDER BY tablespace_name, status;"
    exec_sql "${d}/undo_retention.txt" "SELECT name, value FROM v\$parameter WHERE name LIKE '%undo%';"
}

# ASM 磁盘组
collect_asm_diskgroups() {
    local d="$1"
    log_info "[采集] ASM磁盘组"
    exec_sql "${d}/asm_diskgroups.txt" "SELECT group_number, name, state, type, ROUND(total_mb/1024,2) total_gb, ROUND(free_mb/1024,2) free_gb, ROUND((1-free_mb/NULLIF(total_mb,0))*100,2) usage_pct FROM v\$asm_diskgroup;"
    exec_sql "${d}/asm_disks.txt" "SELECT group_number, disk_number, name, path, mode_status, state, ROUND(total_mb/1024,2) total_gb, ROUND(free_mb/1024,2) free_gb FROM v\$asm_disk;"
}

# 当前会话数与进程数
collect_sessions() {
    local d="$1"
    log_info "[采集] 会话和进程数"
    exec_sql "${d}/sessions.txt" "SELECT (SELECT COUNT(*) FROM v\$session) current_sessions, (SELECT value FROM v\$parameter WHERE name='sessions') max_sessions, (SELECT COUNT(*) FROM v\$process) current_processes, (SELECT value FROM v\$parameter WHERE name='processes') max_processes FROM dual;"
    exec_sql "${d}/session_detail.txt" "SELECT username, status, COUNT(*) cnt FROM v\$session WHERE username IS NOT NULL GROUP BY username, status ORDER BY cnt DESC;"
}

collect_operational_risks() {
    local d="$1"
    log_info "[采集] 资源上限、阻塞、统计信息与高消耗SQL"
    exec_sql "${d}/resource_limits.txt" "SELECT resource_name, current_utilization, max_utilization, initial_allocation, limit_value FROM v\$resource_limit WHERE resource_name IN ('processes','sessions','enqueue_locks','transactions','parallel_max_servers') ORDER BY resource_name;"
    exec_sql "${d}/blocking_sessions.txt" "SELECT s.sid, s.serial#, s.username, s.status, s.event, s.seconds_in_wait, s.blocking_instance, s.blocking_session, s.sql_id, s.machine, s.program FROM v\$session s WHERE s.blocking_session IS NOT NULL ORDER BY s.seconds_in_wait DESC;"
    exec_sql "${d}/stale_statistics.txt" "SELECT owner, COUNT(*) stale_count, MIN(last_analyzed) oldest_analyzed FROM dba_tab_statistics WHERE stale_stats='YES' AND object_type='TABLE' AND owner NOT IN ('SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN') GROUP BY owner ORDER BY stale_count DESC;"
    local sql_text_expr="CAST('[REDACTED]' AS VARCHAR2(300)) sql_text"
    [[ "${COLLECT_SQL_TEXT:-off}" == "on" ]] && sql_text_expr="SUBSTR(REPLACE(REPLACE(sql_text,CHR(10),' '),CHR(13),' '),1,300) sql_text"
    exec_sql "${d}/top_elapsed_sql.txt" "SELECT * FROM (SELECT sql_id, plan_hash_value, executions, ROUND(elapsed_time/POWER(10,6),2) elapsed_sec, ROUND(cpu_time/POWER(10,6),2) cpu_sec, buffer_gets, disk_reads, rows_processed, parsing_schema_name, ${sql_text_expr} FROM v\$sqlarea WHERE executions > 0 ORDER BY elapsed_time DESC) WHERE ROWNUM <= 20;"
}

# 缓冲区命中率
collect_buffer_cache_hit() {
    local d="$1"
    log_info "[采集] 缓冲区命中率"
    exec_sql "${d}/buffer_cache_hit.txt" "SELECT name, physical_reads, db_block_gets, consistent_gets, ROUND((1 - physical_reads/(db_block_gets + consistent_gets))*100, 2) hit_ratio FROM v\$buffer_pool_statistics WHERE db_block_gets + consistent_gets > 0;"
}

# 共享池命中率
collect_library_cache_hit() {
    local d="$1"
    log_info "[采集] Library Cache命中率"
    exec_sql "${d}/library_cache_hit.txt" "SELECT SUM(pins) pins, SUM(reloads) reloads, ROUND((1-SUM(reloads)/NULLIF(SUM(pins),0))*100,2) hit_ratio FROM v\$librarycache;"
}

# SGA 信息
collect_sga_info() {
    local d="$1"
    log_info "[采集] SGA信息"
    exec_sql "${d}/sga_info.txt" "SELECT name, ROUND(value/1024/1024, 2) size_mb FROM v\$sga;"
    exec_sql "${d}/sgastat.txt" "SELECT pool, name, ROUND(bytes/1024/1024, 2) size_mb FROM v\$sgastat ORDER BY pool, bytes DESC;"
    exec_sql "${d}/sga_components.txt" "SELECT component, current_size/1024/1024 current_mb, min_size/1024/1024 min_mb, user_specified_size/1024/1024 specified_mb FROM v\$sga_dynamic_components ORDER BY current_size DESC;"
}

# 数据库等待事件
collect_wait_events() {
    local d="$1"
    log_info "[采集] 等待事件"
    exec_sql "${d}/wait_events.txt" "SELECT * FROM (SELECT event, wait_class, total_waits, time_waited, average_wait, ROUND(time_waited*100/SUM(time_waited) OVER(), 2) wait_pct FROM v\$system_event WHERE wait_class != 'Idle' ORDER BY time_waited DESC) WHERE ROWNUM <= 20;"
    exec_sql "${d}/wait_class.txt" "SELECT wait_class, COUNT(*) event_count, SUM(total_waits) total_waits, SUM(time_waited) total_time_waited FROM v\$system_event WHERE wait_class != 'Idle' GROUP BY wait_class ORDER BY total_time_waited DESC;"
}

# Disk Read 最高的 SQL
collect_top_disk_read_sql() {
    local d="$1"
    log_info "[采集] Disk Read最高SQL"
    local sql_text_expr="CAST('[REDACTED]' AS VARCHAR2(200)) sql_text"
    [[ "${COLLECT_SQL_TEXT:-off}" == "on" ]] && sql_text_expr="SUBSTR(sql_text, 1, 200) sql_text"
    exec_sql "${d}/top_disk_read_sql.txt" "SELECT * FROM (SELECT sql_id, disk_reads, executions, ROUND(disk_reads/NULLIF(executions,0), 2) reads_per_exec, buffer_gets, parsing_schema_name, ${sql_text_expr} FROM v\$sqlarea WHERE disk_reads > 10000 ORDER BY disk_reads DESC) WHERE ROWNUM <= 20;"
}

# 运行很久的 SQL
collect_long_running_sql() {
    local d="$1"
    log_info "[采集] 运行很久的SQL"
    exec_sql "${d}/long_running_sql.txt" "SELECT sid, serial#, opname, target, ROUND(sofar/NULLIF(totalwork,0)*100, 2) pct_complete, elapsed_seconds/60 elapsed_min, time_remaining/60 remaining_min, username, sql_id FROM v\$session_longops WHERE time_remaining > 0 ORDER BY elapsed_seconds DESC;"
}

# 碎片程度高的表
collect_table_fragmentation() {
    local d="$1"
    log_info "[采集] 表碎片"
    exec_sql "${d}/table_fragmentation.txt" "WITH bs AS (SELECT TO_NUMBER(value) AS block_size FROM v\$parameter WHERE name = 'db_block_size') SELECT * FROM (SELECT t.owner, t.table_name, ROUND(t.blocks * bs.block_size / 1024 / 1024, 2) size_mb, ROUND(t.num_rows * t.avg_row_len / 1024 / 1024, 2) actual_mb, ROUND(t.blocks * bs.block_size / 1024 / 1024 - t.num_rows * t.avg_row_len / 1024 / 1024, 2) wasted_mb, ROUND((1 - (t.num_rows * t.avg_row_len / 1024 / 1024) / NULLIF(t.blocks * bs.block_size / 1024 / 1024, 0)) * 100, 2) frag_pct, t.pct_free, t.num_rows, t.blocks, t.avg_row_len, t.last_analyzed FROM dba_tables t, bs WHERE t.blocks > 1000 AND t.num_rows > 0 AND t.owner NOT IN ('SYS','SYSTEM','DBSNMP','APPQOSSYS','DBSFWUSER','GSMADMIN_INTERNAL','LBACSYS','MDSYS','OLAPSYS','ORDDATA','ORDSYS','OUTLN','WMSYS','XDB','XS\$NULL') ORDER BY wasted_mb DESC) WHERE ROWNUM <= 30;"
}

# 长时间不活动会话
collect_dead_processes() {
    local d="$1"
    log_info "[采集] 长时间不活动会话（超过24小时）"
    exec_sql "${d}/dead_processes.txt" "SELECT s.sid, s.serial#, s.username, s.status, s.last_call_et/3600 inactive_hours, s.program, s.machine, s.osuser, s.sql_id FROM v\$session s WHERE s.status='INACTIVE' AND s.last_call_et > 86400 AND s.username IS NOT NULL ORDER BY s.last_call_et DESC;"
}

# System 表空间内容
collect_system_tablespace() {
    local d="$1"
    log_info "[采集] System表空间内容"
    local user_filter="u.username NOT IN ('SYS','SYSTEM','DBSNMP','APPQOSSYS','GSMADMIN_INTERNAL','MDSYS','OLAPSYS','ORDDATA','ORDSYS','OUTLN','WMSYS','XDB')"
    [[ "${HAS_USERS_ORACLE_MAINTAINED:-NO}" == "YES" ]] && user_filter="u.oracle_maintained='N'"
    exec_sql "${d}/system_tablespace.txt" "SELECT s.owner, s.segment_name, s.segment_type, ROUND(s.bytes/1024/1024, 2) size_mb FROM dba_segments s JOIN dba_users u ON u.username=s.owner WHERE s.tablespace_name='SYSTEM' AND ${user_filter} ORDER BY s.bytes DESC;"
}

# 无效对象
collect_invalid_objects() {
    local d="$1"
    log_info "[采集] 无效对象"
    exec_sql "${d}/invalid_objects.txt" "SELECT owner, object_name, object_type, status, created, last_ddl_time FROM dba_objects WHERE status='INVALID' ORDER BY owner, object_type, object_name;"
}

# 失效索引
collect_invalid_indexes() {
    local d="$1"
    log_info "[采集] 失效索引"
    exec_sql "${d}/invalid_indexes.txt" "SELECT owner, index_name, table_name, status, partitioned FROM dba_indexes WHERE status='UNUSABLE' ORDER BY owner, index_name;"
    exec_sql "${d}/invalid_index_partitions.txt" "SELECT index_owner, index_name, partition_name, status FROM dba_ind_partitions WHERE status='UNUSABLE' ORDER BY index_owner, index_name;"
}

# 无效 Trigger
collect_invalid_triggers() {
    local d="$1"
    log_info "[采集] 无效Trigger"
    local user_filter="u.username NOT IN ('SYS','SYSTEM','DBSNMP','APPQOSSYS','GSMADMIN_INTERNAL','MDSYS','OLAPSYS','ORDDATA','ORDSYS','OUTLN','WMSYS','XDB')"
    [[ "${HAS_USERS_ORACLE_MAINTAINED:-NO}" == "YES" ]] && user_filter="u.oracle_maintained='N'"
    exec_sql "${d}/invalid_triggers.txt" "SELECT t.owner, t.trigger_name, t.table_name, t.status, t.trigger_type FROM dba_triggers t JOIN dba_users u ON u.username=t.owner WHERE t.status='DISABLED' AND ${user_filter} ORDER BY t.owner, t.trigger_name;"
}

# AWR 关键指标
collect_awr_metrics() {
    local d="$1"
    log_info "[采集] AWR指标"
    exec_sql "${d}/awr_snapshot.txt" "SELECT * FROM (SELECT snap_id, begin_interval_time, end_interval_time FROM dba_hist_snapshot ORDER BY snap_id DESC) WHERE ROWNUM <= 10;"
    exec_sql "${d}/awr_sysstat.txt" "SELECT * FROM (SELECT ss.snap_id, ss.instance_number, ss.stat_name, ss.value FROM dba_hist_sysstat ss JOIN (SELECT snap_id, MAX(end_interval_time) et FROM dba_hist_snapshot GROUP BY snap_id) s ON ss.snap_id = s.snap_id WHERE ss.stat_name IN ('CPU used by this session', 'db block gets', 'consistent gets', 'physical reads', 'physical writes', 'redo size', 'user commits', 'user rollbacks', 'parse count (total)', 'execute count') ORDER BY s.et DESC) WHERE ROWNUM <= 50;"
    exec_sql "${d}/awr_top_events.txt" "SELECT * FROM (SELECT snap_id, event_name event, wait_class, total_waits, time_waited_micro, ROUND(time_waited_micro/NULLIF(total_waits,0),2) avg_wait_time_micro FROM dba_hist_system_event WHERE wait_class <> 'Idle' ORDER BY snap_id DESC, time_waited_micro DESC) WHERE ROWNUM <= 30;"
    exec_sql "${d}/awr_seg_stats.txt" "SELECT * FROM (SELECT s.snap_id, o.owner, o.object_name, o.tablespace_name, s.physical_reads_delta physical_reads, s.physical_writes_delta physical_writes, s.logical_reads_delta logical_reads, s.row_lock_waits_delta row_lock_waits FROM dba_hist_seg_stat s JOIN dba_hist_seg_stat_obj o ON o.dbid=s.dbid AND o.ts#=s.ts# AND o.obj#=s.obj# AND o.dataobj#=s.dataobj# WHERE NVL(s.physical_reads_delta,0)+NVL(s.physical_writes_delta,0)>0 ORDER BY s.snap_id DESC, (NVL(s.physical_reads_delta,0)+NVL(s.physical_writes_delta,0)) DESC) WHERE ROWNUM <= 20;"
    exec_sql "${d}/awr_sqlstat.txt" "SELECT * FROM (SELECT snap_id, sql_id, plan_hash_value, executions_delta, elapsed_time_delta, cpu_time_delta, buffer_gets_delta, disk_reads_delta, rows_processed_delta FROM dba_hist_sqlstat WHERE executions_delta > 0 ORDER BY snap_id DESC, elapsed_time_delta DESC) WHERE ROWNUM <= 20;"
}

skip_awr_metrics() {
    local d="$1"
    local reason="按配置未启用 AWR 采集（CHECK_AWR=off）"
    local name
    for name in awr_snapshot awr_sysstat awr_top_events awr_seg_stats awr_sqlstat; do
        printf "SKIPPED|%s\n" "${reason}" > "${d}/${name}.txt"
        record_collection "${name}.txt" "SQL" "SKIPPED" "0" "${reason}"
    done
    log_info "[跳过] ${reason}"
}

# 失败的 Job
collect_failed_jobs() {
    local d="$1"
    log_info "[采集] 失败的Job"
    exec_sql "${d}/failed_jobs.txt" "SELECT job_name, status, run_duration, actual_start_date, error#, additional_info FROM dba_scheduler_job_run_details WHERE status='FAILED' AND actual_start_date > SYSDATE - 7 ORDER BY actual_start_date DESC;"
    exec_sql "${d}/dbms_jobs.txt" "SELECT job, what, last_date, next_date, failures, broken FROM dba_jobs WHERE failures > 0 OR broken='Y';"
}

# 从物理 Alert Log 中提取最近指定时间范围的完整日志块。
# 同时兼容 11g 的 "Mon Aug 24 18:00:00 2026" 与 12c+ 的 ISO 时间格式。
extract_recent_alert_log() {
    local alert_file="$1"
    local output_file="$2"
    local cutoff_epoch="$3"
    local metrics_file="$4"

    awk -v cutoff_epoch="${cutoff_epoch}" -v metrics_file="${metrics_file}" '
    BEGIN {
        month["Jan"]=1; month["Feb"]=2; month["Mar"]=3; month["Apr"]=4;
        month["May"]=5; month["Jun"]=6; month["Jul"]=7; month["Aug"]=8;
        month["Sep"]=9; month["Oct"]=10; month["Nov"]=11; month["Dec"]=12;
        day["Mon"]=1; day["Tue"]=1; day["Wed"]=1; day["Thu"]=1;
        day["Fri"]=1; day["Sat"]=1; day["Sun"]=1;
        include_line=0;
        timestamp_count=0;
    }
    function timestamp_epoch(line, fields, count, clock, year, mon, mday, hour, minute, second) {
        if (line ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
            year=substr(line,1,4); mon=substr(line,6,2); mday=substr(line,9,2);
            hour=substr(line,12,2); minute=substr(line,15,2); second=substr(line,18,2);
            return mktime(year " " mon " " mday " " hour " " minute " " second);
        }
        count=split(line,fields,/[[:space:]]+/);
        if (count >= 5 && (fields[1] in day) && (fields[2] in month)) {
            split(fields[4],clock,":");
            return mktime(fields[5] " " month[fields[2]] " " fields[3] " " clock[1] " " clock[2] " " clock[3]);
        }
        return -1;
    }
    {
        epoch=timestamp_epoch($0);
        if (epoch >= 0) {
            if (timestamp_count == 0) first_timestamp_epoch=epoch;
            last_timestamp_epoch=epoch;
            timestamp_count++;
            include_line=(epoch >= cutoff_epoch);
            if (include_line) {
                if (first_included_epoch == "") first_included_epoch=epoch;
                last_included_epoch=epoch;
            }
        }
        if (include_line) print;
    }
    END {
        if (timestamp_count == 0) exit 2;
        print first_timestamp_epoch > metrics_file;
        print first_included_epoch >> metrics_file;
        print last_included_epoch >> metrics_file;
    }
    ' "${alert_file}" > "${output_file}"
}

# Alert Log：只使用 Diag Trace 拼接当前实例的物理日志文件。
collect_alert_log() {
    local d="$1"
    log_info "[采集] Alert Log"
    local diag_dir
    diag_dir=$(sqlplus -L -S "${DB_CONNECT}" <<EOF 2>/dev/null
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF ECHO OFF VERIFY OFF
SELECT value FROM v\$diag_info WHERE name='Diag Trace';
EXIT
EOF
    )
    local diag_rc=$?
    diag_dir=$(printf '%s\n' "${diag_dir}" | awk 'NF { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); print; exit }')

    if [[ "${diag_rc}" -ne 0 || -z "${diag_dir}" ]]; then
        echo "alert_log_path=NOT_FOUND" > "${d}/alert_log_path.txt"
        log_error "无法从 v\$diag_info 获取 Diag Trace (rc=${diag_rc})"
        record_collection "alert_log_30days.txt" "COMMAND" "FAILED" "${diag_rc}" "无法获取 Diag Trace"
        return 1
    fi

    local alert_file="${diag_dir}/alert_${ORACLE_SID}.log"

    if [[ ! -r "${alert_file}" ]]; then
        log_error "Alert Log 不存在或不可读: ${alert_file}"
        record_collection "alert_log_30days.txt" "COMMAND" "FAILED" "1" "${alert_file} 不存在或不可读"
        return 1
    fi

    local alert_size_bytes alert_size_display
    alert_size_bytes=$(stat -c '%s' "${alert_file}" 2>/dev/null)
    [[ "${alert_size_bytes}" =~ ^[0-9]+$ ]] || alert_size_bytes=0
    alert_size_display=$(awk -v bytes="${alert_size_bytes}" 'BEGIN {
        if (bytes >= 1073741824) printf "%.2f GB", bytes/1073741824;
        else if (bytes >= 1048576) printf "%.2f MB", bytes/1048576;
        else if (bytes >= 1024) printf "%.2f KB", bytes/1024;
        else printf "%d B", bytes;
    }')

    # tail 会从文件尾部定位，只读取最后 100001 行，不顺序扫描整个大文件。
    # 多取一行用于判断物理日志是否超过分析上限，最终样本严格限制为 100000 行。
    local sample_candidate="${d}/.alert_log_last_100001.tmp"
    local sample_file="${d}/alert_log_last_100000.txt"
    tail -n 100001 "${alert_file}" > "${sample_candidate}"
    local tail_rc=$?
    if [[ "${tail_rc}" -ne 0 ]]; then
        record_collection "alert_log_last_100000.txt" "COMMAND" "FAILED" "${tail_rc}" "读取 Alert Log 尾部失败"
        return 1
    fi
    local candidate_line_count sample_line_count source_over_limit
    candidate_line_count=$(awk 'END { print NR+0 }' "${sample_candidate}")
    source_over_limit="NO"
    if [[ "${candidate_line_count}" -gt 100000 ]]; then
        source_over_limit="YES"
    fi
    tail -n 100000 "${sample_candidate}" > "${sample_file}"
    rm -f "${sample_candidate}"
    sample_line_count=$(awk 'END { print NR+0 }' "${sample_file}")

    local cutoff_epoch
    cutoff_epoch=$(date -d '30 days ago' '+%s')
    local metrics_file="${d}/.alert_log_metrics.tmp"
    extract_recent_alert_log "${sample_file}" "${d}/alert_log_30days.txt" "${cutoff_epoch}" "${metrics_file}"
    local extract_rc=$?
    if [[ "${extract_rc}" -ne 0 ]]; then
        rm -f "${metrics_file}"
        log_error "无法识别 Alert Log 时间格式: ${alert_file}"
        record_collection "alert_log_30days.txt" "COMMAND" "FAILED" "${extract_rc}" "无法识别日志时间格式"
        return 1
    fi
    local first_sample_epoch first_included_epoch last_included_epoch window_truncated
    first_sample_epoch=$(sed -n '1p' "${metrics_file}" 2>/dev/null)
    first_included_epoch=$(sed -n '2p' "${metrics_file}" 2>/dev/null)
    last_included_epoch=$(sed -n '3p' "${metrics_file}" 2>/dev/null)
    rm -f "${metrics_file}"
    window_truncated="NO"
    if [[ "${source_over_limit}" == "YES" && "${first_sample_epoch}" =~ ^[0-9]+$ && "${first_sample_epoch}" -ge "${cutoff_epoch}" ]]; then
        window_truncated="YES"
    fi

    # 生成报告端使用的结构化告警明细；所有内容均来自上面的实例物理日志。
    {
        echo "EVENT_TIME|MESSAGE_TEXT"
        awk '
        /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[[:space:]]/ || /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/ { event_time=$0 }
        {
            lower=tolower($0);
            if (lower ~ /ora-[0-9][0-9][0-9][0-9][0-9]|tns-[0-9][0-9][0-9][0-9][0-9]|error|critical|fatal|corrupt/) {
                message=$0;
                gsub(/\|/, "/", message);
                print event_time "|" message;
            }
        }
        ' "${d}/alert_log_30days.txt"
    } > "${d}/alert_log_recent.txt"

    awk -F'|' 'NR > 1 { $1=""; sub(/^\|/, ""); print }' OFS='|' \
        "${d}/alert_log_recent.txt" > "${d}/alert_log_errors.txt"
    tail -500 "${d}/alert_log_30days.txt" > "${d}/alert_log_tail.txt"

    local alert_count severe_count first_time last_time host_name analysis_start_time analysis_end_time
    alert_count=$(awk 'NR > 1 { count++ } END { print count+0 }' "${d}/alert_log_recent.txt")
    severe_count=$(awk 'BEGIN { IGNORECASE=1 } /ORA-00600|ORA-00700|ORA-07445|ORA-01578|CORRUPT/ { count++ } END { print count+0 }' "${d}/alert_log_recent.txt")
    first_time=$(awk -F'|' 'NR == 2 { print $1; exit }' "${d}/alert_log_recent.txt")
    last_time=$(awk -F'|' 'NR > 1 { value=$1 } END { print value }' "${d}/alert_log_recent.txt")
    host_name=$(hostname 2>/dev/null)
    analysis_start_time=""
    analysis_end_time=""
    if [[ "${first_included_epoch}" =~ ^[0-9]+$ ]]; then
        analysis_start_time=$(date -d "@${first_included_epoch}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    fi
    if [[ "${last_included_epoch}" =~ ^[0-9]+$ ]]; then
        analysis_end_time=$(date -d "@${last_included_epoch}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    fi
    {
        echo "DATABASE_NAME|INSTANCE_NAME|HOST_NAME|ALERT_FILE|ALERT_COUNT|SEVERE_COUNT|FIRST_TIME|LAST_TIME|WINDOW_DAYS|ANALYZED_LINE_LIMIT|ANALYZED_LINE_COUNT|WINDOW_TRUNCATED|ALERT_FILE_SIZE_BYTES|ALERT_FILE_SIZE_DISPLAY|ANALYSIS_START_TIME|ANALYSIS_END_TIME"
        echo "${ORACLE_SID}|${ORACLE_SID}|${host_name}|${alert_file}|${alert_count}|${severe_count}|${first_time}|${last_time}|30|100000|${sample_line_count}|${window_truncated}|${alert_size_bytes}|${alert_size_display}|${analysis_start_time}|${analysis_end_time}"
    } > "${d}/alert_log_summary.txt"

    {
        echo "alert_log_path=${alert_file}"
        echo "diag_trace=${diag_dir}"
        echo "oracle_sid=${ORACLE_SID}"
        echo "window_days=30"
        echo "analyzed_line_limit=100000"
        echo "analyzed_line_count=${sample_line_count}"
        echo "window_truncated=${window_truncated}"
        echo "alert_file_size_bytes=${alert_size_bytes}"
        echo "alert_file_size_display=${alert_size_display}"
        echo "analysis_start_time=${analysis_start_time}"
        echo "analysis_end_time=${analysis_end_time}"
    } > "${d}/alert_log_path.txt"

    record_collection "alert_log_path.txt" "COMMAND" "OK" "0" ""
    record_collection "alert_log_last_100000.txt" "COMMAND" "OK" "0" ""
    record_collection "alert_log_30days.txt" "COMMAND" "OK" "0" ""
    record_collection "alert_log_recent.txt" "COMMAND" "OK" "0" ""
    record_collection "alert_log_summary.txt" "COMMAND" "OK" "0" ""
}

# 跟踪文件
collect_trace_files() {
    local d="$1"
    log_info "[采集] 跟踪文件"
    exec_sql "${d}/trace_dir.txt" "SELECT name, value FROM v\$diag_info WHERE name IN ('Diag Trace', 'Diag Alert', 'Default Trace File');"

    local trace_dir=$(sqlplus -S "${DB_CONNECT}" <<EOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF
SELECT value FROM v\$diag_info WHERE name='Diag Trace';
EXIT
EOF
)
    trace_dir=$(echo "${trace_dir}" | xargs)

    if [[ -n "${trace_dir}" && -d "${trace_dir}" ]]; then
        find "${trace_dir}" -name "*.trc" -mtime -1 -ls > "${d}/trace_recent.txt" 2>&1 || true
        find "${trace_dir}" -name "*.trc" -mtime -7 -size +100M -ls > "${d}/trace_large.txt" 2>&1 || true
    else
        echo "trace_dir not found" > "${d}/trace_recent.txt"
    fi
}
