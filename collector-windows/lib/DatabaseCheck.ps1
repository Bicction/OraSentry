Set-StrictMode -Version 2.0

function Get-DatabaseQueries {
    param(
        [bool]$CollectSqlText,
        [bool]$HasDgDestExt = $false,
        [bool]$HasDgProcess = $false
    )
    $sqlText = if ($CollectSqlText) { "SUBSTR(REPLACE(REPLACE(sql_text, CHR(10), ' '), CHR(13), ' '), 1, 1000) sql_text" } else { "CAST(NULL AS VARCHAR2(1)) sql_text" }
    $destUnique = if ($HasDgDestExt) { "db_unique_name" } else { "CAST(NULL AS VARCHAR2(30)) db_unique_name" }
    $synchronized = if ($HasDgDestExt) { "synchronized" } else { "CAST(NULL AS VARCHAR2(3)) synchronized" }
    $syncStatus = if ($HasDgDestExt) { "synchronization_status" } else { "CAST(NULL AS VARCHAR2(22)) synchronization_status" }
    $gapStatus = if ($HasDgDestExt) { "gap_status" } else { "CAST(NULL AS VARCHAR2(24)) gap_status" }
    $appliedThread = if ($HasDgDestExt) { "applied_thread#" } else { "CAST(NULL AS NUMBER) applied_thread#" }
    $appliedSeq = if ($HasDgDestExt) { "applied_seq#" } else { "CAST(NULL AS NUMBER) applied_seq#" }
    $dgProcessSql = if ($HasDgProcess) {
        "SELECT role process_role, thread#, sequence#, action process_action, CAST(NULL AS VARCHAR2(16)) client_process FROM v`$dataguard_process ORDER BY role, thread#, sequence#;"
    } else {
        "SELECT process process_role, thread#, sequence#, status process_action, client_process FROM v`$managed_standby ORDER BY process, thread#, sequence#;"
    }
    $dgClusterProcessSql = if ($HasDgProcess) {
        "SELECT i.inst_id, i.instance_name, i.host_name, p.role process_role, p.thread#, p.sequence#, p.action process_action, CAST(NULL AS VARCHAR2(16)) client_process, TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at FROM gv`$instance i LEFT JOIN gv`$dataguard_process p ON p.inst_id=i.inst_id ORDER BY i.inst_id, p.role, p.thread#, p.sequence#;
SELECT 'DG_CLUSTER_OK' dg_marker FROM dual;"
    } else {
        "SELECT i.inst_id, i.instance_name, i.host_name, p.process process_role, p.thread#, p.sequence#, p.status process_action, p.client_process client_process, TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at FROM gv`$instance i LEFT JOIN gv`$managed_standby p ON p.inst_id=i.inst_id ORDER BY i.inst_id, p.process, p.thread#, p.sequence#;
SELECT 'DG_CLUSTER_OK' dg_marker FROM dual;"
    }
    $queries = [ordered]@{
        "db_version.txt" = "SELECT * FROM v`$version;"
        "spfile.txt" = "SELECT name, value, isspecified FROM v`$spparameter WHERE isspecified='TRUE' ORDER BY name;"
        "parameters.txt" = "SHOW PARAMETER;"
        "instance_status.txt" = "SELECT inst_id, instance_name, host_name, status, database_status, version, startup_time FROM gv`$instance ORDER BY inst_id;"
        "database_status.txt" = "SELECT name, open_mode, database_role, created, log_mode FROM v`$database;"
        "db_resilience.txt" = "SELECT force_logging, flashback_on, supplemental_log_data_min, database_role, protection_mode, protection_level, switchover_status FROM v`$database;"
        "dataguard_identity.txt" = "SELECT name, db_unique_name, database_role, open_mode, log_mode, force_logging, flashback_on, protection_mode, protection_level, switchover_status FROM v`$database;"
        "dataguard_dest_config.txt" = "SELECT dest_id, status, target, destination, error FROM v`$archive_dest WHERE target='STANDBY' ORDER BY dest_id;"
        "registry_components.txt" = "SELECT comp_id, comp_name, version, status, modified FROM dba_registry ORDER BY comp_id;"
        "datafile_recovery.txt" = "SELECT r.file#, d.name, r.error, r.online_status, r.change#, r.time FROM v`$recover_file r JOIN v`$datafile d ON d.file#=r.file# ORDER BY r.file#;"
        "block_corruption.txt" = "SELECT file#, block#, blocks, corruption_change#, corruption_type FROM v`$database_block_corruption ORDER BY file#, block#;"
        "dataguard_dest_status.txt" = "SELECT dest_id, status, type, database_mode, recovery_mode, destination, error, archived_thread#, archived_seq# FROM v`$archive_dest_status WHERE status <> 'INACTIVE' ORDER BY dest_id;"
        "dataguard_dest_health.txt" = "SELECT dest_id, status, type, database_mode, recovery_mode, $destUnique, destination, $synchronized, $syncStatus, $gapStatus, error, archived_thread#, archived_seq#, $appliedThread, $appliedSeq FROM v`$archive_dest_status WHERE status <> 'INACTIVE' ORDER BY dest_id;"
        "dataguard_stats.txt" = "SELECT name, value, unit, time_computed, datum_time FROM v`$dataguard_stats ORDER BY name;"
        "dataguard_process.txt" = $dgProcessSql
        "dataguard_context.txt" = "SELECT instance_number inst_id, instance_name, host_name, (SELECT value FROM v`$parameter WHERE name='cluster_database') cluster_database, TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at FROM v`$instance;"
        "dataguard_cluster_stats.txt" = "SELECT inst_id, name, value, unit, time_computed, datum_time, TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at FROM gv`$dataguard_stats ORDER BY inst_id, name;
SELECT 'DG_STATS_OK' dg_marker FROM dual;"
        "dataguard_cluster_process.txt" = $dgClusterProcessSql
        "archive_gap.txt" = "SELECT thread#, low_sequence#, high_sequence# FROM v`$archive_gap ORDER BY thread#, low_sequence#;"
        "dataguard_sequence.txt" = "SELECT thread#, MAX(sequence#) received_seq, MAX(CASE WHEN applied='YES' THEN sequence# END) applied_seq, MAX(CASE WHEN applied='IN-MEMORY' THEN sequence# END) in_memory_seq FROM v`$archived_log WHERE registrar='RFS' AND resetlogs_change#=(SELECT resetlogs_change# FROM v`$database) GROUP BY thread# ORDER BY thread#;"
        "dataguard_redo_config.txt" = "SELECT NVL(o.thread#,s.thread#) thread#, NVL(o.online_groups,0) online_groups, o.online_min_mb, NVL(s.standby_groups,0) standby_groups, s.standby_min_mb FROM (SELECT thread#,COUNT(*) online_groups,ROUND(MIN(bytes)/1024/1024,2) online_min_mb FROM v`$log GROUP BY thread#) o FULL OUTER JOIN (SELECT thread#,COUNT(*) standby_groups,ROUND(MIN(bytes)/1024/1024,2) standby_min_mb FROM v`$standby_log GROUP BY thread#) s ON s.thread#=o.thread# ORDER BY 1;"
        "dataguard_events.txt" = "SELECT timestamp, facility, severity, error_code, dest_id, message FROM v`$dataguard_status WHERE timestamp > SYSDATE-1 AND severity IN ('Warning','Error','Fatal') ORDER BY timestamp DESC;"
        "rac_nodes.txt" = "SELECT inst_id, instance_number, instance_name, host_name, status, database_status, instance_role, startup_time, version FROM gv`$instance ORDER BY inst_id;"
        "rac_services.txt" = "SELECT name, network_name, creation_date, enabled, goal, failover_method, failover_type FROM dba_services ORDER BY name;"
        "nls_params.txt" = "SELECT parameter, value FROM nls_database_parameters ORDER BY parameter;"
        "rman_backup.txt" = "SELECT session_key, start_time, end_time, status, input_type, output_device_type, ROUND(output_bytes/1024/1024/1024,2) output_gb FROM v`$rman_backup_job_details WHERE start_time > SYSDATE - 7 ORDER BY start_time DESC;"
        "rman_status.txt" = "SELECT * FROM (SELECT operation, object_type, status, start_time, end_time FROM v`$rman_status WHERE start_time > SYSDATE - 7 ORDER BY start_time DESC) WHERE ROWNUM <= 50;"
        "recovery_file_dest.txt" = "SELECT name, space_limit/1024/1024/1024 limit_gb, space_used/1024/1024/1024 used_gb, space_reclaimable/1024/1024/1024 reclaimable_gb, ROUND(space_used/NULLIF(space_limit,0)*100,2) usage_pct FROM v`$recovery_file_dest;"
        "archive_log.txt" = "SELECT thread#, sequence#, name, archived, completion_time FROM v`$archived_log WHERE completion_time > SYSDATE - 7 ORDER BY completion_time DESC;"
        "control_files.txt" = "SELECT name, status, is_recovery_dest_file, block_size, file_size_blks FROM v`$controlfile;"
        "redo_logs.txt" = "SELECT a.group#, a.thread#, a.sequence#, a.members, a.archived, a.status, a.bytes/1024/1024 size_mb, b.member FROM v`$log a, v`$logfile b WHERE a.group# = b.group#(+) ORDER BY a.group#, b.member;"
        "redo_switch_freq.txt" = "SELECT TO_CHAR(first_time, 'YYYY-MM-DD HH24') hour_slot, COUNT(*) switch_count FROM v`$log_history WHERE first_time > SYSDATE - 30 GROUP BY TO_CHAR(first_time, 'YYYY-MM-DD HH24') ORDER BY hour_slot;"
        "data_files.txt" = "SELECT file_name, tablespace_name, bytes/1024/1024 size_mb, autoextensible, maxbytes/1024/1024 maxsize_mb, status, online_status FROM dba_data_files ORDER BY tablespace_name, file_name;"
        "tablespaces.txt" = "WITH df AS (SELECT tablespace_name, SUM(bytes) alloc_bytes, SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes, MAX(autoextensible) autoextensible FROM dba_data_files GROUP BY tablespace_name), fs AS (SELECT tablespace_name, SUM(bytes) free_bytes FROM dba_free_space GROUP BY tablespace_name) SELECT df.tablespace_name, t.contents, ROUND(df.alloc_bytes/POWER(1024,3),2) alloc_gb, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/POWER(1024,3),2) used_gb, ROUND(NVL(fs.free_bytes,0)/POWER(1024,3),2) free_gb, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/NULLIF(df.alloc_bytes,0)*100,2) alloc_usage_pct, ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/NULLIF(df.max_bytes,0)*100,2) max_usage_pct, ROUND(df.max_bytes/POWER(1024,3),2) max_gb, df.autoextensible, t.status FROM df JOIN dba_tablespaces t ON t.tablespace_name=df.tablespace_name LEFT JOIN fs ON fs.tablespace_name=df.tablespace_name ORDER BY alloc_usage_pct DESC;"
        "temp_tablespaces.txt" = "WITH tf AS (SELECT tablespace_name, SUM(bytes) alloc_bytes, SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes, MAX(autoextensible) autoextensible FROM dba_temp_files GROUP BY tablespace_name), tu AS (SELECT u.tablespace tablespace_name, SUM(u.blocks*t.block_size) used_bytes FROM v`$tempseg_usage u JOIN dba_tablespaces t ON t.tablespace_name=u.tablespace GROUP BY u.tablespace) SELECT tf.tablespace_name, 'TEMPORARY' contents, ROUND(tf.alloc_bytes/POWER(1024,3),2) alloc_gb, ROUND(NVL(tu.used_bytes,0)/POWER(1024,3),2) used_gb, ROUND((tf.alloc_bytes-NVL(tu.used_bytes,0))/POWER(1024,3),2) free_gb, ROUND(NVL(tu.used_bytes,0)/NULLIF(tf.alloc_bytes,0)*100,2) alloc_usage_pct, ROUND(NVL(tu.used_bytes,0)/NULLIF(tf.max_bytes,0)*100,2) max_usage_pct, ROUND(tf.max_bytes/POWER(1024,3),2) max_gb, tf.autoextensible, t.status FROM tf JOIN dba_tablespaces t ON t.tablespace_name=tf.tablespace_name LEFT JOIN tu ON tu.tablespace_name=tf.tablespace_name ORDER BY alloc_usage_pct DESC;"
        "tablespaces_ext.txt" = "SELECT tablespace_name, file_name, bytes/1024/1024 size_mb, autoextensible, maxbytes/1024/1024 maxsize_mb, increment_by FROM dba_data_files ORDER BY tablespace_name, file_name;"
        "undo_tablespace.txt" = "SELECT tablespace_name, status, ROUND(SUM(bytes)/1024/1024,2) size_mb FROM dba_undo_extents GROUP BY tablespace_name, status ORDER BY tablespace_name, status;"
        "undo_retention.txt" = "SELECT name, value FROM v`$parameter WHERE name LIKE '%undo%';"
        "asm_diskgroups.txt" = "SELECT group_number, name, state, type, ROUND(total_mb/1024,2) total_gb, ROUND(free_mb/1024,2) free_gb, ROUND((1-free_mb/NULLIF(total_mb,0))*100,2) usage_pct FROM v`$asm_diskgroup;"
        "asm_disks.txt" = "SELECT group_number, disk_number, name, path, mode_status, state, ROUND(total_mb/1024,2) total_gb, ROUND(free_mb/1024,2) free_gb FROM v`$asm_disk;"
        "sessions.txt" = "SELECT (SELECT COUNT(*) FROM v`$session) current_sessions, (SELECT value FROM v`$parameter WHERE name='sessions') max_sessions, (SELECT COUNT(*) FROM v`$process) current_processes, (SELECT value FROM v`$parameter WHERE name='processes') max_processes FROM dual;"
        "session_detail.txt" = "SELECT username, status, COUNT(*) cnt FROM v`$session WHERE username IS NOT NULL GROUP BY username, status ORDER BY cnt DESC;"
        "resource_limits.txt" = "SELECT resource_name, current_utilization, max_utilization, initial_allocation, limit_value FROM v`$resource_limit WHERE resource_name IN ('processes','sessions','enqueue_locks','transactions','parallel_max_servers') ORDER BY resource_name;"
        "blocking_sessions.txt" = "SELECT s.sid, s.serial#, s.username, s.status, s.event, s.seconds_in_wait, s.blocking_instance, s.blocking_session, s.sql_id, s.machine, s.program FROM v`$session s WHERE s.blocking_session IS NOT NULL ORDER BY s.seconds_in_wait DESC;"
        "stale_statistics.txt" = "SELECT owner, COUNT(*) stale_count, MIN(last_analyzed) oldest_analyzed FROM dba_tab_statistics WHERE stale_stats='YES' AND object_type='TABLE' AND owner NOT IN ('SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN') GROUP BY owner ORDER BY stale_count DESC;"
        "top_elapsed_sql.txt" = "SELECT * FROM (SELECT sql_id, plan_hash_value, executions, ROUND(elapsed_time/POWER(10,6),2) elapsed_sec, ROUND(cpu_time/POWER(10,6),2) cpu_sec, buffer_gets, disk_reads, rows_processed, parsing_schema_name, $sqlText FROM v`$sqlarea WHERE executions > 0 ORDER BY elapsed_time DESC) WHERE ROWNUM <= 20;"
        "buffer_cache_hit.txt" = "SELECT name, physical_reads, db_block_gets, consistent_gets, ROUND((1-physical_reads/NULLIF(db_block_gets+consistent_gets,0))*100,2) hit_ratio FROM v`$buffer_pool_statistics WHERE db_block_gets + consistent_gets > 0;"
        "library_cache_hit.txt" = "SELECT SUM(pins) pins, SUM(reloads) reloads, ROUND((1-SUM(reloads)/NULLIF(SUM(pins),0))*100,2) hit_ratio FROM v`$librarycache;"
        "sga_info.txt" = "SELECT name, ROUND(value/1024/1024,2) size_mb FROM v`$sga;"
        "sgastat.txt" = "SELECT pool, name, ROUND(bytes/1024/1024,2) size_mb FROM v`$sgastat ORDER BY pool, bytes DESC;"
        "sga_components.txt" = "SELECT component, current_size/1024/1024 current_mb, min_size/1024/1024 min_mb, user_specified_size/1024/1024 specified_mb FROM v`$sga_dynamic_components ORDER BY current_size DESC;"
        "wait_events.txt" = "SELECT * FROM (SELECT event, wait_class, total_waits, time_waited, average_wait, ROUND(time_waited*100/NULLIF(SUM(time_waited) OVER(),0),2) wait_pct FROM v`$system_event WHERE wait_class != 'Idle' ORDER BY time_waited DESC) WHERE ROWNUM <= 20;"
        "wait_class.txt" = "SELECT wait_class, COUNT(*) event_count, SUM(total_waits) total_waits, SUM(time_waited) total_time_waited FROM v`$system_event WHERE wait_class != 'Idle' GROUP BY wait_class ORDER BY total_time_waited DESC;"
        "top_disk_read_sql.txt" = "SELECT * FROM (SELECT sql_id, disk_reads, executions, ROUND(disk_reads/NULLIF(executions,0),2) reads_per_exec, buffer_gets, parsing_schema_name, $sqlText FROM v`$sqlarea WHERE disk_reads > 10000 ORDER BY disk_reads DESC) WHERE ROWNUM <= 20;"
        "long_running_sql.txt" = "SELECT sid, serial#, opname, target, ROUND(sofar/NULLIF(totalwork,0)*100,2) pct_complete, elapsed_seconds/60 elapsed_min, time_remaining/60 remaining_min, username, sql_id FROM v`$session_longops WHERE time_remaining > 0 ORDER BY elapsed_seconds DESC;"
        "table_fragmentation.txt" = "WITH bs AS (SELECT TO_NUMBER(value) block_size FROM v`$parameter WHERE name='db_block_size') SELECT * FROM (SELECT t.owner, t.table_name, ROUND(t.blocks*bs.block_size/1024/1024,2) size_mb, ROUND(t.num_rows*t.avg_row_len/1024/1024,2) actual_mb, ROUND(t.blocks*bs.block_size/1024/1024-t.num_rows*t.avg_row_len/1024/1024,2) wasted_mb, ROUND((1-(t.num_rows*t.avg_row_len)/NULLIF(t.blocks*bs.block_size,0))*100,2) frag_pct, t.pct_free, t.num_rows, t.blocks, t.avg_row_len, t.last_analyzed FROM dba_tables t, bs WHERE t.blocks>1000 AND t.num_rows>0 AND t.owner NOT IN ('SYS','SYSTEM','DBSNMP','MDSYS','XDB','OUTLN') ORDER BY wasted_mb DESC) WHERE ROWNUM <= 30;"
        "dead_processes.txt" = "SELECT s.sid, s.serial#, s.username, s.status, s.last_call_et/3600 inactive_hours, s.program, s.machine, s.osuser, s.sql_id FROM v`$session s WHERE s.status='INACTIVE' AND s.last_call_et>86400 AND s.username IS NOT NULL ORDER BY s.last_call_et DESC;"
        "system_tablespace.txt" = "SELECT s.owner, s.segment_name, s.segment_type, ROUND(s.bytes/1024/1024,2) size_mb FROM dba_segments s WHERE s.tablespace_name='SYSTEM' AND s.owner NOT IN ('SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN','MDSYS','XDB') ORDER BY s.bytes DESC;"
        "invalid_objects.txt" = "SELECT owner, object_name, object_type, status, created, last_ddl_time FROM dba_objects WHERE status='INVALID' ORDER BY owner, object_type, object_name;"
        "invalid_indexes.txt" = "SELECT owner, index_name, table_name, status, partitioned FROM dba_indexes WHERE status='UNUSABLE' ORDER BY owner, index_name;"
        "invalid_index_partitions.txt" = "SELECT index_owner, index_name, partition_name, status FROM dba_ind_partitions WHERE status='UNUSABLE' ORDER BY index_owner, index_name;"
        "invalid_triggers.txt" = "SELECT owner, trigger_name, table_name, status, trigger_type FROM dba_triggers WHERE status='DISABLED' AND owner NOT IN ('SYS','SYSTEM','SYSMAN','DBSNMP','OUTLN','MDSYS','XDB') ORDER BY owner, trigger_name;"
        "failed_jobs.txt" = "SELECT job_name, status, run_duration, actual_start_date, error#, additional_info FROM dba_scheduler_job_run_details WHERE status='FAILED' AND actual_start_date>SYSDATE-7 ORDER BY actual_start_date DESC;"
        "dbms_jobs.txt" = "SELECT job, what, last_date, next_date, failures, broken FROM dba_jobs WHERE failures>0 OR broken='Y';"
        "trace_dir.txt" = "SELECT name, value FROM v`$diag_info WHERE name IN ('Diag Trace','Diag Alert','Default Trace File');"
        "storage_paths.txt" = "SELECT storage_type, storage_path FROM (SELECT 'DATAFILE' storage_type, file_name storage_path FROM dba_data_files UNION ALL SELECT 'TEMPFILE', file_name FROM dba_temp_files UNION ALL SELECT 'REDO', member FROM v`$logfile UNION ALL SELECT 'CONTROL', name FROM v`$controlfile UNION ALL SELECT 'FRA', name FROM v`$recovery_file_dest WHERE name IS NOT NULL UNION ALL SELECT 'DIAG_TRACE', value FROM v`$diag_info WHERE name='Diag Trace' UNION ALL SELECT 'ARCHIVE_DEST', destination FROM v`$archive_dest WHERE status='VALID' AND destination IS NOT NULL) ORDER BY storage_type, storage_path;"
    }
    return $queries
}

function Collect-WindowsStoragePathCapacity {
    param($Context, [string]$DbDir)
    Invoke-CollectionAction $Context "storage_path_capacity.txt" {
        $source = Join-Path $DbDir "storage_paths.txt"
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "storage_paths.txt 不存在" }
        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($line in Get-Content -LiteralPath $source -ErrorAction Stop) {
            $text = ([string]$line).Trim()
            if (-not $text -or $text.StartsWith("-")) { continue }
            $parts = @($text -split '\|', 2)
            if ($parts.Count -lt 2 -or $parts[0].Trim().ToUpperInvariant() -eq "STORAGE_TYPE") { continue }
            $storageType = $parts[0].Trim()
            $path = $parts[1].Trim()
            if ($storageType -and $path) { $entries.Add(@($storageType, $path)) }
        }
        if ($Context.OracleHome) { $entries.Add(@("ORACLE_HOME", [string]$Context.OracleHome)) }

        $groups = @{}
        foreach ($entry in $entries) {
            $storageType = [string]$entry[0]
            $path = [Environment]::ExpandEnvironmentVariables([string]$entry[1])
            $kind = "OTHER"
            $volume = ""
            $totalGb = ""
            $freeGb = ""
            $usagePct = ""
            if ($path.StartsWith("+")) {
                $kind = "ASM"
                $volume = ($path -split '[\\/]', 2)[0]
            } elseif ($path -match '^\\\\') {
                $kind = "UNC"
                if ($path -match '^(\\\\[^\\]+\\[^\\]+)') { $volume = $matches[1] }
            } elseif ([System.IO.Path]::IsPathRooted($path)) {
                $kind = "FILESYSTEM"
                $volume = ([System.IO.Path]::GetPathRoot($path)).TrimEnd('\')
                if ($volume -match '^[A-Za-z]:$') {
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $volume.Replace("'", "''")) -ErrorAction SilentlyContinue
                    if ($disk -and [double]$disk.Size -gt 0) {
                        $totalGb = [Math]::Round([double]$disk.Size / 1GB, 2)
                        $freeGb = [Math]::Round([double]$disk.FreeSpace / 1GB, 2)
                        $usagePct = [Math]::Round((1 - [double]$disk.FreeSpace / [double]$disk.Size) * 100, 2)
                    }
                }
            }
            $key = "{0}|{1}|{2}" -f $storageType, $kind, $volume
            if (-not $groups.ContainsKey($key)) {
                $groups[$key] = [pscustomobject]@{
                    Type=$storageType; Kind=$kind; Volume=$volume; Count=0; Example=$path
                    TotalGb=$totalGb; FreeGb=$freeGb; UsagePct=$usagePct
                }
            }
            $groups[$key].Count++
        }
        if ($groups.Count -eq 0) { throw "未识别到 Oracle 存储路径" }
        $rows = foreach ($group in ($groups.Values | Sort-Object Type, Volume)) {
            ,@($group.Type, $group.Kind, $group.Volume, $group.Count, $group.Example,
                $group.TotalGb, $group.FreeGb, $group.UsagePct)
        }
        Write-PipeTable (Join-Path $DbDir "storage_path_capacity.txt") @(
            "TYPE","STORAGE_KIND","VOLUME","PATH_COUNT","EXAMPLE_PATH","TOTAL_GB","FREE_GB","USAGE_PCT"
        ) $rows
    } -Optional
}

function Collect-WindowsAlertLog {
    param($Context, [string]$DbDir)
    Invoke-CollectionAction $Context "alert_log_summary.txt" {
        $diagDir = (Invoke-OraScalar $Context "SELECT value FROM v`$diag_info WHERE name='Diag Trace';").Trim()
        if (-not $diagDir) { throw "V`$DIAG_INFO 未返回 Diag Trace" }
        $alertFile = Join-Path $diagDir ("alert_{0}.log" -f $Context.OracleSid)
        if (-not (Test-Path -LiteralPath $alertFile -PathType Leaf)) { throw "Alert Log不存在: $alertFile" }
        $file = Get-Item -LiteralPath $alertFile -ErrorAction Stop
        $lines = @(Get-Content -LiteralPath $alertFile -Tail 100000 -Encoding UTF8 -ErrorAction Stop)
        Write-CollectorLines (Join-Path $DbDir "alert_log_last_100000.txt") $lines
        $cutoff = (Get-Date).AddDays(-30)
        $currentTime = $null
        $recentLines = New-Object System.Collections.Generic.List[string]
        $errorRows = New-Object System.Collections.Generic.List[object]
        $firstTime = $null
        $lastTime = $null
        foreach ($line in $lines) {
            $parsed = [DateTime]::MinValue
            $candidate = $line
            if ($line -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $candidate = $line.Substring(0,19) }
            if ([DateTime]::TryParse($candidate, [ref]$parsed)) { $currentTime = $parsed }
            if ($currentTime -and $currentTime -ge $cutoff) {
                $recentLines.Add($line)
                if (-not $firstTime) { $firstTime = $currentTime }
                $lastTime = $currentTime
                if ($line -match '(?i)ORA-\d{5}|TNS-\d{5}|error|critical|fatal|corrupt') {
                    $errorRows.Add(@($(if ($currentTime) { $currentTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }), $line))
                }
            }
        }
        Write-CollectorLines (Join-Path $DbDir "alert_log_30days.txt") $recentLines
        Write-PipeTable (Join-Path $DbDir "alert_log_recent.txt") @("EVENT_TIME","MESSAGE_TEXT") $errorRows
        Write-CollectorLines (Join-Path $DbDir "alert_log_errors.txt") ($errorRows | ForEach-Object { $_[1] })
        Write-CollectorLines (Join-Path $DbDir "alert_log_tail.txt") ($lines | Select-Object -Last 500)
        $severe = @($errorRows | Where-Object { $_[1] -match '(?i)ORA-00600|ORA-00700|ORA-07445|ORA-01578|CORRUPT' }).Count
        $sizeDisplay = if ($file.Length -ge 1GB) { "{0:N2} GB" -f ($file.Length/1GB) } elseif ($file.Length -ge 1MB) { "{0:N2} MB" -f ($file.Length/1MB) } else { "{0:N2} KB" -f ($file.Length/1KB) }
        Write-PipeTable (Join-Path $DbDir "alert_log_summary.txt") @("DATABASE_NAME","INSTANCE_NAME","HOST_NAME","ALERT_FILE","ALERT_COUNT","SEVERE_COUNT","FIRST_TIME","LAST_TIME","WINDOW_DAYS","ANALYZED_LINE_LIMIT","ANALYZED_LINE_COUNT","WINDOW_TRUNCATED","ALERT_FILE_SIZE_BYTES","ALERT_FILE_SIZE_DISPLAY","ANALYSIS_START_TIME","ANALYSIS_END_TIME") @(
            ,@($Context.OracleSid, $Context.OracleSid, $env:COMPUTERNAME, $alertFile, $errorRows.Count, $severe,
                $(if ($firstTime) { $firstTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }),
                $(if ($lastTime) { $lastTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }),
                30, 100000, $lines.Count, "NO", $file.Length, $sizeDisplay,
                $(if ($firstTime) { $firstTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }),
                $(if ($lastTime) { $lastTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }))
        )
        Write-CollectorLines (Join-Path $DbDir "alert_log_path.txt") @(
            "alert_log_path=$alertFile", "diag_trace=$diagDir", "oracle_sid=$($Context.OracleSid)",
            "window_days=30", "analyzed_line_limit=100000", "analyzed_line_count=$($lines.Count)",
            "window_truncated=NO", "alert_file_size_bytes=$($file.Length)", "alert_file_size_display=$sizeDisplay"
        )
        foreach ($name in @("alert_log_last_100000.txt","alert_log_30days.txt","alert_log_recent.txt","alert_log_errors.txt","alert_log_tail.txt","alert_log_path.txt")) {
            Add-CollectionManifest $Context $name "COMMAND" "OK" 0 ""
        }
    }
}

function Collect-WindowsTraceFiles {
    param($Context, [string]$DbDir)
    Invoke-CollectionAction $Context "trace_recent.txt" {
        $diagDir = (Invoke-OraScalar $Context "SELECT value FROM v`$diag_info WHERE name='Diag Trace';").Trim()
        if (-not (Test-Path -LiteralPath $diagDir -PathType Container)) { throw "Trace目录不存在: $diagDir" }
        $recent = Get-ChildItem -LiteralPath $diagDir -Filter *.trc -File -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-1) } |
            Sort-Object Length -Descending |
            Select-Object -First 200 |
            ForEach-Object { "{0}|{1}|{2}" -f $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"), $_.Length, $_.FullName }
        $large = Get-ChildItem -LiteralPath $diagDir -Filter *.trc -File -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-7) -and $_.Length -gt 100MB } |
            Sort-Object Length -Descending |
            ForEach-Object { "{0}|{1}|{2}" -f $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"), $_.Length, $_.FullName }
        Write-CollectorLines (Join-Path $DbDir "trace_recent.txt") $recent
        Write-CollectorLines (Join-Path $DbDir "trace_large.txt") $large
        Add-CollectionManifest $Context "trace_large.txt" "COMMAND" "OK" 0 ""
    } -Optional
}

function Collect-WindowsDatabase {
    param([Parameter(Mandatory=$true)]$Context, [Parameter(Mandatory=$true)][hashtable]$Config)
    $dbDir = Join-Path $Context.RawDir "db"
    New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
    Write-CollectorLog -Context $Context -Message "开始采集 Oracle 数据库数据"

    $version = (Invoke-OraScalar $Context "SELECT version FROM v`$instance;").Trim()
    $major = 0
    if ($version -match '^(\d+)') { $major = [int]$matches[1] }
    $isCdb = "NO"
    if ($major -ge 12) {
        try { $isCdb = (Invoke-OraScalar $Context "SELECT CDB FROM v`$database;").Trim().ToUpperInvariant() } catch { $isCdb = "NO" }
    }
    if ($isCdb -ne "YES") { $isCdb = "NO" }
    $dbRole = ""
    $dbOpenMode = ""
    $dbUniqueName = ""
    try {
        $identity = (Invoke-OraScalar $Context "SELECT database_role || '|' || open_mode || '|' || db_unique_name FROM v`$database;").Trim()
        $identityParts = @($identity -split '\|', 3)
        if ($identityParts.Count -gt 0) { $dbRole = $identityParts[0].Trim() }
        if ($identityParts.Count -gt 1) { $dbOpenMode = $identityParts[1].Trim() }
        if ($identityParts.Count -gt 2) { $dbUniqueName = $identityParts[2].Trim() }
    } catch {}
    $hasDgProcess = $false
    $hasDgDestExt = $false
    try { $hasDgProcess = ((Invoke-OraScalar $Context "SELECT CASE WHEN COUNT(*)>0 THEN 'YES' ELSE 'NO' END FROM dba_objects WHERE owner='SYS' AND object_name='V_`$DATAGUARD_PROCESS';").Trim() -eq "YES") } catch {}
    try { $hasDgDestExt = ((Invoke-OraScalar $Context "SELECT CASE WHEN COUNT(DISTINCT column_name)=6 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='V_`$ARCHIVE_DEST_STATUS' AND column_name IN ('DB_UNIQUE_NAME','SYNCHRONIZED','SYNCHRONIZATION_STATUS','GAP_STATUS','APPLIED_THREAD#','APPLIED_SEQ#');").Trim() -eq "YES") } catch {}
    Add-EnvironmentInfo $Context @(
        "db_version=$version", "db_major_version=$major", "db_is_cdb=$isCdb",
        "db_role=$dbRole", "db_open_mode=$dbOpenMode", "db_unique_name=$dbUniqueName"
    )

    $queries = Get-DatabaseQueries ([bool]$Config.CollectSqlText) $hasDgDestExt $hasDgProcess
    foreach ($entry in $queries.GetEnumerator()) {
        Invoke-RegisteredSql $Context $dbDir $entry.Key $entry.Value -Optional:($entry.Key -in @("asm_diskgroups.txt","asm_disks.txt"))
    }
    Collect-WindowsStoragePathCapacity $Context $dbDir
    Invoke-RegisteredSql $Context $dbDir "windows_large_pages.txt" "SELECT i.instance_name, i.host_name, p.name, p.value FROM v`$instance i CROSS JOIN v`$parameter p WHERE p.name IN ('use_large_pages','lock_sga','sga_target','sga_max_size','memory_target','memory_max_target') ORDER BY p.name;" -Optional
    Collect-OracleWindowsMemory $Context $dbDir

    if ($isCdb -eq "YES") {
        Invoke-RegisteredSql $Context $dbDir "pdb_context_v2.txt" "SELECT TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at,instance_number FROM v`$instance;
SELECT 'PDB_CONTEXT_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_storage_v2.txt" "WITH files AS (SELECT con_id,tablespace_name,file_name FROM cdb_data_files UNION ALL SELECT con_id,tablespace_name,file_name FROM cdb_temp_files) SELECT DISTINCT f.con_id,f.tablespace_name,CASE WHEN f.file_name LIKE '+%' THEN SUBSTR(f.file_name,2,INSTR(f.file_name,'/')-2) ELSE 'FILESYSTEM' END storage_name,g.usable_file_mb FROM files f LEFT JOIN v`$asm_diskgroup g ON f.file_name LIKE '+%' AND UPPER(g.name)=UPPER(SUBSTR(f.file_name,2,INSTR(f.file_name,'/')-2)) ORDER BY f.con_id,f.tablespace_name;
SELECT 'PDB_STORAGE_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_tablespaces_v2.txt" "WITH df AS (SELECT con_id,tablespace_name,SUM(bytes) alloc_bytes,SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes,MAX(autoextensible) autoextensible FROM cdb_data_files GROUP BY con_id,tablespace_name), fs AS (SELECT con_id,tablespace_name,SUM(bytes) free_bytes FROM cdb_free_space GROUP BY con_id,tablespace_name) SELECT c.con_id,c.name pdb_name,t.tablespace_name,t.contents,t.status,ROUND(df.alloc_bytes/1048576,3) alloc_mb,ROUND((df.alloc_bytes-NVL(fs.free_bytes,0))/1048576,3) used_mb,ROUND(NVL(fs.free_bytes,0)/1048576,3) free_mb,ROUND(df.max_bytes/1048576,3) max_mb,df.autoextensible FROM v`$containers c JOIN cdb_tablespaces t ON t.con_id=c.con_id LEFT JOIN df ON df.con_id=t.con_id AND df.tablespace_name=t.tablespace_name LEFT JOIN fs ON fs.con_id=t.con_id AND fs.tablespace_name=t.tablespace_name WHERE t.contents<>'TEMPORARY' ORDER BY c.con_id,t.tablespace_name;
SELECT 'PDB_TABLESPACES_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_temp_v2.txt" "WITH tf AS (SELECT con_id,tablespace_name,SUM(bytes) alloc_bytes,SUM(CASE WHEN autoextensible='YES' THEN GREATEST(bytes,maxbytes) ELSE bytes END) max_bytes FROM cdb_temp_files GROUP BY con_id,tablespace_name), tu AS (SELECT u.con_id,u.tablespace,SUM(u.blocks*t.block_size) used_bytes FROM gv`$tempseg_usage u JOIN cdb_tablespaces t ON t.con_id=u.con_id AND t.tablespace_name=u.tablespace GROUP BY u.con_id,u.tablespace) SELECT c.con_id,c.name pdb_name,t.tablespace_name,t.contents,t.status,ROUND(tf.alloc_bytes/1048576,3) alloc_mb,ROUND(NVL(tu.used_bytes,0)/1048576,3) used_mb,ROUND((tf.alloc_bytes-NVL(tu.used_bytes,0))/1048576,3) free_mb,ROUND(tf.max_bytes/1048576,3) max_mb,'N/A' autoextensible FROM cdb_tablespaces t JOIN v`$containers c ON c.con_id=t.con_id LEFT JOIN tf ON tf.con_id=t.con_id AND tf.tablespace_name=t.tablespace_name LEFT JOIN tu ON tu.con_id=t.con_id AND tu.tablespace=t.tablespace_name WHERE t.contents='TEMPORARY' ORDER BY c.con_id,t.tablespace_name;
SELECT 'PDB_TEMP_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_sessions_v2.txt" "SELECT s.inst_id,s.con_id,s.sid,s.serial#,s.username,s.status,s.sql_id,s.event,s.blocking_instance,s.blocking_session,s.seconds_in_wait,CASE WHEN s.taddr IS NOT NULL THEN s.last_call_et END call_seconds FROM gv`$session s WHERE s.type='USER' AND s.con_id>2 ORDER BY s.con_id,s.inst_id,s.sid;
SELECT 'PDB_SESSIONS_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_transactions_v2.txt" "SELECT s.inst_id,s.con_id,s.sid,s.serial#,s.username,t.start_time,ROUND((SYSDATE-TO_DATE(t.start_time,'MM/DD/RR HH24:MI:SS'))*86400) age_seconds,t.used_ublk,t.used_urec FROM gv`$transaction t JOIN gv`$session s ON s.inst_id=t.inst_id AND s.taddr=t.addr WHERE s.con_id>2;
SELECT 'PDB_TRANSACTIONS_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_temp_users_v2.txt" "SELECT u.inst_id,u.con_id,u.username,u.sql_id,u.tablespace,SUM(u.blocks) blocks FROM gv`$tempseg_usage u GROUP BY u.inst_id,u.con_id,u.username,u.sql_id,u.tablespace ORDER BY SUM(u.blocks) DESC;
SELECT 'PDB_TEMP_USERS_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_health_v2.txt" "WITH business AS (SELECT con_id,username,account_status FROM cdb_users WHERE oracle_maintained='N'), metrics AS ( SELECT o.con_id,'INVALID_OBJECTS' metric,COUNT(*) metric_value FROM cdb_objects o JOIN business b ON b.con_id=o.con_id AND b.username=o.owner WHERE o.status='INVALID' GROUP BY o.con_id UNION ALL SELECT i.con_id,'UNUSABLE_INDEXES',COUNT(*) FROM cdb_indexes i JOIN business b ON b.con_id=i.con_id AND b.username=i.owner WHERE i.status='UNUSABLE' GROUP BY i.con_id UNION ALL SELECT i.con_id,'UNUSABLE_INDEX_PARTS',COUNT(*) FROM cdb_ind_partitions i JOIN business b ON b.con_id=i.con_id AND b.username=i.index_owner WHERE i.status='UNUSABLE' GROUP BY i.con_id UNION ALL SELECT i.con_id,'UNUSABLE_INDEX_SUBPARTS',COUNT(*) FROM cdb_ind_subpartitions i JOIN business b ON b.con_id=i.con_id AND b.username=i.index_owner WHERE i.status='UNUSABLE' GROUP BY i.con_id UNION ALL SELECT t.con_id,'STALE_STATS',COUNT(*) FROM cdb_tab_statistics t JOIN business b ON b.con_id=t.con_id AND b.username=t.owner WHERE t.stale_stats='YES' AND t.object_type='TABLE' GROUP BY t.con_id UNION ALL SELECT t.con_id,'MISSING_STATS',COUNT(*) FROM cdb_tab_statistics t JOIN business b ON b.con_id=t.con_id AND b.username=t.owner WHERE t.last_analyzed IS NULL AND t.object_type='TABLE' GROUP BY t.con_id UNION ALL SELECT j.con_id,'FAILED_JOBS_7D',COUNT(*) FROM cdb_scheduler_job_run_details j JOIN business b ON b.con_id=j.con_id AND b.username=j.owner WHERE j.status='FAILED' AND j.actual_start_date>SYSTIMESTAMP-INTERVAL '7' DAY GROUP BY j.con_id UNION ALL SELECT con_id,'LOCKED_EXPIRED_USERS',COUNT(*) FROM business WHERE account_status<>'OPEN' GROUP BY con_id) SELECT c.con_id,c.name pdb_name,k.metric,NVL(m.metric_value,0) metric_value FROM v`$containers c CROSS JOIN (SELECT 'INVALID_OBJECTS' metric FROM dual UNION ALL SELECT 'UNUSABLE_INDEXES' FROM dual UNION ALL SELECT 'UNUSABLE_INDEX_PARTS' FROM dual UNION ALL SELECT 'UNUSABLE_INDEX_SUBPARTS' FROM dual UNION ALL SELECT 'STALE_STATS' FROM dual UNION ALL SELECT 'MISSING_STATS' FROM dual UNION ALL SELECT 'FAILED_JOBS_7D' FROM dual UNION ALL SELECT 'LOCKED_EXPIRED_USERS' FROM dual) k LEFT JOIN metrics m ON m.con_id=c.con_id AND m.metric=k.metric WHERE c.con_id>2 AND c.open_mode IN ('READ ONLY','READ WRITE') AND EXISTS (SELECT 1 FROM cdb_users u WHERE u.con_id=c.con_id) ORDER BY c.con_id,k.metric;
SELECT 'PDB_HEALTH_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_open_instances_v2.txt" "SELECT p.inst_id,p.con_id,p.name pdb_name,p.open_mode,p.restricted FROM gv`$pdbs p ORDER BY p.con_id,p.inst_id;
SELECT 'PDB_OPEN_INSTANCES_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_services_v2.txt" "SELECT inst_id,con_id,name FROM gv`$active_services WHERE con_id>2 ORDER BY con_id,inst_id,name;
SELECT 'PDB_SERVICES_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_undo_v2.txt" "SELECT con_id,tablespace_name,status,ROUND(SUM(bytes)/1048576,3) size_mb FROM cdb_undo_extents GROUP BY con_id,tablespace_name,status ORDER BY con_id,tablespace_name,status;
SELECT 'PDB_UNDO_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "pdb_undo_errors_v2.txt" "SELECT inst_id,con_id,SUM(ssolderrcnt) snapshot_old,SUM(nospaceerrcnt) no_space FROM gv`$undostat WHERE begin_time>SYSDATE-1 GROUP BY inst_id,con_id;
SELECT 'PDB_UNDO_ERRORS_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "cdb_info.txt" "SELECT CDB FROM v`$database;"
        Invoke-RegisteredSql $Context $dbDir "pdb_info.txt" "SELECT p.pdb_name, p.pdb_id, p.status, v.open_mode, v.restricted, v.open_time, v.total_size/1024/1024/1024 total_size_gb FROM dba_pdbs p JOIN v`$pdbs v ON p.pdb_id=v.con_id ORDER BY p.pdb_id;"
        Invoke-RegisteredSql $Context $dbDir "pdb_datafiles.txt" "SELECT p.pdb_id, p.pdb_name, d.file_id, d.tablespace_name, d.file_name, ROUND(d.maxbytes/1024/1024,2) max_size_mb, ROUND(d.bytes/1024/1024,2) total_size_mb, ROUND(d.user_bytes/1024/1024,2) usable_size_mb, d.autoextensible, d.online_status FROM dba_pdbs p JOIN cdb_data_files d ON p.pdb_id=d.con_id ORDER BY p.pdb_id;"
        Invoke-RegisteredSql $Context $dbDir "pdb_users.txt" "SELECT con_id, username, account_status, created, default_tablespace, profile FROM cdb_users WHERE username NOT IN ('SYS','SYSTEM') ORDER BY con_id, username;"
    } else {
        Write-PipeTable (Join-Path $dbDir "cdb_info.txt") @("CDB") @(,@("NO"))
        Add-CollectionManifest $Context "cdb_info.txt" "SQL" "OK" 0 ""
        Skip-SqlCollection $Context $dbDir "pdb_info.txt" "PDB_NAME|PDB_ID|STATUS|OPEN_MODE|RESTRICTED|OPEN_TIME|TOTAL_SIZE_GB" "当前数据库不是CDB或版本不支持多租户"
        Skip-SqlCollection $Context $dbDir "pdb_datafiles.txt" "PDB_ID|PDB_NAME|FILE_ID|TABLESPACE_NAME|FILE_NAME|MAX_SIZE_MB|TOTAL_SIZE_MB|USED_SIZE_MB|AUTOEXTENSIBLE|ONLINE_STATUS" "当前数据库不是CDB或版本不支持多租户"
        Skip-SqlCollection $Context $dbDir "pdb_users.txt" "CON_ID|USERNAME|ACCOUNT_STATUS|CREATED|DEFAULT_TABLESPACE|PROFILE" "当前数据库不是CDB或版本不支持多租户"
    }

    if ([bool]$Config.CheckAwr) {
        # Preserve CON_ID for the reporter to select one common snapshot scope.
        $awrSysstatCon = "0"; $awrEventCon = "0"; $awrSqlCon = "0"
        if ($major -ge 12) { $awrSysstatCon = "ss.con_id"; $awrEventCon = "e.con_id"; $awrSqlCon = "q.con_id" }
        Invoke-RegisteredSql $Context $dbDir "awr_context_v2.txt" "SELECT d.dbid,d.database_role,i.instance_number,i.instance_name,i.host_name,TO_CHAR(i.startup_time,'YYYY-MM-DD HH24:MI:SS') startup_time,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') collected_at FROM v`$database d CROSS JOIN v`$instance i;
SELECT 'AWR_CONTEXT_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "awr_snapshot_v2.txt" "SELECT * FROM (SELECT s.dbid,s.instance_number,s.snap_id,TO_CHAR(s.startup_time,'YYYY-MM-DD HH24:MI:SS') startup_time,TO_CHAR(s.end_interval_time,'YYYY-MM-DD HH24:MI:SS') end_time,ROW_NUMBER() OVER (PARTITION BY s.dbid,s.instance_number ORDER BY s.snap_id DESC) rn FROM dba_hist_snapshot s WHERE s.dbid=(SELECT dbid FROM v`$database) AND s.instance_number=(SELECT instance_number FROM v`$instance)) WHERE rn<=2;
SELECT 'AWR_SNAPSHOT_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "awr_sysstat_v2.txt" "WITH snaps AS (SELECT * FROM (SELECT s.dbid,s.instance_number,s.snap_id,TO_CHAR(s.startup_time,'YYYY-MM-DD HH24:MI:SS') startup_time,TO_CHAR(s.end_interval_time,'YYYY-MM-DD HH24:MI:SS') end_time,ROW_NUMBER() OVER (PARTITION BY s.dbid,s.instance_number ORDER BY s.snap_id DESC) rn FROM dba_hist_snapshot s WHERE s.dbid=(SELECT dbid FROM v`$database) AND s.instance_number=(SELECT instance_number FROM v`$instance)) WHERE rn<=2) SELECT ss.dbid,ss.instance_number,ss.snap_id,$awrSysstatCon con_id,ss.stat_name,TO_CHAR(ss.value,'FM99999999999999999999999999999999999990') stat_value FROM dba_hist_sysstat ss JOIN snaps s ON s.dbid=ss.dbid AND s.instance_number=ss.instance_number AND s.snap_id=ss.snap_id WHERE ss.stat_name IN ('CPU used by this session','physical reads cache','consistent gets from cache','db block gets from cache','physical reads','physical reads direct','physical writes','redo size','user commits','user rollbacks','parse count (total)','parse count (hard)','parse time elapsed','execute count') ORDER BY ss.snap_id,ss.stat_name;
SELECT 'AWR_SYSSTAT_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "awr_sqlstat_v2.txt" "WITH snaps AS (SELECT * FROM (SELECT s.dbid,s.instance_number,s.snap_id,TO_CHAR(s.startup_time,'YYYY-MM-DD HH24:MI:SS') startup_time,TO_CHAR(s.end_interval_time,'YYYY-MM-DD HH24:MI:SS') end_time,ROW_NUMBER() OVER (PARTITION BY s.dbid,s.instance_number ORDER BY s.snap_id DESC) rn FROM dba_hist_snapshot s WHERE s.dbid=(SELECT dbid FROM v`$database) AND s.instance_number=(SELECT instance_number FROM v`$instance)) WHERE rn<=2) SELECT * FROM (SELECT q.dbid,q.instance_number,q.snap_id,q.sql_id,$awrSqlCon con_id,q.plan_hash_value,TO_CHAR(q.executions_delta,'FM99999999999999999999999999999999999990') executions_delta,TO_CHAR(q.parse_calls_delta,'FM99999999999999999999999999999999999990') parse_calls_delta,TO_CHAR(q.loads_delta,'FM99999999999999999999999999999999999990') loads_delta,TO_CHAR(q.invalidations_delta,'FM99999999999999999999999999999999999990') invalidations_delta,TO_CHAR(q.elapsed_time_delta,'FM99999999999999999999999999999999999990') elapsed_time_delta,TO_CHAR(q.cpu_time_delta,'FM99999999999999999999999999999999999990') cpu_time_delta,TO_CHAR(q.buffer_gets_delta,'FM99999999999999999999999999999999999990') buffer_gets_delta,TO_CHAR(q.disk_reads_delta,'FM99999999999999999999999999999999999990') disk_reads_delta,q.version_count,ROW_NUMBER() OVER (ORDER BY q.elapsed_time_delta DESC,q.sql_id,$awrSqlCon,q.plan_hash_value) rn FROM dba_hist_sqlstat q JOIN snaps s ON s.dbid=q.dbid AND s.instance_number=q.instance_number AND s.snap_id=q.snap_id WHERE s.rn=1) WHERE rn<=30;
SELECT 'AWR_SQLSTAT_V2_OK' FROM dual;" -Optional
        Invoke-RegisteredSql $Context $dbDir "awr_events_v2.txt" "WITH snaps AS (SELECT * FROM (SELECT s.dbid,s.instance_number,s.snap_id,TO_CHAR(s.startup_time,'YYYY-MM-DD HH24:MI:SS') startup_time,TO_CHAR(s.end_interval_time,'YYYY-MM-DD HH24:MI:SS') end_time,ROW_NUMBER() OVER (PARTITION BY s.dbid,s.instance_number ORDER BY s.snap_id DESC) rn FROM dba_hist_snapshot s WHERE s.dbid=(SELECT dbid FROM v`$database) AND s.instance_number=(SELECT instance_number FROM v`$instance)) WHERE rn<=2) SELECT e.dbid,e.instance_number,e.snap_id,$awrEventCon con_id,e.event_name,e.wait_class,TO_CHAR(e.total_waits,'FM99999999999999999999999999999999999990') total_waits,TO_CHAR(e.time_waited_micro,'FM99999999999999999999999999999999999990') time_waited_micro FROM dba_hist_system_event e JOIN snaps s ON s.dbid=e.dbid AND s.instance_number=e.instance_number AND s.snap_id=e.snap_id WHERE e.wait_class<>'Idle';
SELECT 'AWR_EVENTS_V2_OK' FROM dual;" -Optional
        $awr = [ordered]@{
            "awr_snapshot.txt"="SELECT * FROM (SELECT snap_id, begin_interval_time, end_interval_time FROM dba_hist_snapshot ORDER BY snap_id DESC) WHERE ROWNUM<=10;"
            "awr_sysstat.txt"="SELECT * FROM (SELECT snap_id, instance_number, stat_name, value FROM dba_hist_sysstat WHERE stat_name IN ('CPU used by this session','db block gets','consistent gets','physical reads','physical writes','redo size','user commits','execute count') ORDER BY snap_id DESC) WHERE ROWNUM<=50;"
            "awr_top_events.txt"="SELECT * FROM (SELECT snap_id, event_name event, wait_class, total_waits, time_waited_micro, ROUND(time_waited_micro/NULLIF(total_waits,0),2) avg_wait_time_micro FROM dba_hist_system_event WHERE wait_class<>'Idle' ORDER BY snap_id DESC,time_waited_micro DESC) WHERE ROWNUM<=30;"
            "awr_seg_stats.txt"="SELECT * FROM (SELECT s.snap_id,o.owner,o.object_name,o.tablespace_name,s.physical_reads_delta physical_reads,s.physical_writes_delta physical_writes,s.logical_reads_delta logical_reads,s.row_lock_waits_delta row_lock_waits FROM dba_hist_seg_stat s JOIN dba_hist_seg_stat_obj o ON o.dbid=s.dbid AND o.ts#=s.ts# AND o.obj#=s.obj# AND o.dataobj#=s.dataobj# WHERE NVL(s.physical_reads_delta,0)+NVL(s.physical_writes_delta,0)>0 ORDER BY s.snap_id DESC) WHERE ROWNUM<=20;"
            "awr_sqlstat.txt"="SELECT * FROM (SELECT snap_id,sql_id,plan_hash_value,executions_delta,elapsed_time_delta,cpu_time_delta,buffer_gets_delta,disk_reads_delta,rows_processed_delta FROM dba_hist_sqlstat WHERE executions_delta>0 ORDER BY snap_id DESC,elapsed_time_delta DESC) WHERE ROWNUM<=20;"
        }
        foreach ($entry in $awr.GetEnumerator()) { Invoke-RegisteredSql $Context $dbDir $entry.Key $entry.Value -Optional }
    } else {
        foreach ($name in @("awr_snapshot.txt","awr_sysstat.txt","awr_top_events.txt","awr_seg_stats.txt","awr_sqlstat.txt")) {
            Skip-SqlCollection $Context $dbDir $name "SKIPPED|按配置未启用 AWR 采集（CheckAwr=false）" "按配置未启用 AWR 采集"
        }
    }

    Invoke-CollectionAction $Context "opatch.txt" {
        $opatch = Join-Path $Context.OracleHome "OPatch\opatch.bat"
        if (-not (Test-Path -LiteralPath $opatch)) { throw "opatch.bat不存在" }
        $output = & $opatch lsinventory 2>&1 | Out-String
        Write-CollectorText (Join-Path $dbDir "opatch.txt") $output
        if ($LASTEXITCODE -ne 0) { throw "opatch lsinventory失败(rc=$LASTEXITCODE)" }
    } -Optional

    Collect-WindowsAlertLog $Context $dbDir
    Collect-WindowsTraceFiles $Context $dbDir
    Write-CollectorLog -Context $Context -Message "Oracle 数据库数据采集完成"
}
