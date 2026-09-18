# -*- coding: utf-8 -*-
"""
数据库巡检数据解析器
解析 Shell 采集的数据库原始数据，进行阈值判定
"""
import os
import re
from collections import Counter
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import List
from parser.base import (
    CheckResult,
    check_threshold,
    check_threshold_inverse,
    read_file,
    read_lines,
    generate_bar_chart,
    generate_data_table,
    generate_health_percentage,
    parse_env_info,
)
from config import DB_THRESHOLDS
from parser.tablespace_view import effective_usage, render_tablespace_overview


from typing import List, Dict


def _format_plain_number(value) -> str:
    """把 Oracle 科学计数法转换为不丢精度的普通十进制文本。"""
    text = str(value or "").strip()
    try:
        number = Decimal(text)
    except InvalidOperation:
        return text
    if not number.is_finite():
        return text
    rendered = format(number, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _format_alert_time(value) -> str:
    """统一 Alert Log 的 ISO/11g 时间为 YYYY-MM-DD HH:MM:SS。"""
    text = str(value or "").strip()
    if not text:
        return ""
    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", text)
    if iso_match:
        return f"{iso_match.group(1)} {iso_match.group(2)}"
    legacy = re.match(
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})$",
        text,
        re.IGNORECASE,
    )
    if legacy:
        months = {
            name.lower(): index for index, name in enumerate(
                ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1
            )
        }
        month = months[legacy.group(1).lower()]
        return f"{legacy.group(4)}-{month:02d}-{int(legacy.group(2)):02d} {legacy.group(3)}"
    return text


def parse_db(raw_dir: str) -> Dict[str, List[CheckResult]]:
    """解析数据库巡检数据"""
    db_dir = f"{raw_dir}/db"

    db_results = []
    db_results.append(_parse_db_version(db_dir))
    db_results.append(_parse_db_patches(db_dir))
    db_results.append(_parse_init_params(db_dir))
    db_results.append(_parse_instance_status(db_dir))
    db_results.extend(_parse_database_resilience(db_dir))
    db_results.append(_parse_db_language(db_dir))
    db_results.append(_parse_backup_status(db_dir))
    db_results.append(_parse_archive_log(db_dir))
    if str(parse_env_info(raw_dir).get("platform", "")).strip().lower() == "windows":
        db_results.append(_parse_storage_path_capacity(db_dir))
        from parser.windows_baseline_parser import parse_windows_large_pages
        db_results.append(parse_windows_large_pages(raw_dir))
    db_results.append(_parse_control_files(db_dir))
    db_results.append(_parse_redo_logs(db_dir))
    db_results.append(_parse_data_files(db_dir))
    db_results.extend(_parse_tablespaces(db_dir))
    db_results.extend(_parse_awr_metrics(db_dir))
    db_results.append(_parse_rollback_segments(db_dir))
    db_results.append(_parse_asm_diskgroups(db_dir))
    db_results.append(_parse_sessions(db_dir))
    db_results.extend(_parse_operational_risks(db_dir))
    db_results.append(_parse_buffer_cache_hit(db_dir))
    db_results.append(_parse_library_cache_hit(db_dir))
    db_results.append(_parse_sga_info(db_dir))
    db_results.append(_parse_wait_events(db_dir))
    db_results.append(_parse_top_disk_read_sql(db_dir))
    db_results.append(_parse_long_running_sql(db_dir))
    db_results.append(_parse_table_fragmentation(db_dir))
    db_results.append(_parse_dead_processes(db_dir))
    db_results.append(_parse_system_tablespace(db_dir))
    db_results.append(_parse_invalid_objects(db_dir))
    db_results.append(_parse_invalid_indexes(db_dir))
    db_results.append(_parse_invalid_triggers(db_dir))
    db_results.append(_parse_failed_jobs(db_dir))
    db_results.append(_parse_alert_log(db_dir))
    db_results.append(_parse_trace_files(db_dir))

    cdb_results = _parse_cdb_info(db_dir)
    if any(r.name == "CDB/PDB" and "非CDB" not in r.value for r in cdb_results):
        from parser.advanced_checks import parse_pdb
        cdb_results.extend(parse_pdb(db_dir, _pdb_database_role(db_dir)))
    rac_results = _parse_rac_info(db_dir)
    dataguard_results = _parse_dataguard(db_dir)

    # CDB: 有实际PDB数据时才返回（排除"非CDB"和"CDB但无PDB"的情况）
    has_cdb = any(r.name == "CDB/PDB" and "非CDB" not in r.value for r in cdb_results)
    # RAC: 有多节点时才返回（排除"非RAC"和"单节点"的情况）
    has_rac = any(r.name == "RAC集群" and "非RAC" not in r.value and "单节点" not in r.value for r in rac_results)

    return {
        "db": db_results,
        "cdb": cdb_results if has_cdb else [],
        "rac": rac_results if has_rac else [],
        "dg": dataguard_results,
    }


def _parse_pipe_table(content: str) -> list:
    """解析以 | 分隔的 SQL 输出表格"""
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        # 必须保留 NULL 列，否则后续列会左移并造成静默误判。
        parts = [p.strip() for p in line.split("|")]
        if any(parts):
            rows.append(parts)
    return rows


def _data_rows(content: str, header_tokens=()) -> list:
    rows = _parse_pipe_table(content)
    tokens = {str(x).upper() for x in header_tokens}
    return [r for r in rows if r and not (tokens and r[0].upper() in tokens)]


def _parse_database_resilience(db_dir: str) -> List[CheckResult]:
    results = []
    rows = [
        row for row in _parse_pipe_table(read_file(f"{db_dir}/db_resilience.txt"))
        if len(row) >= 7 and row[0].upper() in ("YES", "NO")
    ]
    if not rows or len(rows[0]) < 7:
        results.append(CheckResult("数据库韧性配置", "CRIT", "数据缺失", "无法读取 FORCE LOGGING、Flashback 与保护模式"))
    else:
        r = rows[0]
        force_logging, flashback, supplemental, role, protection_mode, protection_level, switchover = r[:7]
        risks = []
        notes = []
        if force_logging.upper() != "YES":
            notes.append("未启用 FORCE LOGGING")
        if role.upper() == "PRIMARY" and flashback.upper() != "YES":
            notes.append("未启用 Flashback Database（可选恢复能力）")
        status = "WARN" if risks else "OK"
        detail = (f"FORCE LOGGING={force_logging}, FLASHBACK={flashback}, 最小补充日志={supplemental}, "
                  f"角色={role}, 保护模式={protection_mode}, 保护级别={protection_level}, 切换状态={switchover}")
        if notes:
            detail += f"；提示：{'；'.join(notes)}"
        value = "存在风险" if risks else ("存在提示" if notes else "已配置")
        suggestion = (
            "；".join(risks) + "；请结合恢复目标与 Data Guard 策略评估"
            if risks else ""
        )
        results.append(CheckResult("数据库韧性配置", status, value, detail, suggestion))

    comp_rows = _data_rows(read_file(f"{db_dir}/registry_components.txt"), ("COMP_ID",))
    bad_components = [r for r in comp_rows if len(r) >= 4 and r[3].upper() not in ("VALID", "OPTION OFF")]
    comp_status = "CRIT" if bad_components else ("OK" if comp_rows else "CRIT")
    comp_extra = generate_data_table(["组件", "名称", "版本", "状态"], [r[:4] for r in comp_rows]) if comp_rows else ""
    results.append(CheckResult("数据库组件状态", comp_status,
                               f"{len(bad_components)}个异常" if comp_rows else "数据缺失",
                               f"注册组件: {len(comp_rows)}，异常: {len(bad_components)}",
                               "请先修复 INVALID/LOADING 等异常组件再进行升级或补丁操作" if bad_components else "",
                               extra_html=comp_extra))

    recover_rows = _data_rows(read_file(f"{db_dir}/datafile_recovery.txt"), ("FILE#",))
    corrupt_rows = _data_rows(read_file(f"{db_dir}/block_corruption.txt"), ("FILE#",))
    integrity_count = len(recover_rows) + len(corrupt_rows)
    integ_status = "CRIT" if integrity_count else "OK"
    integ_extra = ""
    if recover_rows:
        integ_extra += generate_data_table(["文件#", "文件", "错误", "在线状态", "SCN", "时间"], recover_rows[:50])
    if corrupt_rows:
        integ_extra += generate_data_table(["文件#", "块#", "块数", "损坏SCN", "类型"], corrupt_rows[:50])
    results.append(CheckResult("数据文件恢复与坏块", integ_status, f"{integrity_count}项异常",
                               f"需恢复文件: {len(recover_rows)}，已记录坏块: {len(corrupt_rows)}",
                               "立即核查 RMAN VALIDATE、备份可用性并制定恢复方案" if integrity_count else "",
                               extra_html=integ_extra))

    return results


_DG_STATUS_ORDER = {"INFO": 0, "OK": 1, "UNKNOWN": 2, "WARN": 3, "CRIT": 4}


def _dg_worst(statuses, default="OK") -> str:
    return max(statuses or [default], key=lambda value: _DG_STATUS_ORDER.get(value, 0))


def _parse_dg_interval_seconds(value):
    """解析 V$DATAGUARD_STATS 的 +DD HH:MI:SS[.FF] 间隔。"""
    text = str(value or "").strip()
    if not text or text.upper() in ("UNKNOWN", "N/A", "NULL"):
        return None
    match = re.match(r"^([+-])?(\d+)\s+(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)$", text)
    if match:
        seconds = (int(match.group(2)) * 86400 + int(match.group(3)) * 3600
                   + int(match.group(4)) * 60 + float(match.group(5)))
        return -seconds if match.group(1) == "-" else seconds
    try:
        return float(text)
    except ValueError:
        return None


def _format_dg_duration(seconds) -> str:
    if seconds is None:
        return "未知"
    seconds = max(0, int(round(seconds)))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}天")
    if hours or days:
        parts.append(f"{hours}小时")
    if minutes or hours or days:
        parts.append(f"{minutes}分")
    parts.append(f"{seconds}秒")
    return "".join(parts)


def _parse_dg_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None
    text = re.sub(r"\s+[A-Z]{2,5}$", "", text)
    formats = (
        "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S", "%d-%b-%y %H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _dataguard_identity(db_dir: str):
    rows = _data_rows(read_file(f"{db_dir}/dataguard_identity.txt"), ("NAME",))
    if rows and len(rows[0]) >= 10:
        row = rows[0]
        return {
            "name": row[0], "unique_name": row[1], "role": row[2].upper(),
            "open_mode": row[3].upper(), "log_mode": row[4].upper(),
            "force_logging": row[5].upper(), "flashback": row[6].upper(),
            "protection_mode": row[7].upper(), "protection_level": row[8].upper(),
            "switchover": row[9].upper(), "current": True,
        }

    db_rows = _data_rows(read_file(f"{db_dir}/database_status.txt"), ("NAME",))
    if not db_rows or len(db_rows[0]) < 3:
        return None
    db_row = db_rows[0]
    resilience_rows = [
        row for row in _parse_pipe_table(read_file(f"{db_dir}/db_resilience.txt"))
        if len(row) >= 7 and row[0].upper() in ("YES", "NO")
    ]
    resilience = resilience_rows[0] if resilience_rows else [""] * 7
    return {
        "name": db_row[0], "unique_name": db_row[0], "role": db_row[2].upper(),
        "open_mode": db_row[1].upper(), "log_mode": db_row[4].upper() if len(db_row) > 4 else "",
        "force_logging": resilience[0].upper(), "flashback": resilience[1].upper(),
        "protection_mode": resilience[4].upper(), "protection_level": resilience[5].upper(),
        "switchover": resilience[6].upper(), "current": False,
    }


def _dataguard_dest_rows(db_dir: str):
    health_path = f"{db_dir}/dataguard_dest_health.txt"
    health_content = read_file(health_path)
    if os.path.isfile(health_path) and "ORA-" not in health_content.upper():
        rows = _data_rows(health_content, ("DEST_ID",))
        return [(row + [""] * 15)[:15] for row in rows], True, False

    legacy_path = f"{db_dir}/dataguard_dest_status.txt"
    legacy_content = read_file(legacy_path)
    legacy = _data_rows(legacy_content, ("DEST_ID",))
    rows = []
    for row in legacy:
        if row and re.match(r"^(?:ORA|SP2|TNS|LRM)-\d+", row[0], re.IGNORECASE):
            continue
        row = (row + [""] * 9)[:9]
        rows.append(row[:5] + ["", row[5], "", "", "", row[6], row[7], row[8], "", ""])
    problem = not os.path.isfile(legacy_path) or bool(re.search(r"^(?:ORA|SP2|TNS|LRM)-\d+", legacy_content, re.MULTILINE | re.IGNORECASE))
    return rows, False, problem


def _dg_remote_destinations(rows):
    remote_types = {"PHYSICAL", "LOGICAL", "FAR SYNC", "STANDBY"}
    return [row for row in rows if row[2].strip().upper() in remote_types]


def _dg_deployment_label(role: str, open_mode: str, has_remote: bool) -> str:
    if role == "PRIMARY":
        return "Data Guard主库" if has_remote else "普通主库（未识别Data Guard）"
    if role == "PHYSICAL STANDBY":
        if open_mode == "READ ONLY WITH APPLY":
            return "Active Data Guard实时查询"
        if open_mode == "READ ONLY":
            return "物理备库（只读、未实时应用）"
        return "Data Guard物理备库"
    return {
        "LOGICAL STANDBY": "Data Guard逻辑备库",
        "SNAPSHOT STANDBY": "Data Guard快照备库",
        "FAR SYNC": "Data Guard Far Sync",
    }.get(role, f"Data Guard角色：{role or '未知'}")


def _dg_lag_status(seconds) -> str:
    if seconds is None:
        return "UNKNOWN"
    if seconds >= DB_THRESHOLDS["dataguard_lag_crit_seconds"]:
        return "CRIT"
    if seconds >= DB_THRESHOLDS["dataguard_lag_warn_seconds"]:
        return "WARN"
    return "OK"


def _dg_query_failed(content):
    return bool(re.search(r"(?:ORA|SP2|TNS|LRM)-\d+", content, re.IGNORECASE))


def _dg_apply_process(row):
    # Match only the process role, never a client name or unrelated action.
    return bool(row and re.search(
        r"\b(?:MRP\d*|APPLY|LOGMERGER|MANAGED RECOVERY)\b", row[0], re.IGNORECASE
    ))


def _parse_physical_dg_apply(db_dir, identity):
    """Assess physical standby apply using one package's cluster evidence."""
    def content(name):
        return read_file(f"{db_dir}/{name}.txt")

    local_text = content("dataguard_process")
    local_rows = [r for r in _parse_pipe_table(local_text) if len(r) == 5
                  and r[0].upper() not in ("PROCESS_ROLE", "PROCESS", "PROCESS_R")]
    local_apply = [r for r in local_rows if _dg_apply_process(r)] if not _dg_query_failed(local_text) else []
    ctx_text = content("dataguard_context")
    ctx_rows = [r for r in _parse_pipe_table(ctx_text) if len(r) == 5 and r[0].isdigit()]
    ctx = ctx_rows[0] if len(ctx_rows) == 1 and not _dg_query_failed(ctx_text) else None
    current_id = ctx[0] if ctx else None
    nodes = [r for r in _parse_pipe_table(content("rac_nodes")) if len(r) >= 4 and r[0].isdigit()]
    if not nodes:
        nodes = [r for r in _parse_pipe_table(content("instance_status")) if len(r) >= 4 and r[0].isdigit()]
    node_ids = {r[0] for r in nodes}
    is_rac = len(node_ids) > 1 or bool(ctx and ctx[3].upper() == "TRUE")
    cluster_text = content("dataguard_cluster_process")
    cluster_rows = [r for r in _parse_pipe_table(cluster_text) if len(r) == 9 and r[0].isdigit()]
    cluster_ids = {r[0] for r in cluster_rows}
    has_cluster = os.path.isfile(f"{db_dir}/dataguard_cluster_process.txt")
    cluster_ok = bool(
        ctx and _parse_dg_datetime(ctx[4]) and cluster_rows
        and "DG_CLUSTER_OK" in [line.strip() for line in cluster_text.splitlines()]
        and not _dg_query_failed(cluster_text)
        and current_id in cluster_ids and node_ids.issubset(cluster_ids)
        and all(_parse_dg_datetime(r[8]) for r in cluster_rows)
    )
    if cluster_ok:
        # A mixed/truncated snapshot must not establish that every instance stopped.
        times = [_parse_dg_datetime(r[8]) for r in cluster_rows] + [_parse_dg_datetime(ctx[4])]
        cluster_ok = (max(times) - min(times)).total_seconds() < DB_THRESHOLDS["dataguard_stale_warn_seconds"]
    cluster_apply = [r for r in cluster_rows if _dg_apply_process(r[3:8])] if cluster_ok else []
    statuses, risks = [], []
    value = "状态未知"
    detail = f"本地Apply进程={len(local_apply)}，打开模式={identity['open_mode']}"
    legacy_rac = False
    if cluster_ok:
        if cluster_apply:
            owners = sorted({f"{r[2]} / {r[1]}" for r in cluster_apply})
            value = "由 " + "、".join(owners) + " 执行"
            detail += "；" + ("本实例承担Redo Apply" if any(r[0] == current_id for r in cluster_apply)
                              else "本实例未承担Redo Apply，由同RAC其他实例执行")
            statuses.append("OK")
        else:
            statuses.append("CRIT")
            risks.append("集群未发现Redo Apply/MRP进程（预期应开启应用）")
            value = "集群未发现应用进程"
        detail += f"；集群覆盖实例={','.join(sorted(cluster_ids))}；采集时间={cluster_rows[0][8]}"
    elif has_cluster:
        statuses.append("UNKNOWN")
        risks.append("集群Apply采集失败、上下文缺失或实例覆盖不完整，无法确认集群应用状态")
    elif _dg_query_failed(local_text) or not os.path.isfile(f"{db_dir}/dataguard_process.txt") or not local_text.strip():
        statuses.append("UNKNOWN")
        risks.append("本地Redo Apply进程采集失败或缺失")
    elif local_apply:
        statuses.append("OK")
        value = "本实例承担日志应用"
    elif is_rac:
        legacy_rac = identity["open_mode"] == "READ ONLY WITH APPLY"
        statuses.append("INFO" if legacy_rac else "UNKNOWN")
        value = "本实例未检测到Apply，集群应用实例待确认"
        detail += "；旧采集包仅有本地进程，不能据此判断整个RAC的Redo Apply是否停止"
    else:
        statuses.append("CRIT")
        risks.append("未发现Redo Apply/MRP进程")
        value = "未发现应用进程"

    process_rows = [r[3:8] for r in cluster_apply] if cluster_ok else local_apply
    for row in process_rows:
        action = row[3].strip().upper()
        if any(token in action for token in ("ERROR", "WAIT_FOR_GAP", "WAIT FOR GAP", "STOPPED", "FAILED")):
            statuses.append("CRIT")
            risks.append(f"Apply进程状态异常：{action}")
        elif not action or action in ("IDLE", "UNKNOWN"):
            statuses.append("UNKNOWN")
            risks.append(f"Apply进程运行状态待确认：{action or '缺失'}")
    if identity["open_mode"] == "READ ONLY" and not is_rac:
        statuses.append("CRIT")
        risks.append("物理备库只读打开但未处于READ ONLY WITH APPLY")

    # Do not borrow a non-applying instance's zero lag to declare cluster health.
    selected_stats = []
    if cluster_ok and cluster_apply:
        stats_text = content("dataguard_cluster_stats")
        owners = {r[0] for r in cluster_apply}
        all_stats = [r for r in _parse_pipe_table(stats_text) if len(r) == 7 and r[0] in owners]
        if not _dg_query_failed(stats_text) and "DG_STATS_OK" in [s.strip() for s in stats_text.splitlines()]:
            for owner in sorted(owners):
                matches = [r for r in all_stats if r[0] == owner and r[1].lower() == "apply lag"]
                if matches:
                    selected_stats.extend((r[2], r[4], r[5], r[6], f"实例{owner}") for r in matches)
                else:
                    statuses.append("UNKNOWN")
                    risks.append(f"应用实例{owner}缺少Apply Lag")
        else:
            statuses.append("UNKNOWN")
            risks.append("集群Apply Lag采集失败或缺少完成标记")
    else:
        stats_text = content("dataguard_stats")
        if not _dg_query_failed(stats_text):
            for r in _parse_pipe_table(stats_text):
                if len(r) >= 5 and r[0].lower() == "apply lag":
                    selected_stats.append((r[1], r[3], r[4], ctx[4] if ctx else "", "本地观测"))
        if not selected_stats:
            statuses.append("UNKNOWN")
            risks.append("未获得Apply Lag")
    lag_values = []
    for lag_text, computed_text, datum_text, sampled_text, source in selected_stats:
        lag = _parse_dg_interval_seconds(lag_text)
        computed, datum, sampled = map(_parse_dg_datetime, (computed_text, datum_text, sampled_text))
        if lag is None or lag < 0:
            statuses.append("UNKNOWN")
            risks.append(f"{source}的Apply Lag无效")
        else:
            lag_values.append(lag)
            lag_status = _dg_lag_status(lag)
            if lag_status != "OK":
                statuses.append(lag_status)
                risks.append(f"{source}应用延迟{_format_dg_duration(lag)}")
        if not computed or not datum or (cluster_ok and cluster_apply and not sampled):
            statuses.append("UNKNOWN")
            risks.append(f"{source}的Apply Lag新鲜度无法确认")
        else:
            reference = sampled or computed
            if cluster_ok:
                reference = max(reference, max(_parse_dg_datetime(r[8]) for r in cluster_rows))
            age = max(0, (reference - min(computed, datum)).total_seconds())
            if datum > computed or (sampled and computed > sampled):
                statuses.append("UNKNOWN")
                risks.append(f"{source}的指标时间异常")
            elif age >= DB_THRESHOLDS["dataguard_stale_warn_seconds"]:
                statuses.append("CRIT" if age >= DB_THRESHOLDS["dataguard_stale_crit_seconds"] else "WARN")
                risks.append(f"{source}的DG应用指标已过期{_format_dg_duration(age)}")
    lag_value = max(lag_values) if lag_values else None
    detail += f"；{'应用实例' if cluster_ok and cluster_apply else '本地观测'}Apply Lag={_format_dg_duration(lag_value)}"
    if legacy_rac:
        detail += "；本地延迟值仅供参考，不能证明集群应用正常"
    if cluster_ok and cluster_apply:
        value += f"（{_format_dg_duration(lag_value)}）"

    gap_text = content("archive_gap")
    if not _dg_query_failed(gap_text) and any(r[0].isdigit() for r in _parse_pipe_table(gap_text)):
        statuses.append("CRIT")
        risks.append("存在阻塞Redo Apply的归档缺口")
    suggestion = "；".join(dict.fromkeys(risks))
    if any(s in ("WARN", "CRIT") for s in statuses):
        suggestion += "；请检查Redo Apply、归档缺口和备库资源"
    elif "UNKNOWN" in statuses or legacy_rac:
        suggestion += ("；" if suggestion else "") + "使用新版采集器重新采集集群应用状态"
    extra = generate_data_table(
        ["实例ID", "实例", "主机", "进程角色", "线程", "序列", "动作", "客户端", "采集时间"], cluster_rows
    ) if cluster_ok else generate_data_table(["进程角色", "线程", "序列", "动作", "客户端"], local_rows)
    return CheckResult("DG Redo应用", _dg_worst(statuses, "UNKNOWN"), value, detail, suggestion, extra_html=extra)


def _parse_dataguard(db_dir: str) -> List[CheckResult]:
    """按数据库角色解析 Data Guard/Active Data Guard 健康状态。"""
    identity = _dataguard_identity(db_dir)
    if not identity:
        return []

    dest_rows, has_extended_dest, dest_problem = _dataguard_dest_rows(db_dir)
    remote_rows = _dg_remote_destinations(dest_rows)
    dest_config_path = f"{db_dir}/dataguard_dest_config.txt"
    dest_config_content = read_file(dest_config_path)
    dest_config_rows = _data_rows(dest_config_content, ("DEST_ID",))
    config_problem = bool(re.search(
        r"^(?:ORA|SP2|TNS|LRM)-\d+", dest_config_content, re.MULTILINE | re.IGNORECASE
    ))
    if config_problem:
        dest_config_rows = []
    dest_config_rows = [(row + [""] * 5)[:5] for row in dest_config_rows]
    role = identity["role"]
    open_mode = identity["open_mode"]
    has_remote = bool(remote_rows or dest_config_rows)
    is_dataguard = role not in ("", "PRIMARY") or has_remote
    primary_unknown = (
        role == "PRIMARY" and identity["current"] and not has_remote
        and (not os.path.isfile(dest_config_path) or config_problem or dest_problem)
    )
    label = "主库（Data Guard配置无法判定）" if primary_unknown else _dg_deployment_label(role, open_mode, has_remote)
    identity_extra = generate_data_table(
        ["数据库", "DB_UNIQUE_NAME", "角色", "打开模式", "归档模式", "保护模式", "实际保护级别", "切换状态"],
        [[identity["name"], identity["unique_name"], role, open_mode, identity["log_mode"],
          identity["protection_mode"], identity["protection_level"], identity["switchover"]]],
    )
    results = [CheckResult(
        "DG/ADG部署识别", "INFO", label,
        f"角色={role or '未知'}，打开模式={open_mode or '未知'}；ADG仅表示检测到实时查询运行特征，不代表许可证审计结论",
        extra_html=identity_extra,
    )]
    if primary_unknown:
        results.append(CheckResult(
            "DG Redo传输", "UNKNOWN", "数据缺失",
            "无法读取归档目的端配置，不能判断当前主库是否配置Data Guard",
            "修复V$ARCHIVE_DEST/V$ARCHIVE_DEST_STATUS采集问题后重新巡检",
        ))
        return results
    if not is_dataguard:
        return results

    protection_statuses = []
    protection_risks = []
    if identity["force_logging"] and identity["force_logging"] != "YES":
        protection_statuses.append("WARN")
        protection_risks.append("未启用FORCE LOGGING")
    protection_mode = identity["protection_mode"]
    protection_level = identity["protection_level"]
    if protection_level == "UNPROTECTED":
        protection_statuses.append("CRIT")
        protection_risks.append("当前实际保护级别为UNPROTECTED")
    elif protection_mode and protection_level and protection_mode != protection_level:
        protection_statuses.append("WARN")
        protection_risks.append("配置保护模式与实际保护级别不一致")
    switchover = identity["switchover"]
    if switchover in ("FAILED DESTINATION", "UNRESOLVABLE GAP", "RECOVERY NEEDED"):
        protection_statuses.append("CRIT")
        protection_risks.append(f"切换状态={switchover}")
    elif switchover == "RESOLVABLE GAP":
        protection_statuses.append("WARN")
        protection_risks.append("切换状态存在可解析归档缺口")
    if not identity["current"] and not any((identity["force_logging"], protection_mode, protection_level, switchover)):
        protection_statuses.append("INFO")
    protection_status = _dg_worst(protection_statuses)
    results.append(CheckResult(
        "DG保护模式与切换状态", protection_status,
        protection_level or "未知",
        f"保护模式={protection_mode or '未知'}，实际级别={protection_level or '未知'}，切换状态={switchover or '未知'}，FORCE_LOGGING={identity['force_logging'] or '未知'}",
        "；".join(protection_risks) + ("；请核对Data Guard保护目标与切换条件" if protection_risks else ""),
    ))

    stats_path = f"{db_dir}/dataguard_stats.txt"
    stats_content = read_file(stats_path)
    stats_rows = _data_rows(stats_content, ("NAME",))
    stats = {row[0].strip().lower(): row for row in stats_rows if len(row) >= 2}
    transport_row = stats.get("transport lag")
    apply_row = stats.get("apply lag")
    finish_row = stats.get("apply finish time")
    transport_lag = _parse_dg_interval_seconds(transport_row[1]) if transport_row else None
    apply_lag = _parse_dg_interval_seconds(apply_row[1]) if apply_row else None
    finish_time = _parse_dg_interval_seconds(finish_row[1]) if finish_row else None
    stale_seconds = []
    for row in (transport_row, apply_row):
        if row and len(row) >= 5:
            computed = _parse_dg_datetime(row[3])
            datum = _parse_dg_datetime(row[4])
            if computed and datum:
                stale_seconds.append(max(0, (computed - datum).total_seconds()))
    max_stale = max(stale_seconds) if stale_seconds else None

    transport_statuses = []
    transport_risks = []
    if identity["current"] and dest_problem:
        transport_statuses.append("UNKNOWN")
        transport_risks.append("归档目的端运行状态采集失败")
    elif not identity["current"] and dest_problem and not os.path.isfile(stats_path):
        transport_statuses.append("INFO")
    for row in dest_config_rows:
        status = row[1].strip().upper()
        error = row[4].strip()
        if error or status == "ERROR":
            transport_statuses.append("CRIT")
            transport_risks.append(f"配置DEST {row[0]}错误：{error or status}")
        elif status in ("DEFERRED", "DISABLED", "BAD PARAM"):
            transport_statuses.append("WARN")
            transport_risks.append(f"配置DEST {row[0]}状态={status}")
    for row in remote_rows:
        status = row[1].strip().upper()
        sync_status = row[8].strip().upper()
        gap_status = row[9].strip().upper()
        error = row[10].strip()
        if error or status == "ERROR":
            transport_statuses.append("CRIT")
            transport_risks.append(f"DEST {row[0]}传输错误：{error or status}")
        elif status in ("DEFERRED", "DISABLED", "BAD PARAM"):
            transport_statuses.append("WARN")
            transport_risks.append(f"DEST {row[0]}状态={status}")
        if sync_status in ("CHECK CONNECTIVITY", "DESTINATION HAS A GAP", "CHECK STANDBY REDO LOG"):
            transport_statuses.append("CRIT")
            transport_risks.append(f"DEST {row[0]}同步状态={sync_status}")
        elif sync_status == "CHECK CONFIGURATION" and protection_mode in ("MAXIMUM PROTECTION", "MAXIMUM AVAILABILITY"):
            transport_statuses.append("WARN")
            transport_risks.append(f"DEST {row[0]}需要检查同步配置")
        if row[7].strip().upper() == "NO" and protection_mode in ("MAXIMUM PROTECTION", "MAXIMUM AVAILABILITY"):
            transport_statuses.append("CRIT")
            transport_risks.append(f"DEST {row[0]}未同步")
        if gap_status in ("UNRESOLVABLE GAP", "LOCALLY UNRESOLVABLE GAP"):
            transport_statuses.append("CRIT")
            transport_risks.append(f"DEST {row[0]}存在不可解析Gap")
        elif gap_status in ("RESOLVABLE GAP", "LOG SWITCH GAP"):
            transport_statuses.append("WARN")
            transport_risks.append(f"DEST {row[0]}存在{gap_status}")
    if transport_lag is not None:
        lag_status = _dg_lag_status(transport_lag)
        transport_statuses.append(lag_status)
        if lag_status != "OK":
            transport_risks.append(f"传输延迟{_format_dg_duration(transport_lag)}")
    elif role != "PRIMARY" and identity["current"] and not os.path.isfile(stats_path):
        transport_statuses.append("UNKNOWN")
        transport_risks.append("缺少Transport Lag采集文件")
    elif role != "PRIMARY" and os.path.isfile(stats_path):
        transport_statuses.append("UNKNOWN")
        transport_risks.append("未获得Transport Lag")
    if max_stale is not None:
        if max_stale >= DB_THRESHOLDS["dataguard_stale_crit_seconds"]:
            transport_statuses.append("CRIT")
            transport_risks.append(f"DG指标数据已停滞{_format_dg_duration(max_stale)}")
        elif max_stale >= DB_THRESHOLDS["dataguard_stale_warn_seconds"]:
            transport_statuses.append("WARN")
            transport_risks.append(f"DG指标数据已停滞{_format_dg_duration(max_stale)}")
    if role == "PRIMARY" and not has_remote:
        transport_statuses.append("UNKNOWN")
        transport_risks.append("未获得远程备用库目的端")
    transport_status = _dg_worst(transport_statuses)
    dest_extra = generate_data_table(
        ["DEST", "状态", "类型", "数据库模式", "恢复模式", "远端唯一名", "目标", "同步", "同步诊断", "Gap", "错误", "归档线程", "归档序列", "应用线程", "应用序列"],
        dest_rows,
    ) if dest_rows else ""
    results.append(CheckResult(
        "DG Redo传输", transport_status,
        _format_dg_duration(transport_lag) if transport_lag is not None else f"{max(len(remote_rows), len(dest_config_rows))}个远程目的端",
        f"远程目的端={max(len(remote_rows), len(dest_config_rows))}，Transport Lag={_format_dg_duration(transport_lag)}，指标停滞={_format_dg_duration(max_stale)}" +
        ("；旧采集包不含扩展同步字段" if not has_extended_dest else ""),
        "；".join(dict.fromkeys(transport_risks)) + ("；请检查网络、归档目的端和Redo传输服务" if transport_risks else ""),
        extra_html=(generate_data_table(
            ["配置DEST", "状态", "目标类型", "目标", "错误"], dest_config_rows
        ) if dest_config_rows else "") + dest_extra,
    ))

    if role == "PHYSICAL STANDBY":
        results.append(_parse_physical_dg_apply(db_dir, identity))
    elif role == "LOGICAL STANDBY":
        process_path = f"{db_dir}/dataguard_process.txt"
        process_content = read_file(process_path)
        process_rows = _data_rows(process_content, ("PROCESS_ROLE", "PROCESS"))
        process_problem = bool(re.search(
            r"^(?:ORA|SP2|TNS|LRM)-\d+", process_content, re.MULTILINE | re.IGNORECASE
        ))
        if process_problem:
            process_rows = []
        apply_processes = [
            row for row in process_rows
            if any(token in " ".join(row).upper() for token in ("MRP", "APPLY", "LOGMERGER", "MANAGED RECOVERY"))
        ]
        apply_statuses = []
        apply_risks = []
        if os.path.isfile(process_path) and not apply_processes and apply_lag is None:
            apply_statuses.append("UNKNOWN")
            apply_risks.append("无法确认SQL Apply进程")
        if apply_lag is not None:
            lag_status = _dg_lag_status(apply_lag)
            apply_statuses.append(lag_status)
            if lag_status != "OK":
                apply_risks.append(f"应用延迟{_format_dg_duration(apply_lag)}")
        elif identity["current"] and not os.path.isfile(stats_path):
            apply_statuses.append("UNKNOWN")
            apply_risks.append("缺少Apply Lag采集文件")
        elif os.path.isfile(stats_path):
            apply_statuses.append("UNKNOWN")
            apply_risks.append("未获得Apply Lag")
        apply_status = _dg_worst(apply_statuses, "INFO")
        process_extra = generate_data_table(
            ["进程角色", "线程", "序列", "动作", "客户端进程"], process_rows
        ) if process_rows else ""
        results.append(CheckResult(
            "DG Redo应用", apply_status,
            _format_dg_duration(apply_lag) if apply_lag is not None else ("运行中" if apply_processes else "状态未知"),
            f"Apply进程={len(apply_processes)}，Apply Lag={_format_dg_duration(apply_lag)}，预计追平时间={_format_dg_duration(finish_time)}，打开模式={open_mode}",
            "；".join(dict.fromkeys(apply_risks)) + ("；请检查Redo Apply、归档缺口和备库资源" if apply_risks else ""),
            extra_html=process_extra,
        ))

    gap_path = f"{db_dir}/archive_gap.txt"
    gap_content = read_file(gap_path)
    gap_rows = _data_rows(gap_content, ("THREAD#",))
    gap_problem = bool(re.search(
        r"^(?:ORA|SP2|TNS|LRM)-\d+", gap_content, re.MULTILINE | re.IGNORECASE
    ))
    if gap_problem:
        gap_rows = []
    sequence_path = f"{db_dir}/dataguard_sequence.txt"
    sequence_content = read_file(sequence_path)
    sequence_rows = _data_rows(sequence_content, ("THREAD#",))
    sequence_problem = bool(re.search(
        r"^(?:ORA|SP2|TNS|LRM)-\d+", sequence_content, re.MULTILINE | re.IGNORECASE
    ))
    if sequence_problem:
        sequence_rows = []
    sequence_status = "CRIT" if gap_rows else "OK"
    sequence_risks = ["存在阻塞Redo Apply的归档缺口"] if gap_rows else []
    if not os.path.isfile(gap_path):
        sequence_status = "UNKNOWN" if identity["current"] else "INFO"
        if identity["current"]:
            sequence_risks.append("缺少归档缺口采集文件")
    elif gap_problem:
        sequence_status = "UNKNOWN"
        sequence_risks.append("归档缺口查询失败")
    if sequence_problem:
        sequence_status = _dg_worst([sequence_status, "UNKNOWN"])
        sequence_risks.append("RFS接收/应用序列查询失败")
    elif role != "PRIMARY" and identity["current"] and not os.path.isfile(sequence_path):
        sequence_status = _dg_worst([sequence_status, "UNKNOWN"])
        sequence_risks.append("缺少RFS接收/应用序列采集文件")
    elif role != "PRIMARY" and os.path.isfile(sequence_path) and not sequence_rows:
        sequence_status = _dg_worst([sequence_status, "UNKNOWN"])
        sequence_risks.append("未获得RFS接收/应用序列")
    backlog = []
    for row in sequence_rows:
        if len(row) >= 4:
            try:
                applied_candidates = [int(value) for value in row[2:4] if str(value).strip()]
                if not applied_candidates:
                    raise ValueError
                backlog.append(max(0, int(row[1]) - max(applied_candidates)))
            except (TypeError, ValueError):
                if role != "PRIMARY":
                    sequence_status = _dg_worst([sequence_status, "UNKNOWN"])
                    sequence_risks.append(f"线程{row[0]}缺少可解析的应用序列")
    sequence_extra = ""
    if sequence_rows:
        sequence_extra += generate_data_table(["线程", "已接收序列", "磁盘已应用序列", "内存已应用序列"], sequence_rows)
    if gap_rows:
        sequence_extra += generate_data_table(["线程", "缺口起始", "缺口结束"], gap_rows)
    results.append(CheckResult(
        "DG归档缺口与序列", sequence_status,
        f"{len(gap_rows)}个缺口" + (f"/最大序列差{max(backlog)}" if backlog else ""),
        f"归档缺口={len(gap_rows)}，RAC线程={len(sequence_rows)}" + (f"，最大接收/磁盘应用序列差={max(backlog)}" if backlog else ""),
        "；".join(sequence_risks) + ("；请恢复缺失归档并确认FAL自动补档" if sequence_risks else ""),
        extra_html=sequence_extra,
    ))

    redo_path = f"{db_dir}/dataguard_redo_config.txt"
    redo_content = read_file(redo_path)
    redo_rows = _data_rows(redo_content, ("THREAD#",))
    if role != "FAR SYNC":
        if not os.path.isfile(redo_path):
            redo_status = "UNKNOWN" if identity["current"] else "INFO"
            redo_value = "数据缺失" if identity["current"] else "旧版未采集"
            redo_detail = "缺少Standby Redo Log配置采集文件" if identity["current"] else "旧采集包不含Standby Redo Log配置"
            redo_risks = ["请重新执行当前版本采集器"] if identity["current"] else []
        elif "ORA-" in redo_content.upper() or not redo_rows:
            redo_status = "UNKNOWN"
            redo_value = "数据缺失"
            redo_detail = "无法读取Online Redo与Standby Redo Log配置"
            redo_risks = ["请检查动态性能视图查询权限"]
        else:
            redo_risks = []
            normalized_redo = [(row + [""] * 5)[:5] for row in redo_rows]
            online_rows = []
            unassigned_groups = 0
            unassigned_min_mb = None
            for row in normalized_redo:
                try:
                    if int(row[1]) > 0:
                        online_rows.append(row)
                    elif str(row[0]).strip() == "0":
                        unassigned_groups += int(row[3])
                        if row[4]:
                            value = float(row[4])
                            unassigned_min_mb = value if unassigned_min_mb is None else min(unassigned_min_mb, value)
                except ValueError:
                    redo_risks.append(f"线程{row[0]} Redo配置无法解析")
            for row in online_rows:
                row = (row + [""] * 5)[:5]
                try:
                    online_groups = int(row[1])
                    standby_groups = int(row[3])
                    standby_min_mb = float(row[4]) if row[4] else None
                    if len(online_rows) == 1 and unassigned_groups:
                        standby_groups += unassigned_groups
                        if unassigned_min_mb is not None:
                            standby_min_mb = unassigned_min_mb if standby_min_mb is None else min(standby_min_mb, unassigned_min_mb)
                    if standby_groups < online_groups + 1:
                        redo_risks.append(f"线程{row[0]} SRL组数{standby_groups}，少于建议值{online_groups + 1}")
                    if row[2] and standby_min_mb is not None and standby_min_mb < float(row[2]):
                        redo_risks.append(f"线程{row[0]} SRL最小大小低于Online Redo")
                except ValueError:
                    redo_risks.append(f"线程{row[0]} Redo配置无法解析")
            if len(online_rows) > 1 and unassigned_groups:
                redo_risks.append(f"存在{unassigned_groups}组未分配线程的SRL，RAC环境需按Thread核对")
            if not online_rows:
                redo_status = "UNKNOWN"
                redo_risks.append("未获得Online Redo线程配置")
            else:
                redo_status = "WARN" if redo_risks else "OK"
            redo_value = f"{len(online_rows)}个线程"
            redo_detail = f"已核对{len(online_rows)}个Redo线程的日志组数量和最小大小"
        results.append(CheckResult(
            "DG Standby Redo Log", redo_status, redo_value, redo_detail,
            "；".join(redo_risks) + ("；请按每线程Online Redo组数+1配置同等或更大尺寸的SRL" if redo_risks else ""),
            extra_html=generate_data_table(
                ["线程", "Online组数", "Online最小MB", "Standby组数", "Standby最小MB"], redo_rows
            ) if redo_rows else "",
        ))

    events_path = f"{db_dir}/dataguard_events.txt"
    events_content = read_file(events_path)
    event_rows = _data_rows(events_content, ("TIMESTAMP",))
    if os.path.isfile(events_path):
        event_problem = bool(re.search(
            r"^(?:ORA|SP2|TNS|LRM)-\d+", events_content, re.MULTILINE | re.IGNORECASE
        ))
        if event_problem:
            event_rows = []
        else:
            event_rows = [row[:5] + ["|".join(row[5:])] if len(row) > 6 else row for row in event_rows]
        event_statuses = []
        for row in event_rows:
            severity = row[2].strip().upper() if len(row) > 2 else ""
            event_statuses.append("CRIT" if severity in ("ERROR", "FATAL") else "WARN")
        event_status = "UNKNOWN" if event_problem else _dg_worst(event_statuses)
        results.append(CheckResult(
            "DG近24小时事件", event_status, "采集失败" if event_problem else f"{len(event_rows)}个异常事件",
            "Data Guard事件查询失败" if event_problem else f"Data Guard Warning/Error/Fatal事件={len(event_rows)}",
            "请检查V$DATAGUARD_STATUS查询权限" if event_problem else ("请结合事件时间、错误码和Alert Log处理传输或应用异常" if event_rows else ""),
            extra_html=generate_data_table(
                ["时间", "设施", "级别", "错误码", "DEST", "消息"], event_rows[:100]
            ) if event_rows else "",
        ))
    elif identity["current"]:
        results.append(CheckResult(
            "DG近24小时事件", "UNKNOWN", "数据缺失",
            "缺少Data Guard事件采集文件",
            "请重新执行当前版本采集器",
        ))

    return results


def _parse_db_version(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/db_version.txt")
    version = "N/A"
    if content:
        # v$version 输出格式: BANNER | BANNER_FULL | ...  或  Oracle Database 19c ...
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            # 跳过表头行
            if "BANNER" in line.upper() and "|" in line:
                continue
            # 提取第一个 | 分隔的字段，或整行
            if "|" in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts:
                    version = parts[0]
                    break
            elif "Oracle" in line:
                version = line
                break
    return CheckResult("数据库版本", "OK", version, f"版本: {version}")


def _parse_db_patches(db_dir: str) -> CheckResult:
    """解析数据库补丁信息，列出已安装补丁和时间"""
    content = read_file(f"{db_dir}/opatch.txt")
    if not content or "opatch不可用" in content:
        return CheckResult("数据库补丁", "WARN", "无法获取",
                           "opatch 工具不可用，无法检查补丁信息",
                           "请确认 ORACLE_HOME/opatch 可用")

    # 解析 opatch lsinventory 输出
    # 格式示例:
    # Patch  32545008 : applied on Mon Jun 10 12:34:56 CST 2026
    #    Bugs fixed:
    #      32545008
    patch_data = []  # [(patch_id, date, description)]
    current_patch = None

    for line in content.splitlines():
        line = line.strip()
        # 匹配 "Patch  XXXXXXXX : applied on ..."
        match = re.match(r"Patch\s+(\d+)\s*:\s*applied\s+on\s+(.+)", line, re.IGNORECASE)
        if match:
            if current_patch:
                patch_data.append(current_patch)
            patch_id = match.group(1)
            date_str = match.group(2)
            current_patch = (patch_id, date_str, "")
        elif current_patch and line.startswith("Bugs fixed:"):
            continue
        elif current_patch and line and not line.startswith("Patch") and not line.startswith("OPatch") and not line.startswith("===") and not line.startswith("---") and not line.startswith("List"):
            # 可能是补丁描述
            pass

    if current_patch:
        patch_data.append(current_patch)

    extra = ""
    if patch_data:
        table_rows = [(pid, date, desc if desc else "-") for pid, date, desc in patch_data]
        extra = generate_data_table(
            ["补丁号", "安装时间", "描述"],
            table_rows
        )

    status = "OK"
    suggestion = ""
    if not patch_data:
        status = "WARN"
        suggestion = "未检测到已安装补丁，建议检查 opatch 输出"

    return CheckResult("数据库补丁", status, f"{len(patch_data)}个补丁",
                       f"已安装补丁: {len(patch_data)}个",
                       suggestion, extra_html=extra)


def _parse_init_params(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/spfile.txt")
    has_spfile = False
    params = []
    if content:
        rows = _parse_pipe_table(content)
        for row in rows:
            if row and not any(h in row[0].upper() for h in ["NAME"]):
                name = row[0] if len(row) > 0 else ""
                value = row[1] if len(row) > 1 else ""
                isspecified = row[2] if len(row) > 2 else ""
                params.append((name, value, isspecified))
        has_spfile = len(params) > 0

    extra_html = ""
    if params:
        table_rows = [(p[0], p[1], p[2]) for p in params]
        extra_html = generate_data_table(
            ["参数名", "值", "是否指定"],
            table_rows
        )

    status = "OK" if has_spfile else "WARN"
    suggestion = "" if has_spfile else "未检测到 spfile，建议使用 spfile 管理参数"
    return CheckResult("初始化参数文件", status, "已检查",
                       f"spfile: {'存在' if has_spfile else '未检测到'} (非默认参数: {len(params)}个)",
                       suggestion,
                       extra_html=extra_html)


def _parse_instance_status(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/instance_status.txt")
    db_content = read_file(f"{db_dir}/database_status.txt")
    status = "OK"
    detail = "实例状态未知"
    suggestion = ""
    instance_rows = []
    database_data = None
    abnormal = []

    if content:
        # 检查是否有 SQL 错误
        if "ORA-" in content.upper() or "ERROR" in content.upper():
            # 提取错误信息
            for line in content.splitlines():
                if "ORA-" in line.upper():
                    detail = f"SQL执行错误: {line.strip()}"
                    break
            else:
                detail = f"SQL执行错误，请检查采集脚本"
            status = "CRIT"
            suggestion = "实例状态查询失败，请检查数据库连接和SQL语句"
        else:
            rows = _data_rows(content, ("INST_ID", "INSTANCE_NAME", "INSTANCE"))
            for row in rows:
                if len(row) >= 7:
                    instance_rows.append(row[:7])
                elif len(row) >= 6:  # 兼容旧版 v$instance 单实例数据
                    instance_rows.append([""] + row[:6])
            if instance_rows:
                abnormal = [
                    row for row in instance_rows
                    if row[3].upper() != "OPEN" or row[4].upper() != "ACTIVE"
                ]
                if abnormal:
                    status = "CRIT"
                    suggestion = "存在实例未处于 OPEN/ACTIVE 状态，请立即检查"
                instance_names = "、".join(row[1] for row in instance_rows)
                detail = (
                    f"GV$INSTANCE 返回 {len(instance_rows)} 个实例：{instance_names}；"
                    f"{'全部处于 OPEN/ACTIVE 状态' if not abnormal else f'{len(abnormal)} 个实例状态异常'}"
                )
            else:
                status = "CRIT"
                detail = f"实例状态异常: {content.strip()[:200]}"
                suggestion = "未获得有效的 GV$INSTANCE 数据，请检查实例状态与查询权限"

    # 补充 database 状态
    if db_content and "ORA-" not in db_content.upper():
        db_rows = _data_rows(db_content, ("NAME",))
        if db_rows and len(db_rows[0]) >= 5:
            database_data = db_rows[0][:5]

    # 物理备库正常情况下可以保持 MOUNTED；实例健康必须结合数据库角色和
    # OPEN_MODE 判断，不能沿用主库必须 OPEN/READ WRITE 的单一规则。
    if instance_rows and database_data:
        role = database_data[2].upper()
        open_mode = database_data[1].upper()
        allowed_instance_states = {
            "PHYSICAL STANDBY": {"OPEN", "MOUNTED"},
            "FAR SYNC": {"MOUNTED", "OPEN"},
        }.get(role, {"OPEN"})
        allowed_open_modes = {
            "PRIMARY": {"READ WRITE"},
            "PHYSICAL STANDBY": {"MOUNTED", "READ ONLY", "READ ONLY WITH APPLY"},
            "LOGICAL STANDBY": {"READ WRITE", "READ ONLY"},
            "SNAPSHOT STANDBY": {"READ WRITE"},
            "FAR SYNC": {"MOUNTED"},
        }.get(role, {open_mode})
        abnormal = [
            row for row in instance_rows
            if row[3].upper() not in allowed_instance_states or row[4].upper() != "ACTIVE"
        ]
        mode_abnormal = open_mode not in allowed_open_modes
        if abnormal or mode_abnormal:
            status = "CRIT"
            suggestion = "实例状态或数据库打开模式与当前数据库角色不匹配，请立即检查"
        else:
            status = "OK"
            suggestion = ""
        instance_names = "、".join(row[1] for row in instance_rows)
        detail = (
            f"GV$INSTANCE 返回 {len(instance_rows)} 个实例：{instance_names}；"
            f"数据库角色={role}，打开模式={open_mode}；"
            f"{'状态与角色匹配' if not abnormal and not mode_abnormal else '实例状态或打开模式异常'}"
        )

    extra_parts = []
    if instance_rows:
        extra_parts.extend([
            '<div class="detail-subtitle">实例信息</div>',
            generate_data_table(
                ["实例ID", "实例名", "主机", "实例状态", "数据库状态", "版本", "启动时间"],
                instance_rows,
            ),
        ])
    if database_data:
        extra_parts.extend([
            '<div class="detail-subtitle">数据库信息</div>',
            generate_data_table(
                ["数据库名", "打开模式", "数据库角色", "创建时间", "归档模式"],
                [database_data],
            ),
        ])

    if status == "OK" and len(instance_rows) == 1:
        value = instance_rows[0][3]
    elif status == "OK" and instance_rows:
        value = f"{len(instance_rows)}个实例/全部OPEN"
    else:
        value = f"{len(instance_rows)}个实例/异常" if instance_rows else "异常"
    return CheckResult(
        "实例状态", status, value, detail, suggestion,
        extra_html="".join(extra_parts),
    )


def _pdb_database_role(db_dir):
    """Use collected database roles; conflicting snapshots are not a primary default."""
    roles = set()
    known = {"PRIMARY", "PHYSICAL STANDBY", "LOGICAL STANDBY", "SNAPSHOT STANDBY", "FAR SYNC"}
    for filename in ("dataguard_identity.txt", "database_status.txt"):
        content = read_file(f"{db_dir}/{filename}")
        if _dg_query_failed(content):
            continue
        for row in _parse_pipe_table(content):
            if len(row) >= 3 and row[2].upper() in known:
                roles.add(row[2].upper())
    return next(iter(roles)) if len(roles) == 1 else ""


def _pdb_open_mode_assessment(name, mode, role):
    """PDB OPEN_MODE does not use the CDB-only READ ONLY WITH APPLY value."""
    mode = mode.strip().upper()
    if not mode:
        return "UNKNOWN", "缺少PDB打开模式"
    if name.upper() == "PDB$SEED":
        return (("OK", "种子容器只读或挂载") if mode in {"READ ONLY", "MOUNTED"}
                else ("WARN", "种子容器打开模式异常，预期READ ONLY"))
    # Retain the existing policy accepting deliberately mounted PDBs.
    if mode == "MOUNTED":
        return "OK", "PDB已挂载，按现有巡检策略接受"
    if not role:
        return "UNKNOWN", "数据库角色缺失或采集结果不一致，无法按角色判断PDB打开模式"
    if role == "PHYSICAL STANDBY":
        if mode == "READ ONLY":
            return "OK", "物理备库PDB只读，符合角色预期"
        return "WARN", f"物理备库PDB打开模式为{mode}，与预期READ ONLY不符；核对角色切换或采集数据一致性"
    if role in {"PRIMARY", "SNAPSHOT STANDBY", "LOGICAL STANDBY"}:
        if mode == "READ WRITE":
            return "OK", "PDB读写打开，符合角色预期"
        if mode == "READ ONLY":
            return "INFO", "PDB为只读配置，请按业务用途确认是否符合预期"
        return "WARN", f"PDB打开模式为{mode}，请核对维护状态及业务要求"
    return "UNKNOWN", f"数据库角色{role}不适用于普通PDB打开模式判断"


def _parse_cdb_info(db_dir: str) -> List[CheckResult]:
    """解析 CDB/PDB 信息，判断是否为 CDB，如果是则检查 PDB"""
    results = []

    cdb_content = read_file(f"{db_dir}/cdb_info.txt")
    is_cdb = False
    if cdb_content:
        rows = _parse_pipe_table(cdb_content)
        for row in rows:
            if any(h in row[0].upper() for h in ["CDB"]):
                continue
            if len(row) >= 1 and row[0].upper() == "YES":
                is_cdb = True
                break

    if not is_cdb:
        results.append(CheckResult("CDB/PDB", "OK", "非CDB", "数据库为非CDB架构"))
        return results

    pdb_content = read_file(f"{db_dir}/pdb_info.txt")
    pdb_rows = _parse_pipe_table(pdb_content)
    pdb_data = [r for r in pdb_rows if r and not any(h in r[0].upper() for h in ["PDB_NAME"])]

    if not pdb_data:
        results.append(CheckResult("CDB/PDB", "OK", "CDB", "CDB架构，但未检测到PDB"))
        return results

    pdb_info = []
    role = _pdb_database_role(db_dir)
    assessments = []
    notes = []
    total_size_gb = 0.0

    for r in pdb_data:
        pdb_name = r[0] if len(r) > 0 else ""
        pdb_id = r[1] if len(r) > 1 else ""
        open_mode = r[3] if len(r) > 3 else ""
        restricted = r[4] if len(r) > 4 else ""
        open_time = r[5] if len(r) > 5 else ""
        try:
            size_gb = float(r[6]) if len(r) > 6 else 0.0
        except ValueError:
            size_gb = 0.0
        total_size_gb += size_gb
        state, reason = _pdb_open_mode_assessment(pdb_name, open_mode, role)
        assessments.append(state)
        if state != "OK":
            notes.append(f"{pdb_name}：{reason}")
        pdb_info.append((pdb_name, pdb_id, r[2] if len(r) > 2 else "", open_mode,
                         restricted, f"{size_gb:.2f}", open_time, reason))

    status = _dg_worst([s for s in assessments if s != "OK"], "OK")
    abnormal_count = sum(s in ("WARN", "CRIT") for s in assessments)
    detail = f"CDB架构，共 {len(pdb_info)} 个PDB，总大小 {total_size_gb:.2f}GB；数据库角色={role or '未知或不一致'}"
    if role == "PHYSICAL STANDBY":
        detail += "；物理备库PDB的READ ONLY为正常打开模式"
    if abnormal_count:
        detail += f"；{abnormal_count}个PDB打开模式异常"
    if "UNKNOWN" in assessments:
        detail += "；存在无法判定的PDB打开模式"
    if "INFO" in assessments:
        detail += "；存在需按业务用途确认的只读PDB"
    results.append(CheckResult(
        "CDB/PDB", status, f"{len(pdb_info)}个PDB/{total_size_gb:.2f}GB",
        detail, "；".join(notes),
        extra_html=generate_data_table(
            ["PDB名称", "PDB_ID", "状态", "打开模式", "受限", "大小(GB)", "打开时间", "模式判定"],
            pdb_info,
        ),
    ))

    # PDB 数据文件
    df_content = read_file(f"{db_dir}/pdb_datafiles.txt")
    df_rows = _parse_pipe_table(df_content)
    df_data = [r for r in df_rows if r and not any(h in r[0].upper() for h in ["PDB_ID"])]

    if df_data:
        df_by_pdb = {}
        for r in df_data:
            pdb_id = r[0] if len(r) > 0 else ""
            pdb_name = r[1] if len(r) > 1 else ""
            fname = r[4].split("/")[-1] if len(r) > 4 else ""
            ts = r[3] if len(r) > 3 else ""
            try:
                maxsz = float(r[5]) if len(r) > 5 else 0
            except ValueError:
                maxsz = 0
            try:
                total = float(r[6]) if len(r) > 6 else 0
            except ValueError:
                total = 0
            try:
                used = float(r[7]) if len(r) > 7 else 0
            except ValueError:
                used = 0
            auto = r[8] if len(r) > 8 else ""
            st = r[9] if len(r) > 9 else ""

            key = f"{pdb_id}-{pdb_name}" if pdb_name else pdb_id
            if key not in df_by_pdb:
                df_by_pdb[key] = []
            df_by_pdb[key].append((fname, ts, total, used, maxsz, auto, st))

        df_table_rows = []
        for key, files in df_by_pdb.items():
            pdb_display = key.split("-", 1)[1] if "-" in key else key
            for fname, ts, total, used, maxsz, auto, st in files:
                df_table_rows.append((pdb_display, fname, ts, f"{total:.0f}", f"{used:.0f}", f"{maxsz:.0f}", auto, st))

        results.append(CheckResult(
            "PDB数据文件", "OK", f"{len(df_data)}个",
            f"共 {len(df_data)} 个PDB数据文件；可用数据区是 USER_BYTES，不代表实际已使用空间",
            extra_html=generate_data_table(
                ["PDB", "文件名", "表空间", "总大小(MB)", "可用数据区(MB)", "最大(MB)", "自动扩展", "在线状态"],
                df_table_rows
            )
        ))

    # PDB 用户
    user_content = read_file(f"{db_dir}/pdb_users.txt")
    user_rows = _parse_pipe_table(user_content)
    user_data = [r for r in user_rows if r and not any(h in r[0].upper() for h in ["CON_ID"])]

    if user_data:
        user_table_rows = []
        for r in user_data[:30]:
            con_id = r[0] if len(r) > 0 else ""
            username = r[1] if len(r) > 1 else ""
            account_status = r[2] if len(r) > 2 else ""
            created = r[3] if len(r) > 3 else ""
            ts = r[4] if len(r) > 4 else ""
            profile = r[5] if len(r) > 5 else ""
            user_table_rows.append((f"PDB${con_id}", username, account_status, created, ts, profile))

        results.append(CheckResult(
            "PDB用户", "OK", f"{len(user_data)}个",
            f"共 {len(user_data)} 个PDB用户（不含SYS/SYSTEM）",
            extra_html=generate_data_table(
                ["PDB", "用户名", "账号状态", "创建时间", "默认表空间", "配置文件"],
                user_table_rows
            )
        ))

    return results


def _parse_rac_info(db_dir: str) -> List[CheckResult]:
    """解析 RAC 信息，判断是否为 RAC 部署"""
    results = []

    node_content = read_file(f"{db_dir}/rac_nodes.txt")
    if not node_content or "ORA-" in node_content.upper():
        results.append(CheckResult("RAC集群", "OK", "非RAC", "数据库为单实例部署"))
        return results

    rows = _parse_pipe_table(node_content)
    node_data = [r for r in rows if r and not any(h in r[0].upper() for h in ["INST_ID"])]

    if not node_data:
        results.append(CheckResult("RAC集群", "OK", "非RAC", "数据库为单实例部署"))
        return results

    if len(node_data) <= 1:
        results.append(CheckResult("RAC集群", "OK", "单节点", f"节点数: {len(node_data)}"))
        return results

    node_info = []
    down_count = 0
    for r in node_data:
        inst_id = r[0] if len(r) > 0 else ""
        instance_number = r[1] if len(r) > 1 else ""
        instance_name = r[2] if len(r) > 2 else ""
        host_name = r[3] if len(r) > 3 else ""
        status = r[4] if len(r) > 4 else ""
        database_status = r[5] if len(r) > 5 else ""
        instance_role = r[6] if len(r) > 6 else ""
        startup_time = r[7] if len(r) > 7 else ""
        version = r[8] if len(r) > 8 else ""

        if status.upper() != "OPEN":
            down_count += 1

        node_info.append((inst_id, instance_number, instance_name, host_name,
                         status, database_status, instance_role, startup_time, version))

    status = "OK"
    suggestion = ""
    if down_count > 0:
        status = "CRIT"
        suggestion = f"存在 {down_count} 个节点未OPEN，请立即检查"

    table_rows = []
    for inst_id, inst_num, inst_name, host, st, db_st, role, startup, ver in node_info:
        table_rows.append((inst_id, inst_num, inst_name, host, st, db_st, role, startup, ver))

    extra = generate_data_table(
        ["实例ID", "节点号", "实例名", "主机", "状态", "数据库状态", "角色", "启动时间", "版本"],
        table_rows
    )

    results.append(CheckResult(
        "RAC集群", status, f"{len(node_info)}节点",
        f"RAC部署，共 {len(node_info)} 个节点" +
        (f"，{down_count}个节点异常" if down_count > 0 else ""),
        suggestion,
        extra_html=extra
    ))

    service_content = read_file(f"{db_dir}/rac_services.txt")
    service_rows = _parse_pipe_table(service_content)
    service_data = [r for r in service_rows if r and not any(h in r[0].upper() for h in ["NAME"])]

    if service_data:
        service_table_rows = []
        for r in service_data[:15]:
            name = r[0] if len(r) > 0 else ""
            network_name = r[1] if len(r) > 1 else ""
            creation_date = r[2] if len(r) > 2 else ""
            enabled = r[3] if len(r) > 3 else ""
            goal = r[4] if len(r) > 4 else ""
            failover_method = r[5] if len(r) > 5 else ""
            failover_type = r[6] if len(r) > 6 else ""
            pdb = r[7] if len(r) > 7 else ""
            global_service = r[8] if len(r) > 8 else ""
            service_table_rows.append((name, network_name, creation_date, enabled, goal, failover_method, failover_type, pdb, global_service))

        results.append(CheckResult(
            "RAC服务", "OK", f"{len(service_data)}个",
            f"共 {len(service_data)} 个RAC服务",
            extra_html=generate_data_table(
                ["服务名", "网络名", "创建日期", "启用", "目标", "故障转移方法", "故障转移类型", "PDB", "全局服务"],
                service_table_rows
            )
        ))

    return results


def _parse_awr_metrics(db_dir: str) -> List[CheckResult]:
    from parser.advanced_checks import parse_awr
    return parse_awr(db_dir)


def _parse_db_language(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/nls_params.txt")
    charset = "N/A"
    if content:
        for line in content.splitlines():
            if "NLS_CHARACTERSET" in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                charset = parts[-1] if parts else "N/A"
                break
    return CheckResult("数据库语言", "OK", charset, f"字符集: {charset}")


def _parse_backup_status(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/rman_backup.txt")
    rows = _parse_pipe_table(content)
    # 去掉表头
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["SESSION_KEY", "session_key"])]

    # 解析 RMAN 操作状态
    status_content = read_file(f"{db_dir}/rman_status.txt")
    status_rows = _parse_pipe_table(status_content)
    status_data = [r for r in status_rows if r and not any(h in r[0].upper() for h in ["OPERATION"])]

    status = "OK"
    suggestion = ""
    if not data_rows:
        status = "WARN"
        suggestion = "最近7天未发现RMAN备份记录，请检查备份策略"

    # 分析备份策略
    backup_types = set()
    failed_count = 0
    total_output_gb = 0.0
    for r in data_rows:
        input_type = r[4] if len(r) > 4 else ""
        bstatus = r[3] if len(r) > 3 else ""
        try:
            output_gb = float(r[6]) if len(r) > 6 else 0.0
        except (ValueError, IndexError):
            output_gb = 0.0
        if input_type:
            backup_types.add(input_type.upper())
        if bstatus and bstatus.upper() in ("FAILED", "COMPLETED WITH ERRORS"):
            failed_count += 1
        total_output_gb += output_gb

    # 生成备份任务详情表格
    extra = ""
    detail_parts = []

    if data_rows:
        table_rows = []
        for r in data_rows[:30]:
            session_key = r[0] if len(r) > 0 else ""
            start_time = r[1] if len(r) > 1 else ""
            end_time = r[2] if len(r) > 2 else ""
            bstatus = r[3] if len(r) > 3 else ""
            input_type = r[4] if len(r) > 4 else ""
            device_type = r[5] if len(r) > 5 else ""
            output_gb = r[6] if len(r) > 6 else ""
            table_rows.append((session_key, start_time, end_time, bstatus,
                               input_type, device_type, output_gb))
        detail_parts.append(generate_data_table(
            ["会话KEY", "开始时间", "结束时间", "状态", "备份类型", "设备类型", "输出(GB)"],
            table_rows
        ))

    # RMAN 操作状态表格
    if status_data:
        op_table_rows = []
        for r in status_data[:30]:
            operation = r[0] if len(r) > 0 else ""
            object_type = r[1] if len(r) > 1 else ""
            op_status = r[2] if len(r) > 2 else ""
            op_start = r[3] if len(r) > 3 else ""
            op_end = r[4] if len(r) > 4 else ""
            op_table_rows.append((operation, object_type, op_status, op_start, op_end))
        detail_parts.append('<div class="detail-subtitle">RMAN操作记录</div>')
        detail_parts.append(generate_data_table(
            ["操作", "对象类型", "状态", "开始时间", "结束时间"],
            op_table_rows
        ))

    # 备份策略分析与建议
    analysis_lines = []
    analysis_lines.append('<div class="detail-subtitle">备份策略分析</div>')
    analysis_lines.append('<ul class="detail-list">')

    # 备份类型分析
    if backup_types:
        types_str = "、".join(sorted(backup_types))
        analysis_lines.append(f"<li>备份类型覆盖: {types_str}</li>")
        if "DB FULL" in backup_types or "DB INCR" in backup_types:
            analysis_lines.append("<li>已配置全量/增量备份策略</li>")
        else:
            analysis_lines.append("<li>建议配置全量+增量备份策略，提升恢复效率</li>")
    else:
        analysis_lines.append("<li>未检测到备份类型信息</li>")

    # 备份状态分析
    if failed_count > 0:
        analysis_lines.append(f'<li>存在 {failed_count} 个失败的备份任务，需检查备份日志</li>')
    elif data_rows:
        analysis_lines.append("<li>所有备份任务状态正常</li>")

    # 备份频率分析
    if data_rows:
        analysis_lines.append(f"<li>最近7天备份任务数: {len(data_rows)}，输出总量: {total_output_gb:.2f}GB</li>")

    analysis_lines.append("</ul>")

    # 优化建议
    analysis_lines.append('<div class="detail-subtitle">优化建议</div>')
    analysis_lines.append('<ul class="detail-list">')
    if not data_rows:
        analysis_lines.append("<li>立即配置RMAN备份策略，确保数据安全</li>")
    else:
        analysis_lines.append("<li>定期验证备份可恢复性（RMAN VALIDATE / RESTORE ... VALIDATE）</li>")
        analysis_lines.append("<li>配置备份保留策略（RETENTION POLICY），自动清理过期备份</li>")
        analysis_lines.append("<li>监控归档日志空间，避免FRA空间不足导致备份失败</li>")
        analysis_lines.append("<li>考虑启用备份压缩（COMPRESSION ALGORITHM），减少备份存储空间</li>")
    analysis_lines.append("</ul>")

    # 实施步骤
    analysis_lines.append('<div class="detail-subtitle">实施步骤</div>')
    analysis_lines.append('<ul class="detail-list">')
    analysis_lines.append("<li>1. 配置备份目标: CONFIGURE DEFAULT DEVICE TYPE TO DISK/SBT;</li>")
    analysis_lines.append("<li>2. 配置保留策略: CONFIGURE RETENTION POLICY TO RECOVERY WINDOW OF 7 DAYS;</li>")
    analysis_lines.append("<li>3. 配置压缩: CONFIGURE COMPRESSION ALGORITHM 'BASIC';</li>")
    analysis_lines.append("<li>4. 执行全量备份: BACKUP DATABASE PLUS ARCHIVELOG;</li>")
    analysis_lines.append("<li>5. 定期验证: RESTORE DATABASE VALIDATE;</li>")
    analysis_lines.append("</ul>")

    detail_parts.append("".join(analysis_lines))

    extra = "".join(detail_parts)

    detail = f"最近7天RMAN备份任务数: {len(data_rows)}"
    if data_rows:
        detail += f"，输出总量: {total_output_gb:.2f}GB"
        if failed_count > 0:
            detail += f"，失败: {failed_count}个"

    return CheckResult("备份状态", status, f"{len(data_rows)}个备份任务",
                       detail, suggestion, extra_html=extra)


def _parse_archive_log(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/recovery_file_dest.txt")
    usage = 0.0
    if content:
        for line in content.splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 5:
                try:
                    usage = float(parts[-1])
                    break
                except ValueError:
                    continue

    status = check_threshold(usage, DB_THRESHOLDS["archive_usage_warn"],
                             DB_THRESHOLDS["archive_usage_crit"])
    suggestion = ""
    if status == "CRIT":
        suggestion = "归档日志目录使用率过高，请立即清理或扩容"
    elif status == "WARN":
        suggestion = "归档日志目录使用率偏高，建议关注"

    return CheckResult("归档日志使用率", status, f"{usage:.1f}%",
                       f"归档日志目录使用率: {usage:.1f}%", suggestion)


def _parse_storage_path_capacity(db_dir: str) -> CheckResult:
    """解析 Windows 上 Oracle 数据文件、Redo、归档和诊断目录所在卷容量。"""
    content = read_file(f"{db_dir}/storage_path_capacity.txt")
    if not content:
        return CheckResult("Oracle存储卷容量", "INFO", "旧版未采集", "采集包不含 Oracle 路径与 Windows 卷容量关联数据")
    rows = _data_rows(content, ("TYPE",))
    if not rows:
        return CheckResult("Oracle存储卷容量", "INFO", "无可评估卷", "未识别到盘符文件系统；ASM和UNC容量应在对应存储平台核查")

    status_order = {"OK": 0, "WARN": 1, "CRIT": 2}
    overall = "OK"
    local_rows = 0
    usage_values = []
    table_rows = []
    for row in rows:
        values = list(row) + [""] * max(0, 8 - len(row))
        storage_type, kind, volume, path_count, example, total_text, free_text, usage_text = values[:8]
        item_status = "INFO"
        if kind.upper() == "FILESYSTEM" and total_text and free_text and usage_text:
            local_rows += 1
            try:
                usage = float(usage_text)
                free_gb = float(free_text)
            except ValueError:
                item_status = "UNKNOWN"
            else:
                usage_values.append(usage)
                item_status = check_threshold(
                    usage,
                    DB_THRESHOLDS["oracle_volume_usage_warn"],
                    DB_THRESHOLDS["oracle_volume_usage_crit"],
                )
                if free_gb <= DB_THRESHOLDS["oracle_volume_free_crit_gb"]:
                    item_status = "CRIT"
                elif free_gb <= DB_THRESHOLDS["oracle_volume_free_warn_gb"] and item_status == "OK":
                    item_status = "WARN"
            if item_status in status_order and status_order[item_status] > status_order[overall]:
                overall = item_status
        table_rows.append((storage_type, kind, volume, path_count, example, total_text, free_text, usage_text, item_status))

    if local_rows == 0:
        overall = "INFO"
    worst_usage = max(usage_values, default=0.0)
    suggestion = "请优先清理归档/诊断文件、迁移 Oracle 文件或扩容对应 Windows 卷" if overall in ("WARN", "CRIT") else ""
    return CheckResult(
        "Oracle存储卷容量", overall,
        f"最高{worst_usage:.1f}%" if local_rows else "非盘符存储",
        f"关联 {len(rows)} 组 Oracle 路径，其中 {local_rows} 组可读取 Windows 卷容量",
        suggestion,
        extra_html=generate_data_table(
            ["类型", "存储", "卷", "路径数", "示例路径", "总容量(GB)", "可用(GB)", "使用率(%)", "状态"],
            table_rows,
        ),
    )


def _parse_control_files(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/control_files.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["NAME", "name"])]

    cf_count = len(data_rows)
    status = "OK" if cf_count >= 2 else "WARN"
    suggestion = "" if cf_count >= 2 else f"控制文件仅 {cf_count} 个，建议多路复用(>=2)"
    table_rows = []
    for row in data_rows:
        size_mb = ""
        if len(row) >= 5:
            try:
                size_mb = f"{float(row[3]) * float(row[4]) / 1024 / 1024:.2f}"
            except (TypeError, ValueError):
                size_mb = ""
        table_rows.append((
            row[0] if len(row) > 0 else "",
            row[1] if len(row) > 1 else "",
            row[2] if len(row) > 2 else "",
            row[3] if len(row) > 3 else "",
            size_mb,
        ))
    extra = generate_data_table(
        ["完整路径", "状态", "恢复区文件", "块大小(Byte)", "文件大小(MB)"],
        table_rows,
    ) if table_rows else ""

    return CheckResult("控制文件", status, f"{cf_count}个",
                       f"控制文件数量: {cf_count}", suggestion, extra_html=extra)


def _parse_redo_logs(db_dir: str) -> CheckResult:
    """解析 Redo Log，展示日志详情和切换频率图表"""
    content = read_file(f"{db_dir}/redo_logs.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["GROUP", "group"])]

    status = "OK"
    suggestion = ""

    # 解析日志详情表格
    log_table_rows = []
    for row in data_rows:
        row_str = " ".join(row).upper()
        if "STALE" in row_str:
            status = "WARN"
            suggestion = "存在 STALE 状态的 Redo Log，请检查"
        group = row[0] if len(row) > 0 else ""
        thread = row[1] if len(row) > 1 else ""
        seq = row[2] if len(row) > 2 else ""
        members = row[3] if len(row) > 3 else ""
        archived = row[4] if len(row) > 4 else ""
        log_status = row[5] if len(row) > 5 else ""
        size_mb = row[6] if len(row) > 6 else ""
        member_path = row[7] if len(row) > 7 else ""
        # 截断路径只保留文件名
        short_member = member_path.split("/")[-1] if "/" in member_path else member_path
        log_table_rows.append((group, thread, seq, members, archived, log_status, size_mb, short_member))

    extra = ""
    if log_table_rows:
        extra += generate_data_table(
            ["组#", "线程", "序列号", "成员数", "已归档", "状态", "大小(MB)", "文件"],
            log_table_rows
        )

    # 解析 Redo 切换频率
    freq_content = read_file(f"{db_dir}/redo_switch_freq.txt")
    freq_rows = _parse_pipe_table(freq_content)
    freq_data = [r for r in freq_rows if r and not any(h in r[0].upper() for h in ["HOUR_SLOT", "HOUR"])]

    if freq_data:
        # 计算每小时平均切换次数和最大切换次数
        switch_counts = []
        for r in freq_data:
            try:
                switch_counts.append(int(r[1]))
            except (ValueError, IndexError):
                pass

        if switch_counts:
            avg_switch = sum(switch_counts) / len(switch_counts)
            max_switch = max(switch_counts)
            # 如果平均每小时切换超过3次，发出警告
            if avg_switch > 5:
                if status != "CRIT":
                    status = "WARN"
                suggestion = f"Redo 切换频率偏高（平均 {avg_switch:.1f}次/小时），建议增大 Redo Log 大小"

        # 生成切换频率柱状图（只取最近7天，数据量更合理）
        # 按天汇总
        daily_data = {}  # {date: total_switches}
        for r in freq_data:
            try:
                hour_slot = r[0]  # "2026-06-12 14"
                date_part = hour_slot[:10]  # "2026-06-12"
                count = int(r[1])
                daily_data[date_part] = daily_data.get(date_part, 0) + count
            except (ValueError, IndexError):
                pass

        if daily_data:
            # 按日期排序，取最近30天
            sorted_days = sorted(daily_data.items())
            bar_items = [(day, count, "次") for day, count in sorted_days[-30:]]
            extra += '<div style="margin-top:12px;font-size:13px;font-weight:600;color:#475569;">每日 Redo 切换次数（近30天）</div>'
            extra += generate_bar_chart(bar_items, warn_threshold=72, crit_threshold=120)

    detail = f"Redo Log 组数: {len(log_table_rows)}"
    if freq_data:
        detail += f", 近30天切换记录: {len(freq_data)}小时段"

    return CheckResult("Redo Log", status, f"{len(log_table_rows)}组",
                       detail, suggestion, extra_html=extra)


def _parse_data_files(db_dir: str) -> CheckResult:
    """解析数据文件，展示每个文件的大小、自动扩展、在线状态，以及合计大小"""
    content = read_file(f"{db_dir}/data_files.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0].upper() for h in ["FILE_NAME"])]

    if not data_rows:
        return CheckResult("数据文件", "CRIT", "数据缺失", "无法获取数据文件信息")

    total_size_mb = 0.0
    offline_count = 0
    no_autoext_count = 0
    file_data = []  # [(file_name, ts_name, size_mb, autoext, maxsize_mb, status, online_status)]

    for row in data_rows:
        if len(row) < 7:
            continue
        file_name = row[0]
        ts_name = row[1]
        try:
            size_mb = float(row[2])
        except ValueError:
            size_mb = 0.0
        autoext = row[3].upper() if len(row) > 3 else "N/A"
        try:
            maxsize_mb = float(row[4])
        except ValueError:
            maxsize_mb = 0.0
        status = row[5] if len(row) > 5 else "N/A"
        online_status = row[6] if len(row) > 6 else status

        total_size_mb += size_mb
        if online_status.upper() not in ("ONLINE", "AVAILABLE", "SYSTEM"):
            offline_count += 1
        if autoext != "YES":
            no_autoext_count += 1

        file_data.append((file_name, ts_name, size_mb, autoext, maxsize_mb, online_status))

    # 状态判定
    check_status = "OK"
    suggestion = ""
    if offline_count > 0:
        check_status = "CRIT"
        suggestion = f"存在 {offline_count} 个数据文件不在线，请立即检查"
    elif no_autoext_count > 0:
        check_status = "WARN"
        suggestion = f"存在 {no_autoext_count} 个数据文件未开启自动扩展，建议开启"

    # 生成数据表格
    table_rows = []
    no_autoextend_cells = {}
    for row_index, (fname, ts, sz, auto, maxsz, onl) in enumerate(file_data):
        # 截断过长的文件路径，只保留文件名
        short_name = fname.split("/")[-1] if "/" in fname else fname.split("\\")[-1] if "\\" in fname else fname
        table_rows.append((
            short_name, ts, f"{sz:.0f}",
            auto, f"{maxsz:.0f}" if auto == "YES" else "-",
            onl
        ))
        if auto != "YES":
            no_autoextend_cells[(row_index, 3)] = "metric-warn"

    # 合计行
    table_rows.append(("合计", f"{len(file_data)}个文件", f"{total_size_mb:.0f}", "", "", ""))

    extra = generate_data_table(
        ["文件名", "表空间", "大小(MB)", "自动扩展", "最大(MB)", "状态"],
        table_rows,
        cell_classes=no_autoextend_cells,
    )

    total_gb = total_size_mb / 1024
    detail = f"共 {len(file_data)} 个数据文件, 合计 {total_gb:.2f}GB"
    if offline_count > 0:
        detail += f", 离线: {offline_count}个"
    if no_autoext_count > 0:
        detail += f", 未自动扩展: {no_autoext_count}个"

    return CheckResult("数据文件", check_status, f"{len(file_data)}个/{total_gb:.2f}GB",
                       detail, suggestion, extra_html=extra)


def _parse_tablespaces(db_dir: str) -> List[CheckResult]:
    results = []
    ts_data = []
    for filename in ("tablespaces.txt", "temp_tablespaces.txt"):
        for row in _parse_pipe_table(read_file(f"{db_dir}/{filename}")):
            if not row or "TABLESPACE" in row[0].upper() or len(row) < 10:
                continue
            try:
                ts_data.append({
                    "name": row[0], "contents": row[1], "alloc": float(row[2]), "used": float(row[3]),
                    "free": float(row[4]), "alloc_pct": float(row[5]), "max_pct": float(row[6]),
                    "max": float(row[7]), "auto": row[8], "status": row[9],
                })
            except (ValueError, IndexError):
                continue

    if not ts_data:
        results.append(CheckResult("表空间使用概览", "CRIT", "数据缺失", "无法获取表空间信息"))
    else:
        # 汇总状态：取所有表空间中最严重的
        worst_status = "OK"
        for ts in ts_data:
            effective_pct = effective_usage(ts)
            s = check_threshold(effective_pct, DB_THRESHOLDS["tablespace_usage_warn"],
                                DB_THRESHOLDS["tablespace_usage_crit"])
            if s == "CRIT":
                worst_status = "CRIT"
                break
            elif s == "WARN":
                worst_status = "WARN"

        # 建议
        crit_count = sum(1 for ts in ts_data
                         if check_threshold(effective_usage(ts), DB_THRESHOLDS["tablespace_usage_warn"],
                                            DB_THRESHOLDS["tablespace_usage_crit"]) == "CRIT")
        warn_count = sum(1 for ts in ts_data
                         if check_threshold(effective_usage(ts), DB_THRESHOLDS["tablespace_usage_warn"],
                                            DB_THRESHOLDS["tablespace_usage_crit"]) == "WARN")
        suggestion = ""
        if crit_count > 0:
            suggestion = f"{crit_count} 个表空间使用率严重，请立即扩容"
        elif warn_count > 0:
            suggestion = f"{warn_count} 个表空间使用率偏高，建议关注"

        overview = CheckResult(
            "表空间使用概览", worst_status, f"{len(ts_data)}个表空间",
            f"共 {len(ts_data)} 个表空间；自动扩展=YES 时按最大使用率判定，否则按分配使用率判定"
            + (f"；严重: {crit_count}，警告: {warn_count}" if crit_count or warn_count else ""),
            suggestion,
            extra_html=render_tablespace_overview(ts_data)
        )
        results.append(overview)

    return results


def _parse_rollback_segments(db_dir: str) -> CheckResult:
    undo_rows = _data_rows(
        read_file(f"{db_dir}/undo_tablespace.txt"),
        ("TABLESPACE_NAME",),
    )
    parameter_rows = _data_rows(
        read_file(f"{db_dir}/undo_retention.txt"),
        ("NAME",),
    )
    if not undo_rows and not parameter_rows:
        return CheckResult(
            "UNDO/回滚段管理", "WARN", "数据缺失",
            "未采集到 UNDO 表空间与参数信息",
            "请检查 DBA_UNDO_EXTENTS 访问权限与采集完整性",
        )

    extra_parts = []
    if undo_rows:
        extra_parts.extend([
            '<div class="detail-subtitle">UNDO Extent 状态</div>',
            generate_data_table(
                ["UNDO表空间", "Extent状态", "容量(MB)"],
                [row[:3] for row in undo_rows],
            ),
        ])
    if parameter_rows:
        extra_parts.extend([
            '<div class="detail-subtitle">UNDO 初始化参数</div>',
            generate_data_table(
                ["参数", "值"],
                [row[:2] for row in parameter_rows],
            ),
        ])

    tablespaces = len({row[0] for row in undo_rows if row})
    return CheckResult(
        "UNDO/回滚段管理", "OK", f"{tablespaces}个UNDO表空间",
        f"已记录 {len(undo_rows)} 项 Extent 状态和 {len(parameter_rows)} 个 UNDO 参数",
        extra_html="".join(extra_parts),
    )


def _parse_asm_diskgroups(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/asm_diskgroups.txt")
    if not content or "no rows selected" in content.lower():
        return CheckResult("ASM磁盘组", "INFO", "未使用ASM", "当前数据库未使用ASM存储")

    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["GROUP", "group"])]

    if not data_rows:
        return CheckResult("ASM磁盘组", "INFO", "未使用ASM", "无ASM磁盘组数据")

    # 取最高使用率
    max_usage = 0.0
    for row in data_rows:
        if len(row) >= 7:
            try:
                usage = float(row[-1])
                max_usage = max(max_usage, usage)
            except ValueError:
                pass

    status = check_threshold(max_usage, DB_THRESHOLDS["asm_usage_warn"],
                             DB_THRESHOLDS["asm_usage_crit"])
    suggestion = ""
    if status in ("CRIT", "WARN"):
        suggestion = "ASM磁盘组使用率偏高，请关注磁盘空间"

    # 生成磁盘组详情表格
    detail_parts = []
    dg_table_rows = []
    for r in data_rows:
        group_number = r[0] if len(r) > 0 else ""
        name = r[1] if len(r) > 1 else ""
        state = r[2] if len(r) > 2 else ""
        dg_type = r[3] if len(r) > 3 else ""
        total_gb = r[4] if len(r) > 4 else ""
        free_gb = r[5] if len(r) > 5 else ""
        usage_pct = r[6] if len(r) > 6 else ""
        dg_table_rows.append((group_number, name, state, dg_type, total_gb, free_gb, usage_pct))
    usage_classes = {}
    for row_index, row in enumerate(dg_table_rows):
        try:
            usage = float(row[6])
        except (TypeError, ValueError):
            continue
        usage_status = check_threshold(
            usage, DB_THRESHOLDS["asm_usage_warn"], DB_THRESHOLDS["asm_usage_crit"]
        )
        if usage_status == "CRIT":
            usage_classes[(row_index, 6)] = "metric-crit"
        elif usage_status == "WARN":
            usage_classes[(row_index, 6)] = "metric-warn"
    detail_parts.append(generate_data_table(
        ["组号", "名称", "状态", "类型", "总量(GB)", "空闲(GB)", "使用率(%)"],
        dg_table_rows,
        cell_classes=usage_classes,
    ))

    # ASM 磁盘详情
    disk_content = read_file(f"{db_dir}/asm_disks.txt")
    if disk_content and "no rows selected" not in disk_content.lower():
        disk_rows = _parse_pipe_table(disk_content)
        disk_data = [r for r in disk_rows if r and not any(h in r[0].upper() for h in ["GROUP"])]
        if disk_data:
            detail_parts.append('<div class="detail-subtitle">ASM磁盘详情</div>')
            disk_table_rows = []
            # 构建组号->组名映射
            group_map = {}
            for r in data_rows:
                if len(r) >= 2:
                    group_map[str(r[0])] = r[1]
            for r in disk_data[:50]:
                group_number = r[0] if len(r) > 0 else ""
                disk_number = r[1] if len(r) > 1 else ""
                disk_name = r[2] if len(r) > 2 else ""
                path = r[3] if len(r) > 3 else ""
                mode_status = r[4] if len(r) > 4 else ""
                disk_state = r[5] if len(r) > 5 else ""
                disk_total = r[6] if len(r) > 6 else ""
                disk_free = r[7] if len(r) > 7 else ""
                group_name = group_map.get(str(group_number), group_number)
                disk_table_rows.append((group_name, disk_number, disk_name, path,
                                        mode_status, disk_state, disk_total, disk_free))
            detail_parts.append(generate_data_table(
                ["所属磁盘组", "磁盘号", "磁盘名", "路径", "模式状态", "状态", "总量(GB)", "空闲(GB)"],
                disk_table_rows
            ))

    extra = "".join(detail_parts)

    return CheckResult("ASM磁盘组", status, f"{max_usage:.1f}%",
                       f"ASM磁盘组最高使用率: {max_usage:.1f}%", suggestion, extra_html=extra)


def _parse_sessions(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/sessions.txt")
    session_pct = 0.0
    detail = "会话数据缺失"
    extra = ""

    if content:
        rows = _parse_pipe_table(content)
        for row in rows:
            if len(row) >= 4:
                try:
                    cur = float(row[0])
                    max_s = float(row[1])
                    if max_s > 0:
                        session_pct = cur / max_s * 100
                    detail = f"当前会话: {int(cur)}/{int(max_s)}, 进程: {row[2]}/{row[3]}"
                    break
                except (ValueError, IndexError):
                    pass

    # 读取会话详情
    detail_content = read_file(f"{db_dir}/session_detail.txt")
    if detail_content:
        detail_rows = _parse_pipe_table(detail_content)
        data_rows = [r for r in detail_rows if r and not any(h in r[0].upper() for h in ["USERNAME"])]
        if data_rows:
            table_rows = [(r[0], r[1], r[2] if len(r) > 2 else "") for r in data_rows[:10]]
            extra = generate_data_table(["用户", "状态", "会话数"], table_rows)

    status = check_threshold(session_pct, DB_THRESHOLDS["session_usage_warn"],
                             DB_THRESHOLDS["session_usage_crit"])
    suggestion = ""
    if status in ("CRIT", "WARN"):
        suggestion = "会话使用率偏高，请检查连接池和活跃会话"

    return CheckResult("会话与进程", status, f"{session_pct:.1f}%", detail, suggestion,
                       extra_html=extra)


def _parse_operational_risks(db_dir: str) -> List[CheckResult]:
    results = []
    limit_rows = _data_rows(read_file(f"{db_dir}/resource_limits.txt"), ("RESOURCE_NAME",))
    limit_data = []
    worst = 0.0
    for r in limit_rows:
        if len(r) < 5:
            continue
        try:
            current = float(r[1])
            high = float(r[2])
            limit = float(r[4])
            pct = high / limit * 100 if limit > 0 else 0.0
        except ValueError:
            pct = 0.0
        worst = max(worst, pct)
        limit_data.append((r[0], r[1], r[2], r[3], r[4], f"{pct:.1f}%" if pct else "N/A"))
    limit_status = check_threshold(worst, DB_THRESHOLDS["resource_usage_warn"], DB_THRESHOLDS["resource_usage_crit"])
    if not limit_rows:
        limit_status = "CRIT"
    results.append(CheckResult("数据库资源上限", limit_status, f"最高{worst:.1f}%" if limit_rows else "数据缺失",
                               f"已检查 {len(limit_data)} 类资源的当前值和历史峰值",
                               "资源历史峰值接近上限，请检查连接池并评估 processes/sessions 参数" if limit_status in ("WARN", "CRIT") and limit_rows else "",
                               extra_html=generate_data_table(["资源", "当前", "历史峰值", "初始分配", "上限", "峰值占比"], limit_data) if limit_data else ""))

    block_rows = _data_rows(read_file(f"{db_dir}/blocking_sessions.txt"), ("SID",))
    block_count = len(block_rows)
    block_status = check_threshold(block_count, DB_THRESHOLDS["blocking_session_warn"], DB_THRESHOLDS["blocking_session_crit"])
    results.append(CheckResult("阻塞会话", block_status, f"{block_count}个",
                               f"当前被阻塞会话: {block_count}",
                               "立即定位阻塞源、事务边界及应用提交逻辑" if block_count else "",
                               extra_html=generate_data_table(["SID", "Serial#", "用户", "状态", "事件", "等待秒", "阻塞实例", "阻塞SID", "SQL_ID", "主机", "程序"], block_rows[:50]) if block_rows else ""))

    stale_rows = _data_rows(read_file(f"{db_dir}/stale_statistics.txt"), ("OWNER",))
    stale_total = 0
    for r in stale_rows:
        try:
            stale_total += int(r[1])
        except (ValueError, IndexError):
            pass
    stale_status = check_threshold(stale_total, DB_THRESHOLDS["stale_stats_warn"], DB_THRESHOLDS["stale_stats_crit"])
    results.append(CheckResult("陈旧统计信息", stale_status, f"{stale_total}个表",
                               f"存在陈旧统计信息的业务 Schema: {len(stale_rows)}",
                               "按业务窗口使用 DBMS_STATS 收集陈旧统计信息，并核查自动统计任务" if stale_total else "",
                               extra_html=generate_data_table(["Schema", "陈旧表数", "最早分析时间"], stale_rows) if stale_rows else ""))

    top_rows = _data_rows(read_file(f"{db_dir}/top_elapsed_sql.txt"), ("SQL_ID",))
    results.append(CheckResult("高耗时SQL", "OK" if top_rows else "WARN", f"{len(top_rows)}条",
                               "按累计 elapsed_time 排序的共享池 Top SQL；此项为性能线索，不单独判为故障",
                               "未采集到 SQL 统计，请检查实例状态与采集权限" if not top_rows else "",
                               extra_html=generate_data_table(["SQL_ID", "计划哈希", "执行次数", "耗时(s)", "CPU(s)", "逻辑读", "物理读", "行数", "Schema", "SQL文本"], top_rows[:20]) if top_rows else ""))
    return results


def _parse_buffer_cache_hit(db_dir: str) -> CheckResult:
    from parser.advanced_checks import cache_assessment, number
    content = read_file(f"{db_dir}/buffer_cache_hit.txt")
    rows = _data_rows(content, ("NAME",))
    try:
        if not rows or "ORA-" in content or "SP2-" in content:
            raise ValueError("未获取有效缓冲池计数")
        physical = logical = Decimal(0)
        for row in rows:
            if len(row) < 5:
                raise ValueError("缓冲池计数列不完整")
            physical += number(row[1])
            logical += number(row[2]) + number(row[3])
        status, hit_ratio, meaning = cache_assessment(physical, logical)
    except ValueError as exc:
        return CheckResult("缓冲区命中率", "UNKNOWN", "无法可靠计算", str(exc))
    shown = f"{hit_ratio:.1f}%" if hit_ratio is not None else "N/A"
    table = generate_data_table(["缓冲池", "物理读", "DB Block Gets", "一致性读", "命中率(%)"],
        [[row[0]] + [_format_plain_number(v) for v in row[1:5]] for row in rows])
    chart = generate_health_percentage("Buffer Cache Hit Ratio", hit_ratio, DB_THRESHOLDS["buffer_hit_ratio_warn"], -1) if hit_ratio is not None else ""
    if status == "OK":
        chart = chart.replace("bar-fill-warn", "bar-fill-ok")
    return CheckResult("缓冲区命中率", status, shown,
        "Buffer Cache Hit Ratio: " + shown + "；本地缓冲池累计统计，与 AWR 区间统计的时间范围不同；" + meaning,
        meaning if status in ("WARN", "UNKNOWN") else "", extra_html=chart + table)


def _parse_library_cache_hit(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/library_cache_hit.txt")
    hit_ratio = None
    selected_row = None

    if content:
        rows = _parse_pipe_table(content)
        for row in rows:
            if any(h in row[0].upper() for h in ["PINS"]):
                continue
            if len(row) >= 3:
                try:
                    hit_ratio = float(row[2])
                    selected_row = row[:3]
                except (ValueError, IndexError):
                    pass
                break

    if hit_ratio is None:
        return CheckResult("共享池命中率", "CRIT", "数据缺失", "无法计算 Library Cache Hit Ratio")
    status = check_threshold_inverse(hit_ratio, DB_THRESHOLDS["library_hit_ratio_warn"],
                                     DB_THRESHOLDS["library_hit_ratio_crit"])
    suggestion = ""
    if status in ("CRIT", "WARN"):
        suggestion = f"共享池命中率 {hit_ratio:.1f}% 偏低，建议增大 SHARED_POOL_SIZE"

    chart = generate_health_percentage(
        "Library Cache Hit Ratio",
        hit_ratio,
        DB_THRESHOLDS["library_hit_ratio_warn"],
        DB_THRESHOLDS["library_hit_ratio_crit"],
    )
    table = generate_data_table(
        ["Pins", "Reloads", "命中率(%)"],
        [selected_row],
    ) if selected_row else ""
    return CheckResult("共享池命中率", status, f"{hit_ratio:.1f}%",
                       f"Library Cache Hit Ratio: {hit_ratio:.1f}%", suggestion,
                       extra_html=chart + table)


def _parse_sga_info(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/sga_info.txt")
    extra = ""
    if content:
        rows = _parse_pipe_table(content)
        data_rows = [r for r in rows if r and not any(h in r[0].upper() for h in ["NAME"])]
        if data_rows:
            table_rows = [(r[0], r[1] if len(r) > 1 else "N/A") for r in data_rows]
            extra = generate_data_table(["SGA组件", "大小(MB)"], table_rows)

    return CheckResult("SGA信息", "OK", "已检查",
                       f"SGA各组件分配: {'已记录' if content else '数据缺失'}",
                       extra_html=extra)


def _parse_wait_events(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/wait_events.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["EVENT", "event"])]

    extra = ""
    if data_rows:
        table_rows = []
        for r in data_rows[:10]:
            table_rows.append((
                r[0] if len(r) > 0 else "",
                r[1] if len(r) > 1 else "",
                r[2] if len(r) > 2 else "",
                r[3] if len(r) > 3 else "",
                r[5] if len(r) > 5 else ""
            ))
        extra = generate_data_table(
            ["事件", "等待类别", "总等待次数", "等待时间", "占比(%)"],
            table_rows
        )

    return CheckResult("等待事件", "OK", f"{len(data_rows)}个事件",
                       f"Top等待事件数: {len(data_rows)}",
                       extra_html=extra)


def _parse_top_disk_read_sql(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/top_disk_read_sql.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["SQL_ID", "sql_id"])]
    extra = generate_data_table(
        ["SQL_ID", "物理读", "执行次数", "每次读", "逻辑读", "Schema", "SQL文本"],
        [row[:7] for row in data_rows[:20]],
    ) if data_rows else ""

    return CheckResult("Disk Read最高SQL", "OK", f"{len(data_rows)}条",
                       f"按物理读排序的共享池 Top SQL: {len(data_rows)}条",
                       extra_html=extra)


def _parse_long_running_sql(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/long_running_sql.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["SID", "sid"])]

    status = "WARN" if len(data_rows) > 5 else "OK"
    return CheckResult("运行很久的SQL", status, f"{len(data_rows)}个",
                       f"当前长时间运行SQL: {len(data_rows)}个")


def _parse_table_fragmentation(db_dir: str) -> CheckResult:
    """解析表碎片，考虑 PCTFREE 因素计算实际碎片率"""
    content = read_file(f"{db_dir}/table_fragmentation.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["OWNER", "owner"])]

    frag_tables = []  # 实际碎片率较高的表
    for r in data_rows:
        if len(r) < 6:
            continue
        owner = r[0]
        table_name = r[1]
        try:
            size_mb = float(r[2])
        except ValueError:
            size_mb = 0
        try:
            actual_mb = float(r[3])
        except ValueError:
            actual_mb = 0
        try:
            wasted_mb = float(r[4])
        except ValueError:
            wasted_mb = 0
        try:
            raw_frag_pct = float(r[5])
        except ValueError:
            raw_frag_pct = 0
        # pct_free 列（新增）
        try:
            pct_free = float(r[6]) if len(r) > 6 else 10
        except ValueError:
            pct_free = 10

        # 实际碎片率 = 原始碎片率 - PCTFREE - 块头开销(约3-5%)
        # 只有实际碎片率 > 0 才算真正有碎片
        block_overhead_pct = 5  # 块头+行目录开销约3-5%
        real_frag_pct = max(raw_frag_pct - pct_free - block_overhead_pct, 0)

        if real_frag_pct > 20:  # 实际碎片率超过20%才记录
            frag_tables.append((owner, table_name, size_mb, actual_mb, wasted_mb,
                                raw_frag_pct, pct_free, real_frag_pct))

    count = len(frag_tables)
    status = "OK"
    suggestion = ""
    if count >= DB_THRESHOLDS["frag_table_count_crit"]:
        status = "CRIT"
        suggestion = f"存在 {count} 个高碎片表，建议进行表重建或收缩"
    elif count >= DB_THRESHOLDS["frag_table_count_warn"]:
        status = "WARN"
        suggestion = f"存在 {count} 个高碎片表，建议关注"

    extra = ""
    if frag_tables:
        table_rows = []
        for owner, tname, sz, actual, wasted, raw_pct, pf, real_pct in frag_tables[:15]:
            table_rows.append((
                f"{owner}.{tname}",
                f"{sz:.1f}",
                f"{actual:.1f}",
                f"{wasted:.1f}",
                f"{raw_pct:.1f}",
                f"{pf:.0f}",
                f"{real_pct:.1f}"
            ))
        extra = generate_data_table(
            ["表名", "大小(MB)", "实际(MB)", "浪费(MB)", "原始碎片率%", "PCT_FREE", "实际碎片率%"],
            table_rows
        )

    return CheckResult("表碎片", status, f"{count}个高碎片表",
                       f"实际碎片率>20%的表: {count}个", suggestion,
                       extra_html=extra)


def _parse_dead_processes(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/dead_processes.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["SID", "sid"])]

    count = len(data_rows)
    status = "OK"
    suggestion = ""
    if count >= DB_THRESHOLDS["dead_session_count_crit"]:
        status = "CRIT"
        suggestion = f"存在 {count} 个长时间不活动会话，请检查应用连接管理"
    elif count >= DB_THRESHOLDS["dead_session_count_warn"]:
        status = "WARN"
        suggestion = f"存在 {count} 个长时间不活动会话，建议关注"

    table_rows = []
    for row in data_rows[:30]:
        table_rows.append(tuple(
            row[index] if len(row) > index else ""
            for index in (0, 1, 2, 4, 5, 6, 7, 8)
        ))
    extra = generate_data_table(
        ["SID", "Serial#", "用户", "空闲(小时)", "程序", "客户端主机", "OS用户", "SQL_ID"],
        table_rows,
    ) if table_rows else ""
    if count > 30:
        extra = '<div class="detail-note">按空闲时长降序，仅展示前 30 条。</div>' + extra

    return CheckResult("长时间不活动会话", status, f"{count}个",
                       f"INACTIVE 且不活动超过24小时的会话: {count}个", suggestion,
                       extra_html=extra)


def _parse_system_tablespace(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/system_tablespace.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["OWNER", "owner"])]

    count = len(data_rows)
    status = "WARN" if count > 0 else "OK"
    suggestion = ""
    if count > 0:
        suggestion = f"SYSTEM表空间中存在 {count} 个非SYS/SYSTEM对象，建议迁移到其他表空间"

    # 生成详情表格
    extra = ""
    if data_rows:
        table_rows = []
        for r in data_rows[:30]:
            owner = r[0] if len(r) > 0 else ""
            seg_name = r[1] if len(r) > 1 else ""
            seg_type = r[2] if len(r) > 2 else ""
            size_mb = r[3] if len(r) > 3 else ""
            table_rows.append((owner, seg_name, seg_type, size_mb))
        extra = generate_data_table(
            ["所有者", "段名", "类型", "大小(MB)"],
            table_rows
        )

    return CheckResult("SYSTEM表空间业务对象", status, f"{count}个",
                       f"SYSTEM表空间中非 Oracle 自维护对象: {count}个", suggestion,
                       extra_html=extra)


def _parse_invalid_objects(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/invalid_objects.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and not any(h in r[0] for h in ["OWNER", "owner"])]

    count = len(data_rows)
    status = "WARN" if count > 0 else "OK"
    suggestion = ""
    if count > 0:
        suggestion = f"存在 {count} 个无效对象，建议执行 utlrp.sql 重新编译"

    extra = ""
    if data_rows:
        table_rows = []
        for r in data_rows[:30]:
            owner = r[0] if len(r) > 0 else ""
            obj_name = r[1] if len(r) > 1 else ""
            obj_type = r[2] if len(r) > 2 else ""
            obj_status = r[3] if len(r) > 3 else ""
            created = r[4] if len(r) > 4 else ""
            last_ddl = r[5] if len(r) > 5 else ""
            table_rows.append((f"{owner}.{obj_name}", obj_type, obj_status, created, last_ddl))
        extra = generate_data_table(
            ["对象名", "类型", "状态", "创建时间", "最后DDL时间"],
            table_rows
        )

    return CheckResult("无效对象", status, f"{count}个",
                       f"INVALID状态对象: {count}个", suggestion,
                       extra_html=extra)


def _parse_invalid_indexes(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/invalid_indexes.txt")
    content2 = read_file(f"{db_dir}/invalid_index_partitions.txt")
    rows = _parse_pipe_table(content)
    rows2 = _parse_pipe_table(content2)

    data_rows = [r for r in rows if r and "INDEX" not in r[0].upper()[:5]]
    data_rows2 = [r for r in rows2 if r and "INDEX" not in r[0].upper()[:5]]
    total = len(data_rows) + len(data_rows2)

    status = "WARN" if total > 0 else "OK"
    suggestion = ""
    if total > 0:
        suggestion = f"存在 {total} 个失效索引，建议重建"

    extra = ""
    if data_rows:
        table_rows = []
        for r in data_rows[:20]:
            owner = r[0] if len(r) > 0 else ""
            idx_name = r[1] if len(r) > 1 else ""
            tbl_name = r[2] if len(r) > 2 else ""
            idx_status = r[3] if len(r) > 3 else ""
            partitioned = r[4] if len(r) > 4 else ""
            table_rows.append((f"{owner}.{idx_name}", tbl_name, idx_status, partitioned))
        extra = generate_data_table(
            ["索引名", "所属表", "状态", "分区"],
            table_rows
        )
    if data_rows2:
        table_rows2 = []
        for r in data_rows2[:20]:
            idx_owner = r[0] if len(r) > 0 else ""
            idx_name = r[1] if len(r) > 1 else ""
            part_name = r[2] if len(r) > 2 else ""
            part_status = r[3] if len(r) > 3 else ""
            table_rows2.append((f"{idx_owner}.{idx_name}", part_name, part_status))
        extra += '<div style="margin-top:8px;font-size:12px;font-weight:600;color:#475569;">失效索引分区</div>'
        extra += generate_data_table(
            ["索引名", "分区名", "状态"],
            table_rows2
        )

    return CheckResult("失效索引", status, f"{total}个",
                       f"UNUSABLE状态索引: {total}个", suggestion,
                       extra_html=extra)


def _parse_invalid_triggers(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/invalid_triggers.txt")
    rows = _parse_pipe_table(content)
    data_rows = [r for r in rows if r and "TRIGGER" not in r[0].upper()[:7]]

    count = len(data_rows)
    status = "WARN" if count > 0 else "OK"
    suggestion = ""
    if count > 0:
        suggestion = f"存在 {count} 个禁用触发器，请确认是否为预期行为"

    extra = ""
    if data_rows:
        table_rows = []
        for r in data_rows[:20]:
            owner = r[0] if len(r) > 0 else ""
            trig_name = r[1] if len(r) > 1 else ""
            tbl_name = r[2] if len(r) > 2 else ""
            trig_status = r[3] if len(r) > 3 else ""
            trig_type = r[4] if len(r) > 4 else ""
            table_rows.append((f"{owner}.{trig_name}", tbl_name, trig_status, trig_type))
        extra = generate_data_table(
            ["触发器名", "所属表", "状态", "类型"],
            table_rows
        )

    return CheckResult("无效Trigger", status, f"{count}个",
                       f"DISABLED状态触发器: {count}个", suggestion,
                       extra_html=extra)


def _parse_failed_jobs(db_dir: str) -> CheckResult:
    content = read_file(f"{db_dir}/failed_jobs.txt")
    content2 = read_file(f"{db_dir}/dbms_jobs.txt")
    rows = _parse_pipe_table(content)
    rows2 = _parse_pipe_table(content2)

    count = len([r for r in rows if r and "JOB" not in r[0].upper()[:3]])
    count2 = len([r for r in rows2 if r and "JOB" not in r[0].upper()[:3]])
    total = count + count2

    status = "WARN" if total > 0 else "OK"
    suggestion = ""
    if total > 0:
        suggestion = f"存在 {total} 个失败Job，请检查并修复"

    return CheckResult("失败的Job", status, f"{total}个",
                       f"最近7天失败Job: {total}个", suggestion)


def _parse_alert_log(db_dir: str) -> CheckResult:
    # Import lazily: parser.__init__ also imports db_parser.
    from alert_analyzer import build_alert_check
    return build_alert_check(db_dir)


def _parse_trace_files(db_dir: str) -> CheckResult:
    recent = read_lines(f"{db_dir}/trace_recent.txt")
    large = read_lines(f"{db_dir}/trace_large.txt")

    large_count = len(large)
    status = "WARN" if large_count > 0 else "OK"
    suggestion = ""
    if large_count > 0:
        suggestion = f"近7天存在 {large_count} 个大于100MB的trace文件，建议核查产生原因并按留存策略清理"

    return CheckResult("跟踪文件", status, f"{len(recent)}个近期文件",
                       f"近24h trace: {len(recent)}个, 近7天>100MB: {large_count}个", suggestion)
