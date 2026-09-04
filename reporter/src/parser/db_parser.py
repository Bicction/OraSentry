# -*- coding: utf-8 -*-
"""
数据库巡检数据解析器
解析 Shell 采集的数据库原始数据，进行阈值判定
"""
import re
from collections import Counter
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
    rac_results = _parse_rac_info(db_dir)

    # CDB: 有实际PDB数据时才返回（排除"非CDB"和"CDB但无PDB"的情况）
    has_cdb = any(r.name == "CDB/PDB" and "非CDB" not in r.value for r in cdb_results)
    # RAC: 有多节点时才返回（排除"非RAC"和"单节点"的情况）
    has_rac = any(r.name == "RAC集群" and "非RAC" not in r.value and "单节点" not in r.value for r in rac_results)

    return {
        "db": db_results,
        "cdb": cdb_results if has_cdb else [],
        "rac": rac_results if has_rac else [],
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
            risks.append("未启用 Flashback Database")
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

    dg_rows = _data_rows(read_file(f"{db_dir}/dataguard_dest_status.txt"), ("DEST_ID",))
    gap_rows = _data_rows(read_file(f"{db_dir}/archive_gap.txt"), ("THREAD#",))
    dg_errors = [r for r in dg_rows if any("ORA-" in x.upper() for x in r)]
    dg_status = "CRIT" if gap_rows else ("WARN" if dg_errors else "OK")
    dg_extra = generate_data_table(["DEST", "状态", "类型", "数据库模式", "恢复模式", "目标", "错误", "线程", "序列"], dg_rows) if dg_rows else ""
    if gap_rows:
        dg_extra += generate_data_table(["线程", "缺口起始", "缺口结束"], gap_rows)
    results.append(CheckResult("Data Guard/归档传输", dg_status, f"{len(gap_rows)}个归档缺口",
                               f"启用归档目标: {len(dg_rows)}，传输错误: {len(dg_errors)}，归档缺口: {len(gap_rows)}",
                               "请检查归档传输、应用进程与网络状态" if dg_status != "OK" else "",
                               extra_html=dg_extra))
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
    closed_count = 0
    total_size_gb = 0.0

    for r in pdb_data:
        pdb_name = r[0] if len(r) > 0 else ""
        pdb_id = r[1] if len(r) > 1 else ""
        status = r[2] if len(r) > 2 else ""
        open_mode = r[3] if len(r) > 3 else ""
        restricted = r[4] if len(r) > 4 else ""
        open_time = r[5] if len(r) > 5 else ""
        try:
            size_gb = float(r[6]) if len(r) > 6 else 0.0
        except ValueError:
            size_gb = 0.0

        total_size_gb += size_gb
        om_upper = open_mode.upper()
        # PDB$SEED 是种子容器，正常状态为 READ ONLY
        is_seed = pdb_name.upper() == "PDB$SEED"
        if is_seed:
            # 种子容器 READ ONLY 为正常，其他状态为异常
            if om_upper != "READ ONLY" and om_upper != "MOUNTED":
                closed_count += 1
        else:
            # 普通 PDB 正常状态为 READ WRITE，MOUNTED 可接受
            if om_upper != "READ WRITE" and om_upper != "MOUNTED":
                closed_count += 1

        pdb_info.append((pdb_name, pdb_id, status, open_mode, restricted,
                         open_time, size_gb))

    # PDB 概览
    status = "OK"
    suggestion = ""
    if closed_count > 0:
        status = "WARN"
        suggestion = f"存在 {closed_count} 个 PDB 未正常打开"

    table_rows = []
    for name, pdb_id, st, om, restricted, ot, sz in pdb_info:
        table_rows.append((name, pdb_id, st, om, restricted, f"{sz:.2f}", ot))

    extra = generate_data_table(
        ["PDB名称", "PDB_ID", "状态", "打开模式", "受限", "大小(GB)", "打开时间"],
        table_rows
    )

    results.append(CheckResult(
        "CDB/PDB", status, f"{len(pdb_info)}个PDB/{total_size_gb:.2f}GB",
        f"CDB架构，共 {len(pdb_info)} 个PDB，总大小 {total_size_gb:.2f}GB" +
        (f"，{closed_count}个未打开" if closed_count > 0 else ""),
        suggestion,
        extra_html=extra
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
            for fname, ts, total, used, maxsz, auto, st in files[:10]:
                df_table_rows.append((pdb_display, fname, ts, f"{total:.0f}", f"{used:.0f}", f"{maxsz:.0f}", auto, st))
            if len(files) > 10:
                df_table_rows.append((pdb_display, f"...({len(files)-10}个更多)", "", "", "", "", "", ""))

        results.append(CheckResult(
            "PDB数据文件", "OK", f"{len(df_data)}个",
            f"共 {len(df_data)} 个PDB数据文件",
            extra_html=generate_data_table(
                ["PDB", "文件名", "表空间", "总大小(MB)", "已用(MB)", "最大(MB)", "自动扩展", "在线状态"],
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
    """解析 AWR 关键指标"""
    results = []

    snap_content = read_file(f"{db_dir}/awr_snapshot.txt")
    if snap_content.startswith("SKIPPED|"):
        reason = snap_content.split("|", 1)[1].strip()
        results.append(CheckResult(
            "AWR分析", "INFO", "未启用", reason,
            "如需 AWR 指标，请确认 Oracle 授权范围后设置 CHECK_AWR=on",
        ))
        return results
    if not snap_content or "ORA-" in snap_content.upper():
        results.append(CheckResult("AWR分析", "WARN", "不可用",
                                   "AWR未启用或无快照数据，请检查 AWR 设置"))
        return results

    snap_rows = _parse_pipe_table(snap_content)
    snap_data = [r for r in snap_rows if r and not any(h in r[0].upper() for h in ["SNAP_ID"])]
    if not snap_data:
        results.append(CheckResult("AWR分析", "WARN", "不可用", "无AWR快照数据"))
        return results

    latest_snap_id = snap_data[0][0]

    sysstat_content = read_file(f"{db_dir}/awr_sysstat.txt")
    sysstat_rows = _parse_pipe_table(sysstat_content)
    sysstat_data = [r for r in sysstat_rows if r and not any(h in r[0].upper() for h in ["SNAP_ID"])]

    stats = {}
    for r in sysstat_data:
        if len(r) >= 4:
            snap_id = r[0]
            stat_name = r[2]
            try:
                value = float(r[3])
            except ValueError:
                value = 0
            if snap_id not in stats:
                stats[snap_id] = {}
            stats[snap_id][stat_name] = value

    if len(stats) < 2:
        results.append(CheckResult("AWR分析", "WARN", "数据不足",
                                   "AWR快照数据不足，无法计算差值"))
        return results

    snap_ids = sorted(stats.keys())
    latest_snap = snap_ids[-1]
    prev_snap = snap_ids[-2]

    def get_diff(stat_name):
        curr = stats[latest_snap].get(stat_name, 0)
        prev = stats[prev_snap].get(stat_name, 0)
        return max(curr - prev, 0)

    cpu_used = get_diff("CPU used by this session")
    db_block_gets = get_diff("db block gets")
    cons_gets = get_diff("consistent gets")
    phys_reads = get_diff("physical reads")
    phys_writes = get_diff("physical writes")
    redo_size = get_diff("redo size")
    user_commits = get_diff("user commits")
    user_rollbacks = get_diff("user rollbacks")
    parse_count = get_diff("parse count (total)")
    execute_count = get_diff("execute count")

    total_gets = db_block_gets + cons_gets
    buffer_cache_hit = (1 - phys_reads / total_gets) * 100 if total_gets > 0 else 0
    parse_ratio = (parse_count / execute_count) * 100 if execute_count > 0 else 0

    metrics = []
    metrics.append(("缓冲区命中率", f"{buffer_cache_hit:.1f}%",
                   "OK" if buffer_cache_hit >= 90 else "WARN" if buffer_cache_hit >= 80 else "CRIT"))
    metrics.append(("解析比例", f"{parse_ratio:.1f}%",
                   "OK" if parse_ratio <= 10 else "WARN" if parse_ratio <= 20 else "CRIT"))
    metrics.append(("CPU使用(秒)", f"{cpu_used/100:.1f}", "OK"))
    metrics.append(("物理读(次)", f"{phys_reads:,}", "OK"))
    metrics.append(("物理写(次)", f"{phys_writes:,}", "OK"))
    metrics.append(("Redo大小(KB)", f"{redo_size/1024:.0f}", "OK"))
    metrics.append(("提交次数", f"{user_commits:,}", "OK"))
    metrics.append(("回滚次数", f"{user_rollbacks:,}",
                   "OK" if user_rollbacks <= user_commits * 0.1 else "WARN"))

    table_rows = [(name, value, status) for name, value, status in metrics]
    metrics_table = generate_data_table(["指标", "值", "状态"], table_rows)

    worst_status = "OK"
    for _, _, status in metrics:
        if status == "CRIT":
            worst_status = "CRIT"
            break
        elif status == "WARN":
            worst_status = "WARN"

    results.append(CheckResult(
        "AWR关键指标", worst_status, f"快照#{latest_snap}",
        f"AWR 快照 #{latest_snap} vs #{prev_snap} 的增量指标",
        "解析/执行比例或缓冲区命中率异常；请结合 Top SQL 检查硬解析、游标复用与绑定变量使用" if worst_status != "OK" else "",
        extra_html=metrics_table
    ))

    top_events_content = read_file(f"{db_dir}/awr_top_events.txt")
    top_events_rows = _parse_pipe_table(top_events_content)
    top_events_data = [r for r in top_events_rows if r and not any(h in r[0].upper() for h in ["SNAP_ID"])]

    if top_events_data:
        event_table_rows = []
        for r in top_events_data[:10]:
            snap_id = r[0] if len(r) > 0 else ""
            event = r[1] if len(r) > 1 else ""
            wait_class = r[2] if len(r) > 2 else ""
            try:
                total_waits = int(r[3]) if len(r) > 3 else 0
            except ValueError:
                total_waits = 0
            try:
                time_waited = float(r[4]) / 1000000 if len(r) > 4 else 0
            except ValueError:
                time_waited = 0
            try:
                avg_wait = float(r[5]) / 1000 if len(r) > 5 else 0
            except ValueError:
                avg_wait = 0
            event_table_rows.append((snap_id, event, wait_class, f"{total_waits:,}",
                                     f"{time_waited:.2f}s", f"{avg_wait:.2f}ms"))

        results.append(CheckResult(
            "AWR等待事件", "OK", "已检查",
            f"AWR 顶级等待事件（排除Idle）",
            extra_html=generate_data_table(
                ["快照", "事件", "等待类别", "总等待", "等待时间", "平均等待"],
                event_table_rows
            )
        ))

    seg_stats_content = read_file(f"{db_dir}/awr_seg_stats.txt")
    seg_stats_rows = _parse_pipe_table(seg_stats_content)
    seg_stats_data = [r for r in seg_stats_rows if r and not any(h in r[0].upper() for h in ["SNAP_ID"])]

    if seg_stats_data:
        seg_table_rows = []
        for r in seg_stats_data[:10]:
            snap_id = r[0] if len(r) > 0 else ""
            owner = r[1] if len(r) > 1 else ""
            obj_name = r[2] if len(r) > 2 else ""
            ts = r[3] if len(r) > 3 else ""
            try:
                phys_reads = int(r[4]) if len(r) > 4 else 0
            except ValueError:
                phys_reads = 0
            try:
                phys_writes = int(r[5]) if len(r) > 5 else 0
            except ValueError:
                phys_writes = 0
            try:
                log_reads = int(r[6]) if len(r) > 6 else 0
            except ValueError:
                log_reads = 0
            try:
                lock_waits = int(r[7]) if len(r) > 7 else 0
            except ValueError:
                lock_waits = 0
            seg_table_rows.append((snap_id, f"{owner}.{obj_name}", ts,
                                    f"{phys_reads:,}", f"{phys_writes:,}",
                                    f"{log_reads:,}", f"{lock_waits:,}"))

        results.append(CheckResult(
            "AWR热点段", "OK", "已检查",
            f"AWR 热点段（IO最多的段）",
            extra_html=generate_data_table(
                ["快照", "段名", "表空间", "物理读", "物理写", "逻辑读", "行锁等待"],
                seg_table_rows
            )
        ))

    sqlstat_content = read_file(f"{db_dir}/awr_sqlstat.txt")
    sqlstat_rows = _parse_pipe_table(sqlstat_content)
    sqlstat_data = [r for r in sqlstat_rows if r and not any(h in r[0].upper() for h in ["SNAP_ID"])]

    if sqlstat_data:
        sql_table_rows = []
        for r in sqlstat_data[:10]:
            snap_id = r[0] if len(r) > 0 else ""
            sql_id = r[1] if len(r) > 1 else ""
            execs = int(r[3]) if len(r) > 3 else 0
            elapsed = float(r[4]) / 1000000 if len(r) > 4 else 0
            cpu = float(r[5]) / 1000000 if len(r) > 5 else 0
            buffers = int(r[6]) if len(r) > 6 else 0
            disk_reads = int(r[7]) if len(r) > 7 else 0
            rows = int(r[8]) if len(r) > 8 else 0
            avg_elapsed = elapsed / execs if execs > 0 else 0
            sql_table_rows.append((snap_id, sql_id, f"{execs:,}", f"{elapsed:.2f}s",
                                   f"{cpu:.2f}s", f"{avg_elapsed*1000:.1f}ms",
                                   f"{buffers:,}", f"{disk_reads:,}", f"{rows:,}"))

        results.append(CheckResult(
            "AWR耗时SQL", "OK", "已检查",
            f"AWR 最耗时 SQL（按执行时间排序）",
            extra_html=generate_data_table(
                ["快照", "SQL ID", "执行次数", "总耗时", "CPU耗时", "平均耗时",
                 "逻辑读", "物理读", "处理行数"],
                sql_table_rows
            )
        ))

    return results


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
        # 展示顺序统一按最大使用率从高到低，便于第一眼识别容量风险。
        ts_data.sort(key=lambda ts: (-ts["max_pct"], ts["name"]))

        def effective_usage(ts) -> float:
            """自动扩展文件按最大容量衡量，否则按当前已分配容量衡量。"""
            return ts["max_pct"] if ts["auto"].upper() == "YES" else ts["alloc_pct"]

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

        # 柱状图
        bar_items = [(ts["name"], effective_usage(ts), "%") for ts in ts_data]
        bar_html = generate_bar_chart(bar_items,
                                      warn_threshold=DB_THRESHOLDS["tablespace_usage_warn"],
                                      crit_threshold=DB_THRESHOLDS["tablespace_usage_crit"])

        # 数据表格
        table_rows = [(ts["name"], ts["contents"], f"{ts['alloc']:.2f}", f"{ts['used']:.2f}", f"{ts['free']:.2f}",
                       f"{ts['alloc_pct']:.2f}%", f"{ts['max']:.2f}", f"{ts['max_pct']:.2f}%", ts["auto"], ts["status"])
                      for ts in ts_data]
        table_html = generate_data_table(
            ["表空间", "类型", "已分配(GB)", "已用(GB)", "当前空闲(GB)", "分配使用率", "最大(GB)", "最大使用率", "自动扩展", "状态"],
            table_rows
        )

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
            extra_html=bar_html + table_html
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
    content = read_file(f"{db_dir}/buffer_cache_hit.txt")
    hit_ratio = None
    data_rows = []

    if content:
        data_rows = _data_rows(content, ("NAME",))
        physical_reads = 0.0
        block_gets = 0.0
        consistent_gets = 0.0
        fallback_ratios = []
        for row in data_rows:
            if len(row) >= 5:
                try:
                    physical_reads += float(row[1])
                    block_gets += float(row[2])
                    consistent_gets += float(row[3])
                    fallback_ratios.append(float(row[4]))
                except ValueError:
                    pass
        logical_reads = block_gets + consistent_gets
        if logical_reads > 0:
            hit_ratio = max(0.0, min(100.0, (1 - physical_reads / logical_reads) * 100))
        elif fallback_ratios:
            hit_ratio = fallback_ratios[0]

    if hit_ratio is None:
        return CheckResult("缓冲区命中率", "CRIT", "数据缺失", "无法计算 Buffer Cache Hit Ratio")
    status = check_threshold_inverse(hit_ratio, DB_THRESHOLDS["buffer_hit_ratio_warn"],
                                     DB_THRESHOLDS["buffer_hit_ratio_crit"])
    suggestion = ""
    if status == "CRIT":
        suggestion = f"缓冲区命中率仅 {hit_ratio:.1f}%，建议增大 DB_CACHE_SIZE"
    elif status == "WARN":
        suggestion = f"缓冲区命中率 {hit_ratio:.1f}% 偏低，建议关注"

    chart = generate_health_percentage(
        "Buffer Cache Hit Ratio",
        hit_ratio,
        DB_THRESHOLDS["buffer_hit_ratio_warn"],
        DB_THRESHOLDS["buffer_hit_ratio_crit"],
    )
    display_rows = []
    for row in data_rows:
        formatted = list(row[:5])
        for index in (1, 2, 3, 4):
            if len(formatted) > index:
                formatted[index] = _format_plain_number(formatted[index])
        display_rows.append(formatted)
    table = generate_data_table(
        ["缓冲池", "物理读", "DB Block Gets", "一致性读", "命中率(%)"],
        display_rows,
    ) if data_rows else ""
    return CheckResult("缓冲区命中率", status, f"{hit_ratio:.1f}%",
                       f"Buffer Cache Hit Ratio: {hit_ratio:.1f}%", suggestion,
                       extra_html=chart + table)


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
    def _as_int(value, default):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return default

    summary_rows = _data_rows(
        read_file(f"{db_dir}/alert_log_summary.txt"), ("DATABASE_NAME",)
    )
    summary = summary_rows[0] if summary_rows and len(summary_rows[0]) >= 8 else []
    physical_log_summary = len(summary) >= 9
    window_days = _as_int(summary[8], 30) if physical_log_summary else 7
    analyzed_line_limit = _as_int(summary[9], 0) if len(summary) >= 10 else 0
    analyzed_line_count = _as_int(summary[10], 0) if len(summary) >= 11 else 0
    window_truncated = summary[11].upper() == "YES" if len(summary) >= 12 else False
    alert_file_size_bytes = _as_int(summary[12], 0) if len(summary) >= 13 else 0
    alert_file_size_display = summary[13] if len(summary) >= 14 else ""
    analysis_start_time = _format_alert_time(summary[14]) if len(summary) >= 15 else ""
    analysis_end_time = _format_alert_time(summary[15]) if len(summary) >= 16 else ""
    database_name = summary[0] if summary else ""
    instance_name = summary[1] if summary else ""
    host_name = summary[2] if summary else ""
    alert_file = summary[3] if summary else ""

    recent_all = _data_rows(
        read_file(f"{db_dir}/alert_log_recent.txt"), ("EVENT_TIME", "DATABASE_NAME")
    )
    recent = []
    for r in recent_all:
        # 物理日志格式为“时间|消息”；同时兼容旧版 SQL 五列和过渡版九列格式。
        if len(r) == 2:
            recent.append([_format_alert_time(r[0]), r[1]])
            continue
        level_index = 6 if len(r) >= 9 else 2
        joined = " ".join(r).upper()
        try:
            level = int(r[level_index]) if len(r) > level_index and r[level_index] else 99
        except ValueError:
            level = 99
        if level <= 8 or "ORA-" in joined or "CORRUPT" in joined:
            recent.append(r)
    errors = recent if recent else [[line] for line in read_lines(f"{db_dir}/alert_log_errors.txt")]
    severe = [r for r in errors if any(code in " ".join(r).upper() for code in ("ORA-00600", "ORA-00700", "ORA-07445", "ORA-01578", "CORRUPT"))]

    error_count = _as_int(summary[4], len(errors)) if summary else len(errors)
    severe_count = _as_int(summary[5], len(severe)) if summary else len(severe)
    truncated_legacy = not summary and len(recent) >= 200

    if not alert_file:
        path_info = {}
        for line in read_lines(f"{db_dir}/alert_log_path.txt"):
            key, separator, value = line.partition("=")
            if separator:
                path_info[key.strip()] = value.strip()
        alert_file = path_info.get("alert_log_path", "")
        if alert_file == "NOT_FOUND":
            alert_file = path_info.get("expected_alert_file", "NOT_FOUND")
        analysis_start_time = analysis_start_time or _format_alert_time(
            path_info.get("analysis_start_time", "")
        )
        analysis_end_time = analysis_end_time or _format_alert_time(
            path_info.get("analysis_end_time", "")
        )

    # 兼容旧采集包：没有独立分析范围时，使用告警明细的首末时间。
    if not analysis_start_time and recent:
        analysis_start_time = _format_alert_time(recent[0][0])
    if not analysis_end_time and recent:
        analysis_end_time = _format_alert_time(recent[-1][0])
    if not analysis_start_time and len(summary) >= 7:
        analysis_start_time = _format_alert_time(summary[6])
    if not analysis_end_time and len(summary) >= 8:
        analysis_end_time = _format_alert_time(summary[7])

    status = "OK"
    suggestion = ""
    if severe_count or error_count >= DB_THRESHOLDS["alert_error_count_crit"]:
        status = "CRIT"
        if any("PGA PHYSMEM LIMIT" in " ".join(r).upper() for r in severe):
            suggestion = "反复出现 ORA-00700 [pga physmem limit]；请按物理内存重新评估 PGA_AGGREGATE_TARGET/LIMIT 与 SGA/AMM 配置，并检查相关 incident trace"
        else:
            suggestion = f"Alert Log 中存在 {error_count} 条错误，请立即排查"
    elif error_count >= DB_THRESHOLDS["alert_error_count_warn"]:
        status = "WARN"
        suggestion = f"Alert Log 中存在 {error_count} 条错误，建议排查"
    if alert_file_size_bytes > 2 * 1024 * 1024 * 1024:
        if status == "OK":
            status = "WARN"
        cleanup_suggestion = f"Alert Log 已达到 {alert_file_size_display or str(alert_file_size_bytes) + ' bytes'}，超过2GB，请及时归档并清理"
        suggestion = f"{suggestion}；{cleanup_suggestion}" if suggestion else cleanup_suggestion

    extra_parts = []
    location_rows = []
    if database_name:
        location_rows.append(("数据库", database_name))
    if instance_name:
        location_rows.append(("实例", instance_name))
    if host_name:
        location_rows.append(("主机", host_name))
    if alert_file:
        location_rows.append(("Alert Log 来源", alert_file))
    if alert_file_size_display:
        location_rows.append(("物理日志大小", alert_file_size_display))
    if analysis_start_time or analysis_end_time:
        location_rows.append((
            "分析时间范围",
            f"{analysis_start_time or 'N/A'} 至 {analysis_end_time or 'N/A'}",
        ))
    if window_truncated:
        location_rows.append((
            "分析完整性",
            "30天时间窗口数据量超过采集上限，仅分析最近可用时间范围",
        ))
    if location_rows:
        extra_parts.append(generate_data_table(["定位信息", "值"], location_rows))

    group_rows = _data_rows(
        read_file(f"{db_dir}/alert_log_groups.txt"), ("ALERT_KEY",)
    )
    if group_rows:
        formatted_groups = []
        for row in group_rows[:20]:
            values = list(row[:5])
            for index in (2, 3):
                if len(values) > index:
                    values[index] = _format_alert_time(values[index])
            formatted_groups.append(values)
        extra_parts.append(generate_data_table(
            ["告警类型", "次数", "首次发生", "最后发生", "示例消息"],
            formatted_groups,
        ))
    elif recent:
        message_index = 8 if len(recent[0]) >= 9 else (4 if len(recent[0]) >= 5 else 1)
        messages = [r[message_index] if len(r) > message_index else " ".join(r) for r in recent]

        def alert_key(message):
            upper = message.upper()
            code = re.search(r"(?:ORA|TNS|RMAN)-\d{4,5}", upper)
            if code:
                return code.group(0)
            for keyword in ("FATAL", "CRITICAL", "CORRUPT", "ERROR"):
                if keyword in upper:
                    return keyword
            return "OTHER"

        groups = Counter(alert_key(message) for message in messages)
        extra_parts.append(generate_data_table(
            ["告警类型", "已采集明细次数"], groups.most_common(20)
        ))

    if recent:
        if len(recent[0]) >= 9:
            detail_rows = [
                [r[1], r[2], _format_alert_time(r[4]), r[5], r[6], r[7], r[8]]
                for r in recent[:50]
            ]
            detail_headers = ["实例", "主机", "时间", "消息类型", "级别", "问题键", "消息"]
        elif len(recent[0]) == 2:
            detail_rows = [r[:2] for r in recent[:50]]
            detail_headers = ["时间", "消息"]
        else:
            detail_rows = [r[:5] for r in recent[:50]]
            detail_headers = ["时间", "消息类型", "级别", "问题键", "消息"]
        extra_parts.append(generate_data_table(detail_headers, detail_rows))

    value = f"至少{error_count}条近{window_days}天告警" if truncated_legacy else f"{error_count}条近{window_days}天告警"
    if alert_file_size_display:
        value += f" / 日志 {alert_file_size_display}"
    detail = f"近{window_days}天 Alert Log 告警: {'至少' if truncated_legacy else ''}{error_count}，严重错误: {severe_count}"
    if physical_log_summary:
        detail += f"；物理日志告警明细: {len(recent)} 条"
        if analysis_start_time or analysis_end_time:
            detail += f"，分析时间范围: {analysis_start_time or 'N/A'} 至 {analysis_end_time or 'N/A'}"
        if window_truncated:
            detail += "，30天时间窗口数据量超过采集上限，仅覆盖最近可用时间范围"
        if alert_file_size_display:
            detail += f"，文件大小: {alert_file_size_display}"
    elif summary:
        detail += f"；已采集最近 {len(recent)} 条明细（上限200条）"
    return CheckResult("Alert Log", status, value, detail, suggestion,
                       extra_html="".join(extra_parts))


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
