# -*- coding: utf-8 -*-
"""
解析器基础类和工具函数
"""
from dataclasses import dataclass, field
from typing import List, Optional
import csv
import html
import os
import re


@dataclass
class CheckResult:
    """单项巡检结果"""
    name: str               # 巡检项名称
    status: str             # OK / WARN / CRIT / INFO / UNKNOWN
    value: str              # 当前值（用于显示）
    detail: str             # 详细信息
    suggestion: str = ""    # 建议措施
    extra_html: str = ""    # 额外HTML内容（表格、图表等）


def check_threshold(value: float, warn: float, crit: float, name: str = "") -> str:
    """
    阈值判定（值越高越严重，如使用率）
    返回: OK / WARN / CRIT
    """
    if value >= crit:
        return "CRIT"
    elif value >= warn:
        return "WARN"
    return "OK"


def check_threshold_inverse(value: float, warn: float, crit: float, name: str = "") -> str:
    """
    反向阈值判定（值越低越严重，如命中率）
    返回: OK / WARN / CRIT
    """
    if value <= crit:
        return "CRIT"
    elif value <= warn:
        return "WARN"
    return "OK"


def read_file(filepath: str) -> str:
    """读取文件内容，出错返回空字符串"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def read_lines(filepath: str) -> List[str]:
    """读取文件行列表"""
    content = read_file(filepath)
    if not content:
        return []
    return [line.strip() for line in content.splitlines() if line.strip()]


def parse_env_info(raw_dir: str) -> dict:
    """解析环境信息文件"""
    env = {}
    for line in read_lines(f"{raw_dir}/env.info"):
        if "=" in line:
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip()
    return env


# Retired inspection outputs remain in old packages but are outside report scope.
RETIRED_COLLECTION_ITEMS = {"oracle_config_acl.txt"}


def manifest_warning_is_nonblocking(row: dict, env_info=None) -> bool:
    """Recognize legacy/advisory warnings that did not invalidate collected data."""
    if row.get("status") != "WARN":
        return False
    item = row.get("item", "")
    kind = row.get("type", "")
    exit_code = str(row.get("exit_code", "")).strip()
    if item == "sqlplus_startup_profile" and kind == "ENV" and exit_code in ("", "0"):
        return True
    return False


def parse_collection_integrity(raw_dir: str, scopes=None) -> CheckResult:
    """把指定数据域的采集失败显式呈现在报告中，杜绝“失败即正常”。"""
    failed = []
    incomplete = []
    advisories = []
    skipped = []
    env_info = parse_env_info(raw_dir)
    package_type = env_info.get("check_type", "").lower()
    scope_dirs = [
        os.path.join(raw_dir, scope)
        for scope in (scopes or ())
        if os.path.isdir(os.path.join(raw_dir, scope))
    ]

    def in_scope(item: str) -> bool:
        if os.path.basename(str(item or "").replace("\\", "/")) in RETIRED_COLLECTION_ITEMS:
            return False
        if not scopes:
            return True
        name = os.path.basename(str(item or ""))
        if package_type == "host" and "host" in scopes:
            return True
        if package_type == "db" and any(scope in scopes for scope in ("db", "security")):
            return True
        return any(os.path.isfile(os.path.join(directory, name)) for directory in scope_dirs)

    manifest = f"{raw_dir}/collection_manifest.tsv"
    if os.path.isfile(manifest):
        try:
            with open(manifest, "r", encoding="utf-8", errors="replace", newline="") as f:
                for row in csv.DictReader(f, delimiter="\t"):
                    if not in_scope(row.get("item", "")):
                        continue
                    if manifest_warning_is_nonblocking(row, env_info):
                        if row.get("item") == "sqlplus_startup_profile":
                            advisories.append((row.get("item", "未知"), row.get("message", "")[:160]))
                    elif row.get("status") == "FAILED":
                        failed.append((row.get("item", "未知"), row.get("type", ""), row.get("message", "")[:160]))
                    elif row.get("status") == "WARN":
                        incomplete.append((row.get("item", "未知"), row.get("type", ""), row.get("message", "")[:160]))
                    elif row.get("status") == "SKIPPED":
                        skipped.append((row.get("item", "未知"), row.get("message", "")[:160]))
        except (OSError, csv.Error) as exc:
            failed.append(("collection_manifest.tsv", "MANIFEST", str(exc)))

    sql_errors = []
    # 这些文件的用途就是保存数据库/监听器诊断消息，其中出现 ORA-/TNS-
    # 代表被采集到的真实告警，不代表执行采集 SQL 失败。
    diagnostic_outputs = {
        "alert_log_recent.txt",
        "alert_log_30days.txt",
        "alert_log_last_100000.txt",
        "alert_log_summary.txt",
        "alert_log_groups.txt",
        "alert_log_tail.txt",
        "alert_log_errors.txt",
        "listener_status.txt",
        "listener_services.txt",
        "sqlplus_startup_warning.log",
    }
    err_re = re.compile(r"^(?:ORA|SP2|TNS|LRM)-\d+", re.MULTILINE)
    scan_roots = scope_dirs if scopes else [raw_dir]
    for scan_root in scan_roots:
        for root, _, files in os.walk(scan_root):
            for name in files:
                if name in diagnostic_outputs or name in RETIRED_COLLECTION_ITEMS:
                    continue
                path = os.path.join(root, name)
                try:
                    if os.path.getsize(path) > 5 * 1024 * 1024:
                        continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue
                match = err_re.search(content)
                if match:
                    rel = os.path.relpath(path, raw_dir)
                    sql_errors.append((rel, "SQLPLUS", match.group(0)))

    manifest_problem_names = {os.path.basename(entry[0]) for entry in failed + incomplete}
    detected_sql_failures = [entry for entry in sql_errors if os.path.basename(entry[0]) not in manifest_problem_names]
    if failed or incomplete or detected_sql_failures:
        failure_rows = [(item, "失败", kind, message) for item, kind, message in failed]
        failure_rows += [(item, "失败", kind, message) for item, kind, message in detected_sql_failures]
        incomplete_rows = [(item, "部分采集", kind, message) for item, kind, message in incomplete]
        failure_count = len(failure_rows)
        incomplete_count = len(incomplete_rows)
        summary = []
        if failure_count:
            summary.append(f"{failure_count}项失败")
        if incomplete_count:
            summary.append(f"{incomplete_count}项不完整")
        detail_parts = []
        if failure_count:
            detail_parts.append(f"{failure_count} 个采集命令或SQL执行失败")
        if incomplete_count:
            detail_parts.append(f"{incomplete_count} 个采集项仅获得部分数据")
        return CheckResult(
            "采集完整性", "UNKNOWN", "/".join(summary),
            "采集包中发现" + "、".join(detail_parts) + "；仅表中所列相关指标不能判定为正常，其他成功采集的指标仍然有效",
            "修复表中所列采集问题并重新执行巡检，再判断受影响的指标",
            extra_html=generate_data_table(["项目", "结果", "类型", "原因"], (failure_rows + incomplete_rows)[:100]),
        )
    if not os.path.isfile(manifest):
        return CheckResult("采集完整性", "UNKNOWN", "旧版采集包", "未发现错误文本，但采集包不含执行清单，无法证明所有检查均成功",
                           "建议使用当前版本重新采集")
    if skipped or advisories:
        value_parts = []
        detail_parts = ["所有适用的采集项均执行成功"]
        table_rows = []
        if skipped:
            value_parts.append(f"{len(skipped)}项不适用")
            detail_parts.append(f"{len(skipped)} 项因数据库版本、架构或配置不适用而跳过")
            table_rows.extend(("不适用", item, message) for item, message in skipped)
        if advisories:
            value_parts.append(f"{len(advisories)}项提示")
            detail_parts.append(f"{len(advisories)} 项环境提示不影响已采集数据的完整性")
            table_rows.extend(("提示", item, message) for item, message in advisories)
        return CheckResult(
            "采集完整性", "INFO", "完整（" + "/".join(value_parts) + "）",
            "；".join(detail_parts),
            extra_html=generate_data_table(["分类", "项目", "说明"], table_rows),
        )
    return CheckResult("采集完整性", "INFO", "完整", "所有已登记采集项均执行成功，未发现 SQL*Plus 错误")


# ===== HTML 生成辅助函数 =====

def generate_bar_chart(items: list, warn_threshold: float = 80, crit_threshold: float = 95) -> str:
    """
    生成柱状图 HTML
    items: [(label, value, unit), ...]
    """
    rows_html = ""
    for label, value, unit in items:
        pct = min(value, 100)
        if value >= crit_threshold:
            fill_class = "bar-fill-crit"
        elif value >= warn_threshold:
            fill_class = "bar-fill-warn"
        else:
            fill_class = "bar-fill-ok"

        safe_label = html.escape(str(label))
        rows_html += f"""
            <div class="bar-row">
                <div class="bar-label" title="{safe_label}">{safe_label}</div>
                <div class="bar-track">
                    <div class="bar-fill {fill_class}" style="width:{pct:.1f}%"></div>
                </div>
                <div class="bar-value">{value:.1f}{unit}</div>
            </div>"""

    return f'<div class="bar-chart">{rows_html}</div>'


def generate_health_percentage(label: str, value: float,
                               warn_threshold: float, crit_threshold: float) -> str:
    """生成“数值越高越健康”的百分比进度条。"""
    pct = max(0.0, min(float(value), 100.0))
    if value <= crit_threshold:
        fill_class = "bar-fill-crit"
    elif value <= warn_threshold:
        fill_class = "bar-fill-warn"
    else:
        fill_class = "bar-fill-ok"
    safe_label = html.escape(str(label))
    return f"""
        <div class="health-percentage">
            <div class="health-percentage-head">
                <span>{safe_label}</span>
                <strong>{value:.1f}%</strong>
            </div>
            <div class="health-percentage-track" role="progressbar"
                 aria-label="{safe_label}" aria-valuemin="0" aria-valuemax="100"
                 aria-valuenow="{value:.1f}">
                <div class="health-percentage-fill {fill_class}" style="width:{pct:.1f}%"></div>
            </div>
        </div>"""


def generate_data_table(headers: list, rows: list, *, row_classes=None,
                        cell_classes=None) -> str:
    """
    生成数据表格 HTML
    headers: [列名, ...]
    rows: [[值, ...], ...]
    row_classes: {行号: CSS类名}，行号从0开始
    cell_classes: {(行号, 列号): CSS类名}，行列号从0开始
    """
    th_html = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    column_count = len(headers)
    width_class = " data-table-very-wide" if column_count >= 9 else " data-table-wide" if column_count >= 7 else ""
    scroll_attrs = (' tabindex="0" role="region" aria-label="可横向滚动的巡检明细表"'
                    if width_class else "")
    tr_html = ""
    row_classes = row_classes or {}
    cell_classes = cell_classes or {}
    for row_index, row in enumerate(rows):
        row_class = html.escape(str(row_classes.get(row_index, "")), quote=True)
        row_attr = f' class="{row_class}"' if row_class else ""
        cells = []
        for column_index, cell in enumerate(row):
            cell_class = html.escape(
                str(cell_classes.get((row_index, column_index), "")), quote=True
            )
            cell_attr = f' class="{cell_class}"' if cell_class else ""
            cells.append(f"<td{cell_attr}>{html.escape(str(cell))}</td>")
        tr_html += f"<tr{row_attr}>{''.join(cells)}</tr>"

    return f"""<div class="data-table-wrap"{scroll_attrs}>
        <table class="data-table{width_class}">
            <thead><tr>{th_html}</tr></thead>
            <tbody>{tr_html}</tbody>
        </table>
    </div>"""
