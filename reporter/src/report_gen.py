#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Oracle 巡检报告生成器 - 本地端
读取服务器采集的原始数据，解析、判定，同时生成 HTML 和 DOCX 巡检报告

用法:
  python src/report_gen.py <raw_data_dir_or_tar.gz> [...] [-o output.html]
  python src/report_gen.py ./output/raw/20260612_100000
  python src/report_gen.py oracle_check_20260612_100000.tar.gz
  python src/report_gen.py host_a.tar.gz host_b.tar.gz   # 多份报告时默认再生成汇总摘要
"""
import os
import sys
import tarfile
import tempfile
import shutil
import datetime
import html
from pathlib import Path
from string import Template
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional, Tuple

# 添加源码目录到模块搜索路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import CATEGORY_NAMES, CATEGORY_ORDER, REPORT_CONFIG
from explanations import get_check_explanation
from inspection_summary import InspectionSummary, build_inspection_summary
from parser.base import CheckResult, parse_env_info, parse_collection_integrity, generate_bar_chart, generate_data_table
from parser.host_parser import parse_host
from parser.db_parser import parse_db
from parser.security_parser import parse_security
from scoring import (
    calculate_health_score,
    calculate_score_breakdown,
    overall_status as score_overall_status,
    score_band,
)


APP_VERSION = "4.4"
SUPPORTED_SCHEMA_MAJOR = 4


# 状态样式映射
STATUS_STYLE = {
    "OK": {"class": "badge-ok", "label": "正常", "icon": "&#10004;"},
    "WARN": {"class": "badge-warn", "label": "警告", "icon": "&#9888;"},
    "CRIT": {"class": "badge-crit", "label": "严重", "icon": "&#10008;"},
    "INFO": {"class": "badge-info", "label": "信息", "icon": "&#8505;"},
    "UNKNOWN": {"class": "badge-unknown", "label": "数据异常", "icon": "?"},
}

DEFAULT_OVERVIEW_NAV = """
                <a class="nav-link" href="#overview">&#128202; 总览</a>
                <a class="nav-link" href="#actions">&#9888; 待处理</a>
                <a class="nav-link" href="#toc">&#128203; 巡检目录</a>
"""

# 区域配置
ZONE_CONFIG = {
    "host": {
        "icon": "&#128187;",
        "title": "主机巡检",
        "subtitle": "系统资源、网络、安全基线",
        "sec_class": "host",
        "style_class": "host-style",
        "dot_class": "host",
    },
    "db": {
        "icon": "&#128451;",
        "title": "数据库巡检",
        "subtitle": "实例状态、性能、存储、会话",
        "sec_class": "db",
        "style_class": "db-style",
        "dot_class": "db",
    },
    "cdb": {
        "icon": "&#128203;",
        "title": "CDB/PDB管理",
        "subtitle": "CDB架构、PDB状态、数据文件",
        "sec_class": "cdb",
        "style_class": "cdb-style",
        "dot_class": "cdb",
    },
    "rac": {
        "icon": "&#128172;",
        "title": "RAC集群",
        "subtitle": "节点状态、集群服务、高可用性",
        "sec_class": "rac",
        "style_class": "rac-style",
        "dot_class": "rac",
    },
    "security": {
        "icon": "&#128274;",
        "title": "安全巡检",
        "subtitle": "权限、策略、审计",
        "sec_class": "sec",
        "style_class": "sec-style",
        "dot_class": "sec",
    },
}


def extract_tar_gz(tar_path: str) -> str:
    """解压 tar.gz 到临时目录，返回解压路径"""
    tmp_dir = tempfile.mkdtemp(prefix="oracle_check_")
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > 10000 or sum(max(m.size, 0) for m in members) > 1024 * 1024 * 1024:
                raise ValueError("采集包过大或文件数量异常")
            root = os.path.realpath(tmp_dir)
            for member in members:
                target = os.path.realpath(os.path.join(root, member.name))
                if target != root and not target.startswith(root + os.sep):
                    raise ValueError(f"采集包包含越界路径: {member.name}")
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(f"采集包包含不允许的链接/设备文件: {member.name}")
            try:
                tar.extractall(path=tmp_dir, members=members, filter="data")
            except TypeError:  # Python 3.11 及更早版本
                tar.extractall(path=tmp_dir, members=members)
        return tmp_dir
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def find_raw_dir(path: str) -> str:
    """
    查找原始数据目录
    支持直接指定目录、tar.gz 文件、或包含时间戳子目录的父目录
    """
    lower_path = path.lower()
    if lower_path.endswith(".tar.gz") or lower_path.endswith(".tgz"):
        return extract_tar_gz(path)

    if os.path.isdir(path):
        # 如果目录下有 env.info，说明就是原始数据目录
        if os.path.exists(f"{path}/env.info"):
            return path
        # 否则查找最新的子目录
        subdirs = [d for d in os.listdir(path) if os.path.isdir(f"{path}/{d}")]
        if subdirs:
            latest = sorted(subdirs)[-1]
            candidate = f"{path}/{latest}"
            if os.path.exists(f"{candidate}/env.info"):
                return candidate

    return path


def expand_input_paths(paths: List[str]) -> List[str]:
    """目录里若是一批采集包，展开成多个输入；单个采集目录保持不变。"""
    expanded = []
    for path in paths:
        if not path:
            continue
        normalized = os.path.normpath(path)
        if os.path.isdir(normalized) and not os.path.isfile(
            os.path.join(normalized, "env.info")
        ):
            try:
                names = sorted(os.listdir(normalized))
            except OSError:
                expanded.append(normalized)
                continue
            archives = []
            raw_subdirs = []
            for name in names:
                full = os.path.join(normalized, name)
                lower = name.lower()
                if os.path.isfile(full) and (
                    lower.endswith(".tar.gz") or lower.endswith(".tgz")
                ):
                    archives.append(full)
                elif os.path.isdir(full) and os.path.isfile(
                    os.path.join(full, "env.info")
                ):
                    raw_subdirs.append(full)
            if archives:
                expanded.extend(archives)
                continue
            if len(raw_subdirs) > 1:
                expanded.extend(raw_subdirs)
                continue
        expanded.append(normalized)
    return expanded


@dataclass
class CollectionRef:
    source_path: str
    raw_dir: str
    env: dict
    has_host: bool
    has_db: bool
    temporary_dir: Optional[str] = None
    report_kind: str = "auto"


def _validate_schema(env: dict, source_path: str) -> None:
    """拒绝无法安全解释的未来数据协议；无版本的 v4.0 包保持兼容。"""
    version = str((env or {}).get("schema_version") or "").strip()
    if not version:
        return
    try:
        major = int(version.split(".", 1)[0])
    except ValueError as exc:
        raise ValueError(f"采集包协议版本无效: {version} ({source_path})") from exc
    if major != SUPPORTED_SCHEMA_MAJOR:
        raise ValueError(
            f"不支持采集包协议 {version}；报告端 {APP_VERSION} 仅支持 4.x ({source_path})"
        )


def inspect_collection(path: str) -> CollectionRef:
    lower_path = path.lower()
    is_archive = lower_path.endswith(".tar.gz") or lower_path.endswith(".tgz")
    raw_dir = None
    try:
        raw_dir = find_raw_dir(path)
        env_file = os.path.join(raw_dir, "env.info")
        env = parse_env_info(raw_dir) if os.path.isfile(env_file) else {}
        _validate_schema(env, path)
        has_host = os.path.isdir(os.path.join(raw_dir, "host"))
        has_db = os.path.isdir(os.path.join(raw_dir, "db")) or os.path.isdir(
            os.path.join(raw_dir, "security")
        )
        return CollectionRef(
            path, raw_dir, env, has_host, has_db,
            temporary_dir=raw_dir if is_archive else None,
        )
    except Exception:
        if is_archive and raw_dir:
            shutil.rmtree(raw_dir, ignore_errors=True)
        raise


def _cleanup_collection_refs(jobs: List[List[CollectionRef]]) -> None:
    temp_dirs = {
        ref.temporary_dir
        for job in jobs
        for ref in job
        if ref.temporary_dir
    }
    for temp_dir in temp_dirs:
        shutil.rmtree(temp_dir, ignore_errors=True)


def group_report_jobs(input_paths: List[str]) -> List[List[CollectionRef]]:
    """
    把多个采集包拆成相互独立的报告任务。
    主机数据只生成主机报告，数据库/安全数据只生成 Oracle 报告，永不合并。
    若输入目录同时包含两类数据，则拆成两份逻辑报告任务。
    """
    paths = expand_input_paths(input_paths)
    if not paths:
        return []
    items = []
    try:
        items = [inspect_collection(path) for path in paths]
    except Exception:
        _cleanup_collection_refs([[item] for item in items])
        raise
    jobs: List[List[CollectionRef]] = []
    for item in items:
        if item.has_host:
            jobs.append([replace(item, has_db=False, report_kind="host")])
        if item.has_db:
            jobs.append([replace(item, has_host=False, report_kind="db")])
        if not item.has_host and not item.has_db:
            jobs.append([replace(item, report_kind="auto")])
    return jobs


def run_all_parsers(raw_dir: str, report_kind: str = "auto",
                    cancel_check: Optional[Callable[[], bool]] = None) -> Dict[str, List[CheckResult]]:
    """按报告类型运行解析器，确保主机与 Oracle 巡检项完全隔离。"""
    results = {}
    include_host = report_kind in ("auto", "host")
    include_db = report_kind in ("auto", "db")

    _raise_if_cancelled(cancel_check)
    if include_host and os.path.isdir(f"{raw_dir}/host"):
        results["host"] = parse_host(raw_dir)
        results["host"].insert(0, parse_collection_integrity(raw_dir, ("host",)))

    _raise_if_cancelled(cancel_check)
    if include_db and os.path.isdir(f"{raw_dir}/db"):
        db_data = parse_db(raw_dir)
        results["db"] = db_data["db"]
        results["db"].insert(0, parse_collection_integrity(raw_dir, ("db", "security")))
        if db_data.get("cdb"):
            results["cdb"] = db_data["cdb"]
        if db_data.get("rac"):
            results["rac"] = db_data["rac"]

    _raise_if_cancelled(cancel_check)
    if include_db and os.path.isdir(f"{raw_dir}/security"):
        results["security"] = parse_security(raw_dir)
        if "db" not in results:
            results["security"].insert(0, parse_collection_integrity(raw_dir, ("db", "security")))

    return results


def count_status(results: Dict[str, List[CheckResult]]) -> Dict[str, int]:
    """统计各状态数量"""
    counts = {"OK": 0, "WARN": 0, "CRIT": 0, "INFO": 0, "UNKNOWN": 0, "TOTAL": 0}
    for items in results.values():
        for item in items:
            if item.status in counts:
                counts[item.status] += 1
            counts["TOTAL"] += 1
    return counts


def generate_status_badge(status: str) -> str:
    """生成状态标签 HTML"""
    style = STATUS_STYLE.get(status, STATUS_STYLE["OK"])
    return f'<span class="badge {style["class"]}">{style["icon"]} {style["label"]}</span>'


def generate_summary_section(counts: Dict[str, int], confidence: str) -> str:
    """生成概要统计区域"""
    return f"""
    <div class="summary-row">
        <div class="summary-card sc-ok">
            <div class="sc-number">{counts['OK']}</div>
            <div class="sc-label">正常</div>
        </div>
        <div class="summary-card sc-warn">
            <div class="sc-number">{counts['WARN']}</div>
            <div class="sc-label">警告</div>
        </div>
        <div class="summary-card sc-crit">
            <div class="sc-number">{counts['CRIT']}</div>
            <div class="sc-label">严重</div>
        </div>
        <div class="summary-card sc-info">
            <div class="sc-number">{counts.get('INFO', 0)}</div>
            <div class="sc-label">信息/不适用</div>
        </div>
        <div class="summary-card sc-confidence">
            <div class="sc-text">{html.escape(confidence)}</div>
            <div class="sc-label">数据可信度</div>
        </div>
        <div class="summary-card sc-total">
            <div class="sc-number">{counts['TOTAL']}</div>
            <div class="sc-label">总计</div>
        </div>
    </div>"""


def generate_action_panel(results: Dict[str, List[CheckResult]]) -> str:
    """生成按严重度排序、可跳转的待处理事项面板。"""
    severity_order = {"UNKNOWN": 0, "CRIT": 1, "WARN": 2}
    actions = [
        (index, category, item)
        for index, (category, item) in enumerate(_iter_checks(results))
        if item.status in severity_order
    ]
    actions.sort(key=lambda row: (severity_order[row[2].status], row[0]))

    if not actions:
        return ""

    items_html = ""
    for _, category, item in actions:
        badge = generate_status_badge(item.status)
        anchor = _make_anchor(category, item.name)
        suggestion = f" - {html.escape(str(item.suggestion))}" if item.suggestion else ""
        items_html += (
            f'<a class="action-item" href="#{anchor}">{badge}'
            f'<strong>{html.escape(str(item.name))}</strong>: '
            f'{html.escape(str(item.value))}{suggestion}</a>'
        )

    return f"""
    <div class="action-panel" id="actions">
        <div class="action-panel-header">
            <span>&#9888; 待处理事项</span>
            <span class="count">{len(actions)} 项</span>
        </div>
        <div class="action-list">
            {items_html}
        </div>
    </div>"""


def _ordered_categories(results: Dict[str, List[CheckResult]]) -> List[str]:
    """按固定类别顺序返回报告中存在的类别。"""
    return (
        [category for category in CATEGORY_ORDER if category in results]
        + [category for category in results if category not in CATEGORY_ORDER]
    )


def _iter_checks(results: Dict[str, List[CheckResult]]):
    """以统一顺序遍历 (类别, 巡检项)。"""
    for category in _ordered_categories(results):
        for item in results[category]:
            yield category, item


def _make_anchor(category: str, name: str) -> str:
    """生成包含类别的唯一锚点 ID。"""
    import re
    slug = re.sub(r'-+', '-', re.sub(r'[^\w\u4e00-\u9fff]', '-', name)).strip('-')
    return f"check-{category}-{slug}"


def generate_toc_section(results: Dict[str, List[CheckResult]]) -> str:
    """生成巡检项目目录，带状态圆点和可点击跳转链接"""
    toc_items = []
    for category, item in _iter_checks(results):
        anchor = _make_anchor(category, item.name)
        dot_class = f"dot-{item.status.lower()}"
        toc_items.append(
            f'<a class="toc-item" href="#{anchor}">'
            f'<span class="toc-dot {dot_class}"></span>'
            f'<span class="toc-name">{html.escape(str(item.name))}</span>'
            f'<span class="toc-value">{html.escape(str(item.value))}</span>'
            f'</a>'
        )

    return f"""
    <div class="toc-panel" id="toc">
        <div class="toc-header">
            <span>&#128203; 巡检项目目录</span>
            <span class="toc-count">{len(toc_items)} 项</span>
        </div>
        <div class="toc-grid">
            {"".join(toc_items)}
        </div>
    </div>"""


def generate_sidebar_nav(results: Dict[str, List[CheckResult]]) -> str:
    """按类别分组生成包含每个巡检项的侧边栏导航。"""
    groups = []
    for category in _ordered_categories(results):
        zone = ZONE_CONFIG.get(category, ZONE_CONFIG["host"])
        item_links = []
        for item in results[category]:
            anchor = _make_anchor(category, item.name)
            item_links.append(
                f'<a class="nav-link nav-check" href="#{anchor}" title="{html.escape(str(item.name))}">'
                f'<span class="dot {item.status.lower()}"></span>'
                f'<span class="nav-check-name">{html.escape(str(item.name))}</span></a>'
            )
        groups.append(
            f'<div class="nav-category">'
            f'<a class="nav-link nav-category-link" href="#section-{category}">'
            f'<span class="dot {zone["dot_class"]}"></span>{zone["title"]}</a>'
            f'<div class="nav-check-list">{"".join(item_links)}</div></div>'
        )
    groups.append(
        '<div class="nav-category">'
        '<a class="nav-link nav-category-link" href="#report-summary">'
        '<span class="dot summary"></span>总结</a></div>'
    )
    return "".join(groups)


def generate_category_section(category: str, items: List[CheckResult]) -> str:
    """生成单个巡检类别的详细内容"""
    zone = ZONE_CONFIG.get(category, ZONE_CONFIG["host"])

    # 排序: 概览项置顶，问题项(CRIT/WARN)次之，正常项最后，系统日志固定末尾
    def sort_key(x):
        if "概览" in x.name:
            return (0, 0)
        if x.name == "系统日志":
            return (2, 0)
        status_order = {"UNKNOWN": 0.9, "CRIT": 1, "WARN": 1.1, "INFO": 1.6, "OK": 1.5}
        return (1, status_order.get(x.status, 1.5))
    sorted_items = sorted(items, key=sort_key)

    section_id = f"section-{category}"

    header = f"""
    <section class="section" id="{section_id}">
        <div class="section-header {zone['sec_class']}">
            <div class="sec-icon">{zone['icon']}</div>
            <div>
                <div class="sec-title">{zone['title']}</div>
                <div class="sec-subtitle">{zone['subtitle']}</div>
            </div>
        </div>"""

    if category == "host":
        content = _generate_host_cards(category, sorted_items)
    else:
        content = _generate_table_wrap(category, sorted_items, zone["style_class"])

    return header + content + "</section>"


def generate_report_summary_chapter(content: Optional[InspectionSummary] = None) -> str:
    """生成固定存在的总结章节；未启用时正文保持空白。"""
    body = ""
    subtitle = ""
    if content is not None:
        subtitle = "总体结论、重点问题与处置建议"
        issues = "".join(f"<li>{html.escape(item)}</li>" for item in content.issues)
        if not issues:
            issues = "<li>未发现警告或严重问题。</li>"
        if content.omitted_issues:
            issues += (
                f'<li class="summary-note">另有 {content.omitted_issues} 项风险未在本章展开，'
                "请结合待处理事项和巡检明细查看。</li>"
            )
        recommendations = "".join(
            f"<li>{html.escape(item)}</li>" for item in content.recommendations
        )
        if not recommendations:
            recommendations = "<li>继续保持现有运维策略，并按计划开展周期性复查。</li>"
        if content.omitted_recommendations:
            recommendations += (
                f'<li class="summary-note">另有 {content.omitted_recommendations} 条建议未在本章展开，'
                "请查阅对应巡检项。</li>"
            )
        body = f"""
        <div class="report-summary-content">
            <h3>总体结论</h3>
            <p>{html.escape(content.overview)}</p>
            <p>{html.escape(content.conclusion)}</p>
            <h3>重点问题</h3>
            <ul>{issues}</ul>
            <h3>处置建议</h3>
            <ol>{recommendations}</ol>
        </div>"""
    return f"""
    <section class="section" id="report-summary">
        <div class="section-header summary">
            <div class="sec-icon">&#128221;</div>
            <div>
                <div class="sec-title">总结</div>
                <div class="sec-subtitle">{subtitle}</div>
            </div>
        </div>
        {body}
    </section>"""


def _generate_host_cards(category: str, items: List[CheckResult]) -> str:
    """主机巡检使用卡片网格布局"""
    cards = ""
    for item in items:
        status_lower = item.status.lower()
        badge = generate_status_badge(item.status)
        anchor = _make_anchor(category, item.name)
        explanation = html.escape(get_check_explanation(item.name))
        suggestion_html = f'<div class="cc-suggestion">{html.escape(str(item.suggestion))}</div>' if item.suggestion else ""
        extra_html = (
            '<div class="cc-extra"><span class="extra-toggle">&#9656; 展开详情</span>'
            f'<div class="extra-content">{item.extra_html}'
            f'<div class="check-purpose"><strong>巡检说明：</strong>{explanation}</div>'
            '</div></div>'
        )
        cards += f"""
        <div class="check-card {status_lower}" id="{anchor}">
            <div class="cc-head">
                <span class="cc-name">{html.escape(str(item.name))}</span>
                {badge}
            </div>
            <div class="cc-value">{html.escape(str(item.value))}</div>
            <div class="cc-detail"><strong>检查结果：</strong>{html.escape(str(item.detail))}</div>
            {suggestion_html}
            {extra_html}
        </div>"""

    return f'<div class="check-grid">{cards}</div>'


def _generate_table_wrap(category: str, items: List[CheckResult], style_class: str) -> str:
    """数据库/CDB/RAC/安全巡检使用表格布局"""
    rows = ""
    for item in items:
        badge = generate_status_badge(item.status)
        anchor = _make_anchor(category, item.name)
        explanation = html.escape(get_check_explanation(item.name))
        suggestion_html = f'<div class="cc-suggestion">{html.escape(str(item.suggestion))}</div>' if item.suggestion else ""
        extra_html = (
            '<div class="cc-extra"><span class="extra-toggle">&#9656; 展开详情</span>'
            f'<div class="extra-content">{item.extra_html}'
            f'<div class="check-purpose"><strong>巡检说明：</strong>{explanation}</div>'
            '</div></div>'
        )
        rows += f"""
            <tr id="{anchor}">
                <td>{html.escape(str(item.name))}</td>
                <td class="center">{badge}</td>
                <td>{html.escape(str(item.value))}</td>
                <td class="detail-cell"><div class="check-result"><strong>检查结果：</strong>{html.escape(str(item.detail))}</div>{suggestion_html}{extra_html}</td>
            </tr>"""

    return f"""
    <div class="table-wrap {style_class}">
        <table class="check-table report-detail-table">
            <colgroup>
                <col class="check-col-name">
                <col class="check-col-status">
                <col class="check-col-value">
                <col class="check-col-detail">
            </colgroup>
            <thead>
                <tr>
                    <th>巡检项</th>
                    <th class="center">状态</th>
                    <th>当前值</th>
                    <th>详细信息</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>"""


def generate_report(results: Dict[str, List[CheckResult]], env_info: dict,
                    template_file: str, output_file: str,
                    generate_summary_content: bool = False):
    """生成巡检报告"""
    with open(template_file, "r", encoding="utf-8") as f:
        template_str = f.read()

    counts = count_status(results)
    score_breakdown = calculate_score_breakdown(results)
    health_score = score_breakdown.score
    summary_html = generate_summary_section(counts, score_breakdown.confidence)
    action_html = generate_action_panel(results)
    toc_html = generate_toc_section(results)
    sidebar_nav = generate_sidebar_nav(results)

    # 各类别详情
    detail_html = ""
    for category in CATEGORY_ORDER:
        if category in results:
            detail_html += generate_category_section(category, results[category])
    for category in results:
        if category not in CATEGORY_ORDER:
            detail_html += generate_category_section(category, results[category])
    inspection_summary = (
        build_inspection_summary(results, counts, health_score)
        if generate_summary_content else None
    )
    detail_html += generate_report_summary_chapter(inspection_summary)

    # 根据巡检类别确定报告标题（从配置文件读取）
    has_host = "host" in results
    has_db = any(category in results for category in ("db", "cdb", "rac", "security"))
    if has_db:
        report_title = REPORT_CONFIG["title_db"]
    elif has_host:
        report_title = REPORT_CONFIG["title_host"]
    else:
        report_title = REPORT_CONFIG["title_general"]

    # 总体状态
    overall_status = score_overall_status(counts)

    # 评分圆圈只表达分数色阶；风险状态和数据可信度在旁边独立展示。
    score_class = {
        "OK": "good", "WARN": "warn", "CRIT": "crit", "UNKNOWN": "unknown",
    }[score_band(health_score, score_breakdown.possible > 0)]
    overall_key = "CRIT" if counts.get("CRIT") else "WARN" if counts.get("WARN") else "OK"
    overall_style = STATUS_STYLE[overall_key]

    # 环境信息
    hostname = env_info.get("hostname", "N/A")
    server_ip = env_info.get("server_ip", "N/A")
    oracle_sid = env_info.get("oracle_sid", "N/A")
    check_time = env_info.get("timestamp", "N/A")

    # 格式化巡检时间 (YYYYMMDD_HHMMSS -> YYYY-MM-DD HH:MM:SS)
    formatted_time = check_time
    try:
        if "_" in check_time and len(check_time) == 15:
            dt = datetime.datetime.strptime(check_time, "%Y%m%d_%H%M%S")
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        pass

    # SID 行（有SID时显示）
    safe_hostname = html.escape(str(hostname))
    safe_server_ip = html.escape(str(server_ip))
    safe_sid = html.escape(str(oracle_sid))
    safe_time = html.escape(str(formatted_time))
    project_name = html.escape(str(
        env_info.get("project_name", "") or REPORT_CONFIG["project_name"]
    ))
    sid_line = f'<span>&#128451; {safe_sid}</span>' if oracle_sid and oracle_sid != "N/A" else ""

    # 报告头部
    report_header = f"""
    <header class="report-header" id="overview">
        <div class="score-ring {score_class}">{health_score}</div>
        <div class="header-info">
            <h1>{report_title}</h1>
            <div class="project-name">{project_name}</div>
            <div class="subtitle">总体状态:
                <span class="badge {overall_style['class']}">{overall_style['icon']} {overall_status}</span>
               　数据可信度: {html.escape(score_breakdown.confidence)}
            </div>
            <div class="header-meta">
                <span>&#127968; {safe_hostname}</span>
                <span>&#128421; {safe_server_ip}</span>
                {'<span>&#128451; ' + safe_sid + '</span>' if oracle_sid and oracle_sid != 'N/A' else ''}
                <span>&#128339; {safe_time}</span>
            </div>
        </div>
    </header>"""

    # 组装报告体
    report_body = report_header + summary_html + action_html + toc_html + detail_html

    # 优先使用采集端配置的 footer，否则使用 config.py 中的默认值
    report_footer = html.escape(str(env_info.get("report_footer", "") or REPORT_CONFIG["footer"]))

    template = Template(template_str)
    report_html = template.safe_substitute(
        REPORT_TITLE=report_title,
        REPORT_BRAND=REPORT_CONFIG["brand"],
        REPORT_FOOTER=report_footer,
        HOSTNAME=safe_hostname,
        SERVER_IP=safe_server_ip,
        SID_LINE=sid_line,
        COLLECT_TIME=safe_time,
        OVERVIEW_NAV=DEFAULT_OVERVIEW_NAV,
        DETAIL_NAV_LABEL="巡检详情",
        SIDEBAR_NAV=sidebar_nav,
        REPORT_BODY=report_body,
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_html)

    return health_score, counts


class ReportBuildError(Exception):
    """报告生成失败（输入无效、数据缺失、模板不存在等）。"""


class ReportBuildCancelled(Exception):
    """用户请求安全停止当前报告批次。"""

    def __init__(self, message="用户已停止生成", partial=None):
        super().__init__(message)
        self.partial = partial


def _raise_if_cancelled(cancel_check: Optional[Callable[[], bool]], partial=None) -> None:
    if cancel_check is not None and cancel_check():
        raise ReportBuildCancelled(partial=partial)


@dataclass
class ReportOutputs:
    """一次报告生成产生的全部文件和概要信息。"""
    html: Optional[str]
    docx: Optional[str]
    health_score: int
    counts: dict
    env_info: dict
    results: Dict[str, List[CheckResult]]


@dataclass
class BatchOutputs:
    """一次批量生成的全部报告和失败项。"""
    reports: List[ReportOutputs] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    summary_html: Optional[str] = None
    summary_docx: Optional[str] = None
    cancelled: bool = False


def resource_dir() -> str:
    """报告程序资源根目录。源码模式为 reporter，打包后为 _MEIPASS。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def template_path() -> str:
    return os.path.join(resource_dir(), "resources", "templates", "html_template.html")


def project_root() -> str:
    """Reporter 根目录（开发）或 exe 所在目录（打包后）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return resource_dir()


def _safe_filename_part(value: str) -> str:
    """去掉路径分隔符和 Windows 非法文件名字符。"""
    text = str(value or "").strip()
    for ch in '<>:"/\\|?*':
        text = text.replace(ch, "_")
    text = "_".join(text.split())
    return text.strip(" ._")


def report_date(env_info: dict) -> str:
    """从采集时间戳取出 YYYYMMDD；无法识别时用当天。"""
    timestamp = str(env_info.get("timestamp") or "").strip()
    digits = "".join(ch for ch in timestamp if ch.isdigit())
    if len(digits) >= 8:
        return digits[:8]
    return datetime.datetime.now().strftime("%Y%m%d")


def report_basename(env_info: dict) -> str:
    """报告主文件名：数据库为 Oracle巡检报告_SID_日期，主机为 主机巡检报告_主机名_日期。"""
    date = report_date(env_info)
    sid = _safe_filename_part(env_info.get("oracle_sid", ""))
    if sid.upper() not in ("", "N/A", "NA", "NONE"):
        return f"Oracle巡检报告_{sid}_{date}.html"
    hostname = _safe_filename_part(env_info.get("hostname", ""))
    if hostname.upper() in ("", "N/A", "NA", "NONE", "UNKNOWN"):
        hostname = "unknown"
    return f"主机巡检报告_{hostname}_{date}.html"


def _is_auto_report_name(name: str) -> bool:
    """占位名或自动生成名，生成时应按 SID/主机名/日期重写。"""
    stem = Path(name).stem
    lower = stem.lower()
    return lower in {
        "oracle_inspection",
        "oracle巡检报告",
        "主机巡检报告",
    } or lower.startswith("oracle巡检报告_") or lower.startswith("主机巡检报告_")


def default_output_path(env_info: dict, output_dir: str = None) -> str:
    if not output_dir:
        output_dir = os.path.join(project_root(), "output", "report")
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, report_basename(env_info))


def _unique_output_path(path: str, env_info: dict, used_names: Optional[set]) -> str:
    if used_names is None:
        return path
    output = Path(path)
    if output.name not in used_names:
        used_names.add(output.name)
        return path
    hostname = _safe_filename_part(env_info.get("hostname") or "host") or "host"
    stem = output.stem
    if hostname.lower() not in stem.lower():
        alt = output.with_name(f"{stem}_{hostname}{output.suffix}")
        if alt.name not in used_names:
            used_names.add(alt.name)
            return str(alt)
        stem = alt.stem
    index = 2
    while True:
        alt = output.with_name(f"{stem}_{index}{output.suffix}")
        if alt.name not in used_names:
            used_names.add(alt.name)
            return str(alt)
        index += 1


def resolve_output_file(env_info: dict, output_file: str = None,
                        used_names: Optional[set] = None) -> str:
    """解析最终报告路径；目录或自动命名占位符会改写成标准报告文件名。"""
    if not output_file:
        resolved = default_output_path(env_info)
        return _unique_output_path(resolved, env_info, used_names)

    output_path = Path(output_file).expanduser()
    if output_path.exists() and output_path.is_dir():
        resolved = default_output_path(env_info, str(output_path.resolve()))
        return _unique_output_path(resolved, env_info, used_names)

    output_path = output_path.with_suffix(".html")
    if _is_auto_report_name(output_path.name):
        output_path = output_path.with_name(report_basename(env_info))

    resolved = str(output_path.resolve())
    out_dir = os.path.dirname(resolved)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    return _unique_output_path(resolved, env_info, used_names)


def _clean_report_sidecars(output_file: str) -> None:
    """兼容旧调用；v4.3 继续确保不删除报告生成器未创建的旁路文件。"""
    return None


def _job_label(refs: List[CollectionRef]) -> str:
    return " + ".join(os.path.basename(ref.source_path) for ref in refs)


def _build_from_refs(refs: List[CollectionRef], output_file: str = None,
                     write_html: bool = True, write_docx: bool = True,
                     used_names: Optional[set] = None,
                     project_name: Optional[str] = None,
                     generate_summary_content: bool = False,
                     cancel_check: Optional[Callable[[], bool]] = None) -> ReportOutputs:
    _raise_if_cancelled(cancel_check)
    if not refs:
        raise ReportBuildError("至少需要一个采集包或目录")
    if not write_html and not write_docx:
        raise ReportBuildError("至少选择一种报告格式：HTML 或 Word")

    if len(refs) != 1:
        raise ReportBuildError("主机包与数据库包必须分别生成报告，不再支持合并")

    ref = refs[0]
    raw_dir = ref.raw_dir
    if not os.path.isdir(raw_dir):
        raise ReportBuildError(f"数据目录不存在: {raw_dir}")

    env_info = dict(parse_env_info(raw_dir))
    _raise_if_cancelled(cancel_check)
    env_info["project_name"] = str(
        project_name or REPORT_CONFIG["project_name"]
    ).strip() or REPORT_CONFIG["project_name"]
    results = run_all_parsers(raw_dir, ref.report_kind, cancel_check=cancel_check)
    _raise_if_cancelled(cancel_check)
    if not results:
        raise ReportBuildError("未找到任何巡检数据（采集包中缺少 host/db/security 目录）")
    if ref.report_kind == "host":
        # 混合目录拆分出的主机报告不得因残留 SID 被命名为 Oracle 报告。
        env_info.pop("oracle_sid", None)

    output_file = resolve_output_file(env_info, output_file, used_names)
    html_file = None
    docx_file = None
    counts = count_status(results)
    health_score = calculate_health_score(results)

    if write_html:
        _raise_if_cancelled(cancel_check)
        tpl = template_path()
        if not os.path.exists(tpl):
            raise ReportBuildError(f"模板文件不存在: {tpl}")
        health_score, counts = generate_report(
            results, env_info, tpl, output_file,
            generate_summary_content=generate_summary_content,
        )
        html_file = output_file
        _raise_if_cancelled(
            cancel_check,
            ReportOutputs(html_file, None, health_score, counts, env_info, results),
        )

    if write_docx:
        html_partial = (
            ReportOutputs(html_file, None, health_score, counts, env_info, results)
            if html_file else None
        )
        _raise_if_cancelled(cancel_check, html_partial)
        docx_file = str(Path(output_file).with_suffix(".docx"))
        try:
            from docx_gen import generate_docx_report
            rendered_count = generate_docx_report(
                results, env_info, docx_file, health_score, counts,
                generate_summary_content=generate_summary_content,
                cancellation_check=lambda: _raise_if_cancelled(
                    cancel_check, html_partial
                ),
            )
        except ReportBuildCancelled:
            raise
        except ImportError as exc:
            raise ReportBuildError(
                "缺少 Word 报告依赖，请执行: python -m pip install python-docx"
            ) from exc
        except Exception as exc:
            raise ReportBuildError(f"Word 报告生成失败: {exc}") from exc
        if rendered_count != counts["TOTAL"]:
            raise ReportBuildError(
                f"Word 报告完整性校验失败: 应有 {counts['TOTAL']} 项，实际 {rendered_count} 项"
            )
        _raise_if_cancelled(
            cancel_check,
            ReportOutputs(html_file, docx_file, health_score, counts, env_info, results),
        )
    _clean_report_sidecars(output_file)
    return ReportOutputs(
        html=html_file,
        docx=docx_file,
        health_score=health_score,
        counts=counts,
        env_info=env_info,
        results=results,
    )


def build_report(input_paths: List[str], output_file: str = None,
                 write_html: bool = True, write_docx: bool = True,
                 project_name: Optional[str] = None,
                 generate_summary_content: bool = False,
                 cancel_check: Optional[Callable[[], bool]] = None):
    """
    从采集包或目录生成一份报告。write_html / write_docx 控制输出格式，默认都生成。
    一次只接受一类采集输入；主机包和数据库包必须使用批量生成分别输出。
    """
    jobs = []
    try:
        jobs = group_report_jobs(input_paths)
        if not jobs:
            raise ReportBuildError("至少需要一个采集包或目录")
        if len(jobs) != 1:
            raise ReportBuildError(
                f"检测到 {len(jobs)} 组相互独立的采集包，请使用批量生成；"
                "主机包与数据库包不会合并"
            )
        return _build_from_refs(
            jobs[0], output_file, write_html=write_html, write_docx=write_docx,
            project_name=project_name,
            generate_summary_content=generate_summary_content,
            cancel_check=cancel_check,
        )
    finally:
        _cleanup_collection_refs(jobs)


def _batch_output_dir(batch: BatchOutputs, output_file: str = None) -> str:
    if output_file:
        output_path = Path(output_file).expanduser()
        if output_path.suffix.lower() in {".html", ".htm", ".docx"}:
            parent = str(output_path.parent)
            return parent if parent not in {"", "."} else str(output_path.resolve().parent)
        return str(output_path)
    for item in batch.reports:
        for path in (item.html, item.docx):
            if path:
                return str(Path(path).resolve().parent)
    return os.path.join(project_root(), "output", "report")


def build_reports(input_paths: List[str], output_file: str = None,
                  write_html: bool = True, write_docx: bool = True,
                  write_summary: bool = True,
                  progress: Optional[Callable[[int, int, str], None]] = None,
                  project_name: Optional[str] = None,
                  generate_summary_content: bool = False,
                  cancel_check: Optional[Callable[[], bool]] = None) -> BatchOutputs:
    """按分组批量生成巡检报告；一份失败不影响其他份。

    成功生成两份及以上 Oracle 报告时，默认再输出数据库汇总摘要；主机报告不参与。
    """
    jobs = []
    try:
        jobs = group_report_jobs(input_paths)
        if not jobs:
            raise ReportBuildError("至少需要一个采集包或目录")
        if not write_html and not write_docx:
            raise ReportBuildError("至少选择一种报告格式：HTML 或 Word")

        batch_output = output_file
        if len(jobs) > 1 and output_file:
            output_path = Path(output_file).expanduser()
            if output_path.suffix.lower() in {".html", ".htm", ".docx"}:
                batch_output = str(output_path.parent) if str(output_path.parent) not in {"", "."} else output_file

        batch = BatchOutputs()
        used_names = set()
        for index, job in enumerate(jobs, start=1):
            try:
                _raise_if_cancelled(cancel_check)
            except ReportBuildCancelled as exc:
                if exc.partial is not None:
                    batch.reports.append(exc.partial)
                batch.cancelled = True
                break
            label = _job_label(job)
            if progress:
                progress(index, len(jobs), label)
            try:
                batch.reports.append(
                    _build_from_refs(
                        job, batch_output,
                        write_html=write_html, write_docx=write_docx,
                        used_names=used_names,
                        project_name=project_name,
                        generate_summary_content=generate_summary_content,
                        cancel_check=cancel_check,
                    )
                )
            except ReportBuildCancelled as exc:
                if exc.partial is not None:
                    batch.reports.append(exc.partial)
                batch.cancelled = True
                break
            except (ReportBuildError, ValueError) as exc:
                batch.errors.append((label, str(exc)))
            except Exception as exc:
                batch.errors.append((label, str(exc)))
        if not batch.cancelled and not batch.reports and batch.errors:
            details = "；".join(f"{label}: {message}" for label, message in batch.errors)
            raise ReportBuildError(details)
        oracle_reports = [
            report for report in batch.reports
            if any(category in report.results for category in ("db", "cdb", "rac", "security"))
        ]
        if not batch.cancelled and write_summary and len(oracle_reports) >= 2:
            from summary_gen import generate_summary_reports
            try:
                summary_html, summary_docx = generate_summary_reports(
                    oracle_reports,
                    _batch_output_dir(batch, batch_output),
                    write_html=write_html,
                    write_docx=write_docx,
                    used_names=used_names,
                    project_name=project_name,
                )
                batch.summary_html = summary_html
                batch.summary_docx = summary_docx
            except Exception as exc:
                batch.errors.append(("汇总摘要", str(exc)))
        return batch
    finally:
        _cleanup_collection_refs(jobs)


def main():
    if len(sys.argv) < 2:
        print("用法: python src/report_gen.py <采集目录或tar.gz> [...] [-o output.html] [--summary|--no-summary] [--generate-summary]")
        print("")
        print("示例:")
        print("  python src/report_gen.py ./output/raw/20260612_100000")
        print("  python src/report_gen.py oracle_check_20260612_100000.tar.gz")
        print("  python src/report_gen.py host_check.tar.gz db_check.tar.gz -o report.html")
        print("  python src/report_gen.py host_a.tar.gz host_b.tar.gz --summary")
        sys.exit(1)

    args = sys.argv[1:]
    output_file = None
    write_summary = True
    generate_summary_content = False
    if "--no-summary" in args:
        write_summary = False
        args.remove("--no-summary")
    if "--summary" in args:
        write_summary = True
        args.remove("--summary")
    if "--generate-summary" in args:
        generate_summary_content = True
        args.remove("--generate-summary")
    if "-o" in args or "--output" in args:
        flag = "-o" if "-o" in args else "--output"
        idx = args.index(flag)
        if idx + 1 >= len(args):
            print("ERROR: -o/--output 后必须指定报告文件名")
            sys.exit(2)
        output_file = args[idx + 1]
        del args[idx:idx + 2]
    elif len(args) >= 2 and Path(args[-1]).suffix.lower() in (".html", ".docx"):
        # 兼容旧版的第二位置参数输出方式。
        output_file = args.pop()
    if not args:
        print("ERROR: 至少需要一个采集包或目录")
        sys.exit(2)

    try:
        batch = build_reports(
            args, output_file, write_summary=write_summary,
            generate_summary_content=generate_summary_content,
        )
    except ReportBuildError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    for outputs in batch.reports:
        print(f"主机: {outputs.env_info.get('hostname', 'N/A')}")
        print(f"数据库: {outputs.env_info.get('oracle_sid', 'N/A')}")
        if outputs.html:
            print(f"HTML 报告: {outputs.html}")
        if outputs.docx:
            print(f"Word 报告: {outputs.docx}")
        print(f"健康评分: {outputs.health_score}/100")
        breakdown = calculate_score_breakdown(outputs.results)
        print(f"数据可信度: {breakdown.confidence}")
        print(
            f"正常: {outputs.counts['OK']}, 警告: {outputs.counts['WARN']}, "
            f"严重: {outputs.counts['CRIT']}, 信息: {outputs.counts.get('INFO', 0)}, "
            f"数据异常: {outputs.counts.get('UNKNOWN', 0)}"
        )
        print("")
    if batch.summary_html or batch.summary_docx:
        print("汇总摘要:")
        if batch.summary_html:
            print(f"HTML 报告: {batch.summary_html}")
        if batch.summary_docx:
            print(f"Word 报告: {batch.summary_docx}")
        print("")
    for label, message in batch.errors:
        print(f"ERROR: {label}: {message}")
    if batch.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
