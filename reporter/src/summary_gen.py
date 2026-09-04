# -*- coding: utf-8 -*-
"""将多份巡检报告的执行摘要合并为管理层汇总摘要（HTML + Word）。"""
import datetime
import html
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Dict, List, Optional, Sequence, Tuple

from config import CATEGORY_NAMES, CATEGORY_ORDER, REPORT_CONFIG
from parser.base import CheckResult
from scoring import calculate_score_breakdown, check_weight, score_band


EMPTY_SID = {"", "N/A", "NA", "NONE"}
MAX_WARN_ACTIONS = 80
MAX_SYSTEM_ISSUES = 8
STATUS_LABELS = {
    "OK": "正常", "WARN": "警告", "CRIT": "严重",
    "INFO": "信息", "UNKNOWN": "数据异常",
}
RISK_CLASS = {"高": "risk-high", "中": "risk-mid", "低": "risk-low"}


@dataclass
class IssueRef:
    """单份报告中的一条待处理事项。"""
    category: str
    category_name: str
    name: str
    status: str
    value: str
    suggestion: str
    system_label: str = ""
    hostname: str = ""
    oracle_sid: str = ""


@dataclass
class SystemSummary:
    """一份巡检报告压缩后的摘要视图。"""
    hostname: str = "N/A"
    server_ip: str = "N/A"
    oracle_sid: str = "N/A"
    timestamp: str = ""
    formatted_time: str = "N/A"
    health_score: int = 0
    overall_status: str = "正常"
    confidence: str = "无法验证"
    score_earned: int = 0
    score_possible: int = 0
    critical_weight: int = 0
    counts: Dict[str, int] = field(
        default_factory=lambda: {
            "OK": 0, "WARN": 0, "CRIT": 0,
            "INFO": 0, "UNKNOWN": 0, "TOTAL": 0,
        }
    )
    categories: List[str] = field(default_factory=list)
    issues: List[IssueRef] = field(default_factory=list)
    html_name: str = ""
    docx_name: str = ""
    label: str = ""


@dataclass
class Cluster:
    category: str
    category_name: str
    name: str
    worst_status: str
    systems: List[IssueRef]


@dataclass
class CategoryRollup:
    category: str
    name: str
    ok: int = 0
    warn: int = 0
    crit: int = 0
    info: int = 0
    unknown: int = 0
    total: int = 0


@dataclass
class SummaryModel:
    generated_at: str
    report_no: str
    date_tag: str
    time_range: str
    systems: List[SystemSummary]
    ranked: List[SystemSummary]
    fleet_score: int
    avg_score: int
    min_score: int
    max_score: int
    ok_systems: int
    warn_systems: int
    crit_systems: int
    incomplete_systems: int
    host_count: int
    db_count: int
    counts: Dict[str, int]
    overall_status: str
    risk_level: str
    clusters: List[Cluster]
    rollups: List[CategoryRollup]
    narrative: List[str]
    recommendations: List[str]


def _has_sid(value: str) -> bool:
    return str(value or "").strip().upper() not in EMPTY_SID


def _display(value, fallback="N/A") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def system_label(hostname: str, oracle_sid: str) -> str:
    host = _display(hostname, "未知主机")
    if _has_sid(oracle_sid):
        return f"{host} / {oracle_sid}"
    return host


def format_collect_time(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "N/A"
    try:
        if len(text) == 15 and "_" in text:
            return datetime.datetime.strptime(text, "%Y%m%d_%H%M%S").strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    except ValueError:
        pass
    return text


def overall_status(counts: Dict[str, int]) -> str:
    if counts.get("CRIT"):
        return "存在严重问题"
    if counts.get("WARN"):
        return "存在警告"
    return "正常"


def _score_tone(score: int) -> str:
    return score_band(score).lower()


def _score_fill_class(score: int) -> str:
    return {
        "ok": "bar-fill-ok",
        "warn": "bar-fill-warn",
        "crit": "bar-fill-crit",
    }[_score_tone(score)]


def _date_tag(timestamp: str) -> str:
    digits = "".join(ch for ch in str(timestamp or "") if ch.isdigit())
    if len(digits) >= 8:
        return digits[:8]
    return ""


def _ordered_categories(keys: Sequence[str]) -> List[str]:
    known = [key for key in CATEGORY_ORDER if key in keys]
    extra = [key for key in keys if key not in CATEGORY_ORDER]
    return known + extra


def systems_from_reports(reports) -> List[SystemSummary]:
    """把已生成的单份报告压缩为摘要条目。"""
    systems = []
    for report in reports:
        env = report.env_info or {}
        hostname = _display(env.get("hostname"))
        sid = _display(env.get("oracle_sid"))
        label = system_label(hostname, sid)
        issues = []
        categories = _ordered_categories(list((report.results or {}).keys()))
        for category in categories:
            for item in report.results.get(category) or []:
                if not isinstance(item, CheckResult):
                    continue
                if item.status not in ("CRIT", "WARN"):
                    continue
                issues.append(
                    IssueRef(
                        category=category,
                        category_name=CATEGORY_NAMES.get(category, category),
                        name=item.name,
                        status=item.status,
                        value=str(item.value or ""),
                        suggestion=str(item.suggestion or ""),
                        system_label=label,
                        hostname=hostname,
                        oracle_sid=sid,
                    )
                )
        issues.sort(key=lambda row: (0 if row.status == "CRIT" else 1, row.category, row.name))
        counts = dict(report.counts or {})
        for key in ("OK", "WARN", "CRIT", "INFO", "UNKNOWN", "TOTAL"):
            counts.setdefault(key, 0)
        score_breakdown = calculate_score_breakdown(report.results or {})
        critical_weight = sum(
            check_weight(item)
            for items in (report.results or {}).values()
            for item in items
            if isinstance(item, CheckResult) and item.status == "CRIT"
        )
        systems.append(
            SystemSummary(
                hostname=hostname,
                server_ip=_display(env.get("server_ip")),
                oracle_sid=sid,
                timestamp=str(env.get("timestamp") or ""),
                formatted_time=format_collect_time(env.get("timestamp")),
                health_score=int(report.health_score or 0),
                overall_status=overall_status(counts),
                confidence=score_breakdown.confidence,
                score_earned=score_breakdown.earned,
                score_possible=score_breakdown.possible,
                critical_weight=critical_weight,
                counts=counts,
                categories=categories,
                issues=issues,
                html_name=os.path.basename(report.html) if getattr(report, "html", None) else "",
                docx_name=os.path.basename(report.docx) if getattr(report, "docx", None) else "",
                label=label,
            )
        )
    return systems


def _build_clusters(systems: List[SystemSummary]) -> List[Cluster]:
    grouped: Dict[Tuple[str, str], List[IssueRef]] = defaultdict(list)
    for system in systems:
        seen = set()
        for issue in system.issues:
            key = (issue.category, issue.name)
            if key in seen:
                continue
            seen.add(key)
            grouped[key].append(issue)
    clusters = []
    for (category, name), items in grouped.items():
        if len(items) < 2:
            continue
        worst = "CRIT" if any(item.status == "CRIT" for item in items) else "WARN"
        clusters.append(
            Cluster(
                category=category,
                category_name=CATEGORY_NAMES.get(category, category),
                name=name,
                worst_status=worst,
                systems=items,
            )
        )
    clusters.sort(
        key=lambda row: (
            0 if row.worst_status == "CRIT" else 1,
            -len(row.systems),
            row.category_name,
            row.name,
        )
    )
    return clusters


def _build_rollups(reports) -> List[CategoryRollup]:
    buckets: Dict[str, CategoryRollup] = {}
    for report in reports:
        for category, items in (report.results or {}).items():
            rollup = buckets.setdefault(
                category,
                CategoryRollup(category=category, name=CATEGORY_NAMES.get(category, category)),
            )
            for item in items:
                status = getattr(item, "status", "")
                if status == "OK":
                    rollup.ok += 1
                elif status == "WARN":
                    rollup.warn += 1
                elif status == "CRIT":
                    rollup.crit += 1
                elif status == "INFO":
                    rollup.info += 1
                elif status == "UNKNOWN":
                    rollup.unknown += 1
                rollup.total += 1
    ordered = _ordered_categories(list(buckets.keys()))
    return [buckets[key] for key in ordered]


def _write_narrative(model_kwargs: dict) -> List[str]:
    system_count = model_kwargs["system_count"]
    host_count = model_kwargs["host_count"]
    db_count = model_kwargs["db_count"]
    time_range = model_kwargs["time_range"]
    fleet_score = model_kwargs["fleet_score"]
    avg_score = model_kwargs["avg_score"]
    risk_level = model_kwargs["risk_level"]
    overall = model_kwargs["overall_status"]
    ok_systems = model_kwargs["ok_systems"]
    warn_systems = model_kwargs["warn_systems"]
    crit_systems = model_kwargs["crit_systems"]
    incomplete_systems = model_kwargs["incomplete_systems"]
    counts = model_kwargs["counts"]
    ranked = model_kwargs["ranked"]
    clusters = model_kwargs["clusters"]

    paragraphs = [
        (
            f"本次汇总覆盖 {system_count} 套系统（涉及 {host_count} 台主机、"
            f"{db_count} 个数据库实例），巡检时间范围为 {time_range}。"
            f"数据均来自现场采集包的自动解析结果，本文件只合并各系统执行摘要，"
            f"不替代单机/单库详细巡检报告。"
        ),
        (
            f"按检查项加权，整体健康评分为 {fleet_score}/100，系统平均分为 {avg_score}/100，"
            f"风险等级为「{risk_level}」，总体结论：{overall}。"
            f"其中运行正常 {ok_systems} 套，存在警告 {warn_systems} 套，"
            f"存在严重问题 {crit_systems} 套。"
            f"合计检查 {counts['TOTAL']} 项，正常 {counts['OK']} 项，"
            f"警告 {counts['WARN']} 项，严重 {counts['CRIT']} 项，"
            f"信息/不适用 {counts.get('INFO', 0)} 项。"
        ),
    ]
    if incomplete_systems:
        paragraphs.append(
            f"其中 {incomplete_systems} 套系统的数据可信度不是“完整”，其评分仅供参考，"
            "应先修复采集问题并重新巡检。"
        )
    focus = [item.label for item in ranked[:3] if item.counts.get("CRIT") or item.health_score < 80]
    if not focus:
        focus = [item.label for item in ranked[:3]]
    if focus:
        paragraphs.append(f"建议优先关注：{'、'.join(focus)}。")
    if clusters:
        names = "、".join(
            f"{item.name}（{len(item.systems)}套）" for item in clusters[:5]
        )
        paragraphs.append(f"跨系统共性风险包括：{names}。建议按问题类型统一整改，避免逐台重复处置。")
    else:
        paragraphs.append("本期未发现跨系统共性风险，现存问题主要集中在个别系统，可按系统分别闭环。")
    return paragraphs


def _write_recommendations(counts, crit_systems, warn_systems, clusters, ranked) -> List[str]:
    recs = []
    if counts.get("CRIT"):
        recs.append(
            "立即组织专项处置，优先关闭全部严重项；未关闭前应提高巡检频率，并评估业务影响与回退方案。"
        )
    if counts.get("WARN"):
        recs.append("将警告项纳入本周变更窗口，明确责任人、完成时限与验证标准。")
    if clusters:
        recs.append("对跨系统共性风险制定统一整改方案和验收清单，避免各系统各自为战。")
    priority = [
        item.label for item in ranked
        if item.counts.get("CRIT") or item.health_score < 60
    ][:5]
    if priority:
        recs.append(f"优先处置健康评分偏低或存在严重项的系统：{'、'.join(priority)}。")
    recs.append(
        "各系统的明细数据、图表与整改步骤见对应单机/单库巡检报告；本摘要仅作为管理层总览、风险排序与派工依据。"
    )
    if not counts.get("CRIT") and not counts.get("WARN"):
        recs.append("本期未发现警告或严重项，建议维持现有巡检周期，并持续关注容量、性能与安全基线趋势。")
    if crit_systems or warn_systems:
        recs.append("整改完成后应复检并更新本汇总，确保严重项清零、警告项持续下降。")
    return recs


def build_summary_model(systems: List[SystemSummary], reports=None) -> SummaryModel:
    if not systems:
        raise ValueError("至少需要两份巡检报告才能生成汇总摘要")

    now = datetime.datetime.now()
    dates = [_date_tag(item.timestamp) for item in systems if _date_tag(item.timestamp)]
    date_tag = max(dates) if dates else now.strftime("%Y%m%d")
    time_range = _time_range([item.formatted_time for item in systems])

    counts = {"OK": 0, "WARN": 0, "CRIT": 0, "INFO": 0, "UNKNOWN": 0, "TOTAL": 0}
    for item in systems:
        for key in counts:
            counts[key] += int(item.counts.get(key) or 0)

    scores = [int(item.health_score) for item in systems]
    avg_score = int(round(sum(scores) / max(len(scores), 1)))
    total_earned = sum(int(item.score_earned or 0) for item in systems)
    total_possible = sum(int(item.score_possible or 0) for item in systems)
    fleet_score = (
        int(round(total_earned / total_possible * 100))
        if total_possible else avg_score
    )
    crit_systems = sum(1 for item in systems if item.counts.get("CRIT"))
    warn_systems = sum(
        1 for item in systems if not item.counts.get("CRIT") and item.counts.get("WARN")
    )
    ok_systems = len(systems) - crit_systems - warn_systems
    incomplete_systems = sum(1 for item in systems if item.confidence != "完整")
    hostnames = {item.hostname for item in systems if item.hostname not in EMPTY_SID}
    db_count = sum(1 for item in systems if _has_sid(item.oracle_sid))
    ranked = sorted(
        systems,
        key=lambda item: (
            0 if item.confidence != "完整" else 1,
            -int(item.critical_weight or 0),
            -int(item.counts.get("CRIT", 0) or 0),
            item.health_score,
            item.label,
        ),
    )
    clusters = _build_clusters(systems)
    rollups = _build_rollups(reports) if reports is not None else _rollups_from_systems(systems)
    overall = overall_status(counts)
    risk_level = "高" if counts["CRIT"] or crit_systems else "中" if counts["WARN"] else "低"

    payload = {
        "system_count": len(systems),
        "host_count": len(hostnames),
        "db_count": db_count,
        "time_range": time_range,
        "fleet_score": fleet_score,
        "avg_score": avg_score,
        "risk_level": risk_level,
        "overall_status": overall,
        "ok_systems": ok_systems,
        "warn_systems": warn_systems,
        "crit_systems": crit_systems,
        "incomplete_systems": incomplete_systems,
        "counts": counts,
        "ranked": ranked,
        "clusters": clusters,
    }
    return SummaryModel(
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
        report_no=f"INS-SUM-{date_tag}",
        date_tag=date_tag,
        time_range=time_range,
        systems=systems,
        ranked=ranked,
        fleet_score=fleet_score,
        avg_score=avg_score,
        min_score=min(scores),
        max_score=max(scores),
        ok_systems=ok_systems,
        warn_systems=warn_systems,
        crit_systems=crit_systems,
        incomplete_systems=incomplete_systems,
        host_count=len(hostnames),
        db_count=db_count,
        counts=counts,
        overall_status=overall,
        risk_level=risk_level,
        clusters=clusters,
        rollups=rollups,
        narrative=_write_narrative(payload),
        recommendations=_write_recommendations(
            counts, crit_systems, warn_systems, clusters, ranked
        ),
    )


def _rollups_from_systems(systems: List[SystemSummary]) -> List[CategoryRollup]:
    buckets: Dict[str, CategoryRollup] = {}
    for system in systems:
        for category in system.categories:
            buckets.setdefault(
                category,
                CategoryRollup(category=category, name=CATEGORY_NAMES.get(category, category)),
            )
        for issue in system.issues:
            rollup = buckets.setdefault(
                issue.category,
                CategoryRollup(
                    category=issue.category,
                    name=CATEGORY_NAMES.get(issue.category, issue.category),
                ),
            )
            if issue.status == "WARN":
                rollup.warn += 1
            elif issue.status == "CRIT":
                rollup.crit += 1
            rollup.total += 1
    return [buckets[key] for key in _ordered_categories(list(buckets.keys()))]


def _time_range(values: Sequence[str]) -> str:
    items = [item for item in values if item and item != "N/A"]
    if not items:
        return "未记录"
    unique = sorted(set(items))
    if len(unique) == 1:
        return unique[0]
    return f"{unique[0]} 至 {unique[-1]}"


def _unique_path(path: Path, used_names: Optional[set]) -> Path:
    if used_names is None:
        used_names = set()
    if path.name not in used_names:
        used_names.add(path.name)
        return path
    index = 2
    while True:
        alt = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if alt.name not in used_names:
            used_names.add(alt.name)
            return alt
        index += 1


def resolve_summary_paths(output_dir: str, date_tag: str, used_names: Optional[set] = None):
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    html_path = _unique_path(folder / f"Oracle巡检汇总摘要_{date_tag}.html", used_names)
    docx_path = html_path.with_suffix(".docx")
    if used_names is not None:
        used_names.add(docx_path.name)
    return html_path, docx_path


def _badge(status: str) -> str:
    style = {
        "OK": ("badge-ok", "正常"),
        "WARN": ("badge-warn", "警告"),
        "CRIT": ("badge-crit", "严重"),
    }.get(status, ("badge-ok", status))
    return f'<span class="badge {style[0]}">{style[1]}</span>'


def _score_span(score: int) -> str:
    return f'<span class="matrix-score score-{_score_tone(score)}">{score}</span>'


def _section_header(section_id: str, icon: str, title: str, subtitle: str) -> str:
    return f"""
    <section class="section" id="{section_id}">
        <div class="section-header summary">
            <div class="sec-icon">{icon}</div>
            <div>
                <div class="sec-title">{html.escape(title)}</div>
                <div class="sec-subtitle">{html.escape(subtitle)}</div>
            </div>
        </div>"""


def _overview_nav() -> str:
    items = [
        ("overview", "128202", "总览"),
        ("exec-summary", "128196", "执行摘要"),
        ("fleet-matrix", "128203", "系统一览"),
        ("ranking", "128200", "评分排名"),
        ("clusters", "128268", "共性风险"),
        ("actions", "9888", "待处理"),
        ("systems", "128101", "分系统摘要"),
        ("conclusion", "128221", "结论建议"),
    ]
    return "".join(
        f'<a class="nav-link" href="#{anchor}">&#{icon}; {label}</a>'
        for anchor, icon, label in items
    )


def _system_nav(systems: List[SystemSummary]) -> str:
    links = []
    for index, system in enumerate(systems, start=1):
        tone = (
            "crit" if system.counts.get("CRIT") else
            "warn" if system.counts.get("WARN") else
            "unknown" if system.confidence != "完整" else "ok"
        )
        links.append(
            f'<a class="nav-link nav-check" href="#sys-{index}" title="{html.escape(system.label)}">'
            f'<span class="dot {tone}"></span>'
            f'<span class="nav-check-name">{html.escape(system.label)}</span></a>'
        )
    return (
        '<div class="nav-category">'
        '<a class="nav-link nav-category-link" href="#systems">'
        '<span class="dot db"></span>覆盖系统</a>'
        f'<div class="nav-check-list">{"".join(links)}</div></div>'
    )


def _kpi_section(model: SummaryModel) -> str:
    risk_class = RISK_CLASS.get(model.risk_level, "risk-mid")
    score_class = {
        "OK": "good", "WARN": "warn", "CRIT": "crit", "UNKNOWN": "unknown",
    }[score_band(model.fleet_score)]
    return f"""
    <header class="report-header" id="overview">
        <div class="score-ring {score_class}">{model.fleet_score}</div>
        <div class="header-info">
            <h1>{html.escape(REPORT_CONFIG["title_summary"])}</h1>
            <div class="subtitle">总体结论：{html.escape(model.overall_status)}　风险等级：
                <span class="risk-pill {risk_class}">{html.escape(model.risk_level)}</span>
            </div>
            <div class="header-meta">
                <span>覆盖 {len(model.systems)} 套系统</span>
                <span>主机 {model.host_count} 台</span>
                <span>数据库 {model.db_count} 个</span>
                <span>巡检时间 {html.escape(model.time_range)}</span>
            </div>
        </div>
    </header>
    <div class="summary-row">
        <div class="summary-card sc-total">
            <div class="sc-number">{len(model.systems)}</div>
            <div class="sc-label">覆盖系统</div>
        </div>
        <div class="summary-card sc-ok">
            <div class="sc-number">{model.ok_systems}</div>
            <div class="sc-label">运行正常</div>
        </div>
        <div class="summary-card sc-warn">
            <div class="sc-number">{model.warn_systems}</div>
            <div class="sc-label">存在警告</div>
        </div>
        <div class="summary-card sc-crit">
            <div class="sc-number">{model.crit_systems}</div>
            <div class="sc-label">存在严重问题</div>
        </div>
        <div class="summary-card sc-warn">
            <div class="sc-number">{model.counts['WARN']}</div>
            <div class="sc-label">警告项合计</div>
        </div>
        <div class="summary-card sc-crit">
            <div class="sc-number">{model.counts['CRIT']}</div>
            <div class="sc-label">严重项合计</div>
        </div>
        <div class="summary-card sc-confidence">
            <div class="sc-number">{model.incomplete_systems}</div>
            <div class="sc-label">数据待确认系统</div>
        </div>
    </div>"""


def _exec_summary_html(model: SummaryModel) -> str:
    narrative = "".join(f"<p>{html.escape(paragraph)}</p>" for paragraph in model.narrative)
    risk_class = RISK_CLASS.get(model.risk_level, "risk-mid")
    control = f"""
        <table class="doc-control">
            <tr><th>报告名称</th><td>{html.escape(REPORT_CONFIG["title_summary"])}</td></tr>
            <tr><th>报告编号</th><td>{html.escape(model.report_no)}</td></tr>
            <tr><th>编制时间</th><td>{html.escape(model.generated_at)}</td></tr>
            <tr><th>覆盖范围</th><td>{len(model.systems)} 套系统 / {model.host_count} 台主机 / {model.db_count} 个实例</td></tr>
            <tr><th>巡检时间范围</th><td>{html.escape(model.time_range)}</td></tr>
            <tr><th>整体健康评分</th><td>{model.fleet_score}/100（检查项加权）；系统平均分 {model.avg_score}/100（最低 {model.min_score}，最高 {model.max_score}）</td></tr>
            <tr><th>风险等级</th><td><span class="risk-pill {risk_class}">{html.escape(model.risk_level)}</span>　{html.escape(model.overall_status)}</td></tr>
            <tr><th>数据可信度</th><td>{model.incomplete_systems} 套系统的数据待确认</td></tr>
            <tr><th>数据来源</th><td>现场采集包自动解析，按系统合并执行摘要</td></tr>
        </table>"""
    return (
        _section_header("exec-summary", "&#128196;", "1. 执行摘要", "覆盖范围、总体结论与风险判断")
        + control
        + f'<div class="narrative">{narrative}</div></section>'
    )


def _matrix_html(model: SummaryModel) -> str:
    rows = []
    for index, system in enumerate(model.systems, start=1):
        sid = system.oracle_sid if _has_sid(system.oracle_sid) else "—"
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td><a href='#sys-{index}'>{html.escape(system.hostname)}</a></td>"
            f"<td>{html.escape(system.server_ip)}</td>"
            f"<td>{html.escape(sid)}</td>"
            f"<td>{html.escape(system.formatted_time)}</td>"
            f"<td class='center'>{_score_span(system.health_score)}</td>"
            f"<td>{html.escape(system.overall_status)}</td>"
            f"<td>{html.escape(system.confidence)}</td>"
            f"<td class='center'>{system.counts['OK']}</td>"
            f"<td class='center'>{system.counts['WARN']}</td>"
            f"<td class='center'>{system.counts['CRIT']}</td>"
            f"<td class='center'>{system.counts.get('INFO', 0)}</td>"
            "</tr>"
        )
    rollup_rows = []
    for item in model.rollups:
        rollup_rows.append(
            "<tr>"
            f"<td>{html.escape(item.name)}</td>"
            f"<td class='center'>{item.total}</td>"
            f"<td class='center'>{item.ok}</td>"
            f"<td class='center'>{item.warn}</td>"
            f"<td class='center'>{item.crit}</td>"
            f"<td class='center'>{item.info}</td>"
            f"<td class='center'>{item.unknown}</td>"
            "</tr>"
        )
    return (
        _section_header("fleet-matrix", "&#128203;", "2. 系统健康一览", "各系统评分、状态与检查项分布")
        + """
        <p class="muted-note">下表按生成顺序列出本期纳入汇总的全部巡检报告，点击主机名可跳转到该系统摘要。</p>
        <div class="table-wrap">
            <table class="check-table fleet-matrix-table">
                <thead>
                    <tr>
                        <th>序号</th><th>主机</th><th>地址</th><th>SID</th>
                        <th>巡检时间</th><th class="center">评分</th><th>总体状态</th><th>数据可信度</th>
                        <th class="center">正常</th><th class="center">警告</th><th class="center">严重</th><th class="center">信息</th>
                    </tr>
                </thead>
                <tbody>""" + "".join(rows) + """</tbody>
            </table>
        </div>
        <p class="muted-note">按巡检类别汇总（跨系统合计）：</p>
        <div class="table-wrap">
            <table class="check-table category-matrix-table">
                <thead>
                    <tr>
                        <th>类别</th><th class="center">检查项</th><th class="center">正常</th>
                        <th class="center">警告</th><th class="center">严重</th>
                        <th class="center">信息</th><th class="center">数据异常</th>
                    </tr>
                </thead>
                <tbody>""" + "".join(rollup_rows) + """</tbody>
            </table>
        </div>
        </section>"""
    )


def _ranking_html(model: SummaryModel) -> str:
    rows = []
    for index, system in enumerate(model.ranked, start=1):
        width = max(0, min(system.health_score, 100))
        rows.append(
            '<div class="rank-row">'
            f'<span class="rank-idx">{index}</span>'
            f'<span class="rank-label" title="{html.escape(system.label)}">{html.escape(system.label)}</span>'
            '<div class="bar-track">'
            f'<div class="bar-fill {_score_fill_class(system.health_score)}" style="width:{width}%"></div>'
            "</div>"
            f'<span class="rank-score score-{_score_tone(system.health_score)}">{system.health_score}</span>'
            "</div>"
        )
    return (
        _section_header("ranking", "&#128200;", "3. 风险处置排名", "数据异常、核心严重风险和健康评分综合排序")
        + f'<div class="rank-list">{"".join(rows)}</div></section>'
    )


def _clusters_html(model: SummaryModel) -> str:
    if not model.clusters:
        body = '<div class="narrative"><p>未发现跨系统共性风险。现存问题主要集中在个别系统，可按系统分别闭环。</p></div>'
    else:
        cards = []
        for cluster in model.clusters:
            tone = "crit" if cluster.worst_status == "CRIT" else ""
            lines = []
            for item in cluster.systems:
                suggestion = f"；建议：{html.escape(item.suggestion)}" if item.suggestion else ""
                lines.append(
                    f"<div>{html.escape(item.system_label)}：{html.escape(item.value)} "
                    f"{_badge(item.status)}{suggestion}</div>"
                )
            cards.append(
                f'<div class="cluster-card {tone}">'
                f'<div class="cluster-head">'
                f"<span>{html.escape(cluster.category_name)} / {html.escape(cluster.name)}</span>"
                f"<span>出现于 {len(cluster.systems)} 套系统　{_badge(cluster.worst_status)}</span>"
                f"</div><div class='cluster-sys'>{''.join(lines)}</div></div>"
            )
        body = f'<div class="cluster-list">{"".join(cards)}</div>'
    return (
        _section_header("clusters", "&#128268;", "4. 跨系统共性风险", "同一检查项在两套及以上系统出现警告或严重")
        + body
        + "</section>"
    )


def _actions_html(model: SummaryModel) -> str:
    actions = []
    for system in model.systems:
        for issue in system.issues:
            actions.append(issue)
    actions.sort(key=lambda row: (0 if row.status == "CRIT" else 1, row.system_label, row.name))
    crit_items = [item for item in actions if item.status == "CRIT"]
    warn_items = [item for item in actions if item.status == "WARN"]
    shown_warn = warn_items[:MAX_WARN_ACTIONS]
    omitted = max(0, len(warn_items) - len(shown_warn))

    if not actions:
        items_html = '<div class="action-item">本期未发现需要跟进的警告或严重问题。</div>'
    else:
        items_html = ""
        for item in crit_items + shown_warn:
            suggestion = f" — {html.escape(item.suggestion)}" if item.suggestion else ""
            items_html += (
                f'<div class="action-item">{_badge(item.status)}'
                f'<strong>{html.escape(item.system_label)}</strong>'
                f'　{html.escape(item.category_name)} / {html.escape(item.name)}：'
                f'{html.escape(item.value)}{suggestion}</div>'
            )
        if omitted:
            items_html += (
                f'<div class="action-item">另有 {omitted} 条警告未在此展开，详见各系统详细报告。</div>'
            )
    return f"""
    <div class="action-panel" id="actions">
        <div class="action-panel-header">
            <span>&#9888; 汇总待处理事项</span>
            <span class="count">{len(actions)} 项</span>
        </div>
        <div class="action-list">{items_html}</div>
    </div>"""


def _systems_html(model: SummaryModel) -> str:
    cards = []
    for index, system in enumerate(model.systems, start=1):
        tone = (
            "crit" if system.counts.get("CRIT") else
            "warn" if system.counts.get("WARN") else
            "unknown" if system.confidence != "完整" else "ok"
        )
        issues = system.issues[:MAX_SYSTEM_ISSUES]
        leftover = max(0, len(system.issues) - len(issues))
        if issues:
            issue_html = "".join(
                f'<div class="cluster-sys">{_badge(item.status)} '
                f'{html.escape(item.category_name)} / {html.escape(item.name)}：'
                f'{html.escape(item.value)}'
                f'{" — " + html.escape(item.suggestion) if item.suggestion else ""}</div>'
                for item in issues
            )
            if leftover:
                issue_html += f'<div class="cluster-sys">其余 {leftover} 项见详细报告。</div>'
        else:
            issue_html = '<div class="cluster-sys">无待处理的警告或严重项。</div>'
        links = []
        if system.html_name:
            links.append(f'<a href="{html.escape(system.html_name)}">HTML 详细报告</a>')
        if system.docx_name:
            links.append(f'<a href="{html.escape(system.docx_name)}">Word 详细报告</a>')
        link_html = f'<div class="sys-link">{"　|　".join(links)}</div>' if links else ""
        sid = system.oracle_sid if _has_sid(system.oracle_sid) else "—"
        cards.append(
            f'<div class="sys-card {tone}" id="sys-{index}">'
            f'<div class="sys-title">{index}. {html.escape(system.label)}</div>'
            f'<div class="sys-meta">'
            f'<span>地址 {html.escape(system.server_ip)}</span>'
            f'<span>SID {html.escape(sid)}</span>'
            f'<span>巡检时间 {html.escape(system.formatted_time)}</span>'
            f'<span>评分 {_score_span(system.health_score)}/100</span>'
            f'<span>{html.escape(system.overall_status)}</span>'
            f'<span>数据可信度 {html.escape(system.confidence)}</span>'
            f'<span>正常 {system.counts["OK"]} / 警告 {system.counts["WARN"]} / 严重 {system.counts["CRIT"]} / 信息 {system.counts.get("INFO", 0)}</span>'
            f"</div>{issue_html}{link_html}</div>"
        )
    return (
        _section_header("systems", "&#128101;", "5. 分系统摘要", "各系统执行摘要快照，详细内容见对应巡检报告")
        + "".join(cards)
        + "</section>"
    )


def _conclusion_html(model: SummaryModel) -> str:
    recs = "".join(f"<li>{html.escape(item)}</li>" for item in model.recommendations)
    return (
        _section_header("conclusion", "&#128221;", "6. 结论与建议", "处置优先级与后续工作安排")
        + f'<div class="conclusion-box"><ol>{recs}</ol></div>'
        + """
        <p class="muted-note">以下签批栏供打印归档时手工填写。</p>
        <table class="signoff">
            <thead>
                <tr><th>角色</th><th>姓名</th><th>日期</th><th>签字</th></tr>
            </thead>
            <tbody>
                <tr><td>编制</td><td></td><td></td><td></td></tr>
                <tr><td>审核</td><td></td><td></td><td></td></tr>
                <tr><td>批准</td><td></td><td></td><td></td></tr>
            </tbody>
        </table>
        </section>"""
    )


def generate_summary_html(model: SummaryModel, output_file: str) -> str:
    from report_gen import template_path

    template_file = template_path()
    if not os.path.isfile(template_file):
        raise FileNotFoundError(f"模板文件不存在: {template_file}")
    with open(template_file, "r", encoding="utf-8") as handle:
        template_str = handle.read()

    report_title = REPORT_CONFIG["title_summary"]
    body = (
        _kpi_section(model)
        + _exec_summary_html(model)
        + _matrix_html(model)
        + _ranking_html(model)
        + _clusters_html(model)
        + _actions_html(model)
        + _systems_html(model)
        + _conclusion_html(model)
    )
    report_html = Template(template_str).safe_substitute(
        REPORT_TITLE=report_title,
        REPORT_BRAND=REPORT_CONFIG["brand"],
        REPORT_FOOTER=html.escape(str(REPORT_CONFIG["footer"])),
        HOSTNAME=html.escape(f"{len(model.systems)} 套系统"),
        SERVER_IP=html.escape(model.time_range),
        SID_LINE=f'<span>风险等级 {html.escape(model.risk_level)}</span>',
        COLLECT_TIME=html.escape(model.generated_at),
        OVERVIEW_NAV=_overview_nav(),
        DETAIL_NAV_LABEL="覆盖系统",
        SIDEBAR_NAV=_system_nav(model.systems),
        REPORT_BODY=body,
    )
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_html, encoding="utf-8")
    return str(output_path)


def _docx_score_color(score: int) -> str:
    from docx_gen import COLORS
    return COLORS[score_band(score)]


def generate_summary_docx(model: SummaryModel, output_file: str,
                          project_name: Optional[str] = None) -> str:
    from docx import Document
    from docx.enum.section import WD_SECTION_START
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt, RGBColor
    from docx_gen import (
        COLORS,
        _add_heading,
        _configure_cover_section,
        _configure_content_header_footer,
        _configure_page,
        _configure_styles,
        _normalize_document_fonts,
        _set_cell_shading,
        _set_cell_text,
        _set_repeat_table_header,
        _set_run_font,
    )

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    project_name = str(project_name or REPORT_CONFIG["project_name"]).strip()
    project_name = project_name or REPORT_CONFIG["project_name"]
    document = Document()
    _configure_styles(document)
    _configure_cover_section(document)

    title = REPORT_CONFIG["title_summary"]
    for _ in range(3):
        document.add_paragraph()
    title_p = document.add_paragraph(style="Title")
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run(title)
    _set_run_font(title_run)
    subtitle = document.add_paragraph(style="Subtitle")
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_run = subtitle.add_run("CONSOLIDATED INSPECTION SUMMARY")
    _set_run_font(sub_run)
    line = document.add_paragraph()
    line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    line_run = line.add_run("━" * 32)
    _set_run_font(line_run)
    line_run.font.color.rgb = RGBColor.from_string(COLORS["blue"])

    score = document.add_paragraph()
    score.alignment = WD_ALIGN_PARAGRAPH.CENTER
    score_run = score.add_run(str(model.fleet_score))
    _set_run_font(score_run, 34)
    score_run.bold = True
    score_color = _docx_score_color(model.fleet_score)
    score_run.font.color.rgb = RGBColor.from_string(score_color)
    label = score.add_run("\n整体健康评分 / 100    风险等级：")
    _set_run_font(label, 11)
    risk_key = "CRIT" if model.risk_level == "高" else "WARN" if model.risk_level == "中" else "OK"
    risk_run = score.add_run(f"{model.risk_level}    {model.overall_status}")
    _set_run_font(risk_run, 11)
    risk_run.bold = True
    risk_run.font.color.rgb = RGBColor.from_string(COLORS[risk_key])

    meta = document.add_table(rows=8, cols=2)
    meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta.autofit = True
    cover_rows = [
        ("报告编号", model.report_no),
        ("覆盖范围", f"{len(model.systems)} 套系统 / {model.host_count} 台主机 / {model.db_count} 个实例"),
        ("巡检时间范围", model.time_range),
        ("系统平均分", f"{model.avg_score}/100（最低 {model.min_score}，最高 {model.max_score}）"),
        ("检查项合计", f"正常 {model.counts['OK']} / 警告 {model.counts['WARN']} / 严重 {model.counts['CRIT']} / 信息 {model.counts.get('INFO', 0)}"),
        ("数据可信度", f"{model.incomplete_systems} 套系统待确认"),
        ("编制时间", model.generated_at),
        ("报告标识", REPORT_CONFIG["brand"]),
    ]
    for row, (key, value) in zip(meta.rows, cover_rows):
        _set_cell_shading(row.cells[0], COLORS["header"])
        _set_cell_text(row.cells[0], key, bold=True, color=COLORS["navy"], size=10)
        _set_cell_text(row.cells[1], value, size=10)

    footer = document.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.paragraph_format.space_before = Pt(18)
    foot_run = footer.add_run("本文件合并各系统执行摘要，供管理层总览、风险排序与派工使用")
    _set_run_font(foot_run, 10)
    foot_run.font.color.rgb = RGBColor.from_string(COLORS["muted"])

    content_section = document.add_section(WD_SECTION_START.NEW_PAGE)
    _configure_page(content_section)
    _configure_content_header_footer(
        content_section, title, f"{len(model.systems)}套系统", project_name
    )

    _add_heading(document, "1. 执行摘要", 1)
    for paragraph in model.narrative:
        document.add_paragraph(paragraph)

    kpi = document.add_table(rows=2, cols=4)
    kpi.alignment = WD_TABLE_ALIGNMENT.CENTER
    kpi_labels = ("覆盖系统", "运行正常", "存在警告", "存在严重问题")
    kpi_values = (len(model.systems), model.ok_systems, model.warn_systems, model.crit_systems)
    kpi_fills = (COLORS["header"], COLORS["OK_BG"], COLORS["WARN_BG"], COLORS["CRIT_BG"])
    kpi_colors = (COLORS["navy"], COLORS["OK"], COLORS["WARN"], COLORS["CRIT"])
    for index, text in enumerate(kpi_labels):
        _set_cell_shading(kpi.cell(0, index), kpi_fills[index])
        _set_cell_text(kpi.cell(0, index), text, bold=True, color=kpi_colors[index],
                       align=WD_ALIGN_PARAGRAPH.CENTER)
        _set_cell_text(kpi.cell(1, index), kpi_values[index], bold=True, color=kpi_colors[index],
                       size=16, align=WD_ALIGN_PARAGRAPH.CENTER)

    _add_heading(document, "2. 系统健康一览", 1)
    document.add_paragraph("下表列出本期纳入汇总的全部巡检报告，评分按适用检查项的风险权重归一化计算。")
    matrix_rows = [[
        "序号", "主机", "地址", "SID", "巡检时间", "评分", "总体状态", "可信度", "正常", "警告", "严重", "信息",
    ]]
    for index, system in enumerate(model.systems, start=1):
        sid = system.oracle_sid if _has_sid(system.oracle_sid) else "—"
        matrix_rows.append([
            str(index), system.hostname, system.server_ip, sid, system.formatted_time,
            str(system.health_score), system.overall_status, system.confidence,
            str(system.counts["OK"]), str(system.counts["WARN"]), str(system.counts["CRIT"]),
            str(system.counts.get("INFO", 0)),
        ])
    _add_table(document, matrix_rows, header=True)

    _add_heading(document, "分类统计", 2)
    rollup_rows = [["类别", "检查项", "正常", "警告", "严重", "信息", "数据异常"]]
    for item in model.rollups:
        rollup_rows.append([
            item.name, str(item.total), str(item.ok), str(item.warn), str(item.crit),
            str(item.info), str(item.unknown),
        ])
    _add_table(document, rollup_rows, header=True)

    _add_heading(document, "3. 风险处置排名", 1)
    document.add_paragraph("按数据可信度、核心严重风险权重、严重项数量和健康评分综合排序。")
    rank_rows = [["排名", "系统", "评分", "总体状态", "可信度", "严重", "警告"]]
    for index, system in enumerate(model.ranked, start=1):
        rank_rows.append([
            str(index), system.label, str(system.health_score), system.overall_status, system.confidence,
            str(system.counts["CRIT"]), str(system.counts["WARN"]),
        ])
    _add_table(document, rank_rows, header=True)

    _add_heading(document, "4. 跨系统共性风险", 1)
    if not model.clusters:
        document.add_paragraph("未发现跨系统共性风险。现存问题主要集中在个别系统，可按系统分别闭环。")
    else:
        document.add_paragraph("同一检查项在两套及以上系统出现警告或严重时，视为共性风险。")
        for cluster in model.clusters:
            heading = document.add_paragraph(style="List Bullet")
            run = heading.add_run(
                f"[{STATUS_LABELS[cluster.worst_status]}] {cluster.category_name} / {cluster.name}"
                f"（{len(cluster.systems)} 套）"
            )
            _set_run_font(run, 10)
            run.font.color.rgb = RGBColor.from_string(COLORS[cluster.worst_status])
            for item in cluster.systems:
                line = document.add_paragraph()
                line.paragraph_format.left_indent = Pt(18)
                detail = f"{item.system_label}：{item.value}"
                if item.suggestion:
                    detail += f"；{item.suggestion}"
                detail_run = line.add_run(detail)
                _set_run_font(detail_run, 9.5)

    _add_heading(document, "5. 汇总待处理事项", 1)
    actions = []
    for system in model.systems:
        actions.extend(system.issues)
    actions.sort(key=lambda row: (0 if row.status == "CRIT" else 1, row.system_label, row.name))
    if not actions:
        document.add_paragraph("本期未发现需要跟进的警告或严重问题。")
    else:
        crit_items = [item for item in actions if item.status == "CRIT"]
        warn_items = [item for item in actions if item.status == "WARN"]
        shown = crit_items + warn_items[:MAX_WARN_ACTIONS]
        for item in shown:
            paragraph = document.add_paragraph(style="List Bullet")
            text = (
                f"[{STATUS_LABELS[item.status]}] {item.system_label}　"
                f"{item.category_name} / {item.name}：{item.value}"
            )
            run = paragraph.add_run(text)
            _set_run_font(run, 9.5)
            run.font.color.rgb = RGBColor.from_string(COLORS[item.status])
            if item.suggestion:
                extra = paragraph.add_run(f"；{item.suggestion}")
                _set_run_font(extra, 9.5)
        omitted = max(0, len(warn_items) - min(len(warn_items), MAX_WARN_ACTIONS))
        if omitted:
            document.add_paragraph(f"另有 {omitted} 条警告未在此展开，详见各系统详细报告。")

    _add_heading(document, "6. 分系统摘要", 1)
    for index, system in enumerate(model.systems, start=1):
        _add_heading(document, f"6.{index}  {system.label}", 2)
        snapshot = document.add_table(rows=6, cols=2)
        snapshot.autofit = True
        sid = system.oracle_sid if _has_sid(system.oracle_sid) else "—"
        snapshot_rows = [
            ("主机 / 地址", f"{system.hostname}　{system.server_ip}"),
            ("数据库 SID", sid),
            ("巡检时间", system.formatted_time),
            ("健康评分", f"{system.health_score}/100　{system.overall_status}"),
            ("检查项", f"正常 {system.counts['OK']} / 警告 {system.counts['WARN']} / 严重 {system.counts['CRIT']}"),
            ("详细报告", "　".join(name for name in (system.html_name, system.docx_name) if name) or "—"),
        ]
        for row, (key, value) in zip(snapshot.rows, snapshot_rows):
            _set_cell_shading(row.cells[0], COLORS["header"])
            _set_cell_text(row.cells[0], key, bold=True, color=COLORS["navy"], size=9)
            _set_cell_text(row.cells[1], value, size=9)
        issues = system.issues[:MAX_SYSTEM_ISSUES]
        if not issues:
            document.add_paragraph("无待处理的警告或严重项。")
        else:
            for item in issues:
                paragraph = document.add_paragraph(style="List Bullet")
                run = paragraph.add_run(
                    f"[{STATUS_LABELS[item.status]}] {item.category_name} / {item.name}：{item.value}"
                )
                _set_run_font(run, 9.5)
                run.font.color.rgb = RGBColor.from_string(COLORS[item.status])
                if item.suggestion:
                    extra = paragraph.add_run(f"；{item.suggestion}")
                    _set_run_font(extra, 9.5)
            leftover = len(system.issues) - len(issues)
            if leftover:
                document.add_paragraph(f"其余 {leftover} 项见该系统详细报告。")

    _add_heading(document, "7. 结论与建议", 1)
    for rec in model.recommendations:
        paragraph = document.add_paragraph(style="List Number")
        run = paragraph.add_run(rec)
        _set_run_font(run, 10.5)

    _add_heading(document, "签批栏", 2)
    document.add_paragraph("以下栏目供打印归档时手工填写。")
    sign = document.add_table(rows=4, cols=4)
    sign.style = "Table Grid"
    headers = ("角色", "姓名", "日期", "签字")
    roles = ("编制", "审核", "批准")
    for index, text in enumerate(headers):
        _set_cell_shading(sign.cell(0, index), COLORS["header"])
        _set_cell_text(sign.cell(0, index), text, bold=True, color=COLORS["navy"],
                       align=WD_ALIGN_PARAGRAPH.CENTER)
    _set_repeat_table_header(sign.rows[0])
    for row_index, role in enumerate(roles, start=1):
        _set_cell_text(sign.cell(row_index, 0), role, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
        for col in range(1, 4):
            _set_cell_text(sign.cell(row_index, col), "", align=WD_ALIGN_PARAGRAPH.CENTER)

    document.core_properties.title = title
    document.core_properties.subject = "Oracle 多系统巡检汇总摘要"
    document.core_properties.author = REPORT_CONFIG["brand"]
    document.core_properties.keywords = "Oracle, Inspection, Summary, Fleet"
    _normalize_document_fonts(document)
    document.save(str(output_path))
    return str(output_path)


def _add_table(document, rows: List[List[str]], header=True) -> None:
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx_gen import COLORS, _set_cell_shading, _set_cell_text, _set_repeat_table_header

    if not rows:
        return
    width = max(len(row) for row in rows)
    normalized = [row + [""] * (width - len(row)) for row in rows]
    table = document.add_table(rows=len(normalized), cols=width)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    font_size = 7.5 if width >= 8 else 8.5 if width >= 6 else 9
    for row_index, values in enumerate(normalized):
        for col_index, value in enumerate(values):
            cell = table.cell(row_index, col_index)
            if header and row_index == 0:
                _set_cell_shading(cell, COLORS["header"])
            _set_cell_text(
                cell, value, bold=header and row_index == 0,
                color=COLORS["navy"] if header and row_index == 0 else COLORS["text"],
                size=font_size,
            )
    if header:
        _set_repeat_table_header(table.rows[0])


def generate_summary_reports(reports, output_dir: str, write_html: bool = True,
                             write_docx: bool = True, used_names: Optional[set] = None,
                             project_name: Optional[str] = None):
    """根据已生成的多份报告输出汇总摘要，返回 (html_path, docx_path)。"""
    systems = systems_from_reports(reports)
    if len(systems) < 2:
        return None, None
    model = build_summary_model(systems, reports=reports)
    html_path, docx_path = resolve_summary_paths(output_dir, model.date_tag, used_names)
    html_file = None
    docx_file = None
    if write_html:
        html_file = generate_summary_html(model, str(html_path))
    if write_docx:
        docx_file = generate_summary_docx(
            model, str(docx_path), project_name=project_name
        )
    return html_file, docx_file
