# -*- coding: utf-8 -*-
"""根据单份巡检结果生成可复用的报告总结内容。"""
from dataclasses import dataclass
import re
from typing import Dict, List

from config import CATEGORY_NAMES, CATEGORY_ORDER
from parser.base import CheckResult
from scoring import collection_confidence


MAX_SUMMARY_ISSUES = 12
MAX_SUMMARY_RECOMMENDATIONS = 10


@dataclass
class InspectionSummary:
    overview: str
    conclusion: str
    issues: List[str]
    recommendations: List[str]
    omitted_issues: int = 0
    omitted_recommendations: int = 0


def _compact(value, limit=160) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) > limit:
        return text[:limit - 1].rstrip() + "…"
    return text


def _ordered_categories(results: Dict[str, List[CheckResult]]) -> List[str]:
    return (
        [category for category in CATEGORY_ORDER if category in results]
        + [category for category in results if category not in CATEGORY_ORDER]
    )


def build_inspection_summary(results: Dict[str, List[CheckResult]], counts: dict,
                             health_score: int) -> InspectionSummary:
    """生成总体结论、重点问题和去重后的处置建议。"""
    crit = int(counts.get("CRIT", 0))
    warn = int(counts.get("WARN", 0))
    ok = int(counts.get("OK", 0))
    total = int(counts.get("TOTAL", ok + warn + crit))
    info = int(counts.get("INFO", 0))
    confidence, _ = collection_confidence(results)
    if crit:
        status = "存在严重问题"
        conclusion = (
            "本次巡检发现严重风险，应优先处置严重项，并对相关配置、容量和安全风险"
            "完成复核；警告项应纳入后续整改计划并持续跟踪。"
        )
    elif warn:
        status = "存在警告"
        conclusion = (
            "系统当前具备继续运行条件，但仍存在需要关注的风险项。建议按影响范围和"
            "紧迫程度安排整改，并在变更后进行复查。"
        )
    else:
        status = "正常"
        conclusion = (
            "本次巡检未发现警告或严重问题，建议继续保持现有运维策略，并按计划开展"
            "周期性巡检和容量趋势复核。"
        )

    overview = (
        f"本次巡检共完成 {total} 项检查，其中正常 {ok} 项、警告 {warn} 项、"
        f"严重 {crit} 项、信息/不适用 {info} 项；健康评分为 {int(health_score)}/100，"
        f"总体状态为“{status}”，数据可信度为“{confidence}”。"
    )

    severity_order = {"CRIT": 0, "WARN": 1}
    issue_rows = []
    sequence = 0
    for category in _ordered_categories(results):
        category_name = CATEGORY_NAMES.get(category, category)
        for item in results[category]:
            if item.status not in severity_order:
                continue
            evidence = _compact(item.value) or _compact(item.detail)
            label = "严重" if item.status == "CRIT" else "警告"
            text = f"[{label}] {category_name} / {_compact(item.name, 80)}"
            if evidence:
                text += f"：{evidence}"
            issue_rows.append((severity_order[item.status], sequence, text, item))
            sequence += 1
    issue_rows.sort(key=lambda row: (row[0], row[1]))

    issues = [row[2] for row in issue_rows[:MAX_SUMMARY_ISSUES]]
    omitted_issues = max(0, len(issue_rows) - len(issues))

    recommendations = []
    known = set()
    for _, _, _, item in issue_rows:
        suggestion = _compact(item.suggestion, 180)
        if not suggestion:
            continue
        key = suggestion.casefold()
        if key in known:
            continue
        known.add(key)
        recommendations.append(f"{_compact(item.name, 80)}：{suggestion}")
    omitted_recommendations = max(
        0, len(recommendations) - MAX_SUMMARY_RECOMMENDATIONS
    )
    recommendations = recommendations[:MAX_SUMMARY_RECOMMENDATIONS]

    return InspectionSummary(
        overview=overview,
        conclusion=conclusion,
        issues=issues,
        recommendations=recommendations,
        omitted_issues=omitted_issues,
        omitted_recommendations=omitted_recommendations,
    )
