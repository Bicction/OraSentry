# -*- coding: utf-8 -*-
"""统一的健康评分、风险状态与采集可信度模型。"""
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple, Union

from config import (
    CHECK_SCORE_PREFIX_WEIGHTS,
    CHECK_SCORE_WEIGHTS,
    DEFAULT_SCORE_WEIGHT,
)
from parser.base import CheckResult


STATUS_LOSS = {"OK": 0, "WARN": 1, "CRIT": 3}
SCORE_EXCLUDED_STATUSES = {"INFO", "UNKNOWN"}
SCORE_OK_MIN = 80
SCORE_WARN_MIN = 60


@dataclass(frozen=True)
class ScoreBreakdown:
    score: int
    earned: int
    possible: int
    scored_items: int
    confidence: str
    confidence_detail: str


def check_weight(item: CheckResult) -> int:
    """返回检查项业务权重；非评分项返回 0。"""
    if item.status in SCORE_EXCLUDED_STATUSES or item.name == "采集完整性":
        return 0
    if item.name in CHECK_SCORE_WEIGHTS:
        return max(0, int(CHECK_SCORE_WEIGHTS[item.name]))
    for prefix, weight in CHECK_SCORE_PREFIX_WEIGHTS.items():
        if item.name.startswith(prefix):
            return max(0, int(weight))
    return max(0, int(DEFAULT_SCORE_WEIGHT))


def iter_checks(results: Dict[str, List[CheckResult]]) -> Iterable[Tuple[str, CheckResult]]:
    for category, items in (results or {}).items():
        for item in items or []:
            if isinstance(item, CheckResult):
                yield category, item


def collection_confidence(results: Dict[str, List[CheckResult]]) -> Tuple[str, str]:
    """根据采集完整性项返回可信度标签和说明。"""
    integrity = [item for _, item in iter_checks(results) if item.name == "采集完整性"]
    if not integrity:
        return "无法验证", "报告结果中未包含采集完整性检查"
    unknown = [item for item in integrity if item.status == "UNKNOWN"]
    if unknown:
        if any("旧版" in str(item.value) for item in unknown):
            return "无法验证", "采集包不含执行清单，无法证明所有适用检查均成功"
        details = "；".join(str(item.value) for item in unknown if item.value)
        return "不完整", details or "存在采集失败，健康评分仅供参考"
    return "完整", "所有适用采集项均成功，跳过项不参与健康评分"


def calculate_score_breakdown(results: Dict[str, List[CheckResult]]) -> ScoreBreakdown:
    """按检查项权重和严重度归一化计算 0-100 健康分。"""
    earned = 0
    possible = 0
    scored_items = 0
    for _, item in iter_checks(results):
        weight = check_weight(item)
        if not weight or item.status not in STATUS_LOSS:
            continue
        maximum = weight * 3
        possible += maximum
        earned += maximum - weight * STATUS_LOSS[item.status]
        scored_items += 1
    score = int(earned / possible * 100) if possible else 0
    confidence, detail = collection_confidence(results)
    return ScoreBreakdown(
        score=max(0, min(100, score)),
        earned=earned,
        possible=possible,
        scored_items=scored_items,
        confidence=confidence,
        confidence_detail=detail,
    )


def calculate_health_score(
    source: Union[Dict[str, List[CheckResult]], Dict[str, int]]
) -> int:
    """计算健康分；保留 counts 入参兼容旧调用和外部集成。"""
    count_keys = {"OK", "WARN", "CRIT", "INFO", "UNKNOWN", "TOTAL"}
    if source and (
        any(isinstance(value, list) for value in source.values())
        or any(key not in count_keys for key in source)
    ):
        return calculate_score_breakdown(source).score
    counts = source or {}
    ok = max(0, int(counts.get("OK", 0)))
    warn = max(0, int(counts.get("WARN", 0)))
    crit = max(0, int(counts.get("CRIT", 0)))
    total = ok + warn + crit
    if not total:
        return 0
    earned = ok * 3 + warn * 2
    return int(earned / (total * 3) * 100)


def score_band(score: int, has_score: bool = True) -> str:
    """返回统一的评分色阶；风险状态和数据可信度应单独展示。"""
    if not has_score:
        return "UNKNOWN"
    if int(score) >= SCORE_OK_MIN:
        return "OK"
    if int(score) >= SCORE_WARN_MIN:
        return "WARN"
    return "CRIT"


def overall_status(counts: Dict[str, int]) -> str:
    if counts.get("CRIT"):
        return "存在严重问题"
    if counts.get("WARN"):
        return "存在警告"
    return "正常"


def risk_tone(counts: Dict[str, int], confidence: str = "完整") -> str:
    if counts.get("CRIT"):
        return "crit"
    if counts.get("WARN"):
        return "warn"
    if confidence != "完整":
        return "unknown"
    return "good"
