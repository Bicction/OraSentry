# -*- coding: utf-8 -*-
"""Versioned offline Oracle diagnostic notes; no network or database access.

The catalog prioritizes operationally useful errors but is not the complete
Oracle namespace. A code alone does not prove a root cause or a specific fix.
"""
import copy
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit


CODE_PATTERN = re.compile(r"^(ORA|TNS|KUP)-([0-9]{5,})$")
_INPUT_CODE_PATTERN = re.compile(r"^(ORA|TNS|KUP)\s*-\s*([0-9]+)$", re.IGNORECASE)
_STRING_FIELDS = ("code", "title", "official_title", "category", "severity", "role", "diagnostic_level", "source_url", "version_note")
_LIST_FIELDS = ("causes", "checks", "actions", "cautions", "versions")
_SOURCE_BASE = "https://docs.oracle.com/en/error-help/db/"


class CatalogError(ValueError):
    """The bundled knowledge catalog is missing, unreadable or invalid."""


def _catalog_path():
    if getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS) / "resources" / "ora" / "catalog.json"
    return Path(__file__).resolve().parents[1] / "resources" / "ora" / "catalog.json"


def _validate_catalog(catalog):
    if not isinstance(catalog, dict):
        raise CatalogError("ORA 词典根节点必须为对象")
    if type(catalog.get("schema_version")) is not int or catalog["schema_version"] != 1:
        raise CatalogError("ORA 词典 schema_version 必须为 1")
    for field in ("catalog_version", "coverage_note", "version_note", "source_policy"):
        if not isinstance(catalog.get(field), str) or not catalog[field].strip():
            raise CatalogError("ORA 词典缺少有效字段: " + field)
    if not isinstance(catalog.get("entries"), list) or not catalog["entries"]:
        raise CatalogError("ORA 词典 entries 必须为非空列表")
    seen = set()
    for index, entry in enumerate(catalog["entries"]):
        label = "ORA 词典第 %d 个词条" % (index + 1)
        if not isinstance(entry, dict):
            raise CatalogError(label + "必须为对象")
        for field in _STRING_FIELDS:
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise CatalogError(label + "缺少有效字段: " + field)
        code = entry["code"]
        if not CODE_PATTERN.fullmatch(code):
            raise CatalogError(label + "错误码格式无效: " + code)
        if code in seen:
            raise CatalogError("ORA 词典包含重复错误码: " + code)
        seen.add(code)
        if entry["severity"] not in {"INFO", "WARN", "CRIT", "UNKNOWN"}:
            raise CatalogError(code + "严重度无效")
        if entry["role"] not in {"primary", "context", "wrapper"}:
            raise CatalogError(code + "错误栈角色无效")
        if entry["diagnostic_level"] not in {"curated", "domain"}:
            raise CatalogError(code + "诊断层级无效")
        for field in _LIST_FIELDS:
            value = entry.get(field)
            if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
                raise CatalogError(code + "字段必须为字符串列表: " + field)
            if field in {"checks", "actions"} and not value:
                raise CatalogError(code + "缺少诊断内容: " + field)
        try:
            source = urlsplit(entry["source_url"])
            source_valid = source.scheme == "https" and source.netloc == "docs.oracle.com"
        except ValueError:
            source_valid = False
        if not source_valid:
            raise CatalogError(code + "来源必须为 Oracle 官方 HTTPS 文档链接")
    return catalog


def _deduplicate_catalog_strings(catalog):
    """Share repeated immutable values to reduce the resident catalog size."""
    pool = {}

    def shared(value):
        return pool.setdefault(value, value)

    for field in ("catalog_version", "coverage_note", "version_note", "source_policy"):
        catalog[field] = shared(catalog[field])
    for entry in catalog["entries"]:
        for field in _STRING_FIELDS:
            entry[field] = shared(entry[field])
        for field in _LIST_FIELDS:
            entry[field] = [shared(value) for value in entry[field]]
    return catalog


@lru_cache(maxsize=4)
def _read_catalog(path, mtime_ns, size):
    # File metadata is part of the cache key, so a replacement is noticed.
    del mtime_ns, size
    try:
        with open(path, "r", encoding="utf-8-sig") as source:
            catalog = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CatalogError("ORA 词典无法读取: %s (%s)" % (path, exc)) from exc
    return _deduplicate_catalog_strings(_validate_catalog(catalog))


def _catalog_key():
    path = _catalog_path()
    try:
        info = path.stat()
    except OSError as exc:
        raise CatalogError("ORA 词典资源缺失或不可访问: " + str(path)) from exc
    return str(path), info.st_mtime_ns, info.st_size


def _get_catalog():
    return _read_catalog(*_catalog_key())


@lru_cache(maxsize=4)
def _read_index(path, mtime_ns, size):
    catalog = _read_catalog(path, mtime_ns, size)
    return {entry["code"]: entry for entry in catalog["entries"]}


def _get_entry(code):
    return _read_index(*_catalog_key()).get(code)


def load_catalog():
    """Return a caller-owned catalog; raise CatalogError on resource problems."""
    return copy.deepcopy(_get_catalog())


def catalog_metadata():
    """Return lightweight catalog metadata without copying thousands of entries."""
    catalog = _get_catalog()
    return {
        "catalog_version": catalog["catalog_version"],
        "coverage_note": catalog["coverage_note"],
        "version_note": catalog["version_note"],
        "source_policy": catalog["source_policy"],
        "entry_count": len(catalog["entries"]),
    }


def lookup_code(code, db_version=""):
    """Return a complete diagnostic record, including an explicit unknown fallback.

    ``versions`` lists explicitly verified releases only. Empty means conceptual
    guidance, not a claim that every database release has the same meaning.
    """
    normalized = str(code).strip().upper()
    match = _INPUT_CODE_PATTERN.fullmatch(normalized)
    if match:
        normalized = match.group(1).upper() + "-" + match.group(2).zfill(5)
    entry = _get_entry(normalized)
    version = str(db_version or "").strip()
    if entry is not None:
        result = copy.deepcopy(entry)
        result["known"] = True
        if not result["versions"]:
            result["version_note"] = (
                ("数据库版本 %s：" % version if version else "数据库版本未提供：")
                + entry["version_note"]
            )
        elif version not in result["versions"]:
            result["version_note"] = (
                ("数据库版本 %s 未匹配已核验版本；" % version if version else "数据库版本未提供；")
                + entry["version_note"]
                + "请按目标 Oracle Home 的消息和官方版本资料复核。"
            )
        return result
    custom = bool(re.fullmatch(r"ORA-20[0-9]{3}", normalized))
    valid = bool(CODE_PATTERN.fullmatch(normalized))
    return {
        "code": normalized,
        "title": "应用自定义错误，需结合消息正文与应用代码解释" if custom else "词典未收录此错误码，原因待核实",
        "official_title": "",
        "category": "应用自定义" if custom else "未收录",
        "severity": "UNKNOWN",
        "role": "primary",
        "diagnostic_level": "fallback",
        "causes": [],
        "checks": [
            "保留完整错误栈、发生时间和上下文，核对原始错误文本。",
            "检查触发错误的应用或存储过程及自定义错误映射。" if custom else "在目标 Oracle Home 查询本机消息，或通过官方错误索引核对该版本。",
        ],
        "actions": ["确认真实原因和影响范围后，由对应应用负责人制定处理方案。" if custom else "补充匹配版本的错误说明与上下文后再制定处置方案。"],
        "cautions": ["仅凭错误编号无法确定故障原因；未提供自动修复建议。"],
        "versions": [],
        "source_url": _SOURCE_BASE + normalized.lower() + "/" if valid and not custom else _SOURCE_BASE,
        "known": False,
        "version_note": ("数据库版本 %s；" % version if version else "数据库版本未提供；") + "此编号尚无已核验的离线条目。",
    }
