"""Offline, evidence-preserving Alert Log analysis shared by HTML and Word.

Knowledge describes observed symptoms. A historical log never proves that a
failure still exists, or that a later inspection snapshot caused it.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
import html
import re

from ora_knowledge import catalog_metadata, lookup_code
from parser.alert_event_parser import parse_alert_text, parse_alert_rows
from parser.base import CheckResult, generate_data_table, parse_env_info


MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_DETAILS = 12
MAX_OVERVIEW = 50
RISK_ORDER = {"INFO": 0, "OK": 0, "UNKNOWN": 1, "WARN": 2, "CRIT": 3}


@dataclass
class AlertFinding:
    code: str
    title: str
    official_title: str
    severity: str
    category: str
    causes: List[str]
    checks: List[str]
    actions: List[str]
    cautions: List[str]
    source_url: str
    version_note: str
    confidence: str
    codes: List[str]
    time: str
    last_time: str
    evidence: str
    location: str
    signature: str
    count: int = 1
    related: List[dict] = field(default_factory=list)


@dataclass
class AlertAnalysis:
    findings: List[AlertFinding] = field(default_factory=list)
    source: str = ""
    source_rows: int = 0
    notes: List[str] = field(default_factory=list)
    incomplete: bool = False
    available: bool = False
    catalog_version: str = "不可用"
    db_version: str = "未知"
    summary: dict = field(default_factory=dict)

    @property
    def event_count(self):
        return sum(f.count for f in self.findings if f.severity != "INFO")

    @property
    def information_count(self):
        return sum(f.count for f in self.findings if f.severity == "INFO")


def _read_text(path, notes, limit=MAX_LOG_BYTES):
    """Read one bounded source without silently discarding non-UTF8 evidence."""
    if not path.is_file():
        return None, False
    partial = False
    try:
        with path.open("rb") as stream:
            size = path.stat().st_size
            bom = stream.read(4)
            encoding = "utf-16-le" if bom.startswith(b"\xff\xfe") else "utf-16-be" if bom.startswith(b"\xfe\xff") else "utf-8-sig"
            stream.seek(0)
            if size > limit:
                offset = size - limit
                stream.seek(offset - offset % 2 if encoding.startswith("utf-16") else offset)
                partial = True
                notes.append(f"{path.name} 超过分析大小上限，仅分析末尾可用内容。")
            data = stream.read(limit)
            if partial:
                newline = "\n".encode(encoding if encoding.startswith("utf-16") else "ascii")
                index = data.find(newline)
                if encoding.startswith("utf-16"):
                    while index >= 0 and index % 2:
                        index = data.find(newline, index + 1)
                data = data[index + len(newline):] if index >= 0 else b""
    except OSError as exc:
        notes.append(f"{path.name} 读取失败：{exc.__class__.__name__}。")
        return None, True
    try:
        text = data.decode(encoding).lstrip("\ufeff")
    except UnicodeError:
        try:
            text = data.decode("gb18030")
            notes.append(f"{path.name} 非 UTF-8，已回退按 GB18030 解码；源编码需核对。")
            partial = True
        except UnicodeError:
            text = data.decode("utf-8", errors="replace")
    replacements = text.count("\ufffd")
    if replacements:
        notes.append(f"{path.name} 含 {replacements} 个乱码替换字符；错误码可识别，原文证据不完整。")
        partial = True
    return text, partial


def _table_rows(text):
    rows = []
    columns = 0
    for line in (text or "").splitlines():
        if not line.strip() or re.fullmatch(r"[\s|+-]+", line):
            continue
        if "MESSAGE_TEXT" in line.upper() and "|" in line:
            columns = len(line.split("|"))
            continue
        if columns:
            rows.append([x.strip() for x in line.split("|", columns - 1)])
        elif "|" in line:
            rows.append([x.strip() for x in line.split("|")])
        else:
            rows.append(["", line])
    return rows


def _summary(text):
    lines = [s for s in (text or "").splitlines() if s.strip()]
    header = next((i for i, s in enumerate(lines) if s.lstrip().startswith("DATABASE_NAME|")), None)
    if header is None:
        return {}
    keys = [s.strip() for s in lines[header].split("|")]
    for line in lines[header + 1:]:
        if re.fullmatch(r"[\s|+-]+", line):
            continue
        return dict(zip(keys, [s.strip() for s in line.split("|")]))
    return {}


def _integer(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _generic_entry(code, title, severity="UNKNOWN"):
    return dict(code=code, title=title, official_title="", severity=severity, category="日志诊断", role="primary",
                diagnostic_level="fallback",
                causes=["现有日志不足以确定根因，需要核对完整错误栈与发生时的环境。"],
                checks=["按日志时间检查同一进程的 trace、前后文及当时实例状态。"],
                actions=["确认原因和业务影响后制定处置措施；保存诊断证据。"],
                cautions=["仅表示本次日志中观察到的现象，未确认当前故障是否仍存在。"],
                source_url="", version_note="通用排查建议", known=False)


def _choose_entry(event, entries):
    """Prefer specific error chains; generic wrappers cannot hide root codes."""
    message = "\n".join(event.lines)
    upper = message.upper()
    codes = set(event.codes)
    if {"ORA-00313", "ORA-27041"}.issubset(codes):
        entry = dict(entries["ORA-00313"])
        missing = bool(re.search(r"(?:O/S-ERROR:\s*\(OS\s*2\b|(?:OS|LINUX[^\n:]*|UNIX[^\n:]*)\s+ERROR\s*:\s*2\b)", upper))
        entry.update(title="Redo 成员文件打开失败" + ("（伴随 OS 2）" if missing else ""),
                     severity="CRIT",
                     causes=["Redo 文件打开操作失败；伴随的 ORA-00312 给出成员路径，ORA-27041 指向文件访问问题。"],
                     checks=["核对错误栈中的 Redo 成员路径、磁盘/挂载点、文件是否存在及 Oracle 服务账号权限。",
                             "查询 V$LOG、V$LOGFILE，核对日志组状态、冗余成员和近期迁移/恢复操作；不要把后续正常快照视为当时状态。"],
                     actions=["若确认路径、挂载或权限变化，按变更流程恢复正确访问；涉及 Redo 缺失时，由 DBA 结合日志组状态、备份和恢复要求制定方案。"],
                     cautions=["不要仅凭该错误执行 CLEAR LOGFILE、删除日志组或 RESETLOGS；可能影响恢复能力。"])
        if missing:
            entry["causes"].append("OS 2 支持文件或路径不可找到的判断；仍需在目标主机核实。")
        return entry, "redo-open", "高（错误链吻合；具体文件状态待核实）"
    if "DBMS_QOPATCH" in upper and "KUP-04020" in codes and codes.intersection({"ORA-06502", "ORA-29913", "ORA-29400"}):
        entry = dict(entries["KUP-04020"])
        entry.update(title="QOPatch 补丁清单读取失败", severity="WARN", category="补丁清单",
                     causes=["DBMS_QOPATCH 读取外部表时遇到超过支持缓冲区的记录；ORA-06512 是调用栈位置，不能独立计为故障。"],
                     checks=["核对 SYS.DBMS_QOPATCH 调用栈、KUP-04020 原始记录长度和 QOpatch 预处理输出。",
                             "在对应 Oracle Home 核对 OPatch 版本和 opatch lsinventory 输出，检查预处理脚本权限、输出格式及完整 RU 版本。"],
                     actions=["保存输出并确认补丁清单来源；若预处理输出异常，按对应版本官方指导修复。若版本缺陷仍有嫌疑，将 trace 和 OPatch 清单提交 Oracle Support 核实。"],
                     cautions=["该日志证明补丁信息读取失败，不等同于数据库已损坏或实际补丁安装失败。"])
        return entry, "qopatch-record", "高（子系统和伴随码吻合；底层原因待核实）"
    if "ORA-00700" in codes and "PGA PHYSMEM LIMIT" in upper:
        entry = dict(entries["ORA-00700"])
        entry.update(title="PGA 物理内存相关软断言", severity="WARN",
                     checks=["保留 [pga physmem limit] 完整参数和 incident trace，核对完整 RU 版本。",
                             "核对发生时物理/可用内存、PGA_AGGREGATE_TARGET、PGA_AGGREGATE_LIMIT、SGA/AMM 及并发负载；当前快照仅用于辅助。"],
                     actions=["确认内存压力和具体参数含义后由 DBA 评估内存预算与负载；重复出现或伴随进程终止时升级 Oracle Support。"],
                     cautions=["ORA-00700 是软内部错误；该签名不能单独证明物理内存不足，也不直接给出参数调整值。"])
        return entry, "pga-physmem", "中（签名命中，须结合 trace 和版本）"
    primary = [entries[c] for c in event.codes if entries[c].get("role") == "primary"]
    if primary:
        entry = max(primary, key=lambda e: RISK_ORDER.get(e["severity"], 1))
        signature = ""
        if entry["code"] in ("ORA-00600", "ORA-00700", "ORA-07445"):
            match = re.search(re.escape(entry["code"]) + r"[^\n]*?\[([^\]]+)\]", message, re.I)
            signature = match.group(1)[:100] if match else "参数缺失"
        entry = dict(entry)
        if signature:
            entry["title"] += f" [{signature}]"
        if not entry.get("known"):
            confidence = "低（词典未收录）"
        elif entry.get("diagnostic_level") == "domain":
            confidence = "低（官方编号和消息已核验；排查为故障域通用模板）"
        else:
            confidence = "中（精细代码释义；根因待上下文核实）"
        return entry, signature, confidence
    if event.codes:
        if all(c == "ORA-00000" for c in event.codes):
            return dict(entries["ORA-00000"]), "success", "高（成功状态码）"
        wrappers = [entries[c] for c in event.codes if entries[c].get("role") == "wrapper"]
        if wrappers:
            entry = dict(max(wrappers, key=lambda e: RISK_ORDER.get(e["severity"], 1)))
            entry["cautions"] = list(entry["cautions"]) + ["此事件缺少具体下层错误，已知失败现象仍保留，根因待补充完整错误栈。"]
            return entry, "wrapper-only", "低（下层根因码缺失）"
        entry = dict(entries[event.codes[0]])
        entry["severity"] = "UNKNOWN"
        entry["causes"] = ["仅发现调用栈、定位或包装错误；详细根因码缺失，不能据此确定故障原因。"]
        return entry, "context-only", "低（错误栈不完整）"
    if re.search(r"(?:TERMINATING (?:THE )?INSTANCE|INSTANCE (?:HAS BEEN )?TERMINATED)", upper):
        return _generic_entry("INSTANCE-TERMINATED", "实例异常终止记录", "CRIT"), "", "中（日志现象）"
    if re.search(r"HANG ID\s+\d+\s+BLOCKS\s+\d+\s+SESSIONS|HANG DETECTED|DEADLOCK DETECTED", upper):
        return _generic_entry("HANG-DETECTED", "检测到会话挂起链", "WARN"), "", "中（日志现象）"
    if re.search(r"(?:CORRUPT(?:ED|ION)?\s+(?:DATA\s+)?BLOCK|BLOCK\s+CORRUPTION)", upper) and not re.search(r"\bNO\s+(?:CORRUPT|BLOCK)|\b0\s+CORRUPT", upper):
        return _generic_entry("BLOCK-CORRUPTION", "数据块损坏相关记录", "CRIT"), "", "中（需核实验证结果）"
    if "FATAL NI CONNECT ERROR" in upper:
        return _generic_entry("NET-CONNECT", "网络连接失败记录", "WARN"), "", "中（详细错误码缺失）"
    if "ERRORS IN FILE" in upper or re.search(r"\b(?:ERROR|FATAL|CRITICAL)\s*:", upper):
        return _generic_entry("TRACE-ERROR", "日志指向诊断错误，原因待确认"), "", "低（缺少根因码）"
    # The event parser already selects diagnostic candidates. Keep an unfamiliar
    # candidate visible instead of turning an unclassified error into OK.
    return _generic_entry("UNCLASSIFIED-ALERT", "待核实的日志诊断记录"), "", "低（尚无专项规则）"


def _finding(event, entry, variant, confidence, source, entries):
    message = "\n".join(event.lines)
    # Keep distinct file/PDB/instance signatures separate even when codes match.
    code_lines = [s for s in event.lines if re.search(r"(?:ORA|TNS|KUP)-\d", s, re.I)]
    paths = re.findall(r"(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\")", "\n".join(code_lines))
    objects = "|".join(sorted({a or b for a, b in paths}))
    # Storage/object parameters are meaningful even when not quoted, including
    # ASM member names and tablespace names. Do not merge distinct resources.
    if entry["code"] in ("ORA-00313", "ORA-01110", "ORA-01652", "ORA-01653", "ORA-01654", "ORA-01688"):
        objects += "|" + "|".join(re.sub(r"\s+", " ", s.strip()) for s in code_lines if entry["code"] in s.upper() or "ORA-00312" in s.upper() or "ORA-01110" in s.upper())
    if not entry.get("known") and event.codes:
        objects += "|" + next((s[:300] for s in code_lines if entry["code"] in s.upper()), "")
    pdb = re.search(r"(?m)^([\w$#.-]+)\(\d+\):", message)
    signature = "|".join((entry["code"], variant, event.instance, event.host, objects, pdb.group(1) if pdb else ""))
    return AlertFinding(
        code=entry["code"], title=entry["title"], official_title=entry.get("official_title", ""),
        severity=entry["severity"], category=entry["category"],
        causes=list(entry["causes"]), checks=list(entry["checks"]), actions=list(entry["actions"]),
        cautions=list(entry["cautions"]), source_url=entry["source_url"], version_note=entry["version_note"],
        confidence=confidence, codes=list(event.codes), time=event.time, last_time=event.time,
        evidence=message[:5000], location=f"{source} 第 {event.line_start}–{event.line_end} " + ("数据行（不含表头/分隔行）" if source == "alert_log_recent.txt" else "行") +
        (f"；实例 {event.instance}" if event.instance else "") + (f"；主机 {event.host}" if event.host else ""),
        signature=signature, related=[dict(entries[c]) for c in event.codes if c != entry["code"]],
    )


def analyze_alert_directory(db_dir):
    analysis = AlertAnalysis()
    root = Path(db_dir)
    summary_text, summary_partial = _read_text(root / "alert_log_summary.txt", analysis.notes)
    analysis.summary = _summary(summary_text)
    analysis.incomplete = summary_partial
    path_text, path_partial = _read_text(root / "alert_log_path.txt", analysis.notes)
    path_info = dict(line.split("=", 1) for line in (path_text or "").splitlines() if "=" in line)
    for field_name, source_name in (("ALERT_FILE", "alert_log_path"), ("ALERT_FILE_SIZE_DISPLAY", "alert_file_size_display"),
                                    ("ALERT_FILE_SIZE_BYTES", "alert_file_size_bytes"), ("ANALYSIS_START_TIME", "analysis_start_time"),
                                    ("ANALYSIS_END_TIME", "analysis_end_time"), ("WINDOW_TRUNCATED", "window_truncated")):
        if not analysis.summary.get(field_name) and path_info.get(source_name):
            analysis.summary[field_name] = path_info[source_name]
    analysis.incomplete |= path_partial
    env = parse_env_info(str(root.parent))
    version_text, _ = _read_text(root / "db_version.txt", [])
    version_match = re.search(r"\bVersion\s+(\d+(?:\.\d+){1,4})", version_text or "", re.I)
    analysis.db_version = version_match.group(1) if version_match else env.get("db_version", "未知")
    raw, partial = _read_text(root / "alert_log_30days.txt", analysis.notes)
    events = []
    if raw is not None and (raw.strip() or analysis.summary.get("ALERT_COUNT") == "0"):
        analysis.source = "alert_log_30days.txt"
        analysis.source_rows = len(raw.splitlines())
        analysis.available = True
        analysis.incomplete |= partial
        events = parse_alert_text(raw)
    else:
        recent, recent_partial = _read_text(root / "alert_log_recent.txt", analysis.notes)
        if recent is not None:
            analysis.source = "alert_log_recent.txt"
            rows = _table_rows(recent)
            analysis.source_rows = len(rows)
            events = parse_alert_rows(rows)
            analysis.available = True
            analysis.incomplete |= recent_partial
        else:
            errors, errors_partial = _read_text(root / "alert_log_errors.txt", analysis.notes)
            if errors is not None:
                analysis.source = "alert_log_errors.txt"
                analysis.source_rows = len(errors.splitlines())
                events = parse_alert_text(errors)
                analysis.available = True
                analysis.incomplete |= errors_partial
        if analysis.available:
            analysis.notes.append("缺少完整时间窗口原文，使用已筛选明细归并；可能缺少上下文，事件数只代表可见明细。")
            # A filtered source can confirm a code but cannot prove no errors.
            trusted_empty = analysis.summary.get("ALERT_COUNT") == "0" and not events and analysis.source_rows == 0
            analysis.incomplete |= not trusted_empty
        else:
            analysis.notes.append("未找到可分析的 Alert 日志原文或明细；汇总数字不能替代错误栈。")
            analysis.incomplete = True
    if partial:
        analysis.incomplete = True
    if analysis.summary.get("WINDOW_TRUNCATED", "").upper() == "YES":
        analysis.notes.append("时间窗口数据量超过采集上限，仅覆盖最近可用范围，事件数为下限。")
        analysis.incomplete = True
    if env.get("platform", "").lower() == "windows" and _integer(analysis.summary.get("ANALYZED_LINE_COUNT")) >= 100000:
        analysis.notes.append("Windows 日志达到采集行数上限，旧采集端截断标记可能不准确，完整时间窗口需核实。")
        analysis.incomplete = True
    if analysis.source == "alert_log_recent.txt" and not analysis.summary and analysis.source_rows >= 200:
        analysis.notes.append("旧版明细可能达到 200 行采集上限，不能推断完整窗口的总事件数。")
        analysis.incomplete = True
    if analysis.source == "alert_log_30days.txt" and not events and _integer(analysis.summary.get("SEVERE_COUNT")) > 0:
        analysis.notes.append("原文未识别到事件，但采集汇总有严重关键词记录；请核对采集完整性。")
        analysis.incomplete = True
    if analysis.source == "alert_log_30days.txt" and raw and raw.strip() and not re.search(
            r"(?m)^\s*(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Za-z]{3}\s+\d)", raw):
        analysis.notes.append("原文没有可识别的时间戳，无法核实事件时间与时间窗口。")
        analysis.incomplete = True

    catalog_available = False
    if any(event.codes for event in events):
        try:
            metadata = catalog_metadata()
            analysis.catalog_version = metadata["catalog_version"]
            catalog_available = True
        except (OSError, ValueError, KeyError, TypeError) as exc:
            analysis.notes.append(f"ORA 词典不可用（{exc.__class__.__name__}），仅展示日志现象，请重新安装完整报告程序。")
            analysis.incomplete = True
    elif analysis.available:
        analysis.catalog_version = "按需未加载（无 ORA/TNS/KUP 事件）"

    entries = {}
    grouped = {}
    for event in events:
        for code in event.codes:
            if code not in entries:
                entries[code] = lookup_code(code, analysis.db_version) if catalog_available else _generic_entry(code, "词典不可用，含义待核实")
        entry, variant, confidence = _choose_entry(event, entries)
        if entry is None:
            continue
        known_severities = [entries[c]["severity"] for c in event.codes
                            if entries[c].get("known") and entries[c].get("role") != "context"]
        if known_severities:
            entry["severity"] = max([entry["severity"]] + known_severities, key=lambda s: RISK_ORDER[s])
        if re.search(r"(?:TERMINATING (?:THE )?INSTANCE|INSTANCE (?:HAS BEEN )?TERMINATED)", "\n".join(event.lines), re.I):
            entry["severity"] = "CRIT"
            entry["cautions"] = list(entry["cautions"]) + ["同一日志事件出现实例终止记录，应优先核实实例可用性和业务影响。"]
        finding = _finding(event, entry, variant, confidence, analysis.source, entries)
        if any(("截断" in line or "truncated" in line.lower()) and "[" in line for line in event.lines):
            analysis.incomplete = True
            analysis.notes.append("部分超长事件的展示证据被截断，请核对原始采集文件。")
        if any("交错" in line or "interleav" in line.lower() for line in event.lines):
            analysis.incomplete = True
            finding.confidence = "低（并发日志交错，错误栈归属待核实）"
            analysis.notes.append("部分日志存在并发交错，错误链关联和事件数仅作初步归并，需核对对应进程 trace。")
        if not event.time:
            analysis.incomplete = True
            analysis.notes.append("部分事件缺少时间戳，事件顺序保留但发生时间待核实。")
        existing = grouped.get(finding.signature)
        if existing:
            existing.count += 1
            existing.last_time = finding.last_time or existing.last_time
            if RISK_ORDER[finding.severity] > RISK_ORDER[existing.severity]:
                existing.severity = finding.severity
                existing.cautions = finding.cautions
                existing.evidence = finding.evidence
                existing.location = finding.location
            for code in finding.codes:
                if code not in existing.codes:
                    existing.codes.append(code)
                    existing.related.append(dict(entries[code]))
        else:
            grouped[finding.signature] = finding
    analysis.findings = sorted(grouped.values(), key=lambda f: (-RISK_ORDER.get(f.severity, 1), -f.count, f.code, f.signature))
    analysis.notes = list(dict.fromkeys(analysis.notes))
    return analysis


def _paragraph(text, css=""):
    return '<p' + (f' class="{css}"' if css else '') + '>' + html.escape(str(text)) + '</p>'


def _bullets(title, values):
    if not values:
        return ""
    return _paragraph(title, "detail-subtitle") + "<ul>" + "".join("<li>" + html.escape(v) + "</li>" for v in values) + "</ul>"


def render_alert_analysis(analysis):
    summary = analysis.summary
    parts = []
    location = [(label, summary[key]) for key, label in (
        ("DATABASE_NAME", "数据库"), ("INSTANCE_NAME", "实例"), ("HOST_NAME", "主机"),
        ("ALERT_FILE", "Alert Log 来源"), ("ALERT_FILE_SIZE_DISPLAY", "物理日志大小")) if summary.get(key)]
    location.extend([("分析文件", analysis.source or "缺失"), ("数据库版本", analysis.db_version),
                     ("知识库", analysis.catalog_version)])
    start = summary.get("ANALYSIS_START_TIME") or summary.get("FIRST_TIME", "")
    end = summary.get("ANALYSIS_END_TIME") or summary.get("LAST_TIME", "")
    if start or end:
        location.append(("分析时间范围", f"{start or '未知'} 至 {end or '未知'}"))
    if "ALERT_COUNT" in summary:
        location.append(("采集端关键词命中行数", f"{summary['ALERT_COUNT']} 行（含错误栈、重复行和可能的普通文本，不等于事件数）"))
    parts.append(generate_data_table(["定位信息", "值"], location))
    parts.append(_paragraph("以下结论描述日志记录的历史现象，当前状态与根因需按排查步骤核实。一次错误栈可能包含多个代码；重复事件按特征分组，发生次数仍保留。", "detail-note"))
    for note in analysis.notes:
        parts.append(_paragraph(note, "detail-note"))
    visible = [f for f in analysis.findings if f.severity != "INFO"]
    if visible:
        parts.append(generate_data_table(["主要错误 / 现象", "风险", "事件次数", "首次记录", "最后记录"], [
            (f"{f.code}：{f.title}", f.severity, str(f.count), f.time or "时间缺失", f.last_time or "时间缺失")
            for f in visible[:MAX_OVERVIEW]
        ]))
        if len(visible) > MAX_OVERVIEW:
            parts.append(_paragraph(f"共 {len(visible)} 个分组，概览展示优先级最高的 {MAX_OVERVIEW} 个，其余需查看原文。", "detail-note"))
        if len(visible) > MAX_DETAILS:
            parts.append(_paragraph(f"下方展开 {MAX_DETAILS} 个优先处理分组；未展开分组仍计入统计。", "detail-note"))
        for finding in visible[:MAX_DETAILS]:
            parts.append(_paragraph(f"{finding.code} — {finding.title}", "detail-subtitle"))
            if finding.official_title and finding.official_title != finding.title:
                parts.append(_paragraph("官方消息：" + finding.official_title))
            parts.append(_paragraph(f"置信度：{finding.confidence}；{finding.version_note}"))
            parts.append(_paragraph("关联错误栈：" + (" → ".join(finding.codes) or "无标准错误码")))
            parts.append(_bullets("含义与候选原因", finding.causes))
            if finding.related:
                parts.append(generate_data_table(["伴随代码", "含义", "作用"], [
                    (e["code"], e["title"], {"context": "上下文/调用栈", "wrapper": "包装错误", "primary": "需结合错误链"}.get(e.get("role"), "待核实"))
                    for e in finding.related
                ]))
            parts.append(_bullets("建议排查（仅供人工核查）", finding.checks))
            parts.append(_bullets("处理建议", finding.actions))
            parts.append(_bullets("注意事项", finding.cautions))
            parts.append(_paragraph("证据位置：" + finding.location, "detail-note"))
            parts.append(generate_data_table(["原始错误栈示例"], [(s,) for s in finding.evidence.splitlines()[:30]]))
            if len(finding.evidence.splitlines()) > 30 or len(finding.evidence) >= 5000:
                parts.append(_paragraph("示例已截短，完整错误栈见所标注的采集文件。", "detail-note"))
            if finding.source_url:
                # Display URL as text too, so the Word renderer preserves it.
                url = html.escape(finding.source_url, quote=True)
                parts.append(f'<p><a href="{url}">官方参考：{url}</a></p>')
    if analysis.information_count:
        parts.append(_paragraph(f"另识别 {analysis.information_count} 个信息性记录，未计入告警事件。", "detail-note"))
    return "".join(parts)


def build_alert_check(db_dir):
    analysis = analyze_alert_directory(db_dir)
    visible = [f for f in analysis.findings if f.severity != "INFO"]
    status = max((f.severity for f in visible), key=lambda s: RISK_ORDER.get(s, 1), default="OK")
    if analysis.incomplete and status == "OK":
        status = "UNKNOWN"
    suggestion = "；".join(f"{f.code}：{f.title}，{f.checks[0]}" for f in visible[:2])
    if not visible and analysis.incomplete:
        suggestion = "补充完整 Alert 日志及错误栈，核对采集时间范围和来源。"
    size = _integer(analysis.summary.get("ALERT_FILE_SIZE_BYTES"))
    size_display = analysis.summary.get("ALERT_FILE_SIZE_DISPLAY", "")
    if size > 2 * 1024 * 1024 * 1024:
        if RISK_ORDER[status] < RISK_ORDER["WARN"]:
            status = "WARN"
        cleanup = "Alert Log 超过2GB，先保留诊断证据，再按日志保留策略归档清理。"
        suggestion = f"{suggestion}；{cleanup}" if suggestion else cleanup
    value = f"{analysis.event_count}个已观测告警事件 / {len(visible)}组"
    if analysis.incomplete and analysis.available:
        value += "（证据有限）"
    if not analysis.available:
        value = "缺少可分析的 Alert 日志"
    if size_display:
        value += f" / 日志 {size_display}"
    detail = f"按错误栈归并：{analysis.event_count}个事件，严重事件 {sum(f.count for f in visible if f.severity == 'CRIT')} 个"
    if "ALERT_COUNT" in analysis.summary:
        detail += f"；采集端关键词命中 {analysis.summary['ALERT_COUNT']} 行（非事件数）"
    start = analysis.summary.get("ANALYSIS_START_TIME") or analysis.summary.get("FIRST_TIME", "")
    end = analysis.summary.get("ANALYSIS_END_TIME") or analysis.summary.get("LAST_TIME", "")
    if start or end:
        detail += f"；分析时间范围: {start or '未知'} 至 {end or '未知'}"
    if analysis.incomplete:
        detail += "；证据覆盖有限，详见分析完整性说明"
    return CheckResult("Alert Log", status, value, detail, suggestion, render_alert_analysis(analysis))
