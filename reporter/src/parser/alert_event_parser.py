# -*- coding: utf-8 -*-
"""Pure, bounded-context parsing of physical and tabular Oracle alert logs.

An event is a message stack, not one matching line. Timestamps, explicit trace
headers, recurring primary messages and instance/host changes delimit stacks.
This module only identifies candidates; severity and diagnosis belong to the
analyzer. It deliberately does not treat arbitrary ``error``/``critical`` words
as evidence of a fault.

Per event we retain at most 256 source lines (plus explicit notices), 8 KiB
per line and 256 distinct codes. The beginning, recent diagnostic lines and
recent other context survive an oversized block. All input is still scanned,
so a later independent stack is not swallowed by an earlier oversized one.
The returned list naturally grows with the number of real event candidates.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple


@dataclass
class AlertEvent:
    time: str
    lines: List[str]
    codes: List[str]
    line_start: int
    line_end: int
    instance: str = ""
    host: str = ""


MAX_EVENT_LINES = 256
MAX_LINE_CHARS = 8192
MAX_EVENT_CODES = 256
TRUNCATION_MARKER = "[Alert context truncated: 上下文截断;"
INTERLEAVING_MARKER = "[Alert context interleaved: 并发 NI 日志交错，伴随错误和客户端归属不确定]"
_PRELUDE_LINES = 16
_DIAGNOSTIC_LINES = 128
_OTHER_LINES = MAX_EVENT_LINES - _PRELUDE_LINES - _DIAGNOSTIC_LINES

_CODE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<prefix>ORA|TNS|RMAN|KUP|PLS|CRS|ASM|LRM|SP2|DIA|NZE|OPW|DBV)-"
    r"(?P<number>[0-9]{3,6})(?![A-Za-z0-9_])", re.IGNORECASE
)
_ISO_TIME_RE = re.compile(
    r"^\s*\ufeff?(?P<time>[0-9]{4}-[0-9]{2}-[0-9]{2}[T ]"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?"
    r"(?:Z|\s*[+-][0-9]{2}:?[0-9]{2})?)(?=$|\s|\|)(?P<rest>.*)$",
    re.IGNORECASE,
)
_LEGACY_TIME_RE = re.compile(
    r"^\s*\ufeff?(?P<time>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\s+[A-Za-z]{2,5})?\s+[0-9]{4})(?=$|\s|\|)(?P<rest>.*)$",
    re.IGNORECASE,
)
_TRACE_START_RE = re.compile(r"^\s*(?:[A-Za-z0-9_]+\s*\([^)]*\):\s*)?Errors? in file\s+\S", re.IGNORECASE)
_NONCODE_RE = re.compile(
    r"\bFatal NI connect error\s+[0-9]+\b|"
    r"\b(?:instance|PMON|LGWR|DBW[0-9]*|SMON)\b[^\r\n]{0,120}\bterminat(?:ed|ing)\b|"
    r"\b(?:corrupt(?:ed|ion)?\s+(?:block|file)|(?:block|file|redo|controlfile)\b[^\r\n]{0,32}\bcorrupt(?:ed|ion)?)\b|"
    r"\b(?:hang detected|deadlock detected|instance is hung|instance hang detected)\b",
    re.IGNORECASE,
)
_ZERO_CORRUPTION_RE = re.compile(r"\b(?:no corrupt(?:ion|ed)?(?:\s+blocks?)?|(?:corrupt(?:ed)? blocks?|corruption)\s*(?:found)?\s*[:=]\s*0\b)", re.IGNORECASE)
_CONTEXT_RE = re.compile(
    r"\b(?:Linux|Unix|Windows|OS|O/S|Solaris|AIX|HP-UX)(?:-[A-Za-z0-9_ ]+)?\s*(?:Error|error code)\b|"
    r"\b(?:Additional information|Incident details|incident=|trace file|Error stack|Call stack|Current SQL)\b|"
    r"\b(?:ns (?:main|secondary) err code|nt (?:main|secondary|OS) err code|Tns error struct|Client address)\b",
    re.IGNORECASE,
)
_LINE_END_RE = re.compile(r"\r\n|\r|\n")

# These messages locate or describe another error and may repeat in one stack.
_CONTEXT_CODES = frozenset({"ORA-06512", "ORA-00312", "ORA-01110", "ORA-02063", "TNS-00505"})
# Internal incidents are separate occurrences from adjacent unrelated errors,
# even in legacy extracts that have lost timestamps or blank separators.
_INDEPENDENT_CODES = frozenset({"ORA-00600", "ORA-00700", "ORA-07445"})


def extract_codes(text: str) -> List[str]:
    """Return ordered unique codes, padding short numbers without truncation."""
    return _scan_codes(text)[0]


def _scan_codes(text: str, limit: Optional[int] = None) -> Tuple[List[str], bool]:
    """Internal bounded variant also reports whether codes were omitted."""
    found = []
    seen = set()
    omitted = False
    for match in _CODE_RE.finditer(text or ""):
        code = match.group("prefix").upper() + "-" + match.group("number").zfill(5)
        if code not in seen:
            if limit is None or len(found) < limit:
                seen.add(code)
                found.append(code)
            else:
                omitted = True
    return found, omitted


def _iter_lines(text: str) -> Iterable[str]:
    """Yield CR/LF lines without allocating a second whole-log list."""
    start = 0
    for match in _LINE_END_RE.finditer(text):
        yield text[start:match.start()]
        start = match.end()
    if start < len(text):
        yield text[start:]


def _clip_line(line: str) -> str:
    if len(line) <= MAX_LINE_CHARS:
        return line
    marker = " [... source line truncated ...] "
    head = (MAX_LINE_CHARS - len(marker)) // 2
    return line[:head] + marker + line[-(MAX_LINE_CHARS - head - len(marker)):]


def _is_noncode_candidate(line: str) -> bool:
    if _TRACE_START_RE.search(line):
        return True
    # Preserve other positive diagnostics even if a line also reports zero
    # corrupt blocks. Only suppress the corruption alternative itself.
    match = _NONCODE_RE.search(line)
    return bool(match and not ("corrupt" in match.group(0).lower() and _ZERO_CORRUPTION_RE.search(line)))


@dataclass
class _EventBuffer:
    time: str
    instance: str
    host: str
    head: list = field(default_factory=list)
    diagnostics: deque = field(default_factory=lambda: deque(maxlen=_DIAGNOSTIC_LINES))
    other: deque = field(default_factory=lambda: deque(maxlen=_OTHER_LINES))
    codes: List[str] = field(default_factory=list)
    seen_codes: set = field(default_factory=set)
    primary: str = ""
    total_lines: int = 0
    line_start: int = 0
    line_end: int = 0
    clipped_lines: int = 0
    omitted_codes: bool = False
    neutral_lines: int = 0
    fatal_ni_count: int = 0
    interleaved_ni: bool = False

    def append(self, serial: int, line_number: int, line: str, codes: List[str],
               omitted_codes: bool = False) -> None:
        if not self.total_lines:
            self.line_start = line_number
        self.line_end = line_number
        self.total_lines += 1
        self.omitted_codes = self.omitted_codes or omitted_codes
        if re.search(r"\bFatal NI connect error\s+[0-9]+", line, re.IGNORECASE):
            self.fatal_ni_count += 1
            self.interleaved_ni = self.interleaved_ni or self.fatal_ni_count > 1
        if len(line) > MAX_LINE_CHARS:
            self.clipped_lines += 1
        entry = (serial, _clip_line(line))
        diagnostic = bool(codes or _is_noncode_candidate(line) or _CONTEXT_RE.search(line))
        if len(self.head) < _PRELUDE_LINES:
            self.head.append(entry)
        elif diagnostic:
            self.diagnostics.append(entry)
        else:
            self.other.append(entry)
        self.neutral_lines = 0 if diagnostic else self.neutral_lines + 1
        if not self.primary:
            self.primary = next((code for code in codes if code not in _CONTEXT_CODES), "")
        for code in codes:
            if code not in self.seen_codes:
                if len(self.codes) < MAX_EVENT_CODES:
                    self.seen_codes.add(code)
                    self.codes.append(code)
                else:
                    self.omitted_codes = True

    def finish(self) -> AlertEvent:
        kept = sorted(self.head + list(self.diagnostics) + list(self.other))
        lines = [line for _, line in kept]
        omitted = self.total_lines - len(kept)
        if omitted or self.clipped_lines or self.omitted_codes:
            lines.append(
                f"{TRUNCATION_MARKER} omitted {omitted} source lines; "
                f"clipped {self.clipped_lines} long lines; "
                f"code limit reached {'yes' if self.omitted_codes else 'no'}]"
            )
        if self.interleaved_ni:
            lines.append(INTERLEAVING_MARKER)
        return AlertEvent(self.time, lines, self.codes, self.line_start,
                          self.line_end, self.instance, self.host)


class _Parser:
    def __init__(self) -> None:
        self.events: List[AlertEvent] = []
        self.current: Optional[_EventBuffer] = None
        self.prelude: deque = deque(maxlen=_PRELUDE_LINES)
        self.identity: Tuple[str, str, str] = ("", "", "")
        self.serial = 0
        self.interleaved_ni = False

    def flush(self) -> None:
        if self.current is not None:
            self.events.append(self.current.finish())
            self.current = None
        self.prelude.clear()

    def feed(self, line: str, line_number: int, time: str = "", instance: str = "",
             host: str = "", timestamp_boundary: bool = False) -> None:
        self.serial += 1
        identity = (time, instance, host)
        # Concurrent NI writers can insert the identical date header between
        # their preamble and TNS lines. Preserve this block, with uncertainty
        # marked, rather than count the preamble as another independent fault.
        same_ni_time = (identity == self.identity and self.current is not None and
                        (self.current.fatal_ni_count or self.current.primary.startswith("TNS-")))
        if identity != self.identity or (timestamp_boundary and not same_ni_time):
            self.flush()
            self.identity = identity
            self.interleaved_ni = False
        elif timestamp_boundary and same_ni_time:
            self.interleaved_ni = True
            self.current.interleaved_ni = True
        codes, omitted_codes = _scan_codes(line, MAX_EVENT_CODES)
        primary_codes = [code for code in codes if code not in _CONTEXT_CODES]
        candidate = bool(codes or _is_noncode_candidate(line))
        if self.current is not None:
            repeated_primary = self.current.primary and self.current.primary in primary_codes
            independent = self.current.primary and primary_codes and (
                self.current.primary in _INDEPENDENT_CODES or
                any(code in _INDEPENDENT_CODES for code in primary_codes)
            )
            separated = self.current.primary and primary_codes and self.current.neutral_lines >= 8
            if _TRACE_START_RE.search(line) or repeated_primary or independent or separated:
                self.interleaved_ni = self.interleaved_ni or self.current.interleaved_ni
                self.flush()
        if self.current is None:
            if not candidate:
                self.prelude.append((self.serial, line_number, _clip_line(line)))
                return
            self.current = _EventBuffer(time, instance, host)
            self.current.interleaved_ni = self.interleaved_ni and any(code.startswith("TNS-") for code in codes)
            for serial, previous_number, previous in self.prelude:
                self.current.append(serial, previous_number, previous, [])
            self.prelude.clear()
        self.current.append(self.serial, line_number, line, codes, omitted_codes)

    def finish(self) -> List[AlertEvent]:
        self.flush()
        return self.events


def parse_alert_text(text: str) -> List[AlertEvent]:
    """Parse physical text; positions are one-based physical source lines.

    ISO timestamp precision/timezone and 11g English dates are retained verbatim.
    A repeated physical timestamp header starts a new block, whereas repeated
    timestamps in tabular rows below can be continuation rows of one stack.
    """
    parser = _Parser()
    time = ""
    for number, line in enumerate(_iter_lines(text or ""), 1):
        timestamp = _ISO_TIME_RE.match(line) or _LEGACY_TIME_RE.match(line)
        if timestamp:
            time = timestamp.group("time")
        parser.feed(line, number, time, timestamp_boundary=bool(timestamp))
    return parser.finish()


def parse_alert_rows(rows: List[List[str]]) -> List[AlertEvent]:
    """Parse collector 2/5/9-column rows; positions refer to input row numbers.

    Nine columns: database/instance/host/(...)/time/type/level/problem/message.
    Five columns: time/type/level/problem/message. Two: time/message. One-column
    legacy error extracts and embedded multiline messages are also accepted.
    Metadata is never scanned as an error message (e.g. a problem-key ORA code).
    """
    parser = _Parser()
    legacy_time = ""
    for number, row in enumerate(rows or [], 1):
        if not row:
            continue
        values = ["" if cell is None else str(cell) for cell in row]
        first = values[0].strip().lstrip("\ufeff")
        if first.upper() in {"EVENT_TIME", "DATABASE_NAME", "ORIGINATING_TIMESTAMP"}:
            continue
        if all(not value.strip(" -|\t") for value in values):
            continue
        instance = host = ""
        if len(values) >= 9:
            time, instance, host = values[4].strip(), values[1].strip(), values[2].strip()
            message = "|".join(values[8:])
        elif len(values) >= 5:
            time, message = values[0].strip(), "|".join(values[4:])
        elif len(values) >= 2:
            time, message = values[0].strip(), "|".join(values[1:])
        else:
            time, message = legacy_time, values[0]
        for line in _iter_lines(message):
            timestamp = (_ISO_TIME_RE.match(line) or _LEGACY_TIME_RE.match(line)) if len(values) == 1 else None
            if timestamp:
                time = legacy_time = timestamp.group("time")
            parser.feed(line, number, time, instance, host, timestamp_boundary=bool(timestamp))
    return parser.finish()
