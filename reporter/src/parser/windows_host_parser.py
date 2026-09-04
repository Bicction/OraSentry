# -*- coding: utf-8 -*-
"""Windows 主机巡检结构化数据解析器。"""
import csv
import math
import os
from collections import Counter
from typing import Dict, List

from config import HOST_THRESHOLDS
from parser.base import CheckResult, check_threshold, generate_data_table, read_file


STATUS_ORDER = {"INFO": -1, "UNKNOWN": -1, "OK": 0, "WARN": 1, "CRIT": 2}


def _table(path: str) -> List[Dict[str, str]]:
    lines = [line.strip() for line in read_file(path).splitlines() if line.strip()]
    if not lines:
        return []
    headers = [item.strip().lstrip("\ufeff") for item in lines[0].split("|")]
    rows = []
    for line in lines[1:]:
        if line.startswith("-"):
            continue
        values = [item.strip() for item in line.split("|")]
        values += [""] * max(0, len(headers) - len(values))
        rows.append(dict(zip(headers, values)))
    return rows


def _number(value, default=0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _percentile(values, percentile=95.0) -> float:
    numbers = sorted(float(value) for value in values)
    if not numbers:
        return 0.0
    index = max(0, min(len(numbers) - 1, math.ceil(len(numbers) * percentile / 100.0) - 1))
    return numbers[index]


def _worst_status(*statuses: str) -> str:
    return max(statuses, key=lambda item: STATUS_ORDER.get(item, -1))


def _system_samples(host_dir: str) -> List[Dict[str, str]]:
    """性能文件按物理盘展开，系统指标需按采样编号去重。"""
    unique = {}
    for row in _table(f"{host_dir}/performance_samples.txt"):
        key = row.get("SAMPLE") or row.get("TIME")
        if key not in unique:
            unique[key] = row
    return list(unique.values())


def _collection_problem(host_dir: str, item: str) -> bool:
    """区分旧包未提供增强文件与当前采集器明确报告采集失败。"""
    manifest = os.path.join(os.path.dirname(host_dir), "collection_manifest.tsv")
    try:
        with open(manifest, "r", encoding="utf-8", errors="replace", newline="") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                if row.get("item") == item and row.get("status") in ("WARN", "FAILED"):
                    return True
    except (OSError, csv.Error):
        pass
    return False


def parse_windows_host(raw_dir: str) -> List[CheckResult]:
    host_dir = f"{raw_dir}/host"
    results: List[CheckResult] = []
    results.extend(_parse_disks(host_dir))
    results.append(CheckResult("inode使用率", "INFO", "不适用", "Windows NTFS/ReFS 不使用 Linux inode 容量模型"))
    results.append(_parse_cpu(host_dir))
    results.append(_parse_memory(host_dir))
    results.append(_parse_pagefile(host_dir))
    results.append(_parse_disk_io(host_dir))
    results.append(_parse_login(host_dir))
    results.append(_parse_firewall(host_dir))
    results.append(_parse_firewall_exposure(host_dir))
    results.append(CheckResult("Linux内核参数", "INFO", "不适用", "Windows 主机不使用 Linux sysctl、HugePages 与 THP 配置"))
    results.append(_parse_time(host_dir))
    results.append(_parse_network(host_dir))
    results.append(_parse_events(host_dir))
    results.append(_parse_critical_events(host_dir))
    results.append(_parse_oracle_services(host_dir))
    results.append(_parse_oracle_processes(host_dir))
    results.append(_parse_windows_maintenance(host_dir))
    from parser.windows_baseline_parser import parse_windows_baseline
    results.extend(parse_windows_baseline(raw_dir))
    return results


def _parse_disks(host_dir: str) -> List[CheckResult]:
    rows = _table(f"{host_dir}/disk_usage.txt")
    if not rows:
        return [CheckResult("磁盘使用率", "CRIT", "数据缺失", "无法获取 Windows 固定磁盘信息")]
    results = []
    table_rows = []
    for row in rows:
        volume = row.get("VOLUME", "?")
        usage = _number(row.get("USAGE_PCT"))
        free_gb = _number(row.get("FREE_GB"))
        status = check_threshold(usage, HOST_THRESHOLDS["disk_usage_warn"], HOST_THRESHOLDS["disk_usage_crit"])
        if free_gb <= HOST_THRESHOLDS["disk_free_crit"]:
            status = "CRIT"
        elif free_gb <= HOST_THRESHOLDS["disk_free_warn"] and status == "OK":
            status = "WARN"
        suggestion = f"卷 {volume} 空间偏低，请清理、迁移诊断文件或扩容" if status != "OK" else ""
        results.append(CheckResult(
            f"磁盘使用率-{volume}", status, f"{usage:.1f}%",
            f"文件系统: {row.get('FILESYSTEM') or 'N/A'}, 总容量: {row.get('TOTAL_GB')}GB, "
            f"已用: {row.get('USED_GB')}GB, 可用: {free_gb:.2f}GB", suggestion,
        ))
        table_rows.append((volume, row.get("LABEL", ""), row.get("FILESYSTEM", ""),
                           row.get("TOTAL_GB", ""), row.get("USED_GB", ""),
                           row.get("FREE_GB", ""), f"{usage:.1f}%"))
    results.insert(0, CheckResult(
        "磁盘使用概览", "OK", f"{len(rows)}个固定卷", "Windows 固定磁盘容量一览",
        extra_html=generate_data_table(
            ["卷", "标签", "文件系统", "总容量(GB)", "已用(GB)", "可用(GB)", "使用率"], table_rows,
        ),
    ))
    return results


def _parse_cpu(host_dir: str) -> CheckResult:
    base_rows = _table(f"{host_dir}/cpu_metrics.txt")
    if not base_rows:
        return CheckResult("CPU使用率", "CRIT", "数据缺失", "无法获取 Windows CPU 性能数据")
    base = base_rows[0]
    samples = _system_samples(host_dir)
    cpu_count = max(1, int(_number(base.get("CPU_COUNT"), 1)))
    if samples:
        usages = [_number(row.get("CPU_TOTAL_PCT")) for row in samples]
        privileged = [_number(row.get("CPU_PRIVILEGED_PCT")) for row in samples]
        queues = [_number(row.get("PROCESSOR_QUEUE_LENGTH")) / cpu_count for row in samples]
        avg_usage = sum(usages) / len(usages)
        p95_usage = _percentile(usages)
        max_usage = max(usages)
        p95_privileged = _percentile(privileged)
        p95_queue = _percentile(queues)
        status = _worst_status(
            check_threshold(p95_usage, HOST_THRESHOLDS["cpu_usage_warn"], HOST_THRESHOLDS["cpu_usage_crit"]),
            check_threshold(p95_privileged, HOST_THRESHOLDS["cpu_privileged_warn"], HOST_THRESHOLDS["cpu_privileged_crit"]),
            check_threshold(p95_queue, HOST_THRESHOLDS["cpu_queue_per_core_warn"], HOST_THRESHOLDS["cpu_queue_per_core_crit"]),
        )
        return CheckResult(
            "CPU使用率", status, f"P95 {p95_usage:.1f}%",
            f"{len(samples)}次采样，平均 {avg_usage:.1f}%，峰值 {max_usage:.1f}%，"
            f"特权时间P95 {p95_privileged:.1f}%，每CPU队列P95 {p95_queue:.2f}；逻辑CPU {cpu_count}",
            "CPU持续繁忙、特权时间或调度队列偏高，请检查 Oracle 与系统进程" if status != "OK" else "",
        )
    if not str(base.get("CPU_USAGE_PCT", "")).strip():
        return CheckResult("CPU使用率", "UNKNOWN", "无法评估",
                           f"逻辑CPU: {base.get('CPU_COUNT')}, 当前权限无法读取CPU性能计数器",
                           "建议使用管理员权限重新采集")
    usage = _number(base.get("CPU_USAGE_PCT"))
    status = check_threshold(usage, HOST_THRESHOLDS["cpu_usage_warn"], HOST_THRESHOLDS["cpu_usage_crit"])
    return CheckResult("CPU使用率", status, f"{usage:.1f}%",
                       f"单点采样；逻辑CPU: {base.get('CPU_COUNT')}, 系统运行: {base.get('UPTIME_HOURS')}小时",
                       "CPU使用率偏高，请检查 Oracle 和其他高占用进程" if status != "OK" else "")


def _parse_memory(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/memory_metrics.txt")
    if not rows:
        return CheckResult("内存使用率", "CRIT", "数据缺失", "无法获取 Windows 内存数据")
    row = rows[0]
    total_mb = _number(row.get("TOTAL_MB"))
    usage = _number(row.get("USAGE_PCT"))
    status = check_threshold(usage, HOST_THRESHOLDS["mem_usage_warn"], HOST_THRESHOLDS["mem_usage_crit"])
    samples = _system_samples(host_dir)
    detail = f"总内存: {row.get('TOTAL_MB')}MB, 已用: {row.get('USED_MB')}MB, 可用: {row.get('AVAILABLE_MB')}MB"
    if samples:
        commit_p95 = _percentile(_number(sample.get("COMMITTED_PCT")) for sample in samples)
        pages_p95 = _percentile(_number(sample.get("PAGES_PER_SEC")) for sample in samples)
        available_min = min((_number(sample.get("AVAILABLE_MB")) for sample in samples), default=0.0)
        available_pct = available_min / total_mb * 100 if total_mb else 100.0
        status = _worst_status(status, check_threshold(
            commit_p95, HOST_THRESHOLDS["mem_commit_warn"], HOST_THRESHOLDS["mem_commit_crit"]
        ))
        if pages_p95 >= HOST_THRESHOLDS["pages_per_sec_crit"] and available_pct <= 5:
            status = "CRIT"
        elif pages_p95 >= HOST_THRESHOLDS["pages_per_sec_warn"] and available_pct <= 10 and status == "OK":
            status = "WARN"
        detail += (f"；{len(samples)}次采样：提交率P95 {commit_p95:.1f}%，最小可用 {available_min:.0f}MB，"
                   f"Pages/sec P95 {pages_p95:.1f}")
    return CheckResult("内存使用率", status, f"{usage:.1f}%", detail,
                       "内存提交率或换页压力偏高，请检查 Oracle SGA/PGA 与系统进程" if status != "OK" else "")


def _parse_pagefile(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/pagefile_metrics.txt")
    if not rows:
        return CheckResult("页面文件使用率", "INFO", "未配置/未采集", "未发现 Windows 页面文件数据")
    worst = max((_number(row.get("USAGE_PCT")) for row in rows), default=0.0)
    status = check_threshold(worst, HOST_THRESHOLDS["swap_usage_warn"], HOST_THRESHOLDS["swap_usage_crit"])
    table_rows = [(row.get("NAME"), row.get("ALLOCATED_MB"), row.get("USED_MB"),
                   row.get("PEAK_MB"), row.get("USAGE_PCT")) for row in rows]
    return CheckResult("页面文件使用率", status, f"最高{worst:.1f}%", f"共检查 {len(rows)} 个页面文件",
                       "页面文件占用偏高，请结合可用内存和 Oracle 内存配置排查" if status != "OK" else "",
                       extra_html=generate_data_table(["文件", "分配(MB)", "当前(MB)", "峰值(MB)", "使用率(%)"], table_rows))


def _parse_disk_io(host_dir: str) -> CheckResult:
    sample_rows = [row for row in _table(f"{host_dir}/performance_samples.txt") if row.get("DISK")]
    if sample_rows:
        grouped = {}
        for row in sample_rows:
            grouped.setdefault(row.get("DISK", "?"), []).append(row)
        display = []
        overall = "OK"
        worst_latency = 0.0
        for disk, rows in grouped.items():
            latencies = [max(_number(row.get("READ_LATENCY_MS")), _number(row.get("WRITE_LATENCY_MS"))) for row in rows]
            busy = [_number(row.get("BUSY_PCT")) for row in rows]
            queues = [_number(row.get("QUEUE_LENGTH")) for row in rows]
            p95_latency = _percentile(latencies)
            p95_busy = _percentile(busy)
            p95_queue = _percentile(queues)
            disk_status = _worst_status(
                check_threshold(p95_latency, HOST_THRESHOLDS["disk_await_warn_ms"], HOST_THRESHOLDS["disk_await_crit_ms"]),
                check_threshold(p95_busy, HOST_THRESHOLDS["disk_util_warn"], HOST_THRESHOLDS["disk_util_crit"]),
                check_threshold(p95_queue, HOST_THRESHOLDS["disk_queue_warn"], HOST_THRESHOLDS["disk_queue_crit"]),
            )
            overall = _worst_status(overall, disk_status)
            worst_latency = max(worst_latency, p95_latency)
            display.append((disk, f"{p95_latency:.1f}", f"{p95_busy:.1f}", f"{p95_queue:.1f}",
                            f"{max(latencies):.1f}", disk_status))
        return CheckResult(
            "磁盘IO延迟", overall, f"P95最高{worst_latency:.1f}ms",
            f"10秒持续采样，共 {len(grouped)} 个物理磁盘",
            "磁盘持续延迟、忙碌率或队列偏高，请结合 Oracle 等待事件排查" if overall != "OK" else "",
            extra_html=generate_data_table(["磁盘", "延迟P95(ms)", "忙碌率P95(%)", "队列P95", "峰值延迟(ms)", "状态"], display),
        )
    rows = _table(f"{host_dir}/disk_io.txt")
    if not rows:
        return CheckResult("磁盘IO延迟", "UNKNOWN", "无法评估", "Windows 磁盘性能计数器不可用")
    values = [(row, max(_number(row.get("READ_LATENCY_MS")), _number(row.get("WRITE_LATENCY_MS"))),
               _number(row.get("BUSY_PCT"))) for row in rows]
    max_latency = max((item[1] for item in values), default=0.0)
    max_busy = max((item[2] for item in values), default=0.0)
    status = _worst_status(
        check_threshold(max_latency, HOST_THRESHOLDS["disk_await_warn_ms"], HOST_THRESHOLDS["disk_await_crit_ms"]),
        check_threshold(max_busy, HOST_THRESHOLDS["disk_util_warn"], HOST_THRESHOLDS["disk_util_crit"]),
    )
    table_rows = [(row.get("DISK"), row.get("READ_LATENCY_MS"), row.get("WRITE_LATENCY_MS"),
                   row.get("BUSY_PCT"), row.get("READ_IOPS"), row.get("WRITE_IOPS")) for row, _, _ in values]
    return CheckResult("磁盘IO延迟", status, f"单点最高{max_latency:.1f}ms", f"最高磁盘忙碌率: {max_busy:.1f}%",
                       "磁盘延迟或忙碌率偏高，请结合 Oracle 等待事件排查" if status != "OK" else "",
                       extra_html=generate_data_table(["磁盘", "读延迟(ms)", "写延迟(ms)", "忙碌率(%)", "读IOPS", "写IOPS"], table_rows))


def _parse_login(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/login_metrics.txt")
    if not rows:
        return CheckResult("操作系统登录", "UNKNOWN", "数据缺失", "无法读取 Windows Security 登录事件，可能缺少管理员权限")
    active = int(_number(rows[0].get("ACTIVE_SESSION_COUNT")))
    failed = int(_number(rows[0].get("FAILED_LOGIN_7D_SAMPLED")))
    status = "WARN" if failed > 50 else "OK"
    return CheckResult("操作系统登录", status, f"{active}个交互会话", f"最近7天抽样失败登录: {failed}次",
                       "失败登录较多，请核查来源、账号锁定和远程桌面暴露面" if status == "WARN" else "")


def _parse_firewall(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/firewall_profiles.txt")
    if not rows:
        return CheckResult("防火墙状态", "WARN", "无法确认", "未能读取 Windows Defender 防火墙配置",
                           "请人工核对本机及外围网络访问控制")
    disabled = [row for row in rows if row.get("ENABLED", "").lower() != "true"]
    permissive = [row for row in rows if row.get("INBOUND_ACTION", "").lower() == "allow"]
    status = "WARN" if disabled or permissive else "OK"
    detail = ", ".join(
        f"{row.get('PROFILE')}={'启用' if row not in disabled else '关闭'}，入站={row.get('INBOUND_ACTION') or '未配置'}"
        for row in rows
    )
    risks = []
    if disabled:
        risks.append("存在关闭的防火墙配置文件")
    if permissive:
        risks.append("存在默认允许入站的配置文件")
    return CheckResult("防火墙状态", status, f"{len(rows) - len(disabled)}/{len(rows)}配置文件启用", detail,
                       "；".join(risks))


def _parse_firewall_exposure(host_dir: str) -> CheckResult:
    path = f"{host_dir}/firewall_oracle_rules.txt"
    if not os.path.isfile(path):
        if _collection_problem(host_dir, "firewall_oracle_rules.txt"):
            return CheckResult("Oracle端口暴露", "UNKNOWN", "采集失败", "无法读取 Oracle 端口对应的 Windows 防火墙规则")
        return CheckResult("Oracle端口暴露", "INFO", "旧版未采集", "采集包不含 Oracle 防火墙规则明细")
    rows = _table(path)
    if not rows:
        return CheckResult("Oracle端口暴露", "INFO", "无监听端点", "未发现 oracle/tnslsnr 进程的 TCP 监听端点")
    exposed = [row for row in rows if row.get("EXPOSURE") == "ANY"]
    status = "WARN" if exposed else "OK"
    table_rows = [(row.get("PORT"), row.get("PROCESS"), row.get("LOCAL_ADDRESS"), row.get("RULE_NAME"),
                   row.get("PROFILE"), row.get("REMOTE_ADDRESS"), row.get("EXPOSURE")) for row in rows]
    return CheckResult(
        "Oracle端口暴露", status, f"{len(exposed)}项全网放行",
        f"检查 {len(rows)} 条 Oracle 监听端点与入站允许规则",
        "请将 Oracle 入站规则的远程地址限制到应用服务器、管理网或可信网段" if exposed else "",
        extra_html=generate_data_table(["端口", "进程", "监听地址", "规则", "Profile", "远程地址", "暴露"], table_rows),
    )


def _parse_time(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/time_sync.txt")
    if not rows:
        return CheckResult("时间同步", "WARN", "无法确认", "未能读取 Windows Time 状态")
    row = rows[0]
    running = row.get("SERVICE_STATUS", "").lower() == "running"
    source = row.get("SOURCE", "")
    local_source = any(marker in source.lower() for marker in ("local cmos", "free-running", "n/a", "本地 cmos", "未同步"))
    status = "OK" if running and not local_source else "WARN"
    offset_text = str(row.get("OFFSET_MS", "")).strip()
    if offset_text:
        offset = _number(offset_text)
        status = _worst_status(status, check_threshold(offset, HOST_THRESHOLDS["time_offset_warn_ms"], HOST_THRESHOLDS["time_offset_crit_ms"]))
        value = f"偏移{offset:.1f}ms"
    else:
        value = "服务运行" if running else "服务未运行"
    detail = (f"系统时间: {row.get('LOCAL_TIME')}, 时区: {row.get('TIMEZONE')}, 时间源: {source or 'N/A'}, "
              f"测得偏移: {offset_text + 'ms' if offset_text else '未获得'}")
    suggestion = "请修复 Windows Time 时间源并校准时钟；数据库、集群和审计依赖一致时间" if status != "OK" else ""
    return CheckResult("时间同步", status, value, detail, suggestion)


def _parse_network(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/network_listen.txt")
    if not rows:
        return CheckResult("网络监听端口", "UNKNOWN", "数据缺失", "无法获取 Windows 监听端口")
    table_rows = [(row.get("PROTOCOL"), row.get("LOCAL_ADDRESS"), row.get("LOCAL_PORT"),
                   row.get("PID"), row.get("PROCESS")) for row in rows]
    return CheckResult("网络监听端口", "INFO", f"{len(rows)}个监听端口", "端口清单仅用于暴露面核查，不直接代表健康",
                       extra_html=generate_data_table(["协议", "地址", "端口", "PID", "进程"], table_rows))


def _parse_events(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/event_log_errors.txt")
    critical = [row for row in rows if row.get("LEVEL", "").lower() in ("critical", "关键")]
    status = "WARN" if critical else "INFO"
    table_rows = [(row.get("TIME"), row.get("LOG"), row.get("EVENT_ID"), row.get("LEVEL"),
                   row.get("PROVIDER"), (row.get("MESSAGE") or "")[:160]) for row in rows[:30]]
    return CheckResult("Windows事件日志", status, f"{len(rows)}条错误/严重事件",
                       f"最近7天最多抽样100条；关键事件由独立分类规则判定，原始严重事件 {len(critical)} 条",
                       "请核查未被关键事件分类覆盖的 Critical 事件" if critical else "",
                       extra_html=generate_data_table(["时间", "日志", "ID", "级别", "来源", "摘要"], table_rows) if table_rows else "")


def _parse_critical_events(host_dir: str) -> CheckResult:
    path = f"{host_dir}/critical_events.txt"
    if not os.path.isfile(path):
        if _collection_problem(host_dir, "critical_events.txt"):
            return CheckResult("Windows关键事件", "UNKNOWN", "采集失败", "无法读取关键事件日志，不能判定为0项")
        return CheckResult("Windows关键事件", "INFO", "旧版未采集", "采集包不含结构化关键事件分类")
    rows = _table(path)
    if not rows:
        if _collection_problem(host_dir, "critical_events.txt"):
            return CheckResult("Windows关键事件", "UNKNOWN", "部分采集失败", "关键事件文件为空，但部分事件日志查询失败，不能判定为0项")
        return CheckResult("Windows关键事件", "OK", "0项", "最近7天未发现已定义的存储、硬件、资源、Oracle服务或审计关键事件")
    counts = Counter(row.get("CATEGORY") for row in rows)
    critical = [row for row in rows if row.get("SEVERITY") == "CRIT"]
    warnings = [row for row in rows if row.get("SEVERITY") == "WARN"]
    status = "CRIT" if critical or counts.get("STORAGE_RESET", 0) >= 3 else "WARN"
    table_rows = [(row.get("TIME"), row.get("CATEGORY"), row.get("SEVERITY"), row.get("PROVIDER"),
                   row.get("EVENT_ID"), (row.get("MESSAGE") or "")[:180]) for row in rows[:50]]
    return CheckResult(
        "Windows关键事件", status, f"严重{len(critical)}/警告{len(warnings)}",
        "，".join(f"{name}:{count}" for name, count in counts.most_common()),
        "请优先处理磁盘/文件系统、硬件、资源耗尽、异常关机和 Oracle 服务崩溃事件",
        extra_html=generate_data_table(["时间", "分类", "级别", "来源", "事件ID", "摘要"], table_rows),
    )


def _parse_oracle_services(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/oracle_services.txt")
    database_services = [row for row in rows if (row.get("NAME") or "").lower().startswith("oracleservice")]
    listener_services = [row for row in rows if "listener" in ((row.get("NAME") or "") + (row.get("DISPLAY_NAME") or "")).lower()]
    stopped_db = [row for row in database_services if row.get("STATE", "").lower() != "running"]
    stopped_listener_auto = [row for row in listener_services if row.get("STATE", "").lower() != "running" and row.get("START_MODE", "").lower() == "auto"]
    stopped_auto = [row for row in rows if row.get("STATE", "").lower() != "running" and row.get("START_MODE", "").lower() == "auto"]
    nonzero_exit = [row for row in rows if _number(row.get("EXIT_CODE")) or _number(row.get("SERVICE_EXIT_CODE"))]
    if stopped_db or stopped_listener_auto:
        status = "CRIT"
    elif stopped_auto or nonzero_exit:
        status = "WARN"
    else:
        status = "OK" if database_services else "WARN"
    table_rows = [(row.get("NAME"), row.get("STATE"), row.get("START_MODE"), row.get("ACCOUNT"),
                   row.get("PID"), row.get("EXIT_CODE"), (row.get("RECOVERY_ACTIONS") or "")[:100]) for row in rows]
    detail = (f"数据库服务 {len(database_services)} 个、Listener服务 {len(listener_services)} 个；"
              f"停止的数据库服务 {len(stopped_db)} 个，自动启动但停止 {len(stopped_auto)} 个，异常退出码 {len(nonzero_exit)} 个")
    return CheckResult("Oracle服务", status, f"{len(database_services)}个数据库服务", detail,
                       "检查停止服务、登录账户、可执行路径和服务恢复动作" if status != "OK" else "",
                       extra_html=generate_data_table(["服务", "状态", "启动方式", "账号", "PID", "退出码", "恢复动作"], table_rows) if table_rows else "")


def _parse_oracle_processes(host_dir: str) -> CheckResult:
    path = f"{host_dir}/oracle_processes.txt"
    if not os.path.isfile(path):
        if _collection_problem(host_dir, "oracle_processes.txt"):
            return CheckResult("Oracle进程健康", "UNKNOWN", "采集失败", "无法读取 Oracle 进程及资源数据")
        return CheckResult("Oracle进程健康", "INFO", "旧版未采集", "采集包不含 Oracle 进程明细")
    rows = _table(path)
    services = _table(f"{host_dir}/oracle_services.txt")
    running_db = [row for row in services if (row.get("NAME") or "").lower().startswith("oracleservice") and row.get("STATE", "").lower() == "running"]
    running_listener = [row for row in services if "listener" in ((row.get("NAME") or "") + (row.get("DISPLAY_NAME") or "")).lower() and row.get("STATE", "").lower() == "running"]
    oracle_processes = [row for row in rows if (row.get("NAME") or "").lower().startswith("oracle")]
    listener_processes = [row for row in rows if (row.get("NAME") or "").lower().startswith("tnslsnr")]
    missing = []
    if running_db and not oracle_processes:
        missing.append("数据库服务运行但未发现 oracle.exe")
    if running_listener and not listener_processes:
        missing.append("Listener服务运行但未发现 tnslsnr.exe")
    high_cpu = [row for row in rows if _number(row.get("CPU_PCT")) >= HOST_THRESHOLDS["cpu_usage_crit"]]
    status = "CRIT" if missing else ("WARN" if high_cpu else ("OK" if rows else "WARN"))
    table_rows = [(row.get("PID"), row.get("NAME"), row.get("CPU_PCT"), row.get("WORKING_SET_MB"),
                   row.get("PRIVATE_MB"), row.get("THREADS"), row.get("HANDLES"), row.get("UPTIME_HOURS"),
                   row.get("PATH")) for row in rows]
    return CheckResult(
        "Oracle进程健康", status, f"{len(rows)}个进程",
        "；".join(missing) if missing else f"oracle.exe {len(oracle_processes)} 个，tnslsnr.exe {len(listener_processes)} 个，高CPU进程 {len(high_cpu)} 个",
        "请核对 Oracle 服务与实际进程，并排查高CPU或异常退出" if status != "OK" else "",
        extra_html=generate_data_table(["PID", "进程", "CPU(%)", "工作集(MB)", "私有内存(MB)", "线程", "句柄", "运行小时", "路径"], table_rows) if table_rows else "",
    )


def _parse_windows_maintenance(host_dir: str) -> CheckResult:
    path = f"{host_dir}/windows_maintenance.txt"
    if not os.path.isfile(path):
        if _collection_problem(host_dir, "windows_maintenance.txt"):
            return CheckResult("Windows补丁与重启", "UNKNOWN", "采集失败", "无法读取 Windows 版本、HotFix和待重启状态")
        return CheckResult("Windows补丁与重启", "INFO", "旧版未采集", "采集包不含补丁与待重启状态")
    rows = _table(path)
    if not rows:
        return CheckResult("Windows补丁与重启", "UNKNOWN", "数据缺失", "无法读取 Windows 版本和维护状态")
    row = rows[0]
    pending = row.get("PENDING_REBOOT", "").lower() == "true"
    patch_age_text = str(row.get("PATCH_AGE_DAYS", "")).strip()
    status = "WARN" if pending else "OK"
    if patch_age_text:
        patch_age = _number(patch_age_text)
        status = _worst_status(status, check_threshold(patch_age, HOST_THRESHOLDS["patch_age_warn_days"], HOST_THRESHOLDS["patch_age_crit_days"]))
        patch_detail = f"最近HotFix距今 {int(patch_age)} 天"
    else:
        patch_detail = "未获得最近HotFix安装日期"
        if status == "OK":
            status = "UNKNOWN"
    detail = (f"{row.get('CAPTION')} {row.get('VERSION')} Build {row.get('BUILD')}.{row.get('UBR')}；"
              f"最近HotFix {row.get('LAST_HOTFIX') or 'N/A'}（{row.get('LAST_HOTFIX_DATE') or 'N/A'}），{patch_detail}；"
              f"待重启={'是' if pending else '否'} {row.get('PENDING_REASONS') or ''}；最近启动 {row.get('LAST_BOOT_TIME')}")
    suggestion = "请按维护窗口安装经验证的安全更新并完成待处理重启" if status in ("WARN", "CRIT") else ""
    return CheckResult("Windows补丁与重启", status, "待重启" if pending else patch_detail, detail, suggestion)
