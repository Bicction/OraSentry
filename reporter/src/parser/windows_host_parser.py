# -*- coding: utf-8 -*-
"""Windows 主机巡检结构化数据解析器。"""
from typing import Dict, List

from config import HOST_THRESHOLDS
from parser.base import CheckResult, check_threshold, generate_data_table, read_file


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


def parse_windows_host(raw_dir: str) -> List[CheckResult]:
    host_dir = f"{raw_dir}/host"
    results: List[CheckResult] = []
    results.extend(_parse_disks(host_dir))
    results.append(CheckResult("inode使用率", "INFO", "不适用", "Windows NTFS/ReFS 不使用 Linux inode 容量模型"))
    results.append(_parse_cpu(host_dir))
    results.append(_parse_memory(host_dir))
    results.append(_parse_pagefile(host_dir))
    results.append(_parse_login(host_dir))
    results.append(_parse_firewall(host_dir))
    results.append(CheckResult("Linux内核参数", "INFO", "不适用", "Windows 主机不使用 Linux sysctl、HugePages 与 THP 配置"))
    results.append(_parse_time(host_dir))
    results.append(_parse_network(host_dir))
    results.append(_parse_events(host_dir))
    results.append(_parse_oracle_services(host_dir))
    results.append(_parse_disk_io(host_dir))
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
        suggestion = ""
        if status != "OK":
            suggestion = f"卷 {volume} 空间偏低，请清理、迁移诊断文件或扩容"
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
    rows = _table(f"{host_dir}/cpu_metrics.txt")
    if not rows:
        return CheckResult("CPU使用率", "CRIT", "数据缺失", "无法获取 Windows CPU 性能数据")
    row = rows[0]
    if not str(row.get("CPU_USAGE_PCT", "")).strip():
        return CheckResult("CPU使用率", "UNKNOWN", "无法评估",
                           f"逻辑CPU: {row.get('CPU_COUNT')}, 当前权限无法读取CPU性能计数器",
                           "建议使用管理员权限重新采集")
    usage = _number(row.get("CPU_USAGE_PCT"))
    status = check_threshold(usage, HOST_THRESHOLDS["cpu_usage_warn"], HOST_THRESHOLDS["cpu_usage_crit"])
    return CheckResult("CPU使用率", status, f"{usage:.1f}%",
                       f"逻辑CPU: {row.get('CPU_COUNT')}, 系统运行: {row.get('UPTIME_HOURS')}小时",
                       "CPU使用率偏高，请检查 Oracle 和其他高占用进程" if status != "OK" else "")


def _parse_memory(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/memory_metrics.txt")
    if not rows:
        return CheckResult("内存使用率", "CRIT", "数据缺失", "无法获取 Windows 内存数据")
    row = rows[0]
    usage = _number(row.get("USAGE_PCT"))
    status = check_threshold(usage, HOST_THRESHOLDS["mem_usage_warn"], HOST_THRESHOLDS["mem_usage_crit"])
    return CheckResult("内存使用率", status, f"{usage:.1f}%",
                       f"总内存: {row.get('TOTAL_MB')}MB, 已用: {row.get('USED_MB')}MB, 可用: {row.get('AVAILABLE_MB')}MB",
                       "内存使用率偏高，请检查 Oracle SGA/PGA 与系统进程" if status != "OK" else "")


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
    enabled = [row for row in rows if row.get("ENABLED", "").lower() == "true"]
    detail = ", ".join(f"{r.get('PROFILE')}={'启用' if r in enabled else '关闭'}" for r in rows)
    return CheckResult("防火墙状态", "OK", f"{len(enabled)}/{len(rows)}配置文件启用", detail)


def _parse_time(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/time_sync.txt")
    if not rows:
        return CheckResult("时间同步", "WARN", "无法确认", "未能读取 Windows Time 状态")
    row = rows[0]
    running = row.get("SERVICE_STATUS", "").lower() == "running"
    status = "OK" if running else "WARN"
    return CheckResult("时间同步", status, "服务运行" if running else "服务未运行",
                       f"系统时间: {row.get('LOCAL_TIME')}, 时区: {row.get('TIMEZONE')}, 时间源: {row.get('SOURCE')}",
                       "请启动并校准 Windows Time 服务" if status == "WARN" else "")


def _parse_network(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/network_listen.txt")
    if not rows:
        return CheckResult("网络监听端口", "CRIT", "数据缺失", "无法获取 Windows 监听端口")
    table_rows = [(r.get("PROTOCOL"), r.get("LOCAL_ADDRESS"), r.get("LOCAL_PORT"),
                   r.get("PID"), r.get("PROCESS")) for r in rows]
    return CheckResult("网络监听端口", "OK", f"{len(rows)}个监听端口", "列出本机 TCP/UDP 监听端点",
                       extra_html=generate_data_table(["协议", "地址", "端口", "PID", "进程"], table_rows))


def _parse_events(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/event_log_errors.txt")
    critical = [row for row in rows if row.get("LEVEL", "").lower() == "critical"]
    status = "CRIT" if critical else ("WARN" if len(rows) > 20 else "OK")
    table_rows = [(r.get("TIME"), r.get("LOG"), r.get("EVENT_ID"), r.get("LEVEL"),
                   r.get("PROVIDER"), (r.get("MESSAGE") or "")[:160]) for r in rows[:30]]
    return CheckResult("Windows事件日志", status, f"{len(rows)}条错误/严重事件",
                       f"最近7天最多抽样100条，严重事件 {len(critical)} 条",
                       "请结合事件ID和提供程序排查系统或应用错误" if status != "OK" else "",
                       extra_html=generate_data_table(["时间", "日志", "ID", "级别", "来源", "摘要"], table_rows) if table_rows else "")


def _parse_oracle_services(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/oracle_services.txt")
    database_services = [row for row in rows if (row.get("NAME") or "").lower().startswith("oracleservice")]
    stopped = [row for row in database_services if row.get("STATE", "").lower() != "running"]
    status = "CRIT" if stopped else ("OK" if database_services else "WARN")
    table_rows = [(r.get("NAME"), r.get("STATE"), r.get("START_MODE"), r.get("ACCOUNT"), r.get("PID")) for r in rows]
    return CheckResult("Oracle服务", status, f"{len(database_services)}个数据库服务",
                       f"停止的数据库服务: {len(stopped)}",
                       "存在停止的 OracleService 服务，请确认实例状态与启动策略" if stopped else "",
                       extra_html=generate_data_table(["服务", "状态", "启动方式", "账号", "PID"], table_rows) if table_rows else "")


def _parse_disk_io(host_dir: str) -> CheckResult:
    rows = _table(f"{host_dir}/disk_io.txt")
    if not rows:
        return CheckResult("磁盘IO延迟", "UNKNOWN", "无法评估", "Windows 磁盘性能计数器不可用")
    values = []
    for row in rows:
        latency = max(_number(row.get("READ_LATENCY_MS")), _number(row.get("WRITE_LATENCY_MS")))
        busy = _number(row.get("BUSY_PCT"))
        values.append((row, latency, busy))
    max_latency = max((item[1] for item in values), default=0.0)
    max_busy = max((item[2] for item in values), default=0.0)
    latency_status = check_threshold(max_latency, HOST_THRESHOLDS["disk_await_warn_ms"], HOST_THRESHOLDS["disk_await_crit_ms"])
    busy_status = check_threshold(max_busy, HOST_THRESHOLDS["disk_util_warn"], HOST_THRESHOLDS["disk_util_crit"])
    order = {"OK": 0, "WARN": 1, "CRIT": 2}
    status = max((latency_status, busy_status), key=lambda item: order[item])
    table_rows = [(r.get("DISK"), r.get("READ_LATENCY_MS"), r.get("WRITE_LATENCY_MS"),
                   r.get("BUSY_PCT"), r.get("READ_IOPS"), r.get("WRITE_IOPS")) for r, _, _ in values]
    return CheckResult("磁盘IO延迟", status, f"最高{max_latency:.1f}ms", f"最高磁盘忙碌率: {max_busy:.1f}%",
                       "磁盘延迟或忙碌率偏高，请结合 Oracle 等待事件排查" if status != "OK" else "",
                       extra_html=generate_data_table(["磁盘", "读延迟(ms)", "写延迟(ms)", "忙碌率(%)", "读IOPS", "写IOPS"], table_rows))
