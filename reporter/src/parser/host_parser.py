# -*- coding: utf-8 -*-
"""
主机巡检数据解析器
解析 Shell 采集的主机原始数据，进行阈值判定
"""
import re
from typing import Dict, List, Optional, Tuple
from parser.base import CheckResult, check_threshold, read_file, read_lines, generate_bar_chart, generate_data_table, parse_env_info
from config import HOST_THRESHOLDS
from parser.disk_capacity import assess_disk_capacity


def parse_host(raw_dir: str) -> List[CheckResult]:
    """解析主机巡检数据，返回巡检结果列表"""
    platform = str(parse_env_info(raw_dir).get("platform", "linux")).strip().lower()
    if platform == "windows":
        from parser.windows_host_parser import parse_windows_host
        return parse_windows_host(raw_dir)
    results = []
    host_dir = f"{raw_dir}/host"

    results.extend(_parse_disk_usage(host_dir))
    results.append(_parse_inode_usage(host_dir))
    results.extend(_parse_cpu(host_dir))
    results.extend(_parse_memory(host_dir))
    results.append(_parse_os_login(host_dir))
    results.append(_parse_firewall(host_dir))
    results.append(_parse_kernel_params(host_dir))
    results.append(_parse_time_sync(host_dir))
    results.append(_parse_network(host_dir))
    results.append(_parse_syslog(host_dir))
    results.extend(_parse_oracle_host_readiness(host_dir))
    from parser.grid_parser import parse_grid_status
    results.append(parse_grid_status(host_dir))

    return results


def _parse_size_to_gb(size_str: str) -> float:
    """将 df -h 输出的容量字符串转换为 GB，如 '50G' -> 50.0, '500M' -> 0.49"""
    size_str = size_str.strip().upper()
    try:
        if size_str.endswith("G"):
            return float(size_str[:-1])
        elif size_str.endswith("T"):
            return float(size_str[:-1]) * 1024
        elif size_str.endswith("M"):
            return float(size_str[:-1]) / 1024
        elif size_str.endswith("K"):
            return float(size_str[:-1]) / 1024 / 1024
        else:
            return float(size_str) / 1024 / 1024 / 1024  # 假设为字节
    except (ValueError, IndexError):
        return 0.0


def _is_boot_mount(mount: str) -> bool:
    """/boot、/boot/efi 等启动分区容量小、使用率高，不作为磁盘告警。"""
    path = (mount or "").rstrip("/") or "/"
    return path in {"/boot", "/efi"} or path.startswith("/boot/")


def _unescape_findmnt_field(value: str) -> str:
    """还原 findmnt 为空格等字符使用的八进制转义。"""
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _read_mount_metadata(host_dir: str) -> Dict[str, Tuple[str, str, str]]:
    """读取挂载点对应的来源、文件系统类型和挂载选项。"""
    metadata = {}
    content = read_file(f"{host_dir}/mounts.txt")
    for line in content.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) != 4:
            continue
        source, fs_type, options, mount = (_unescape_findmnt_field(part) for part in parts)
        metadata[mount] = (source, fs_type.lower(), options.lower())
    return metadata


def _is_read_only_media(source: str, fs_type: str, options: str) -> bool:
    """只读光盘和不可变镜像的 100% 使用率是正常状态，不参与容量告警。"""
    option_set = set(options.split(","))
    if fs_type in {"iso9660", "squashfs", "erofs", "cramfs"}:
        return True
    if fs_type == "udf" and "ro" in option_set:
        return True
    return "ro" in option_set and bool(re.match(
        r"^/dev/(?:sr\d+|scd\d+|cdrom\d*|dvd\d*)$", source, re.IGNORECASE
    ))


def _parse_disk_usage(host_dir: str) -> List[CheckResult]:
    """解析磁盘使用率"""
    results = []
    content = read_file(f"{host_dir}/disk_usage.txt")
    if not content:
        results.append(CheckResult("磁盘使用率", "CRIT", "数据缺失", "无法获取磁盘信息"))
        return results

    disk_data = []  # [(mount, usage_pct, total, used, avail, avail_gb), ...]
    ignored_read_only_media = []  # [(mount, fs_type), ...]
    mount_metadata = _read_mount_metadata(host_dir)

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("Filesystem") or line.startswith("文件系统"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue

        mount = parts[5] if len(parts) > 5 else parts[-1]
        usage_str = parts[4].replace("%", "")

        # 跳过特殊文件系统
        fs_type = parts[0]  # 文件系统列，如 /dev/sda1, tmpfs 等
        skip_fs_types = ["tmpfs", "devtmpfs", "none", "overlay", "shm"]
        if fs_type in skip_fs_types:
            continue
        # 跳过特殊挂载点；boot 分区（含 /boot/efi）不参与容量告警
        skip_mounts = ["/dev", "/dev/shm", "/proc", "/sys", "/run", "/tmp"]
        if mount in skip_mounts or _is_boot_mount(mount):
            continue

        source, mount_fs_type, mount_options = mount_metadata.get(mount, (fs_type, "", ""))
        if _is_read_only_media(source, mount_fs_type, mount_options):
            ignored_read_only_media.append((mount, mount_fs_type or "只读介质"))
            continue

        try:
            usage = float(usage_str)
        except ValueError:
            continue

        total = parts[1]
        used = parts[2]
        avail = parts[3]
        avail_gb = _parse_size_to_gb(avail)

        disk_data.append((mount, usage, total, used, avail, avail_gb))

        status, free_status = assess_disk_capacity(usage, _parse_size_to_gb(total), avail_gb)

        suggestion = ""
        if status == "CRIT":
            if free_status == "CRIT":
                suggestion = f"磁盘 {mount} 可用空间仅 {avail_gb:.1f}GB，请立即清理或扩容"
            else:
                suggestion = f"磁盘 {mount} 使用率已达 {usage}%，请立即清理或扩容"
        elif status == "WARN":
            if free_status == "WARN":
                suggestion = f"磁盘 {mount} 可用空间 {avail_gb:.1f}GB 偏低，建议关注"
            else:
                suggestion = f"磁盘 {mount} 使用率 {usage}%，建议关注并清理"

        results.append(CheckResult(
            f"磁盘使用率-{mount}", status, f"{usage}%",
            f"总容量: {total}, 已用: {used}, 可用: {avail}({avail_gb:.1f}GB), 挂载点: {mount}",
            suggestion
        ))

    # 无有效数据时的兜底
    if not results and not disk_data and not ignored_read_only_media:
        results.append(CheckResult("磁盘使用率", "CRIT", "数据缺失", "无法解析磁盘使用信息"))

    # 添加磁盘使用概览（含柱状图和数据表格）
    if disk_data or ignored_read_only_media:
        overview_html = ""
        overview_detail = f"共 {len(disk_data)} 个文件系统挂载点参与容量检查"
        if ignored_read_only_media:
            ignored_text = ", ".join(
                f"{mount}({fs_type})" for mount, fs_type in ignored_read_only_media
            )
            overview_detail += (
                f"；已忽略 {len(ignored_read_only_media)} 个只读光盘/镜像文件系统: {ignored_text}"
            )

    if disk_data:
        bar_items = [(mount, pct, "%") for mount, pct, _, _, _, _ in disk_data]
        bar_html = generate_bar_chart(bar_items,
                                      warn_threshold=HOST_THRESHOLDS["disk_usage_warn"],
                                      crit_threshold=HOST_THRESHOLDS["disk_usage_crit"])

        table_rows = [(mount, total, used, avail, f"{pct}%", f"{avail_gb:.1f}GB")
                      for mount, pct, total, used, avail, avail_gb in disk_data]
        table_html = generate_data_table(
            ["挂载点", "总容量", "已用", "可用", "使用率", "可用(GB)"],
            table_rows
        )
        overview_html = bar_html + table_html

    if disk_data or ignored_read_only_media:
        overview = CheckResult(
            "磁盘使用概览", "OK", f"{len(disk_data)}个挂载点",
            overview_detail,
            extra_html=overview_html
        )
        results.insert(0, overview)

    return results


def _parse_inode_usage(host_dir: str) -> CheckResult:
    """检查 inode 耗尽风险；容量充足并不代表仍可创建文件。"""
    content = read_file(f"{host_dir}/disk_inode.txt")
    if not content:
        return CheckResult("inode使用率", "CRIT", "数据缺失", "无法获取文件系统 inode 信息")
    rows = []
    worst = 0.0
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].lower().startswith(("filesystem", "文件系统")):
            continue
        if parts[0] in ("tmpfs", "devtmpfs", "overlay"):
            continue
        mount = parts[-1]
        if _is_boot_mount(mount) or mount in {"/dev", "/dev/shm", "/proc", "/sys", "/run", "/tmp"}:
            continue
        try:
            pct = float(parts[4].rstrip("%"))
        except ValueError:
            continue
        rows.append((parts[-1], parts[1], parts[2], parts[3], f"{pct:.0f}%"))
        worst = max(worst, pct)
    if not rows:
        return CheckResult("inode使用率", "CRIT", "无法解析", "inode 输出格式无法识别")
    status = check_threshold(worst, HOST_THRESHOLDS["inode_usage_warn"], HOST_THRESHOLDS["inode_usage_crit"])
    suggestion = "inode 使用率偏高，请定位并清理大量小文件" if status != "OK" else ""
    return CheckResult("inode使用率", status, f"最高{worst:.0f}%", f"已检查 {len(rows)} 个持久文件系统", suggestion,
                       extra_html=generate_data_table(["挂载点", "总inode", "已用", "可用", "使用率"], rows))


def _parse_cpu(host_dir: str) -> List[CheckResult]:
    """解析 CPU 负载"""
    results = []

    # 从 uptime 获取负载均值
    uptime_content = read_file(f"{host_dir}/cpu_load.txt")
    load_avg = "N/A"
    load_values = []
    if uptime_content:
        match = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", uptime_content)
        if match:
            load_avg = f"{match.group(1)}, {match.group(2)}, {match.group(3)}"
            load_values = [float(match.group(i)) for i in range(1, 4)]

    # 从 mpstat 获取 CPU 使用率
    cpu_usage = None
    io_wait = 0.0
    mpstat_content = read_file(f"{host_dir}/mpstat.txt")
    if mpstat_content:
        lines = mpstat_content.strip().splitlines()
        if len(lines) >= 2:
            last_line = lines[-1].strip()
            parts = last_line.split()
            if parts:
                try:
                    cpu_idle = float(parts[-1])
                    cpu_usage = 100.0 - cpu_idle
                    # mpstat 的 %iowait 位于 idle 前第 6 列（兼容带 Average: 的输出）。
                    if len(parts) >= 7:
                        io_wait = float(parts[-6])
                except ValueError:
                    pass

    cpu_count = len(re.findall(r"^processor\s*:", read_file(f"{host_dir}/cpu_info.txt"), re.MULTILINE)) or 1
    if cpu_usage is None:
        status = "WARN"
        cpu_usage = 0.0
    else:
        status = check_threshold(cpu_usage, HOST_THRESHOLDS["cpu_usage_warn"], HOST_THRESHOLDS["cpu_usage_crit"])
    load_per_cpu = (load_values[0] / cpu_count) if load_values else 0.0
    load_status = check_threshold(load_per_cpu, HOST_THRESHOLDS["load_per_cpu_warn"], HOST_THRESHOLDS["load_per_cpu_crit"])
    io_status = check_threshold(io_wait, HOST_THRESHOLDS["iowait_warn"], HOST_THRESHOLDS["iowait_crit"])
    order = {"OK": 0, "WARN": 1, "CRIT": 2}
    status = max((status, load_status, io_status), key=lambda x: order[x])
    suggestion = ""
    if status == "CRIT":
        suggestion = "CPU 使用率过高，请检查占用进程"
    elif status == "WARN":
        suggestion = "CPU 使用率偏高，建议关注"

    results.append(CheckResult(
        "CPU使用率", status, f"{cpu_usage:.1f}%",
        f"CPU数: {cpu_count}, 负载均值(1/5/15min): {load_avg}, 单CPU负载: {load_per_cpu:.2f}, IO等待: {io_wait:.1f}%",
        suggestion
    ))
    return results


def _parse_vmstat_swap_activity(host_dir: str) -> Tuple[float, float, bool, int]:
    """读取 vmstat 实时采样，返回平均 si/so、是否持续换页及有效采样数。"""
    content = read_file(f"{host_dir}/vmstat.txt")
    header = None
    samples = []
    for line in content.splitlines():
        parts = line.split()
        if "si" in parts and "so" in parts and parts[:2] == ["r", "b"]:
            header = parts
            continue
        if not header or len(parts) < len(header):
            continue
        try:
            samples.append((float(parts[header.index("si")]), float(parts[header.index("so")])))
        except (ValueError, IndexError):
            continue

    # vmstat 第一行是开机以来的平均值；后续行才是采样间隔内的实时数据。
    recent_samples = samples[1:] if len(samples) > 1 else []
    if not recent_samples:
        return 0.0, 0.0, False, 0

    avg_si = sum(sample[0] for sample in recent_samples) / len(recent_samples)
    avg_so = sum(sample[1] for sample in recent_samples) / len(recent_samples)
    sustained = len(recent_samples) >= 2 and all(
        si > 0 or so > 0 for si, so in recent_samples
    )
    return avg_si, avg_so, sustained, len(recent_samples)


def _parse_meminfo_values(host_dir: str) -> Dict[str, int]:
    """读取 /proc/meminfo，返回以 kB 为单位的字段。"""
    values = {}
    for line in read_file(f"{host_dir}/meminfo.txt").splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)", line)
        if match:
            values[match.group(1)] = int(match.group(2))
    return values


def _parse_free_values(content: str) -> Tuple[Dict[str, int], Optional[int], Optional[int], int, int]:
    """兼容解析新旧 procps 的 free -m 输出。"""
    header = None
    memory = {}
    legacy_used = legacy_available = None
    swap_total = swap_used = 0

    for line in content.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "total" and "used" in parts and "free" in parts:
            header = parts
            continue
        if parts[0] == "Mem:":
            try:
                numbers = [int(value) for value in parts[1:]]
            except ValueError:
                continue
            if header and len(numbers) >= len(header):
                memory = dict(zip(header, numbers))
            continue
        if line.lstrip().startswith("-/+ buffers/cache:"):
            try:
                legacy_used, legacy_available = int(parts[-2]), int(parts[-1])
            except (ValueError, IndexError):
                pass
            continue
        if parts[0] == "Swap:" and len(parts) >= 3:
            try:
                swap_total, swap_used = int(parts[1]), int(parts[2])
            except ValueError:
                pass

    return memory, legacy_used, legacy_available, swap_total, swap_used


def _parse_memory(host_dir: str) -> List[CheckResult]:
    """解析内存使用"""
    results = []
    content = read_file(f"{host_dir}/memory.txt")
    free_values, legacy_used, legacy_available, swap_total, swap_used = _parse_free_values(content)
    meminfo = _parse_meminfo_values(host_dir)

    # 优先使用内核提供的 MemAvailable；旧内核按 procps-ng 的兼容口径估算。
    mem_total = mem_avail = mem_cache = 0
    calculation_basis = ""
    total_kb = meminfo.get("MemTotal", 0)
    if total_kb > 0:
        if "MemAvailable" in meminfo:
            available_kb = meminfo["MemAvailable"]
            calculation_basis = "MemAvailable"
        else:
            available_kb = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
                + meminfo.get("SReclaimable", 0)
                - meminfo.get("Shmem", 0)
            )
            calculation_basis = "旧内核兼容估算"
        available_kb = min(total_kb, max(0, available_kb))
        cache_kb = (
            meminfo.get("Buffers", 0)
            + meminfo.get("Cached", 0)
            + meminfo.get("SReclaimable", 0)
        )
        mem_total = total_kb // 1024
        mem_avail = available_kb // 1024
        mem_cache = max(0, cache_kb // 1024)
    elif free_values.get("total", 0) > 0:
        mem_total = free_values["total"]
        if "available" in free_values:
            mem_avail = free_values["available"]
            calculation_basis = "free available"
        elif legacy_available is not None:
            mem_avail = legacy_available
            calculation_basis = "free -/+ buffers/cache"
        elif "buffers" in free_values and "cached" in free_values:
            mem_avail = (
                free_values.get("free", 0)
                + free_values["buffers"]
                + free_values["cached"]
            )
            calculation_basis = "旧版 free 兼容估算"
        else:
            mem_avail = max(0, mem_total - free_values.get("used", mem_total))
            calculation_basis = "free used 降级值"
        mem_avail = min(mem_total, max(0, mem_avail))
        mem_cache = free_values.get(
            "buff/cache",
            free_values.get("buffers", 0) + free_values.get("cached", 0),
        )
    else:
        results.append(CheckResult("内存使用率", "CRIT", "数据异常", "无法解析有效的内存总量和可用内存"))
        return results

    if swap_total <= 0 and meminfo.get("SwapTotal", 0) > 0:
        swap_total = meminfo["SwapTotal"] // 1024
        swap_used = max(0, (meminfo["SwapTotal"] - meminfo.get("SwapFree", 0)) // 1024)

    mem_used = mem_total - mem_avail
    mem_usage = (mem_used / mem_total * 100) if mem_total > 0 else 0
    status = check_threshold(mem_usage, HOST_THRESHOLDS["mem_usage_warn"],
                             HOST_THRESHOLDS["mem_usage_crit"])
    suggestion = ""
    if status in ("CRIT", "WARN"):
        suggestion = "内存使用率偏高，请检查内存占用进程或考虑扩容"

    results.append(CheckResult(
        "内存使用率", status, f"{mem_usage:.1f}%",
        f"总内存: {mem_total}MB, 实际占用: {mem_used}MB, 可用: {mem_avail}MB, "
        f"缓冲/缓存: {mem_cache}MB（可回收部分计入可用）, 计算口径: {calculation_basis}, "
        f"Swap已用: {swap_used}MB/{swap_total}MB",
        suggestion
    ))
    swap_usage = (swap_used / swap_total * 100) if swap_total > 0 else 0.0
    swap_status = check_threshold(
        swap_usage,
        HOST_THRESHOLDS["swap_usage_warn"],
        HOST_THRESHOLDS["swap_usage_crit"],
    )
    avg_si, avg_so, sustained_swap, swap_sample_count = _parse_vmstat_swap_activity(host_dir)

    # 持续换页比静态占用率更能反映当前压力；严重内存不足且持续换页时升级为严重。
    if swap_total > 0 and sustained_swap:
        activity_status = "CRIT" if mem_usage >= HOST_THRESHOLDS["mem_usage_crit"] else "WARN"
        status_order = {"OK": 0, "WARN": 1, "CRIT": 2}
        if status_order[activity_status] > status_order[swap_status]:
            swap_status = activity_status

    if swap_sample_count:
        swap_activity_detail = (
            f"最近{swap_sample_count}次实时采样平均换入(si): {avg_si:.1f}KB/s, "
            f"换出(so): {avg_so:.1f}KB/s, 持续换页: {'是' if sustained_swap else '否'}"
        )
    else:
        swap_activity_detail = "vmstat 实时换页采样不可用"

    swap_suggestion = ""
    if swap_status == "CRIT":
        if swap_usage >= HOST_THRESHOLDS["swap_usage_crit"]:
            swap_suggestion = f"Swap 使用率已达 {swap_usage:.1f}%，请立即检查内存压力和数据库内存配置"
        else:
            swap_suggestion = "内存严重不足且存在持续换页，请立即检查高内存进程和数据库内存配置"
    elif swap_status == "WARN":
        if sustained_swap:
            swap_suggestion = "检测到持续换页，请检查当前内存压力和数据库内存配置"
        else:
            swap_suggestion = f"Swap 使用率 {swap_usage:.1f}% 偏高，建议关注内存压力"

    results.append(CheckResult(
        "Swap使用率", swap_status, f"{swap_usage:.1f}%",
        f"Swap总量: {swap_total}MB, 已用: {swap_used}MB, "
        f"可用内存: {mem_avail}MB/{mem_total}MB, {swap_activity_detail}",
        swap_suggestion,
    ))
    return results


def _parse_os_login(host_dir: str) -> CheckResult:
    """解析操作系统登录"""
    current_users = read_lines(f"{host_dir}/current_users.txt")
    failed_logins = read_lines(f"{host_dir}/login_failed.txt")

    user_count = len(current_users)
    failed_count = len(failed_logins)

    status = "OK"
    suggestion = ""
    if failed_count > 50:
        status = "WARN"
        suggestion = "近期失败登录次数较多，可能存在暴力破解风险"

    return CheckResult(
        "操作系统登录", status, f"{user_count}个在线用户",
        f"当前在线用户: {user_count}, 近期失败登录: {failed_count}次",
        suggestion
    )


def _parse_firewall(host_dir: str) -> CheckResult:
    """解析防火墙状态"""
    fw_content = read_file(f"{host_dir}/firewall.txt")
    ipt_content = read_file(f"{host_dir}/iptables.txt")

    fw_status = "unknown"
    detail_hint = ""
    if "active (running)" in fw_content:
        fw_status = "running(firewalld)"
    elif "Chain" in ipt_content:
        input_match = re.search(r"Chain INPUT \(policy (\w+)\)", ipt_content)
        input_policy = input_match.group(1).upper() if input_match else "UNKNOWN"
        if input_policy in ("DROP", "REJECT"):
            fw_status = f"running(iptables, INPUT {input_policy})"
        elif input_policy == "ACCEPT":
            fw_status = f"open(iptables, INPUT {input_policy})"
            detail_hint = "；INPUT 未执行默认阻断，按 Oracle 数据库主机部署要求核对即可"
    elif any(marker in (fw_content + "\n" + ipt_content).lower() for marker in (
        "inactive", "not running", "could not be found", "command not found",
        "unrecognized service", "no such file or directory",
    )):
        fw_status = "stopped"
        detail_hint = "；Oracle 数据库主机关闭本机防火墙属于可接受配置，不作为告警"

    # Oracle 数据库主机常见部署要求关闭本机防火墙，stopped/open 均为信息性正常项。
    # 只有采集结果为空或无法识别时提示人工核对，避免把“未采集”误当成“已关闭”。
    status = "WARN" if fw_status == "unknown" else "OK"
    suggestion = "无法确认防火墙状态，请人工核对主机及外围网络访问控制" if status == "WARN" else ""

    return CheckResult(
        "防火墙状态", status, fw_status,
        f"防火墙状态: {fw_status}{detail_hint}",
        suggestion
    )


def _parse_kernel_params(host_dir: str) -> CheckResult:
    """解析内核参数"""
    sem = read_file(f"{host_dir}/kernel_sem.txt").strip()
    shmmax = read_file(f"{host_dir}/kernel_shmmax.txt").strip()
    shmmni = read_file(f"{host_dir}/kernel_shmmni.txt").strip()
    shmall = read_file(f"{host_dir}/kernel_shmall.txt").strip()

    # 提取数值
    shmmax_val = 0
    match = re.search(r"=\s*(\d+)", shmmax)
    if match:
        shmmax_val = int(match.group(1))

    detail_parts = []
    for label, val in [("sem", sem), ("shmmax", shmmax), ("shmmni", shmmni), ("shmall", shmall)]:
        detail_parts.append(f"{label}={val.split('=')[-1].strip() if '=' in val else val}")
    detail = ", ".join(detail_parts)

    status = "OK"
    suggestion = ""
    if shmmax_val > 0 and shmmax_val < 4294967296:
        status = "WARN"
        suggestion = "kernel.shmmax 建议 >= 4294967296 (4G)"

    return CheckResult("内核参数", status, "已检查", detail, suggestion)


def _parse_time_sync(host_dir: str) -> CheckResult:
    """解析时间同步"""
    dt = read_file(f"{host_dir}/datetime.txt").strip()
    ntp = read_file(f"{host_dir}/ntp.txt").strip()
    timedatectl_content = read_file(f"{host_dir}/timedatectl.txt").strip()

    # 过滤调试输出 (set -x 产生的 ++ 前缀行)
    dt_line = "N/A"
    if dt:
        for line in dt.splitlines():
            line = line.strip()
            if line and not line.startswith("+") and not line.startswith("++"):
                dt_line = line
                break

    # 检查 NTP 同步状态
    ntp_status = "未知"
    if timedatectl_content:
        for line in timedatectl_content.splitlines():
            if "NTP synchronized" in line or "System clock synchronized" in line:
                if "yes" in line.lower():
                    ntp_status = "已同步"
                elif "no" in line.lower():
                    ntp_status = "未同步"
                break
    elif ntp and "Connection refused" not in ntp:
        ntp_status = "已配置"

    status = "OK"
    hint = ""
    if ntp_status not in ("已同步", "已配置"):
        hint = "。提示：未与 NTP/Chrony 同步时，可能影响审计、RAC 与故障定位"
    return CheckResult(
        "时间同步", status, ntp_status,
        f"系统时间: {dt_line}, NTP状态: {ntp_status}{hint}",
        ""
    )


def _parse_network(host_dir: str) -> CheckResult:
    """解析网络状态，罗列所有监听端口"""
    content = read_file(f"{host_dir}/network_listen.txt")
    if not content:
        return CheckResult("网络状态", "CRIT", "数据缺失", "无法获取网络监听信息")

    port_data = []  # [(proto, local_addr, port, process), ...]
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        # 判断协议
        proto = "TCP"
        if parts[0].startswith("udp"):
            proto = "UDP"

        # 解析 Local Address:Port
        local_addr = parts[3] if len(parts) > 3 else parts[-2] if len(parts) > 1 else ""
        addr_port = local_addr.rsplit(":", 1) if ":" in local_addr else local_addr.rsplit(".", 1)
        addr = addr_port[0] if len(addr_port) > 1 else "*"
        port = addr_port[1] if len(addr_port) > 1 else local_addr

        # 解析进程名（ss -tlnp 输出中在最后，含 users:(("xxx",pid))
        process = ""
        for p in parts:
            if 'users:(("' in p or 'users:((' in p:
                # 提取进程名
                match = re.search(r'users:\(\("([^"]+)"', line)
                if match:
                    process = match.group(1)
                break
        if not process and len(parts) > 5:
            # netstat -tlnp 格式，最后一列是 PID/进程名
            last = parts[-1]
            if "/" in last:
                process = last.split("/", 1)[1] if "/" in last else last

        port_data.append((proto, addr, port, process))

    extra = ""
    if port_data:
        table_rows = [(p, a, pt, proc if proc else "-") for p, a, pt, proc in port_data]
        extra = generate_data_table(
            ["协议", "地址", "端口", "进程"],
            table_rows
        )

    return CheckResult(
        "网络监听端口", "OK", f"{len(port_data)}个监听端口",
        f"监听端口数: {len(port_data)}",
        extra_html=extra
    )


def _parse_syslog(host_dir: str) -> CheckResult:
    """解析系统日志，列出日志来源和最近错误摘要"""
    errors = read_lines(f"{host_dir}/syslog_errors.txt")
    error_count = len(errors)

    status = "OK"
    suggestion = ""
    if error_count > 20:
        status = "WARN"
        suggestion = "系统日志中存在较多错误信息，建议排查"

    # 构建错误摘要表格（最多展示最近20条）
    extra = ""
    if errors:
        # 解析 syslog 行格式: "Mon DD HH:MM:SS hostname process: message"
        summary_rows = []
        for line in errors[:20]:
            line = line.strip()
            if not line:
                continue
            # 尝试提取时间和消息
            parts = line.split(None, 4)
            if len(parts) >= 5:
                timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
                host = parts[3]
                msg = parts[4][:120]  # 截断过长消息
                summary_rows.append((timestamp, host, msg))
            else:
                summary_rows.append(("-", "-", line[:120]))

        if summary_rows:
            extra = generate_data_table(
                ["时间", "主机", "错误摘要"],
                summary_rows
            )
            extra = f'<div style="font-size:12px;color:#64748b;margin-bottom:4px;">来源: /var/log/messages (最近 {len(summary_rows)} 条)</div>' + extra

    return CheckResult(
        "系统日志", status, f"{error_count}条错误",
        f"系统日志中发现 {error_count} 条错误/关键信息",
        suggestion,
        extra_html=extra
    )


def _parse_oracle_host_readiness(host_dir: str) -> List[CheckResult]:
    results = []
    meminfo = read_file(f"{host_dir}/meminfo.txt")
    def mem_value(name: str) -> int:
        m = re.search(rf"^{re.escape(name)}:\s+(\d+)", meminfo, re.MULTILINE)
        return int(m.group(1)) if m else 0

    hp_total = mem_value("HugePages_Total")
    hp_free = mem_value("HugePages_Free")
    hp_size_kb = mem_value("Hugepagesize")
    hp_detail = f"HugePages总数: {hp_total}, 空闲: {hp_free}, 页大小: {hp_size_kb}KB"
    if hp_total == 0:
        hp_detail += "。未配置 HugePages 属合理情况，不作为告警。"
    results.append(CheckResult(
        "Oracle HugePages", "OK", f"{hp_total}页",
        hp_detail, ""
    ))

    thp = read_file(f"{host_dir}/transparent_hugepage.txt")
    thp_enabled = bool(re.search(r"enabled=.*\[(always|madvise)\]", thp))
    results.append(CheckResult(
        "Transparent HugePages", "WARN" if thp_enabled else "OK",
        "已启用" if thp_enabled else "已禁用/不可用", thp.strip() or "未采集",
        "Oracle 数据库主机通常应禁用 THP，并使用静态 HugePages" if thp_enabled else ""
    ))

    proc = read_file(f"{host_dir}/process_summary.txt")
    zombie = 0
    for line in proc.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "Z":
            try:
                zombie = int(parts[1])
            except ValueError:
                pass
    results.append(CheckResult(
        "僵尸进程", "WARN" if zombie else "OK", f"{zombie}个", f"僵尸进程数: {zombie}",
        "请定位父进程并修复进程回收逻辑" if zombie else ""
    ))

    iostat = read_file(f"{host_dir}/iostat.txt")
    devices = []
    # iostat 第一段是开机以来累计值，低 IOPS 设备会产生失真的高 await；只分析后续采样段。
    sample_sections = re.split(r"(?m)^Device:\s+", iostat)[1:]
    if len(sample_sections) > 1:
        sample_sections = sample_sections[1:]
    for section in sample_sections[-2:]:
        for line in section.splitlines():
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                await_ms = float(parts[-5])
                util = float(parts[-1])
                iops = float(parts[3]) + float(parts[4])
                if iops > 0 and re.match(r"^(sd|vd|xvd|dm-|nvme)", parts[0]):
                    devices.append((parts[0], await_ms, util))
            except (ValueError, IndexError):
                continue
    if devices:
        max_await = max(x[1] for x in devices)
        max_util = max(x[2] for x in devices)
        await_status = check_threshold(max_await, HOST_THRESHOLDS["disk_await_warn_ms"], HOST_THRESHOLDS["disk_await_crit_ms"])
        util_status = check_threshold(max_util, HOST_THRESHOLDS["disk_util_warn"], HOST_THRESHOLDS["disk_util_crit"])
        order = {"OK": 0, "WARN": 1, "CRIT": 2}
        io_status = max((await_status, util_status), key=lambda x: order[x])
        rows = [(d, f"{a:.1f}", f"{u:.1f}%") for d, a, u in devices[-20:]]
        results.append(CheckResult("磁盘IO延迟", io_status, f"最高{max_await:.1f}ms", f"最高利用率: {max_util:.1f}%",
                                   "磁盘延迟或利用率偏高，请结合数据库等待事件持续观察" if io_status != "OK" else "",
                                   extra_html=generate_data_table(["设备", "await(ms)", "利用率"], rows)))
    else:
        results.append(CheckResult("磁盘IO延迟", "WARN", "无法评估", "iostat 不可用或输出无法识别", "建议安装 sysstat 并持续采集磁盘延迟"))
    return results
