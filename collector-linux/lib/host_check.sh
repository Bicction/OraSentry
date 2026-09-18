#!/bin/bash
#==============================================================
# 主机巡检 - 纯数据采集
# 仅收集主机相关命令输出，不做任何判定
# 由 collect/main_host.sh 加载 common.sh 后 source 本文件
#==============================================================

host_collect() {
    log_info "========== 开始主机数据采集 =========="

    local d="${RAW_DIR}/host"
    mkdir -p "${d}"

    # 1. 硬盘使用率
    collect_cmd "${d}/disk_usage.txt" "df -h"
    collect_cmd "${d}/disk_inode.txt" "df -i"
    collect_cmd "${d}/mounts.txt" "findmnt -rn -o SOURCE,FSTYPE,OPTIONS,TARGET"

    # 2. CPU 负载
    collect_cmd "${d}/cpu_load.txt" "uptime"
    collect_cmd "${d}/cpu_info.txt" "cat /proc/cpuinfo"
    collect_cmd "${d}/cpu_stat.txt" "cat /proc/stat"
    mpstat 1 3 > "${d}/mpstat.txt" 2>&1 || true
    collect_optional_cmd "${d}/iostat.txt" "iostat -xz 1 3"

    # 3. 内存使用
    collect_cmd "${d}/memory.txt" "free -m"
    collect_cmd "${d}/vmstat.txt" "vmstat 1 3"
    collect_cmd "${d}/meminfo.txt" "cat /proc/meminfo"
    collect_optional_cmd "${d}/transparent_hugepage.txt" "for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag; do printf '%s=' \"\$f\"; cat \"\$f\"; done"

    # 4. 操作系统登录检查
    collect_cmd "${d}/login_history.txt" "last -20"
    collect_cmd "${d}/current_users.txt" "who"
    collect_cmd "${d}/login_failed.txt" "lastb -10 2>/dev/null"
    collect_cmd "${d}/lastlog.txt" "lastlog"

    # 5. 防火墙状态
    systemctl status firewalld > "${d}/firewall.txt" 2>&1 || true
    iptables -L -n > "${d}/iptables.txt" 2>&1 || true
    firewall-cmd --list-all > "${d}/firewall_rules.txt" 2>&1 || true

    # 6. 内核参数
    collect_cmd "${d}/kernel_params.txt" "sysctl -a 2>/dev/null"
    collect_cmd "${d}/kernel_sem.txt" "sysctl kernel.sem"
    collect_cmd "${d}/kernel_shmmax.txt" "sysctl kernel.shmmax"
    collect_cmd "${d}/kernel_shmmni.txt" "sysctl kernel.shmmni"
    collect_cmd "${d}/kernel_shmall.txt" "sysctl kernel.shmall"
    collect_cmd "${d}/kernel_aio.txt" "sysctl fs.aio-max-nr fs.aio-nr fs.file-max"
    collect_cmd "${d}/kernel_network.txt" "sysctl net.ipv4.ip_local_port_range net.core.rmem_max net.core.wmem_max"

    # 7. 系统时间同步
    collect_cmd "${d}/datetime.txt" "date"
    ntpq -p > "${d}/ntp.txt" 2>&1 || chronyc sources > "${d}/ntp.txt" 2>&1 || true
    timedatectl > "${d}/timedatectl.txt" 2>&1 || true

    # 8. 网络状态
    ss -tlnp > "${d}/network_listen.txt" 2>&1 || netstat -tlnp > "${d}/network_listen.txt" 2>&1 || true
    ss -s > "${d}/network_summary.txt" 2>&1 || netstat -s > "${d}/network_summary.txt" 2>&1 || true
    collect_cmd "${d}/network_interfaces.txt" "ip addr"

    # 9. 系统日志
    grep -i "error\|critical\|panic" /var/log/messages 2>/dev/null | tail -100 > "${d}/syslog_errors.txt" || true
    dmesg | grep -i "error\|warn\|fail" | tail -50 > "${d}/dmesg_errors.txt" 2>&1 || true

    # 10. Oracle 相关进程
    collect_cmd "${d}/oracle_processes.txt" "ps -ef | grep ora_"
    collect_cmd "${d}/process_summary.txt" "ps -eo stat= | awk '{c[substr(\$1,1,1)]++} END {for (s in c) print s, c[s]}'"
    # 兼容旧版 procps：-o 使用 pcpu/pmem 而不是 %cpu/%mem，运行时长使用
    # POSIX/旧版支持更广的 etime 而不是 etimes。sed 会完整读取管道，避免
    # pipefail 下 head 提前关闭管道导致 ps 以 SIGPIPE/141 退出。
    # Top 进程仅为辅助明细，采集失败不应让整次巡检失败。
    collect_optional_cmd "${d}/top_cpu_processes.txt" "ps -eo pid,user,stat,pcpu,pmem,etime,comm,args --sort=-pcpu | sed -n '1,21p'"
    collect_optional_cmd "${d}/top_mem_processes.txt" "ps -eo pid,user,stat,pcpu,pmem,rss,etime,comm,args --sort=-rss | sed -n '1,21p'"
    collect_optional_cmd "${d}/oracle_limits.txt" "su - oracle -s /bin/bash -c 'ulimit -a'"
    collect_optional_cmd "${d}/selinux.txt" "getenforce"
    collect_optional_cmd "${d}/os_release.txt" "cat /etc/os-release"

    # Grid commands must run with the Grid owner's login environment.
    collect_grid_rac "${d}"

    log_info "========== 主机数据采集完成 =========="
}

collect_grid_rac() {
    local d="$1" output_file="$1/grid_rac.txt" rc=0
    if ! id grid >/dev/null 2>&1; then
        printf 'GRID_COLLECTION=SKIPPED\nGRID_REASON=本机未发现grid用户\n' > "${output_file}"
        record_collection 'grid_rac.txt' 'OPTIONAL_COMMAND' 'SKIPPED' '0' '本机未发现grid用户'
        return 0
    fi
    if ! command -v timeout >/dev/null 2>&1; then
        printf 'GRID_COLLECTION=FAILED\nGRID_REASON=缺少timeout，无法执行有时限的Grid检查\n' > "${output_file}"
        rc=1
    elif [[ "$(id -un)" == "grid" ]]; then
        timeout -k 3s 95s /bin/bash -s < "${COLLECT_DIR}/lib/grid_check.sh" > "${output_file}" 2>&1 || rc=$?
    elif [[ "$(id -u)" -eq 0 ]]; then
        # Open the script as root and pass it through stdin, so grid need not
        # have access to a collector installed under /root. Output stays root-owned.
        timeout -k 3s 95s su - grid -s /bin/bash -c 'exec /bin/bash -s' < "${COLLECT_DIR}/lib/grid_check.sh" > "${output_file}" 2>&1 || rc=$?
    else
        printf 'GRID_COLLECTION=FAILED\nGRID_REASON=发现grid用户，但当前用户无权切换；请使用root运行主机巡检\n' > "${output_file}"
        rc=1
    fi
    if [[ "${rc}" -ne 0 ]]; then
        printf '\nGRID_COLLECTION=FAILED\nGRID_EXIT_CODE=%s\n' "${rc}" >> "${output_file}"
        record_collection 'grid_rac.txt' 'OPTIONAL_COMMAND' 'WARN' "${rc}" 'Grid检查未完整执行，详见grid_rac.txt'
    else
        record_collection 'grid_rac.txt' 'OPTIONAL_COMMAND' 'OK' '0' ''
    fi
    return 0
}
