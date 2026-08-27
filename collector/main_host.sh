#!/bin/bash
#==============================================================
# 主机巡检采集脚本
# 使用 root 用户执行，采集主机相关数据
#==============================================================

COLLECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${COLLECT_DIR}/lib/common.sh"

show_help() {
    echo "主机巡检采集工具 v4.2"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --no-pack    采集后不打包"
    echo "  --help       显示帮助信息"
    echo ""
    echo "示例 (root 用户执行):"
    echo "  # ./main_host.sh"
    echo "  # ./main_host.sh --no-pack"
}

NO_PACK=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-pack)  NO_PACK=true; shift ;;
        --help)     show_help; exit 0 ;;
        *)          echo "未知选项: $1"; show_help; exit 1 ;;
    esac
done

main() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "WARNING: 主机巡检建议使用 root 用户执行，部分数据可能无法采集"
    fi

    echo "============================================"
    echo "  主机巡检数据采集 v4.2"
    echo "============================================"
    echo ""

    init_env_host || exit 2

    local start_time=$(date +%s)

    if [[ "${CHECK_HOST}" == "on" ]]; then
        source "${COLLECT_DIR}/lib/host_check.sh"
        host_collect
    else
        log_warn "主机巡检已关闭 (CHECK_HOST=${CHECK_HOST})"
    fi

    local collect_rc=0
    finalize_collection || collect_rc=$?
    pack_collection "host_check_${CHECK_TIMESTAMP}.tar.gz" || collect_rc=1

    local duration=$(( $(date +%s) - start_time ))
    print_collect_summary "主机巡检采集完成!" "${duration}" \
        "下一步: 使用 oracle 用户执行数据库巡检" \
        "su - oracle -c \"cd ${COLLECT_DIR} && ./main_db.sh\""
    return "${collect_rc}"
}

main
exit $?
