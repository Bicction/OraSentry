#!/bin/bash
#==============================================================
# 数据库巡检采集脚本
# 使用 oracle 用户执行，采集数据库和安全相关数据
#==============================================================

COLLECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${COLLECT_DIR}/lib/common.sh"

show_help() {
    echo "数据库巡检采集工具 v4.2"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -d, --db        仅采集数据库数据"
    echo "  -s, --security  仅采集安全数据"
    echo "  -a, --all       采集全部 (数据库+安全, 默认)"
    echo "  --no-pack       采集后不打包"
    echo "  --help          显示帮助信息"
    echo ""
    echo "示例 (oracle 用户执行):"
    echo "  # ./main_db.sh"
    echo "  # DB_INTERACTIVE_LOGIN=on 时按提示输入连接信息"
    echo "  # ./main_db.sh -d"
    echo "  # ./main_db.sh --no-pack"
}

DO_DB=false
DO_SECURITY=false
DO_ALL=true
NO_PACK=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--db)       DO_DB=true; DO_ALL=false; shift ;;
        -s|--security) DO_SECURITY=true; DO_ALL=false; shift ;;
        -a|--all)      DO_ALL=true; shift ;;
        --no-pack)     NO_PACK=true; shift ;;
        --help)        show_help; exit 0 ;;
        *)             echo "未知选项: $1"; show_help; exit 1 ;;
    esac
done

if [[ "${DO_ALL}" == true ]]; then
    DO_DB=true
    DO_SECURITY=true
fi

main() {
    if [[ "$(whoami)" == "root" ]]; then
        echo "ERROR: 数据库巡检不能使用 root 用户执行，请切换到 oracle 用户"
        echo "  su - oracle -c \"cd ${COLLECT_DIR} && ./main_db.sh\""
        exit 1
    fi

    echo "============================================"
    echo "  数据库巡检数据采集 v4.2"
    echo "============================================"
    echo ""

    init_env_db || exit 2

    local start_time=$(date +%s)

    if [[ "${DO_DB}" == true ]] && [[ "${CHECK_DB}" == "on" ]]; then
        source "${COLLECT_DIR}/lib/db_check.sh"
        db_collect
    fi

    if [[ "${DO_SECURITY}" == true ]] && [[ "${CHECK_SECURITY}" == "on" ]]; then
        source "${COLLECT_DIR}/lib/security_check.sh"
        security_collect
    fi

    local collect_rc=0
    finalize_collection || collect_rc=$?
    local safe_sid="${ORACLE_SID//[!A-Za-z0-9_.-]/_}"
    pack_collection "db_check_${safe_sid}_${CHECK_TIMESTAMP}.tar.gz" || collect_rc=1

    local duration=$(( $(date +%s) - start_time ))
    print_collect_summary "数据库巡检采集完成!" "${duration}" \
        "请将 output/raw 下的采集包拷贝至 reporter 生成报告"
    return "${collect_rc}"
}

main
exit $?
