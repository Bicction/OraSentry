#!/bin/bash
#==============================================================
# Oracle 巡检统一入口
# 根据当前用户自动分发到对应采集脚本:
#   root 用户   -> main_host.sh (主机巡检)
#   oracle 用户 -> main_db.sh   (数据库+安全巡检)
#==============================================================

COLLECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    echo "Oracle 巡检数据采集工具 v4.2"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "自动根据当前用户执行对应采集:"
    echo "  root 用户   -> 主机巡检 (main_host.sh)"
    echo "  oracle 用户 -> 数据库巡检 (main_db.sh)"
    echo ""
    echo "选项:"
    echo "  --host       强制执行主机巡检 (需 root)"
    echo "  --db         强制执行数据库巡检 (需 oracle)"
    echo "  --no-pack    采集后不打包"
    echo "  --help       显示帮助信息"
    echo ""
    echo "推荐用法:"
    echo "  # 1. root 用户执行主机巡检"
    echo "  ./main_host.sh"
    echo ""
    echo "  # 2. oracle 用户执行数据库巡检"
    echo "  su - oracle -c \"cd ${COLLECT_DIR} && ./main_db.sh\""
    echo ""
    echo "  # 3. 将 output/raw 下的 tar.gz 拷贝至 reporter"
}

FORCE_HOST=false
FORCE_DB=false
PASS_THROUGH_ARGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)     FORCE_HOST=true; shift ;;
        --db)       FORCE_DB=true; shift ;;
        --no-pack)  PASS_THROUGH_ARGS="${PASS_THROUGH_ARGS} --no-pack"; shift ;;
        --help)     show_help; exit 0 ;;
        *)          echo "未知选项: $1"; show_help; exit 1 ;;
    esac
done

if [[ "${FORCE_HOST}" == true ]]; then
    exec "${COLLECT_DIR}/main_host.sh" ${PASS_THROUGH_ARGS}
fi

if [[ "${FORCE_DB}" == true ]]; then
    exec "${COLLECT_DIR}/main_db.sh" ${PASS_THROUGH_ARGS}
fi

current_user=$(whoami)

if [[ "${current_user}" == "root" ]]; then
    echo "检测到 root 用户，执行主机巡检..."
    echo ""
    exec "${COLLECT_DIR}/main_host.sh" ${PASS_THROUGH_ARGS}
elif [[ "${current_user}" == "oracle" ]]; then
    echo "检测到 oracle 用户，执行数据库巡检..."
    echo ""
    exec "${COLLECT_DIR}/main_db.sh" ${PASS_THROUGH_ARGS}
else
    echo "ERROR: 当前用户为 '${current_user}'，不支持自动分发"
    echo ""
    echo "请使用以下方式执行:"
    echo "  root 用户:   ${COLLECT_DIR}/main_host.sh"
    echo "  oracle 用户: ${COLLECT_DIR}/main_db.sh"
    echo ""
    echo "或强制指定:"
    echo "  $0 --host    (主机巡检)"
    echo "  $0 --db      (数据库巡检)"
    exit 1
fi
