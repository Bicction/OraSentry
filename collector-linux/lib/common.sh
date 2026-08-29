#!/bin/bash
#==============================================================
# 公共函数库 - 纯采集版
# 仅提供日志、SQL执行、目录初始化等基础功能
# 不做任何阈值判定和结果分析
#==============================================================

if [[ -n "${ORACLE_CHECK_COMMON_LOADED:-}" ]]; then
    return 0
fi
ORACLE_CHECK_COMMON_LOADED=1
COLLECTOR_VERSION="4.3.0"
SCHEMA_VERSION="4.3"

# collector-linux/lib -> collector-linux
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT_DIR="$(cd "${LIB_DIR}/.." && pwd)"
CONF_FILE="${COLLECT_DIR}/conf/check.conf"

# 采集过程不因单个可选项失败而中断，但必须完整记录失败并让主程序返回非 0。
: "${COLLECT_FAILURES:=0}"
: "${COLLECT_WARNINGS:=0}"

config_has_key() {
    grep -v '^\s*#' "${CONF_FILE}" 2>/dev/null | grep -q "^${1}="
}

# 加载配置文件
load_config() {
    if [[ ! -f "${CONF_FILE}" ]]; then
        echo "ERROR: 配置文件不存在: ${CONF_FILE}"
        exit 1
    fi
    while IFS='=' read -r key value; do
        key=$(echo "${key}" | xargs)
        value=$(echo "${value}" | xargs)
        if [[ -n "${key}" && ! "${key}" =~ ^# && "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            export "${key}=${value}"
        fi
    done < <(grep -v '^\s*#' "${CONF_FILE}" | grep -v '^\s*$')
}

# 创建输出目录和日志文件（公共部分，被 init_env_host/init_env_db 调用）
_init_dirs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    export CHECK_TIMESTAMP="${timestamp}"
    local raw_base
    if [[ "${RAW_DATA_DIR}" = /* ]]; then
        raw_base="${RAW_DATA_DIR}"
    else
        raw_base="${COLLECT_DIR}/${RAW_DATA_DIR}"
    fi

    # root 完成主机采集后，oracle 用户仍需能在同一 output/raw 下创建目录。
    # 使用 oracle 主组和 setgid 目录，避免不安全的 0777。
    mkdir -p "${raw_base}" || {
        echo "ERROR: 无法创建输出目录: ${raw_base}" >&2
        return 1
    }
    if [[ "$(id -u)" -eq 0 ]] && id oracle >/dev/null 2>&1; then
        local oracle_group
        oracle_group=$(id -gn oracle 2>/dev/null)
        chgrp "${oracle_group}" "${raw_base}" 2>/dev/null || true
        chmod 2775 "${raw_base}" 2>/dev/null || true
    fi
    if [[ ! -w "${raw_base}" ]]; then
        echo "ERROR: 当前用户 $(whoami) 无权写入输出目录: ${raw_base}" >&2
        return 1
    fi

    # 极短时间内并发执行时避免目录碰撞。
    local run_dir="${raw_base}/${timestamp}"
    if [[ -e "${run_dir}" ]]; then
        run_dir="${raw_base}/${timestamp}_$$_${RANDOM}"
        export CHECK_TIMESTAMP="$(basename "${run_dir}")"
    fi
    export RAW_BASE="${raw_base}"
    export RAW_DIR="${run_dir}"
    umask 0002
    mkdir -p "${RAW_DIR}" || {
        echo "ERROR: 无法创建本次采集目录: ${RAW_DIR}" >&2
        return 1
    }
    export LOG_FILE="${RAW_DIR}/collect.log"
    export MANIFEST_FILE="${RAW_DIR}/collection_manifest.tsv"
    printf "item\ttype\tstatus\texit_code\tmessage\n" > "${MANIFEST_FILE}"

    # 调试模式: 开启后 set -x 输出每一步执行细节
    if [[ "${DEBUG}" == "on" ]]; then
        log_info "调试模式已开启 (DEBUG=on)"
        exec 2>&1
        set -x
        exec > >(tee -a "${LOG_FILE}")
    fi
}

# 初始化主机采集环境（root 用户执行）
init_env_host() {
    load_config
    _init_dirs || return 1

    log_info "=== 主机巡检采集 (root) ==="
    log_info "当前用户: $(whoami)"
    write_env_base "host"
}

# 交互读取数据库连接信息。DEBUG=on 时必须在整个读取和校验阶段关闭
# xtrace，避免密码值因条件判断或变量展开进入调试日志。
prompt_database_login() {
    local restore_xtrace=false
    local prompt_rc=0
    if [[ "$-" == *x* ]]; then
        restore_xtrace=true
        set +x
    fi

    echo "请输入数据库连接信息（密码不会显示）:"
    read -r -p "  IP/主机名: " DB_LOGIN_HOST || prompt_rc=1
    read -r -p "  端口 [1521]: " DB_LOGIN_PORT || prompt_rc=1
    DB_LOGIN_PORT="${DB_LOGIN_PORT:-1521}"
    read -r -p "  连接类型 [SERVICE_NAME/SID，默认 SERVICE_NAME]: " DB_LOGIN_CONNECT_TYPE || prompt_rc=1
    DB_LOGIN_CONNECT_TYPE=$(printf '%s' "${DB_LOGIN_CONNECT_TYPE:-SERVICE_NAME}" | tr '[:lower:]' '[:upper:]')
    read -r -p "  服务名/SID: " DB_LOGIN_CONNECT_NAME || prompt_rc=1
    read -r -p "  账号: " DB_LOGIN_USER || prompt_rc=1
    IFS= read -r -s -p "  密码: " DB_LOGIN_PASSWORD || prompt_rc=1
    printf '\n' >&2
    read -r -p "  角色 [SYSDBA/SYSOPER/NORMAL，默认 SYSDBA]: " DB_LOGIN_ROLE || prompt_rc=1
    DB_LOGIN_ROLE=$(printf '%s' "${DB_LOGIN_ROLE:-SYSDBA}" | tr '[:lower:]' '[:upper:]')

    if [[ ! "${DB_LOGIN_HOST:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]; then
        log_error "数据库 IP/主机名为空或包含不允许的字符"
        prompt_rc=1
    fi
    if [[ ! "${DB_LOGIN_PORT:-}" =~ ^[0-9]+$ ]] ||
       [[ "${DB_LOGIN_PORT:-0}" -lt 1 || "${DB_LOGIN_PORT:-0}" -gt 65535 ]]; then
        log_error "数据库端口必须是 1-65535 的整数"
        prompt_rc=1
    fi
    case "${DB_LOGIN_CONNECT_TYPE:-}" in
        SERVICE_NAME|SID) ;;
        *)
            log_error "数据库连接类型只支持 SERVICE_NAME 或 SID"
            prompt_rc=1
            ;;
    esac
    if [[ ! "${DB_LOGIN_CONNECT_NAME:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
        log_error "数据库服务名/SID 为空或包含不允许的字符"
        prompt_rc=1
    fi
    if [[ ! "${DB_LOGIN_USER:-}" =~ ^[A-Za-z][A-Za-z0-9_$#]*$ ]]; then
        log_error "数据库账号为空或不是有效的普通 Oracle 用户名"
        prompt_rc=1
    fi
    if [[ -z "${DB_LOGIN_PASSWORD:-}" ]]; then
        log_error "数据库密码不能为空"
        prompt_rc=1
    fi
    case "${DB_LOGIN_ROLE:-}" in
        SYSDBA|SYSOPER|NORMAL) ;;
        *)
            log_error "数据库角色只支持 SYSDBA、SYSOPER 或 NORMAL"
            prompt_rc=1
            ;;
    esac

    if [[ "${restore_xtrace}" == true ]]; then
        set -x
    fi
    return "${prompt_rc}"
}

# 所有 SQL*Plus 调用统一经过此入口。交互认证先以 /nolog 启动，再从
# 标准输入执行包含已安全引用密码的 CONNECT；账号、连接描述符、角色和
# 密码均不会成为进程启动参数。传递认证信息期间同样关闭 xtrace。
db_sqlplus() {
    local sqlplus_bin="${ORACLE_HOME}/bin/sqlplus"
    if [[ "${DB_AUTH_MODE:-os}" != "interactive_password" ]]; then
        "${sqlplus_bin}" "$@" "${DB_CONNECT}"
        return $?
    fi

    local restore_xtrace=false
    if [[ "$-" == *x* ]]; then
        restore_xtrace=true
        set +x
    fi

    # 从此处开始才展开密码，确保 DEBUG=on 的 xtrace 也无法记录其值。
    # 双引号可保留 @、/、空格等字符；密码本身的双引号按 Oracle 引用
    # 规则加倍。整个 CONNECT 仅通过 stdin 发送。
    local quoted_password="${DB_LOGIN_PASSWORD//\"/\"\"}"
    local connect_target="${DB_LOGIN_USER}/\"${quoted_password}\"@${DB_CONNECT_DESCRIPTOR}"
    if [[ "${DB_LOGIN_ROLE}" != "NORMAL" ]]; then
        connect_target="${connect_target} AS ${DB_LOGIN_ROLE}"
    fi

    {
        printf '%s\n' "SET ECHO OFF"
        printf '%s\n' "SET DEFINE OFF"
        printf '%s\n' "WHENEVER OSERROR EXIT FAILURE"
        printf '%s\n' "WHENEVER SQLERROR EXIT SQL.SQLCODE"
        printf 'CONNECT %s\n' "${connect_target}"
        cat
    } | "${sqlplus_bin}" "$@" /nolog
    local pipeline_status=("${PIPESTATUS[@]}")
    local sqlplus_rc="${pipeline_status[1]:-1}"
    if [[ "${restore_xtrace}" == true ]]; then
        set -x
    fi
    return "${sqlplus_rc}"
}

# 初始化数据库采集环境（oracle 用户执行）
init_env_db() {
    load_config
    _init_dirs || return 1

    log_info "=== 数据库巡检采集 (oracle) ==="
    log_info "当前用户: $(whoami)"

    # 不允许从配置或环境变量读取明文密码。交互模式使用不同的内部变量，
    # 且密码只存在于当前 Shell 进程内存中。
    if [[ -n "${DB_USER:-}" || -n "${DB_PASS:-}" ]]; then
        log_error "不支持通过 DB_USER/DB_PASS 保存明文认证；请使用交互认证、OS 认证或 Oracle Wallet"
        return 1
    fi
    case "${DB_INTERACTIVE_LOGIN:-off}" in
        on)
            prompt_database_login || return 1
            # SERVICE_NAME 可能是 PDB 服务，不能覆盖用于本地 Alert Log 的
            # ORACLE_SID。只有环境中没有实例 SID 且明确选择 SID 时才回填。
            if [[ -z "${ORACLE_SID:-}" && "${DB_LOGIN_CONNECT_TYPE}" == "SID" ]]; then
                export ORACLE_SID="${DB_LOGIN_CONNECT_NAME}"
            fi
            ;;
        off) ;;
        *)
            log_error "DB_INTERACTIVE_LOGIN 只能设置为 on 或 off"
            return 1
            ;;
    esac

    # ORACLE_SID: 配置文件优先，否则使用操作系统环境变量
    if [[ -z "${ORACLE_SID}" ]]; then
        export ORACLE_SID="${ORACLE_SID:-$(cat /etc/oratab 2>/dev/null | grep -v '^#' | grep -v '^$' | head -1 | cut -d: -f1)}"
        # 如果 oratab 也没有，尝试从进程获取
        if [[ -z "${ORACLE_SID}" ]]; then
            export ORACLE_SID=$(ps -ef | grep ora_pmon_ | grep -v grep | head -1 | awk -F_ '{print $NF}')
        fi
    fi
    log_info "ORACLE_SID=${ORACLE_SID} (来源: $(config_has_key ORACLE_SID && echo '配置文件' || echo '操作系统'))"

    # ORACLE_HOME: 配置文件优先，否则从 oratab 或环境变量获取
    if [[ -z "${ORACLE_HOME}" ]]; then
        if [[ -f /etc/oratab ]]; then
            export ORACLE_HOME=$(grep "^${ORACLE_SID}:" /etc/oratab 2>/dev/null | cut -d: -f2)
        fi
        if [[ -z "${ORACLE_HOME}" ]]; then
            export ORACLE_HOME="${ORACLE_HOME:-$(which oracle 2>/dev/null | xargs dirname 2>/dev/null | xargs dirname 2>/dev/null)}"
        fi
    fi
    log_info "ORACLE_HOME=${ORACLE_HOME} (来源: $(config_has_key ORACLE_HOME && echo '配置文件' || echo '操作系统'))"

    if [[ "${DB_INTERACTIVE_LOGIN:-off}" == "on" ]]; then
        DB_CONNECT_DESCRIPTOR="(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${DB_LOGIN_HOST})(PORT=${DB_LOGIN_PORT}))(CONNECT_DATA=(${DB_LOGIN_CONNECT_TYPE}=${DB_LOGIN_CONNECT_NAME})))"
        DB_AUTH_MODE="interactive_password"
        log_info "数据库连接: 交互式账号认证 (${DB_LOGIN_HOST}:${DB_LOGIN_PORT}, ${DB_LOGIN_CONNECT_TYPE}=${DB_LOGIN_CONNECT_NAME}, 用户=${DB_LOGIN_USER}, 角色=${DB_LOGIN_ROLE})"
    elif [[ -n "${DB_WALLET_ALIAS:-}" ]]; then
        if [[ ! "${DB_WALLET_ALIAS}" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
            log_error "DB_WALLET_ALIAS 包含不允许的字符"
            return 1
        fi
        export DB_CONNECT="/@${DB_WALLET_ALIAS} as sysdba"
        export DB_AUTH_MODE="wallet"
        log_info "数据库连接: Oracle Wallet (${DB_WALLET_ALIAS})"
    else
        export DB_CONNECT="/ as sysdba"
        export DB_AUTH_MODE="os"
        log_info "数据库连接: 操作系统认证 (/ as sysdba)"
    fi

    export PATH="${ORACLE_HOME}/bin:${PATH}"

    if [[ -z "${ORACLE_SID}" || -z "${ORACLE_HOME}" || ! -x "${ORACLE_HOME}/bin/sqlplus" ]]; then
        log_error "Oracle 环境无效: ORACLE_SID=${ORACLE_SID:-N/A}, ORACLE_HOME=${ORACLE_HOME:-N/A}"
        return 1
    fi

    write_env_base "db"
    {
        echo "oracle_sid=${ORACLE_SID}"
        echo "oracle_home=${ORACLE_HOME}"
        # 不把数据库密码写入采集包。
        echo "db_auth=${DB_AUTH_MODE}"
    } >> "${RAW_DIR}/env.info"

    # 通过数据字典探测实际能力，而不是只依赖版本号。部分 12c 字段在不同
    # patch set 中并不一致，能力探测可以避免在旧版本上产生 ORA-00904/00942。
    init_db_capabilities || return 1
}

write_env_base() {
    local check_type="$1"
    {
        echo "schema_version=${SCHEMA_VERSION}"
        echo "collector_version=${COLLECTOR_VERSION}"
        echo "data_classification=confidential"
        echo "platform=linux"
        echo "platform_family=linux"
        echo "hostname=$(hostname)"
        echo "server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || hostname -i 2>/dev/null || echo 'N/A')"
        echo "os=$(uname -a)"
        echo "kernel=$(uname -r)"
        echo "timestamp=${CHECK_TIMESTAMP}"
        echo "check_type=${check_type}"
        echo "debug=${DEBUG}"
        echo "report_footer=${REPORT_FOOTER}"
    } > "${RAW_DIR}/env.info"
}

# 日志函数
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*" | tee -a "${LOG_FILE}"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "${LOG_FILE}"
}

# 调试日志，仅在 DEBUG=on 时输出
log_debug() {
    if [[ "${DEBUG}" == "on" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" | tee -a "${LOG_FILE}"
    fi
}

record_collection() {
    local item="$1"
    local item_type="$2"
    local status="$3"
    local exit_code="$4"
    local message="${5:-}"
    message=$(printf "%s" "${message}" | tr '\t\r\n' '   ')
    printf "%s\t%s\t%s\t%s\t%s\n" "${item}" "${item_type}" "${status}" "${exit_code}" "${message}" >> "${MANIFEST_FILE}"
    if [[ "${status}" == "FAILED" ]]; then
        COLLECT_FAILURES=$((COLLECT_FAILURES + 1))
    elif [[ "${status}" == "WARN" ]]; then
        COLLECT_WARNINGS=$((COLLECT_WARNINGS + 1))
    fi
}

# 探测跨版本 SQL 所需的视图和字段。所有查询本身只依赖 11g 已存在的
# DBA_TAB_COLUMNS/DBA_OBJECTS，因此可用于当前支持的 11g 及以上版本。
init_db_capabilities() {
    local capability_output
    capability_output=$(db_sqlplus -L -S <<EOF 2>&1
WHENEVER OSERROR EXIT FAILURE
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF ECHO OFF VERIFY OFF
SET LINESIZE 1000 TRIMSPOOL ON
SELECT 'DB_VERSION|' || version FROM v\$instance;
SELECT 'HAS_VDATABASE_CDB|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='V_\$DATABASE' AND column_name='CDB';
SELECT 'HAS_DBA_PDBS|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_objects WHERE owner='SYS' AND object_name='DBA_PDBS' AND object_type='VIEW';
SELECT 'HAS_TEMPSEG_CON_ID|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name IN ('V_\$TEMPSEG_USAGE','GV_\$TEMPSEG_USAGE','V_\$SORT_USAGE','GV_\$SORT_USAGE') AND column_name='CON_ID';
SELECT 'HAS_USERS_LAST_LOGIN|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_USERS' AND column_name='LAST_LOGIN';
SELECT 'HAS_USERS_AUTH_TYPE|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_USERS' AND column_name='AUTHENTICATION_TYPE';
SELECT 'HAS_USERS_PASSWORD_VERSIONS|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_USERS' AND column_name='PASSWORD_VERSIONS';
SELECT 'HAS_USERS_ORACLE_MAINTAINED|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_USERS' AND column_name='ORACLE_MAINTAINED';
SELECT 'HAS_USERS_COMMON|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_USERS' AND column_name='COMMON';
SELECT 'HAS_ROLES_ORACLE_MAINTAINED|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_ROLES' AND column_name='ORACLE_MAINTAINED';
SELECT 'HAS_SERVICES_PDB|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_SERVICES' AND column_name='PDB';
SELECT 'HAS_SERVICES_GLOBAL|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_tab_columns WHERE owner='SYS' AND table_name='DBA_SERVICES' AND column_name='GLOBAL_SERVICE';
SELECT 'HAS_UNIFIED_AUDIT_VIEW|' || CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO' END FROM dba_objects WHERE owner='SYS' AND object_name='AUDIT_UNIFIED_ENABLED_POLICIES' AND object_type='VIEW';
EXIT
EOF
)
    local rc=$?
    if [[ "${rc}" -ne 0 ]] || grep -Eq '^(ORA|SP2|TNS|LRM)-[0-9]+' <<< "${capability_output}"; then
        log_error "数据库版本/能力探测失败 (rc=${rc})"
        local oracle_error
        oracle_error=$(printf '%s\n' "${capability_output}" |
            grep -E '^(ORA|SP2|TNS|LRM)-[0-9]+' | tail -3 | tr '\r\n' '  ')
        if [[ -n "${oracle_error}" ]]; then
            log_error "Oracle 返回: ${oracle_error}"
        fi
        log_debug "${capability_output}"
        return 1
    fi

    export DB_FULL_VERSION=""
    export DB_IS_CDB="NO"
    export HAS_VDATABASE_CDB="NO"
    export HAS_DBA_PDBS="NO"
    export HAS_TEMPSEG_CON_ID="NO"
    export HAS_USERS_LAST_LOGIN="NO"
    export HAS_USERS_AUTH_TYPE="NO"
    export HAS_USERS_PASSWORD_VERSIONS="NO"
    export HAS_USERS_ORACLE_MAINTAINED="NO"
    export HAS_USERS_COMMON="NO"
    export HAS_ROLES_ORACLE_MAINTAINED="NO"
    export HAS_SERVICES_PDB="NO"
    export HAS_SERVICES_GLOBAL="NO"
    export HAS_UNIFIED_AUDIT_VIEW="NO"

    local key value
    while IFS='|' read -r key value; do
        key=$(echo "${key}" | xargs)
        value=$(echo "${value}" | xargs)
        case "${key}" in
            DB_VERSION) DB_FULL_VERSION="${value}" ;;
            HAS_VDATABASE_CDB|HAS_DBA_PDBS|HAS_TEMPSEG_CON_ID|HAS_USERS_LAST_LOGIN|HAS_USERS_AUTH_TYPE|HAS_USERS_PASSWORD_VERSIONS|HAS_USERS_ORACLE_MAINTAINED|HAS_USERS_COMMON|HAS_ROLES_ORACLE_MAINTAINED|HAS_SERVICES_PDB|HAS_SERVICES_GLOBAL|HAS_UNIFIED_AUDIT_VIEW)
                export "${key}=${value}"
                ;;
        esac
    done <<< "${capability_output}"

    if [[ -z "${DB_FULL_VERSION}" ]]; then
        log_error "未能从 v\$instance 识别数据库版本"
        return 1
    fi
    export DB_MAJOR_VERSION="${DB_FULL_VERSION%%.*}"

    if [[ "${HAS_VDATABASE_CDB}" == "YES" ]]; then
        DB_IS_CDB=$(db_sqlplus -L -S <<EOF 2>/dev/null
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF ECHO OFF
SELECT cdb FROM v\$database;
EXIT
EOF
)
        DB_IS_CDB=$(echo "${DB_IS_CDB}" | xargs | tr '[:lower:]' '[:upper:]')
        [[ "${DB_IS_CDB}" == "YES" ]] || DB_IS_CDB="NO"
        export DB_IS_CDB
    fi

    {
        echo "db_version=${DB_FULL_VERSION}"
        echo "db_major_version=${DB_MAJOR_VERSION}"
        echo "db_is_cdb=${DB_IS_CDB}"
    } >> "${RAW_DIR}/env.info"
    log_info "数据库版本=${DB_FULL_VERSION}, CDB=${DB_IS_CDB}"
}

# 对当前版本或数据库架构不适用的 SQL 项生成只有表头的结果文件，并在
# manifest 中显式登记为 SKIPPED，供报告区分“不适用”和“执行失败”。
skip_sql_collection() {
    local output_file="$1"
    local header="$2"
    local reason="$3"
    printf "%s\n" "${header}" > "${output_file}"
    log_info "跳过不适用SQL: ${output_file} (${reason})"
    record_collection "$(basename "${output_file}")" "SQL" "SKIPPED" "0" "${reason}"
}

finalize_collection() {
    {
        echo "collection_failures=${COLLECT_FAILURES}"
        echo "collection_warnings=${COLLECT_WARNINGS}"
        echo "collection_completed_at=$(date '+%Y-%m-%d %H:%M:%S %z')"
    } >> "${RAW_DIR}/env.info"

    if [[ "${COLLECT_FAILURES}" -gt 0 ]]; then
        log_error "采集完成但存在 ${COLLECT_FAILURES} 个失败项；详见 collection_manifest.tsv"
        return 1
    fi
    log_info "采集完整性校验通过"
    return 0
}

pack_collection() {
    local pack_name="$1"
    unset PACK_FILE
    if [[ "${NO_PACK:-false}" == true ]]; then
        return 0
    fi
    log_info "打包采集数据..."
    local pack_file="${RAW_BASE}/${pack_name}"
    if tar -czf "${pack_file}" -C "${RAW_DIR}" .; then
        chmod 0660 "${pack_file}" 2>/dev/null || true
        log_info "数据已打包: ${pack_file}"
        export PACK_FILE="${pack_file}"
        return 0
    fi
    log_error "打包失败: ${pack_file}"
    return 1
}

print_collect_summary() {
    local title="$1"
    local duration="$2"
    shift 2
    echo ""
    echo "============================================"
    echo "  ${title}"
    echo "============================================"
    echo "  耗时: ${duration} 秒"
    echo "  数据目录: ${RAW_DIR}"
    if [[ -n "${PACK_FILE:-}" ]]; then
        echo "  打包文件: $(basename "${PACK_FILE}")"
    fi
    echo ""
    local line
    for line in "$@"; do
        echo "  ${line}"
    done
    echo "============================================"
}

# 执行单条 SQL，结果输出到指定文件
# 用法: exec_sql <output_file> <sql_statement...>
exec_sql() {
    local output_file="$1"
    shift
    local sql="$*"

    log_info "执行SQL: ${output_file}"
    log_debug "SQL内容: ${sql}"
    log_debug "数据库认证模式=${DB_AUTH_MODE:-os}（连接串已隐藏）"
    db_sqlplus -L -S <<EOF > "${output_file}" 2>&1
WHENEVER OSERROR EXIT FAILURE ROLLBACK
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET LINESIZE 32767
SET PAGESIZE 50000
SET FEEDBACK OFF
SET HEADING ON
SET ECHO OFF
SET TRIMSPOOL ON
SET COLSEP '|'
${sql}
EXIT
EOF
    local rc=$?
    if [[ "${rc}" -ne 0 ]] || grep -Eq '^(ORA|SP2|TNS|LRM)-[0-9]+' "${output_file}"; then
        log_error "SQL执行失败: ${output_file} (rc=${rc})"
        record_collection "$(basename "${output_file}")" "SQL" "FAILED" "${rc}" "$(tail -3 "${output_file}")"
        return 1
    fi
    record_collection "$(basename "${output_file}")" "SQL" "OK" "0" ""
    return 0
}

# 采集 Shell 命令输出到文件
# 用法: collect_cmd <output_file> <command...>
collect_cmd() {
    local output_file="$1"
    shift
    local cmd="$*"

    log_info "采集命令: ${cmd} -> ${output_file}"
    log_debug "完整命令: ${cmd}"
    bash -o pipefail -c "${cmd}" > "${output_file}" 2>&1
    local rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        log_warn "命令采集失败: ${cmd} (rc=${rc})"
        record_collection "$(basename "${output_file}")" "COMMAND" "FAILED" "${rc}" "$(tail -2 "${output_file}")"
        return 1
    fi
    record_collection "$(basename "${output_file}")" "COMMAND" "OK" "0" ""
    return 0
}

# 可选命令缺失不使整次巡检失败，但会在清单中明确标记为 WARN。
collect_optional_cmd() {
    local output_file="$1"
    shift
    local cmd="$*"
    log_info "采集可选命令: ${cmd} -> ${output_file}"
    bash -o pipefail -c "${cmd}" > "${output_file}" 2>&1
    local rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        log_warn "可选命令不可用: ${cmd} (rc=${rc})"
        record_collection "$(basename "${output_file}")" "OPTIONAL_COMMAND" "WARN" "${rc}" "$(tail -2 "${output_file}")"
        return 0
    fi
    record_collection "$(basename "${output_file}")" "OPTIONAL_COMMAND" "OK" "0" ""
    return 0
}
