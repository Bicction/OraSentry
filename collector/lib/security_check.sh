#!/bin/bash
#==============================================================
# 安全巡检 - 纯数据采集
# 仅收集安全相关命令和SQL输出，不做任何判定
# 由 collect/main_db.sh 加载 common.sh 后 source 本文件
#==============================================================

security_collect() {
    log_info "========== 开始安全数据采集 =========="

    local d="${RAW_DIR}/security"
    mkdir -p "${d}"

    # 1. 密码过期策略
    collect_password_policy "${d}"

    # 2. 数据库安全性管理
    collect_db_security "${d}"

    # 3. 操作系统安全性管理
    collect_os_security "${d}"

    # 4. 监听器安全
    collect_listener_security "${d}"

    log_info "========== 安全数据采集完成 =========="
}

# 密码过期策略
collect_password_policy() {
    local d="$1"
    log_info "[采集] 密码过期策略"
    exec_sql "${d}/password_policy.txt" "SELECT profile, resource_name, resource_type, limit FROM dba_profiles WHERE resource_name IN ('PASSWORD_LIFE_TIME', 'PASSWORD_REUSE_TIME', 'PASSWORD_REUSE_MAX', 'PASSWORD_LOCK_TIME', 'PASSWORD_GRACE_TIME', 'PASSWORD_VERIFY_FUNCTION', 'FAILED_LOGIN_ATTEMPTS') ORDER BY profile, resource_name;"
    exec_sql "${d}/profiles.txt" "SELECT DISTINCT profile FROM dba_profiles ORDER BY profile;"
}

# 数据库安全性管理
collect_db_security() {
    local d="$1"
    log_info "[采集] 数据库安全性"
    local last_login_expr="CAST(NULL AS VARCHAR2(64)) last_login"
    local auth_type_expr="CAST(NULL AS VARCHAR2(30)) authentication_type"
    local password_versions_expr="CAST(NULL AS VARCHAR2(30)) password_versions"
    local oracle_maintained_expr="CAST('N' AS VARCHAR2(1)) oracle_maintained"
    local common_expr="CAST('NO' AS VARCHAR2(3)) common"
    [[ "${HAS_USERS_LAST_LOGIN:-NO}" == "YES" ]] && last_login_expr="last_login"
    [[ "${HAS_USERS_AUTH_TYPE:-NO}" == "YES" ]] && auth_type_expr="authentication_type"
    [[ "${HAS_USERS_PASSWORD_VERSIONS:-NO}" == "YES" ]] && password_versions_expr="password_versions"
    [[ "${HAS_USERS_ORACLE_MAINTAINED:-NO}" == "YES" ]] && oracle_maintained_expr="oracle_maintained"
    [[ "${HAS_USERS_COMMON:-NO}" == "YES" ]] && common_expr="common"
    exec_sql "${d}/db_users.txt" "SELECT username, account_status, expiry_date, lock_date, default_tablespace, profile, created, ${last_login_expr}, ${auth_type_expr}, ${password_versions_expr}, ${oracle_maintained_expr}, ${common_expr} FROM dba_users ORDER BY username;"
    exec_sql "${d}/dba_role_users.txt" "SELECT grantee, granted_role FROM dba_role_privs WHERE granted_role='DBA' ORDER BY grantee;"
    if [[ "${HAS_USERS_ORACLE_MAINTAINED:-NO}" == "YES" && "${HAS_ROLES_ORACLE_MAINTAINED:-NO}" == "YES" ]]; then
        exec_sql "${d}/sys_privs.txt" "WITH principals AS (SELECT username principal FROM dba_users WHERE oracle_maintained='N' UNION SELECT role FROM dba_roles WHERE oracle_maintained='N') SELECT DISTINCT p.grantee, p.privilege, p.admin_option FROM dba_sys_privs p JOIN principals x ON x.principal=p.grantee ORDER BY p.grantee, p.privilege;"
    else
        exec_sql "${d}/sys_privs.txt" "WITH business_users AS (SELECT username FROM dba_users WHERE username NOT IN ('SYS','SYSTEM','DBSNMP','APPQOSSYS','GSMADMIN_INTERNAL','LBACSYS','MDSYS','OLAPSYS','ORDDATA','ORDSYS','OUTLN','SYSMAN','WMSYS','XDB','XS\$NULL')), principals AS (SELECT username principal FROM business_users UNION SELECT granted_role FROM dba_role_privs WHERE grantee IN (SELECT username FROM business_users) AND granted_role NOT IN ('CONNECT','RESOURCE','DBA')) SELECT DISTINCT p.grantee, p.privilege, p.admin_option FROM dba_sys_privs p JOIN principals x ON x.principal=p.grantee ORDER BY p.grantee, p.privilege;"
    fi
    exec_sql "${d}/audit_settings.txt" "SELECT name, value FROM v\$parameter WHERE name LIKE '%audit%';"
    if [[ "${HAS_UNIFIED_AUDIT_VIEW:-NO}" == "YES" ]]; then
        exec_sql "${d}/unified_audit_policies.txt" "SELECT * FROM audit_unified_enabled_policies;"
    else
        skip_sql_collection "${d}/unified_audit_policies.txt" "POLICY_NAME" "当前版本不支持统一审计视图"
    fi
    exec_sql "${d}/traditional_audit_options.txt" "SELECT user_name, proxy_name, audit_option, success, failure FROM dba_stmt_audit_opts ORDER BY user_name, audit_option;"
    exec_sql "${d}/public_risky_grants.txt" "SELECT owner, table_name, privilege, grantable FROM dba_tab_privs WHERE grantee='PUBLIC' AND privilege IN ('EXECUTE','READ','WRITE') AND table_name IN ('UTL_FILE','UTL_HTTP','UTL_TCP','UTL_SMTP','DBMS_SCHEDULER','DBMS_JOB','DBMS_LOB','DBMS_SQL','DBMS_RANDOM') ORDER BY owner, table_name, privilege;"
    exec_sql "${d}/security_parameters.txt" "SELECT name, value, isdefault FROM v\$parameter WHERE name IN ('remote_login_passwordfile','remote_os_authent','os_authent_prefix','sec_case_sensitive_logon','sql92_security','_allow_insert_with_update_check') ORDER BY name;"
}

# 操作系统安全性管理
collect_os_security() {
    local d="$1"
    log_info "[采集] 操作系统安全性"
    collect_cmd "${d}/oracle_bin_perm.txt" "ls -la ${ORACLE_HOME}/bin/oracle"
    collect_cmd "${d}/oracle_net_perm.txt" "ls -la ${ORACLE_HOME}/network/admin/"
    collect_cmd "${d}/oracle_dbs_perm.txt" "ls -la ${ORACLE_HOME}/dbs/"
    collect_cmd "${d}/oracle_home_perm.txt" "ls -la ${ORACLE_HOME}/"
    stat -c "%a %U %G %n" "${ORACLE_HOME}/bin/oracle" > "${d}/oracle_bin_stat.txt" 2>&1 || true
    # 检查敏感文件权限
    collect_cmd "${d}/etc_passwd.txt" "cat /etc/passwd"
    collect_cmd "${d}/etc_shadow_perm.txt" "ls -la /etc/shadow"
    collect_cmd "${d}/sudoers_perm.txt" "ls -la /etc/sudoers"
}

# 监听器安全
collect_listener_security() {
    local d="$1"
    log_info "[采集] 监听器安全"
    lsnrctl status > "${d}/listener_status.txt" 2>&1 || true
    lsnrctl services > "${d}/listener_services.txt" 2>&1 || true
    cat "${ORACLE_HOME}/network/admin/listener.ora" > "${d}/listener_ora.txt" 2>&1 || true
    cat "${ORACLE_HOME}/network/admin/sqlnet.ora" > "${d}/sqlnet_ora.txt" 2>&1 || true
    cat "${ORACLE_HOME}/network/admin/tnsnames.ora" > "${d}/tnsnames_ora.txt" 2>&1 || true
}
