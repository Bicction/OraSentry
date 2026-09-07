# -*- coding: utf-8 -*-
"""
安全巡检数据解析器
解析 Shell 采集的安全原始数据，进行阈值判定
"""
import re
from typing import List
from parser.base import CheckResult, read_file, read_lines, generate_data_table, parse_env_info
from config import SECURITY_THRESHOLDS


# Used for legacy collection packages that predate DBA_USERS.ORACLE_MAINTAINED.
# New collectors additionally export the database's own authoritative flag.
ORACLE_BUILTIN_PRINCIPALS = {
    "ANONYMOUS", "APEX_PUBLIC_USER", "APPQOSSYS", "AUDSYS", "CTXSYS",
    "DBSFWUSER", "DBSNMP", "DIP", "DVF", "DVSYS", "EXFSYS", "FLOWS_FILES",
    "GGSYS", "GSMADMIN_INTERNAL", "GSMCATUSER", "GSMUSER", "LBACSYS",
    "MDDATA", "MDSYS", "OJVMSYS", "OLAPSYS", "ORACLE_OCM", "ORDDATA",
    "ORDSYS", "OUTLN", "REMOTE_SCHEDULER_AGENT", "SI_INFORMTN_SCHEMA",
    "SPATIAL_CSW_ADMIN_USR", "SPATIAL_WFS_ADMIN_USR", "SYS", "SYS$UMF",
    "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "SYSTEM", "WMSYS", "XDB",
    "XS$NULL", "AQ_ADMINISTRATOR_ROLE", "AQ_USER_ROLE", "CONNECT", "CTXAPP", "DBA",
    "DATAPUMP_EXP_FULL_DATABASE", "DATAPUMP_IMP_FULL_DATABASE",
    "DELETE_CATALOG_ROLE", "EM_EXPRESS_ALL", "EM_EXPRESS_BASIC",
    "EXECUTE_CATALOG_ROLE", "EXP_FULL_DATABASE", "GATHER_SYSTEM_STATISTICS",
    "GLOBAL_AQ_USER_ROLE", "GSMADMIN_ROLE", "GSMUSER_ROLE", "HS_ADMIN_EXECUTE_ROLE", "HS_ADMIN_ROLE",
    "HS_ADMIN_SELECT_ROLE", "IMP_FULL_DATABASE", "JAVA_ADMIN", "JAVA_DEPLOY",
    "JAVADEBUGPRIV", "JAVAIDPRIV", "JAVASYSPRIV", "JAVAUSERPRIV",
    "LOGSTDBY_ADMINISTRATOR", "OEM_MONITOR", "OLAP_DBA", "OLAP_USER",
    "OPTIMIZER_PROCESSING_RATE", "RECOVERY_CATALOG_OWNER", "RESOURCE",
    "SCHEDULER_ADMIN", "SELECT_CATALOG_ROLE", "SYSUMF_ROLE", "WM_ADMIN_ROLE", "XDBADMIN",
    "XDB_SET_INVOKER", "XDB_WEBSERVICES", "XDB_WEBSERVICES_OVER_HTTP",
    "XDB_WEBSERVICES_WITH_PUBLIC",
}


def parse_security(raw_dir: str) -> List[CheckResult]:
    """解析安全巡检数据"""
    results = []
    sec_dir = f"{raw_dir}/security"

    results.append(_parse_password_policy(sec_dir))
    results.append(_parse_db_security(sec_dir))
    results.extend(_parse_audit_and_access_controls(sec_dir))
    platform = str(parse_env_info(raw_dir).get("platform", "linux")).strip().lower()
    if platform == "windows":
        from parser.windows_security_parser import parse_windows_os_security
        results.append(parse_windows_os_security(sec_dir))
    else:
        results.append(_parse_os_security(sec_dir))
    results.append(_parse_listener_security(sec_dir))

    return results


def _data_rows(content: str, header: str) -> list:
    return [r for r in _parse_pipe_table(content) if r and r[0].upper() != header.upper()]


def _parse_pipe_table(content: str) -> list:
    """解析以 | 分隔的 SQL 输出表格"""
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if any(parts):
            rows.append(parts)
    return rows


def _oracle_maintained_principals(sec_dir: str) -> set:
    """Combine authoritative collector metadata with a legacy-safe fallback."""
    maintained = set(ORACLE_BUILTIN_PRINCIPALS)
    rows = _parse_pipe_table(read_file(f"{sec_dir}/db_users.txt"))
    header_index = next(
        (index for index, row in enumerate(rows)
         if "USERNAME" in [cell.upper() for cell in row]
         and "ORACLE_MAINTAINED" in [cell.upper() for cell in row]),
        None,
    )
    if header_index is None:
        return maintained
    header = [cell.upper() for cell in rows[header_index]]
    username_index = header.index("USERNAME")
    maintained_index = header.index("ORACLE_MAINTAINED")
    for row in rows[header_index + 1:]:
        if len(row) > max(username_index, maintained_index) and row[maintained_index].upper() == "Y":
            maintained.add(row[username_index].upper())
    return maintained


def _parse_password_policy(sec_dir: str) -> CheckResult:
    """解析密码过期策略"""
    content = read_file(f"{sec_dir}/password_policy.txt")
    if not content:
        return CheckResult("密码过期策略", "CRIT", "数据缺失", "无法获取密码策略信息")

    # 检查 DEFAULT profile 的 PASSWORD_LIFE_TIME
    default_life = "N/A"
    unlimited_warn = False
    for line in content.splitlines():
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) >= 4 and "DEFAULT" in parts[0] and "PASSWORD_LIFE_TIME" in parts[1]:
            default_life = parts[3]
            if parts[3].upper() == "UNLIMITED" and SECURITY_THRESHOLDS["password_life_unlimited_warn"]:
                unlimited_warn = True

    status = "WARN" if unlimited_warn else "OK"
    suggestion = ""
    if unlimited_warn:
        suggestion = "DEFAULT profile 密码永不过期，存在安全风险，建议设置密码有效期"

    return CheckResult("密码过期策略", status, f"DEFAULT有效期: {default_life}",
                       f"DEFAULT profile PASSWORD_LIFE_TIME: {default_life}", suggestion)


def _parse_db_security(sec_dir: str) -> CheckResult:
    """解析数据库安全性"""
    # 检查默认账户
    users_content = read_file(f"{sec_dir}/db_users.txt")
    default_accounts = []
    default_names = ["SCOTT", "HR", "OE", "SH", "PM", "IX", "BI", "DBSNMP"]

    if users_content:
        for line in users_content.splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2:
                username = parts[0].upper()
                if username in default_names and "OPEN" in " ".join(parts).upper():
                    default_accounts.append(username)

    # 检查非SYS的DBA用户
    dba_content = read_file(f"{sec_dir}/dba_role_users.txt")
    non_sys_dba = []
    if dba_content:
        for line in dba_content.splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2:
                grantee = parts[0].upper()
                if grantee not in ("SYS", "SYSTEM") and "DBA" in parts[1].upper():
                    non_sys_dba.append(grantee)

    status = "OK"
    suggestions = []
    if default_accounts and SECURITY_THRESHOLDS["default_account_open_warn"]:
        status = "WARN"
        suggestions.append(f"活跃默认账户: {', '.join(default_accounts)}，建议锁定")
    if non_sys_dba and SECURITY_THRESHOLDS["non_sys_dba_warn"]:
        status = "WARN"
        suggestions.append(f"非SYS的DBA用户: {', '.join(non_sys_dba)}，请确认权限合理性")

    detail = f"默认账户: {len(default_accounts)}个, 非SYS的DBA: {len(non_sys_dba)}个"
    suggestion = "; ".join(suggestions)

    # 生成DBA用户表格
    extra = ""
    if non_sys_dba:
        extra = generate_data_table(["DBA用户"], [(u,) for u in non_sys_dba])

    return CheckResult("数据库安全性", status, detail, detail, suggestion, extra_html=extra)


def _parse_audit_and_access_controls(sec_dir: str) -> List[CheckResult]:
    results = []
    audit_params = read_file(f"{sec_dir}/audit_settings.txt")
    audit_trail = "UNKNOWN"
    audit_sys = "UNKNOWN"
    for r in _parse_pipe_table(audit_params):
        if len(r) < 2:
            continue
        if r[0].lower() == "audit_trail":
            audit_trail = r[1].upper() or "NONE"
        elif r[0].lower() == "audit_sys_operations":
            audit_sys = r[1].upper()
    unified = [r for r in _parse_pipe_table(read_file(f"{sec_dir}/unified_audit_policies.txt"))
               if r and not any("POLICY_NAME" in cell.upper() for cell in r)]
    traditional = _data_rows(read_file(f"{sec_dir}/traditional_audit_options.txt"), "USER_NAME")
    auditing_enabled = audit_trail not in ("NONE", "UNKNOWN") or bool(unified) or bool(traditional)
    audit_status = "OK" if auditing_enabled and audit_sys == "TRUE" else "WARN"
    results.append(CheckResult(
        "数据库审计", audit_status, "已启用" if auditing_enabled else "未启用",
        f"audit_trail={audit_trail}, audit_sys_operations={audit_sys}, Unified策略={len(unified)}, 传统审计项={len(traditional)}",
        "建议启用统一审计/审计策略并确保 SYS 操作被记录，日志需设置留存与防篡改措施" if audit_status != "OK" else "",
        extra_html=(generate_data_table([f"列{i+1}" for i in range(max(len(r) for r in unified))], unified[:50]) if unified else "")
    ))

    maintained = _oracle_maintained_principals(sec_dir)
    raw_public_grants = _data_rows(read_file(f"{sec_dir}/public_risky_grants.txt"), "OWNER")
    public_grants = [r for r in raw_public_grants if r and r[0].upper() not in maintained]
    public_excluded = len(raw_public_grants) - len(public_grants)
    public_status = "WARN" if public_grants else "OK"
    results.append(CheckResult(
        "PUBLIC高风险授权", public_status, f"{len(public_grants)}项",
        f"检查非 Oracle 内置所有者的高风险 PUBLIC 授权；已排除内置授权 {public_excluded} 项",
        "按最小权限原则评估并回收不必要的 PUBLIC 授权；变更前验证应用依赖" if public_grants else "",
        extra_html=generate_data_table(["所有者", "对象", "权限", "可转授权"], public_grants) if public_grants else ""
    ))

    raw_sys_privs = _data_rows(read_file(f"{sec_dir}/sys_privs.txt"), "GRANTEE")
    sys_privs = [r for r in raw_sys_privs if r and r[0].upper() not in maintained]
    sys_excluded = len(raw_sys_privs) - len(sys_privs)
    admin_privs = [r for r in sys_privs if len(r) >= 3 and r[2].upper() == "YES"]
    priv_status = "WARN" if admin_privs else "OK"
    results.append(CheckResult(
        "系统权限最小化", priv_status, f"{len(sys_privs)}项非内置主体授权",
        f"非 Oracle 内置主体的系统权限: {len(sys_privs)}，含 ADMIN OPTION: {len(admin_privs)}；已排除内置授权 {sys_excluded} 项",
        "重点复核带 ADMIN OPTION 的系统权限及高权限业务账号" if admin_privs else "",
        extra_html=generate_data_table(["被授权人", "系统权限", "ADMIN OPTION"], sys_privs[:100]) if sys_privs else ""
    ))

    sec_params = _data_rows(read_file(f"{sec_dir}/security_parameters.txt"), "NAME")
    risky = []
    for r in sec_params:
        if len(r) < 2:
            continue
        name, value = r[0].lower(), r[1].upper()
        if name == "remote_os_authent" and value == "TRUE":
            risky.append("REMOTE_OS_AUTHENT=TRUE")
        if name == "remote_login_passwordfile" and value == "NONE":
            # 不一定是风险，仅记录；不加入 risky。
            pass
    results.append(CheckResult(
        "安全参数", "WARN" if risky else "OK", f"{len(risky)}项风险",
        "，".join("=".join(r[:2]) for r in sec_params if len(r) >= 2),
        "；".join(risky) if risky else "",
        extra_html=generate_data_table(["参数", "值", "默认值"], sec_params) if sec_params else ""
    ))
    return results


def _parse_os_security(sec_dir: str) -> CheckResult:
    """解析操作系统安全性"""
    content = read_file(f"{sec_dir}/oracle_bin_stat.txt")
    perm = "unknown"
    status = "OK"
    suggestion = ""

    if content:
        match = re.search(r'^(\d{3,4})\s', content.strip())
        if match:
            perm = match.group(1)
            expected = SECURITY_THRESHOLDS["oracle_bin_perm_expected"]
            if perm != expected:
                status = "WARN"
                suggestion = f"oracle 二进制权限为 {perm}，建议设置为 {expected}"

    # 检查 shadow 文件权限
    shadow_perm = read_file(f"{sec_dir}/etc_shadow_perm.txt")
    detail = f"oracle二进制权限: {perm}"
    if shadow_perm:
        detail += f", shadow文件: {'已记录' if shadow_perm else 'N/A'}"

    return CheckResult("操作系统安全性", status, f"权限: {perm}", detail, suggestion)


def _parse_listener_security(sec_dir: str) -> CheckResult:
    """解析监听器安全"""
    listener_ora = read_file(f"{sec_dir}/listener_ora.txt")
    sqlnet_ora = read_file(f"{sec_dir}/sqlnet_ora.txt")

    listener_status = read_file(f"{sec_dir}/listener_status.txt")
    local_os_auth = "Security" in listener_status and "Local OS Authentication" in listener_status
    listener_ok = "The command completed successfully" in listener_status and "status READY" in listener_status
    has_admin_restriction = bool(re.search(r"ADMIN_RESTRICTIONS_[A-Za-z0-9_]+\s*=\s*ON", listener_ora, re.IGNORECASE))
    tcp_endpoints = sorted(set(re.findall(r"\(PROTOCOL=tcp\).*?\(PORT=(\d+)\)", listener_status, re.IGNORECASE)))
    encryption_required = bool(re.search(r"SQLNET\.ENCRYPTION_SERVER\s*=\s*(REQUIRED|REQUESTED)", sqlnet_ora, re.IGNORECASE))

    status = "OK"
    risks = []
    if not listener_ok:
        status = "CRIT"
        risks.append("监听器或服务未处于 READY")
    if not local_os_auth:
        status = "WARN" if status == "OK" else status
        risks.append("未检测到监听器本地 OS 管理认证")

    detail = (f"监听服务={'正常' if listener_ok else '异常'}, 本地OS管理认证={'是' if local_os_auth else '否'}, "
              f"ADMIN_RESTRICTIONS={'ON' if has_admin_restriction else '未配置'}, 监听端口={','.join(tcp_endpoints) or 'N/A'}, "
              f"传输加密={'已要求' if encryption_required else '未要求'}")
    return CheckResult("监听器与SQL*Net安全", status, "已检查", detail, "；".join(risks))
