# -*- coding: utf-8 -*-
"""Windows Oracle Home ACL 安全解析。"""
from parser.base import CheckResult, generate_data_table, read_file


def _rows(path: str):
    lines = [line.strip() for line in read_file(path).splitlines() if line.strip()]
    if not lines:
        return []
    headers = [item.strip().lstrip("\ufeff") for item in lines[0].split("|")]
    return [dict(zip(headers, [item.strip() for item in line.split("|")])) for line in lines[1:]]


def parse_windows_os_security(sec_dir: str) -> CheckResult:
    rows = []
    for name in ("oracle_home_acl.txt", "oracle_bin_acl.txt", "oracle_network_acl.txt", "oracle_password_file_acl.txt"):
        rows.extend(_rows(f"{sec_dir}/{name}"))
    if not rows:
        return CheckResult("操作系统安全性", "UNKNOWN", "ACL数据缺失", "无法读取 Oracle Home 和敏感文件 ACL",
                           "请使用具备读取ACL权限的账号重新采集")
    risky = []
    broad_markers = ("everyone", "authenticated users", "builtin\\users", "\\users", "用户", "经过身份验证")
    write_markers = ("fullcontrol", "modify", "write", "changepermissions", "takeownership")
    for row in rows:
        identity = (row.get("IDENTITY") or "").lower()
        rights = (row.get("RIGHTS") or "").lower()
        access_type = (row.get("TYPE") or "").lower()
        if access_type != "deny" and any(item in identity for item in broad_markers) and any(item in rights for item in write_markers):
            risky.append(row)
    display = [(r.get("PATH"), r.get("OWNER"), r.get("IDENTITY"), r.get("RIGHTS"), r.get("INHERITED")) for r in rows[:100]]
    return CheckResult(
        "操作系统安全性", "WARN" if risky else "OK", f"{len(risky)}项宽泛写权限",
        f"检查 Oracle Home、oracle.exe、网络配置和密码文件，共 {len(rows)} 条 ACL",
        "请回收 Everyone/Users 等宽泛主体对 Oracle 关键路径的写入或完全控制权限" if risky else "",
        extra_html=generate_data_table(["路径", "所有者", "主体", "权限", "继承"], display),
    )
