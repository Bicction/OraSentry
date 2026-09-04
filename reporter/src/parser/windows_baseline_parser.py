# -*- coding: utf-8 -*-
"""Windows phase-2 baseline: evidence-aware optional 4.x extensions."""
import csv
import math
import os
from pathlib import Path

from config import HOST_THRESHOLDS
from parser.base import (CheckResult, check_threshold, generate_data_table,
                         manifest_warning_is_nonblocking, parse_env_info, read_file)


def _load(directory, filename, name, columns):
    path = Path(directory) / filename
    manifest = read_file(str(Path(directory).parent / "collection_manifest.tsv"))
    entries = [r for r in csv.DictReader(manifest.splitlines(), delimiter="\t") if r.get("item") == filename]
    env_info = parse_env_info(str(Path(directory).parent))
    effective_entries = [r for r in entries if not manifest_warning_is_nonblocking(r, env_info)]
    problem = any(r.get("status") in ("WARN", "FAILED") for r in effective_entries)
    if not path.is_file():
        current = bool(effective_entries)
        return [], CheckResult(name, "UNKNOWN" if current else "INFO", "采集数据缺失" if current else "旧版未采集",
                               f"{filename} 未提供"), problem
    lines = [line for line in read_file(str(path)).splitlines() if line.strip()]
    if not lines:
        return [], CheckResult(name, "UNKNOWN", "数据为空", f"{filename} 无表头和有效数据"), True
    headers = [cell.strip().lstrip("\ufeff") for cell in lines[0].split("|")]
    if not set(columns).issubset(headers):
        return [], CheckResult(name, "UNKNOWN", "格式异常", f"{filename} 缺少必要字段"), True
    rows = []
    for line in lines[1:]:
        if line.lstrip().startswith("-"):
            continue
        values = [cell.strip() for cell in line.split("|")]
        if len(values) != len(headers):
            problem = True
            continue
        row = dict(zip(headers, values))
        if row.get("EVIDENCE") == "QUERY_FAILED":
            problem = True
        rows.append(row)
    return rows, None, problem


def _number(value):
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (ValueError, TypeError):
        return None


def _bool(value):
    return {"true": True, "false": False, "1": True, "0": False}.get(str(value).lower())


def _worst(statuses, default="INFO"):
    return max(statuses, key=lambda s: {"INFO": 0, "OK": 1, "UNKNOWN": 2, "WARN": 3, "CRIT": 4}[s], default=default)


def _result(name, status, value, detail, headers, rows, problem=False, suggestion=""):
    if problem:
        detail += "；部分采集失败或字段不可用，结论不完整"
        if status in ("OK", "INFO"):
            status = "UNKNOWN"
    return CheckResult(name, status, value, detail, suggestion,
                       extra_html=generate_data_table(headers, rows) if rows else "")


def parse_network_config(directory):
    name = "Windows网络配置"
    rows, missing, problem = _load(directory, "network_config.txt", name, ("KIND", "IF_INDEX", "STATE", "ADDRESS", "NEXT_HOP"))
    if missing:
        return missing
    adapters = {r["IF_INDEX"]: r for r in rows if r["KIND"] == "ADAPTER"}
    routes = [r for r in rows if r["KIND"] == "DEFAULT_ROUTE"]
    down = [r for r in routes if r["IF_INDEX"] in adapters and adapters[r["IF_INDEX"]]["STATE"].lower() != "up"]
    return _result(name, "WARN" if down else "INFO", f"{len(adapters)}个接口/{len(routes)}条默认路由",
                   "展示网卡状态/速率、IP、DNS及默认路由；不主动发包，不由配置推断DNS可达性；" + f"默认路由关联非Up接口 {len(down)} 个",
                   ["类型", "接口", "状态", "速率", "地址/DNS", "下一跳", "跃点"],
                   [(r["KIND"], r.get("NAME"), r["STATE"], r.get("LINK_SPEED"), r["ADDRESS"], r["NEXT_HOP"], r.get("METRIC")) for r in rows],
                   problem or not rows, "核查默认路由与网卡状态；隔离网段无默认路由不自动告警" if down else "")


def parse_network_quality(directory):
    name = "Windows网络质量"
    rows, missing, problem = _load(directory, "network_quality.txt", name,
                                   ("KIND", "NAME", "SECONDS", "PACKETS", "ERRORS", "DISCARDS", "TCP_SENT", "TCP_RETRANS", "COUNTER_STATE"))
    if missing:
        return missing
    statuses, display = [], []
    for row in rows:
        seconds = _number(row["SECONDS"])
        status, value = "INFO", "流量不足，仅展示"
        if row["COUNTER_STATE"] != "VALID" or not seconds:
            status, value = "UNKNOWN", "计数器重置/不可用"
        elif row["KIND"] == "NIC":
            packets, errors, drops = (_number(row[k]) for k in ("PACKETS", "ERRORS", "DISCARDS"))
            if None in (packets, errors, drops):
                status, value = "UNKNOWN", "增量字段不可用"
            else:
                total = packets + errors + drops
                ratio = 100 * (errors + drops) / total if total else 0
                value = f"包增量{packets:g}，错误{errors:g}，丢弃{drops:g}，异常率{ratio:.2f}%"
                if total >= HOST_THRESHOLDS["network_min_packets"]:
                    status = check_threshold(ratio, HOST_THRESHOLDS["network_error_warn_pct"], HOST_THRESHOLDS["network_error_crit_pct"])
                rx, tx = _number(row.get("RX_BYTES")), _number(row.get("TX_BYTES"))
                if rx is not None and tx is not None:
                    value += f"，收/发 {rx / seconds / 1048576:.2f}/{tx / seconds / 1048576:.2f} MiB/s"
        elif row["KIND"] == "TCP":
            sent, retrans = (_number(row[k]) for k in ("TCP_SENT", "TCP_RETRANS"))
            if sent is None or retrans is None or retrans > sent:
                status, value = "UNKNOWN", "TCP增量字段无效"
            else:
                ratio = 100 * retrans / sent if sent else 0
                value = f"发送段{sent:g}，重传{retrans:g}，重传率{ratio:.2f}%"
                if sent >= HOST_THRESHOLDS["network_min_packets"]:
                    status = check_threshold(ratio, HOST_THRESHOLDS["tcp_retrans_warn_pct"], HOST_THRESHOLDS["tcp_retrans_crit_pct"])
        else:
            status, value = "UNKNOWN", "未识别的计数器类型"
        statuses.append(status)
        display.append((row["KIND"], row["NAME"], row["SECONDS"], value, status))
    status = _worst(statuses)
    return _result(name, status, "间隔增量评估", "5秒窗口，使用计数器差值；不足100包/段不据百分比告警，不能代表长期网络质量",
                   ["类型", "接口/协议", "秒", "观测", "状态"], display, problem or not rows,
                   "结合交换机、驱动、TCP重传和业务时段复测；未主动测试丢包" if status in ("WARN", "CRIT") else "")


def parse_protection(directory):
    name = "Windows终端防护"
    rows, missing, problem = _load(directory, "endpoint_protection.txt", name,
                                   ("KIND", "MODE", "SERVICE_ENABLED", "ANTIVIRUS_ENABLED", "REALTIME_ENABLED", "SIGNATURE_AGE_DAYS", "EVIDENCE"))
    if missing:
        return missing
    statuses = []
    for row in rows:
        if row["KIND"] != "DEFENDER":
            continue
        if row["EVIDENCE"] != "OBSERVED":
            statuses.append("UNKNOWN")
            continue
        mode = row["MODE"].lower()
        if mode != "normal":
            # Passive/EDR block mode do not establish another AV's protection health.
            statuses.append("UNKNOWN")
            continue
        flags = [_bool(row[k]) for k in ("SERVICE_ENABLED", "ANTIVIRUS_ENABLED", "REALTIME_ENABLED")]
        statuses.append("WARN" if False in flags else "UNKNOWN" if None in flags else "OK")
        age = _number(row["SIGNATURE_AGE_DAYS"])
        statuses.append("UNKNOWN" if age is None else check_threshold(age, HOST_THRESHOLDS["defender_signature_warn_days"], HOST_THRESHOLDS["defender_signature_crit_days"]))
    return _result(name, _worst(statuses, "UNKNOWN"), "Defender/EDR观测", "Defender正常模式按实时防护和签名时效判定；被动模式、注册产品及Sense服务仅作线索，第三方EDR健康须控制台核验",
                   ["类型", "产品", "模式/服务状态", "实时防护", "签名版本", "签名时间", "距今天", "证据"],
                   [(r["KIND"], r.get("PRODUCT"), r["MODE"], r["REALTIME_ENABLED"], r.get("SIGNATURE_VERSION"), r.get("SIGNATURE_UPDATED"), r["SIGNATURE_AGE_DAYS"], r["EVIDENCE"]) for r in rows],
                   problem, "确认组织批准的防护产品工作正常；第三方防护环境不要直接启用双重实时扫描")


def _broad_sid(sid):
    return sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546") or (sid.startswith("S-1-5-21-") and sid.endswith("-513"))


def parse_groups(directory):
    name = "Windows高权限组"
    rows, missing, problem = _load(directory, "privileged_groups.txt", name, ("GROUP", "GROUP_SID", "MEMBER", "MEMBER_SID", "EVIDENCE"))
    if missing:
        return missing
    broad = [r for r in rows if _broad_sid(r["MEMBER_SID"])]
    unresolved = any(r["MEMBER"] and not r["MEMBER_SID"] for r in rows)
    return _result(name, "WARN" if broad else "INFO", f"{len(broad)}项宽泛授权",
                   "本地Administrators及ORA_*_DBA/OPER直接成员清单；按SID识别宽泛主体，不按人数告警；域组嵌套和职责授权需人工复核",
                   ["组", "组SID", "成员", "成员SID", "成员类型", "证据"],
                   [(r["GROUP"], r["GROUP_SID"], r["MEMBER"], r["MEMBER_SID"], r.get("MEMBER_TYPE"), r["EVIDENCE"]) for r in rows],
                   problem or unresolved, "核对高权限组成员的授权依据，移除不需要的宽泛组" if broad else "")


def parse_audit_policy(directory):
    name = "Windows审计策略"
    rows, missing, problem = _load(directory, "windows_audit_policy.txt", name, ("SUBCATEGORY", "GUID", "SUCCESS", "FAILURE"))
    if missing:
        return missing
    expected = {"Logon", "AuditPolicyChange", "UserAccountManagement", "SecurityGroupManagement"}
    statuses, display = [], []
    for row in rows:
        success, failure = _bool(row["SUCCESS"]), _bool(row["FAILURE"])
        required_failure = row["SUBCATEGORY"] == "Logon"
        status = "UNKNOWN" if success is None or (required_failure and failure is None) else "WARN" if not success or (required_failure and not failure) else "OK"
        statuses.append(status)
        display.append((row["SUBCATEGORY"], row["GUID"], row["SUCCESS"], row["FAILURE"], status))
    return _result(name, _worst(statuses), "系统级高级审计", "默认基线：登录成功+失败；审计策略变更、用户及安全组管理记录成功事件；不代表全量审计合规",
                   ["子类别", "GUID", "成功", "失败", "状态"], display,
                   problem or not expected.issubset({r["SUBCATEGORY"] for r in rows}), "按组织审计要求配置并验证Security日志留存与集中转发")


def parse_cluster(directory):
    name = "Windows故障转移集群"
    rows, missing, problem = _load(directory, "windows_cluster.txt", name, ("KIND", "NAME", "STATE", "OWNER", "DETAIL"))
    if missing:
        return missing
    statuses = []
    for row in rows:
        kind, state = row["KIND"], row["STATE"].lower()
        status = "INFO"
        if kind == "CLUSTER" and state in ("not_installed", "not_configured"):
            continue
        if state == "failed" or (kind == "SERVICE" and state != "running") or (kind == "NODE" and state == "down"):
            status = "CRIT"
        elif kind in ("GROUP", "RESOURCE", "NETWORK", "NODE", "QUORUM"):
            if state in ("online", "up"):
                status = "OK"
            elif state in ("offline", "paused", "partialonline", "partitioned"):
                status = "WARN"
            elif state != "no_witness":
                status = "UNKNOWN"
        statuses.append(status)
    configured = any(r["KIND"] == "CLUSTER" and r["STATE"] == "CONFIGURED" for r in rows)
    return _result(name, _worst(statuses), "已配置" if configured else "未配置/未确认",
                   "Windows Failover Cluster（非Oracle RAC）：节点、组、资源、网络及仲裁快照；离线可能为维护状态，无见证不单独告警",
                   ["类型", "名称", "状态", "所有者", "说明"], [(r["KIND"], r["NAME"], r["STATE"], r["OWNER"], r["DETAIL"]) for r in rows],
                   problem or not rows, "核查失败或离线资源、仲裁可用性及维护计划；本检查不执行切换")


def parse_oracle_memory(directory, name="Oracle锁页权限与大页配置"):
    rows, missing, problem = _load(directory, "oracle_memory_config.txt", name,
                                   ("SERVICE", "SID", "ACCOUNT", "ORA_LPENABLE", "ORA_SID_LPENABLE", "LOCK_PAGES_GRANT", "EVIDENCE"))
    if missing:
        return missing
    statuses, display = [], []
    for row in rows:
        mode = row["ORA_SID_LPENABLE"] or row["ORA_LPENABLE"] or "未设置"
        status = "INFO"
        if row["EVIDENCE"] not in ("CONFIG_ONLY", "NO_LOCAL_SERVICE"):
            status = "UNKNOWN"
        elif mode in ("1", "2") and row["LOCK_PAGES_GRANT"] in ("UNCONFIRMED", "UNRESOLVED_ACCOUNT"):
            status = "UNKNOWN"
        elif mode not in ("未设置", "0", "1", "2"):
            status = "WARN"
        statuses.append(status)
        display.append((row["SERVICE"], row["ACCOUNT"], row.get("ORACLE_HOME"), row.get("REGISTRY_KEY"), mode, row["LOCK_PAGES_GRANT"], row["EVIDENCE"]))
    return _result(name, _worst(statuses), "配置证据，非实际使用量", "实例ORA_SID_LPENABLE优先于ORA_LPENABLE：1常规、2混合模式；锁页仅确认直接/已枚举本地组授权，域继承和运行中令牌未验证。未启用大页不自动视为故障",
                   ["服务", "账号", "Oracle Home", "注册表", "大页模式", "锁页授权", "证据"], display, problem or not rows,
                   "启用前核验服务账号SeLockMemoryPrivilege、版本支持和SGA容量；实际使用需当前实例启动日志/运行时证据")


def parse_windows_large_pages(raw_dir):
    directory = os.path.join(raw_dir, "db")
    name = "Oracle Windows大页"
    rows, missing, problem = _load(directory, "windows_large_pages.txt", name, ("INSTANCE_NAME", "HOST_NAME", "NAME", "VALUE"))
    if missing:
        return missing
    local = parse_env_info(raw_dir).get("hostname", "").split(".")[0].lower()
    remote = not local or any(r["HOST_NAME"].split(".")[0].lower() != local for r in rows)
    memory = parse_oracle_memory(directory, name)
    params = {r["NAME"].lower(): r["VALUE"] for r in rows}
    detail = "；".join(f"{k}={v}" for k, v in params.items())
    detail += "；USE_LARGE_PAGES为Linux参数，Windows不据此确认大页生效"
    if remote:
        return CheckResult(name, "UNKNOWN", "远程/主机身份未确认", detail + "；数据库HOST_NAME与采集机不一致，不能关联本地注册表和服务账号")
    status = memory.status
    config, _, config_problem = _load(directory, "oracle_memory_config.txt", name, ("SID", "ORA_LPENABLE", "ORA_SID_LPENABLE"))
    instances = {r["INSTANCE_NAME"].lower() for r in rows}
    matched = [r for r in config if r["SID"].lower() in instances and r.get("EVIDENCE") == "CONFIG_ONLY"]
    if not matched:
        status = "UNKNOWN"
        detail += "；未匹配到本地实例服务和Oracle Home注册表"
    enabled = any((r["ORA_SID_LPENABLE"] or r["ORA_LPENABLE"]) in ("1", "2") for r in matched)
    if enabled and params.get("lock_sga", "").upper() == "TRUE":
        status = "WARN"
        detail += "；大页配置与LOCK_SGA同时启用，存在启动冲突风险"
    if (problem or config_problem or not rows) and status not in ("WARN", "CRIT"):
        status = "UNKNOWN"
    return CheckResult(name, status, memory.value, detail + "；" + memory.detail, memory.suggestion, extra_html=memory.extra_html)


def parse_configuration_acl(directory):
    name = "Oracle配置ACL"
    rows, missing, problem = _load(directory, "oracle_config_acl.txt", name,
                                   ("KIND", "PATH", "IDENTITY", "IDENTITY_SID", "RIGHTS", "TYPE", "EVIDENCE"))
    if missing:
        return missing
    # 4.3.3 and earlier packages may contain Wallet ACL rows. They are outside
    # the current inspection scope and must not affect display or scoring.
    rows = [row for row in rows if row["KIND"] != "WALLET"]
    if not rows:
        return CheckResult(name, "UNKNOWN" if problem else "INFO", "无适用记录",
                           "未发现适用的Listener/SQLNet/TNS候选配置或匹配Oracle Home注册表ACL记录"
                           + ("；部分采集失败，结论不完整" if problem else ""))
    risky = []
    for row in rows:
        rights = row["RIGHTS"].lower()
        if row["TYPE"].lower() == "allow" and _broad_sid(row["IDENTITY_SID"]):
            writable = any(r in rights for r in ("write", "modify", "fullcontrol", "setvalue", "createsubkey", "changepermissions", "takeownership", "delete"))
            if writable:
                risky.append(row)
    unknown = any(r["EVIDENCE"] == "UNRESOLVED_PATH" or (r["EVIDENCE"] == "OBSERVED" and not r["IDENTITY_SID"]) for r in rows)
    observed = [r for r in rows if r["EVIDENCE"] == "OBSERVED"]
    return _result(name, "WARN" if risky else "INFO", f"{len(risky)}项潜在宽泛权限",
                   "检查Listener/SQLNet/TNS候选配置及匹配Oracle Home注册表ACL；按SID识别宽泛写权限；Deny/嵌套组的有效访问需复核",
                   ["类型", "路径", "主体", "SID", "权限", "Allow/Deny", "修改时间UTC", "证据"],
                   [(r["KIND"], r["PATH"], r["IDENTITY"], r["IDENTITY_SID"], r["RIGHTS"], r["TYPE"], r.get("MODIFIED_UTC"), r["EVIDENCE"]) for r in rows],
                   problem or unknown or not observed, "核验有效ACL并收紧配置写权限；不自动修改授权" if risky else "")


def parse_windows_baseline(raw_dir):
    directory = os.path.join(raw_dir, "host")
    return [parser(directory) for parser in (
        parse_network_config, parse_network_quality, parse_protection, parse_groups,
        parse_audit_policy, parse_cluster, parse_oracle_memory,
    )]
