# Windows 巡检第二期（4.3.2）

第二期实现原方案的网络、安全基线、Oracle锁页/大页与配置ACL、Windows集群检查。只采集和评估，不修改系统策略、组成员、服务、注册表、防护配置或集群状态。默认继续生成独立主机包与数据库包。

## 增量协议

schema_version仍为4.3。采集表为UTF-8无BOM、竖线分隔。新增文件缺失且manifest无记录视为旧包INFO；已登记但文件缺失、格式异常、部分查询失败为UNKNOWN。若部分结果已明确发现风险，保留WARN/CRIT并注明不完整；manifest中的FAILED表示执行失败，WARN表示只获得部分数据，均使受影响指标为UNKNOWN。已过滤且不影响SQL结果的SQL*Plus启动脚本提示不降低完整性。信息清单和不适用项不纳入健康分。

| 域/文件 | 内容与报告项 |
|---|---|
| host/network_config.txt | 网卡IF_INDEX/名称/状态/速率、IP、DNS、默认路由与跃点 |
| host/network_quality.txt | 5秒两次快照的NIC包/错误/丢弃/字节增量，TCPv4/v6发送段和重传段增量、计数器状态 |
| host/endpoint_protection.txt | Defender模式、服务/实时防护、签名版本/时间/天数，Sense及注册产品信息 |
| host/privileged_groups.txt | 本地管理员、ORA_DBA/ORA_OPER及Home特定组的直接成员、SID、成员类型 |
| host/windows_audit_policy.txt | 登录、审计策略变更、用户及安全组管理的GUID与成功/失败标志 |
| host/windows_cluster.txt | 是否安装/配置、ClusSvc、节点、组、资源、网络、仲裁 |
| host或db/oracle_memory_config.txt | Oracle服务/SID/账号、Oracle Home/注册表、全局及实例大页模式、锁页授权证据 |
| db/windows_large_pages.txt | 数据库实例/主机、USE_LARGE_PAGES、LOCK_SGA、SGA及AMM参数 |
| security/oracle_config_acl.txt | 网络配置及匹配Oracle Home注册表：路径、所有者、SID、ACL、文件修改时间及证据状态 |

## 默认规则与边界

- 网络至少100包/段才按比率判定：NIC错误+丢弃率0.1%/1%为WARN/CRIT；TCP重传率2%/5%为WARN/CRIT。计数器下降、缺失或无效值为UNKNOWN。两次快照不是长期监控，窗口内正常不保证其他时段正常。DNS和路由仅展示配置，无默认路由或未用网卡断开不直接告警。
- Defender在Normal模式检查防护状态和签名；签名7/14天为WARN/CRIT。被动模式、未运行、未知模式或仅发现第三方注册产品为UNKNOWN，需安全控制台核验。Windows Server不依赖SecurityCenter2；不按任意服务名称猜测第三方EDR健康。
- 高权限组按SID识别Everyone、Authenticated Users、Users、Guests、Domain Users等宽泛主体，潜在宽泛授权为WARN；不按成员数量判定。域组嵌套未展开。
- 审计默认要求登录成功+失败，其余三个子类别记录成功事件。通过Windows API读系统策略，与显示语言无关；不是全量合规认证。读取时只临时启用调用进程已被授予的SeSecurityPrivilege，随后恢复。
- 大页按实例ORA_SID_LPENABLE优先、全局ORA_LPENABLE兜底。0/未设置不自动告警；1为常规、2为混合模式。仅直接SID/已枚举本地组可以确认配置授权，域继承与运行中服务令牌未验证。未匹配注册表或已配置大页但授权未确认为UNKNOWN。数据来自配置，并不证明当前SGA实际使用大页。
- 数据库HOST_NAME与采集机不匹配时不关联本地注册表/服务；Windows的大页不能仅凭USE_LARGE_PAGES判定。匹配本地配置且同时启用大页和LOCK_SGA时提示WARN，需按版本核验启动冲突。
- ACL只保存Oracle网络配置及匹配Oracle Home注册表的元数据。检查Oracle Home默认network/admin、采集进程TNS_ADMIN及匹配Home注册表TNS_ADMIN作为候选路径，不能保证均为服务实际生效目录。UNC、含未展开变量、非本地绝对路径仅记录待核验，不触发网络认证。Deny优先级及嵌套组的最终有效权限仍需复核。
- 集群为Windows Failover Cluster，不是Oracle RAC。未安装/未配置为INFO；节点Down、资源Failed或已配置但ClusSvc停止为CRIT；Offline/Paused为WARN并提示核查维护状态。NodeMajority没有见证并不自动认定仲裁失败。管理模块/权限不可用为UNKNOWN。

阈值集中在reporter/src/config.py。所有操作需在目标服务器本地执行；远程SQL连接不使Windows采集自动转移到数据库服务器。CHECK_SECURITY仍控制数据库安全模块，主机基线随主机巡检运行。

## 验证与交付

在项目根目录运行三套测试，再通过指定脚本构建Windows EXE：

```powershell
python -m unittest discover -s collector-linux\tests -v
python -m unittest discover -s collector-windows\tests -v
python -m unittest discover -s reporter\tests -v
powershell -NoProfile -ExecutionPolicy Bypass -File reporter\tools\build_windows.ps1
```

验收包括旧包INFO、采集失败UNKNOWN、格式异常、低流量/计数器重置、Defender被动模式、SID本地化、审计缺项、集群不可用/离线/失败、大页实例覆盖与远程身份隔离、配置文件及注册表写权限，以及HTML/DOCX输出。必须另用实际主机采集包验证受影响报告，并核对EXE时间戳晚于源码且SHA256匹配。没有真实Oracle/集群的环境只可验证相应回归数据，不应声称完成生产集群联调。

## 规则参考

- [Oracle Windows大页配置（21c）](https://docs.oracle.com/en/database/oracle/oracle-database/21/ntqrf/enabling-large-page-support.html)：Windows注册表模式与LOCK_SGA限制；具体版本应另行确认。
- [Oracle USE_LARGE_PAGES（19c）](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/USE_LARGE_PAGES.html)：参数适用平台说明。
- [Microsoft Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)：Defender状态属性。
- [Microsoft AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)：高级审计查询与权限要求。
- [Microsoft secedit /export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)：只导出合并用户权限策略，临时全量权限文件在读取目标权限后移除，不进入采集包。
