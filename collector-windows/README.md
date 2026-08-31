# OraSentry Windows Collector v4.3

该目录可独立复制到 Windows Oracle 服务器，使用系统自带的 Windows PowerShell 5.1 采集主机、数据库和安全数据，不依赖 Python、WSL、Cygwin 或外部 tar 工具。

## 环境要求

- Windows Server 2012 R2 或更高版本。
- Windows PowerShell 5.1。
- Oracle Database 11g 至 23ai，目标 Oracle Home 包含 `sqlplus.exe` 和 `lsnrctl.exe`。
- 完整主机、Security 事件日志和 ACL 巡检建议使用管理员权限。
- OS 数据库认证账号应属于本机 `ORA_DBA` 组。

PowerShell 源文件使用 UTF-8 BOM，以兼容 Windows PowerShell 5.1 的中文脚本解析；采集数据统一写为 UTF-8 无 BOM。

## 使用

首次使用先按需修改 `conf\check.psd1`，然后直接双击：

```text
开始巡检.cmd
```

启动器会检查 Windows PowerShell 5.1、申请管理员权限、按配置执行主机与数据库巡检，并在结束窗口中列出本次生成的采集包。无需手工打开命令行；如果启用了 `DB_INTERACTIVE_LOGIN`，窗口会继续提示输入数据库连接参数和隐藏密码。

以下命令行入口仍保留，供计划任务、批处理或故障排查使用。

默认同时采集主机和数据库，但仍生成两份相互独立的采集包：

```powershell
cd C:\OraSentry\collector-windows
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1
```

按类型运行：

```powershell
# Windows主机巡检
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Host

# Oracle数据库与安全巡检
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Database

# 等价的独立入口
powershell -ExecutionPolicy Bypass -File .\main_host.ps1
powershell -ExecutionPolicy Bypass -File .\main_db.ps1
```

输出文件：

```text
output\raw\host_check_<hostname>_<timestamp>.tar.gz
output\raw\db_check_<SID>_<timestamp>.tar.gz
```

每次运行还会保留带时间戳的原始数据目录，包含 `env.info`、`collection_manifest.tsv`、`collect.log` 和相应数据域。传输时只需要 tar.gz；采集包属于机密运维数据，应使用受控通道传输并按组织策略保留。

## 配置

配置文件为 `conf\check.psd1`，键名与 Linux 版 `conf/check.conf` 保持一致。`ORACLE_SID` 和 `ORACLE_HOME` 留空时，程序依次从当前进程环境、`PATH` 中的 `sqlplus.exe`、Oracle 注册表和 `OracleService<SID>` 服务探测。检测到多个实例时必须显式指定 SID。

默认配置：

```powershell
ORACLE_SID = ""
ORACLE_HOME = ""
DB_INTERACTIVE_LOGIN = "off"
DB_WALLET_ALIAS = ""
CHECK_HOST = "on"
CHECK_DB = "on"
CHECK_SECURITY = "on"
CHECK_AWR = "off"
COLLECT_SQL_TEXT = "off"
```

禁止在配置文件中增加数据库密码。SQL 文本和 AWR 默认关闭，启用前需确认数据分类及 Oracle 授权。

### OS认证

默认使用本机 OS 认证，相当于：

```text
CONNECT / AS SYSDBA
```

运行账号必须具备对应 Oracle 本机组权限。

### Oracle Wallet

在 `check.psd1` 中设置 Wallet 别名，并保持交互登录关闭：

```powershell
DB_INTERACTIVE_LOGIN = "off"
DB_WALLET_ALIAS = "orcl_wallet"
```

### 运行时交互认证

在 `check.psd1` 中设置：

```powershell
DB_INTERACTIVE_LOGIN = "on"
```

之后双击 `开始巡检.cmd`，程序会提示账号、数据库地址、端口、连接类型、服务名/SID、角色和隐藏密码。密码仅保存在当前 PowerShell 进程内存中，通过 SQL*Plus 标准输入建立连接，不写入参数、配置、日志或采集包。

命令行临时覆盖仍可使用 `powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Database -InteractiveLogin`，无需修改配置文件。

远程数据库连接只能完成 SQL 指标采集。Alert Log、Trace、Windows 服务、事件日志和 ACL 仍读取 Collector 所在服务器，因此完整巡检必须在目标数据库服务器本地运行。

## Windows主机检查范围

- 固定卷容量和文件系统。
- CPU、物理内存、页面文件和磁盘性能计数器。
- 交互登录会话和最近7天失败登录抽样。
- Windows Defender 防火墙配置文件。
- Windows Time 服务、时区和时间源。
- TCP/UDP 监听端点和对应进程。
- System/Application 错误及严重事件。
- Oracle 服务、进程和启动状态。
- Oracle Home、`oracle.exe`、网络配置及密码文件 NTFS ACL。

Linux inode、sysctl、HugePages 和 THP 等检查在 Windows 报告中标记为不适用，不参与健康评分。

## 返回码和失败处理

单项失败不会中止其他采集，但会写入 `collection_manifest.tsv`，并使主程序返回非零。即使存在失败，程序仍会打包已有数据，报告端将采集完整性标记为不完整，避免把缺失数据误判为正常。

## 验证

在项目根目录执行：

```powershell
python -m unittest discover -s collector-windows\tests -v
```

测试覆盖 PowerShell 语法、UTF-8 BOM、无明文密码配置、4.3 平台协议、统一文件名和不依赖外部工具的 tar.gz 兼容性。
