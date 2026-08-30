# v4.3 升级说明

## 目录调整

原 Linux 采集端目录和统一入口已更名：

```text
collector/          -> collector-linux/
collector/main.sh   -> collector-linux/OraSentry.sh
```

Linux 自动化任务、上传脚本和运维文档需要同步修改路径。`main_host.sh`、`main_db.sh` 的职责保持不变。

新增 Windows 采集端：

```text
collector-windows/
├── 开始巡检.cmd
├── Start-OraSentry.ps1
├── OraSentry.ps1
├── main_host.ps1
├── main_db.ps1
├── conf/check.psd1
└── lib/
```

## 协议和文件名

新采集包使用 `schema_version=4.3`，并包含 `platform=linux` 或 `platform=windows`。报告端继续兼容无版本的 v4.0 包和所有 `schema_version=4.x` 包。

主机包统一增加主机名：

```text
host_check_<hostname>_<timestamp>.tar.gz
db_check_<SID>_<timestamp>.tar.gz
```

依赖旧版 `host_check_<timestamp>.tar.gz` 文件名的传输或归档规则需要更新；报告端不依赖文件名判断平台。

## Windows 部署

把整个 `collector-windows` 目录复制到目标 Windows Oracle 服务器，按需修改 `conf\check.psd1` 后双击 `开始巡检.cmd`。启动器使用 Windows PowerShell 5.1 并自动申请管理员权限；数据库 OS 认证账号应属于本机 `ORA_DBA` 组。`OraSentry.ps1`、`main_host.ps1` 和 `main_db.ps1` 继续作为自动化命令行入口。

```powershell
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Host
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Database
```

配置文件不得保存数据库明文密码。Windows 与 Linux 使用一致的 `DB_INTERACTIVE_LOGIN`、`DB_WALLET_ALIAS`、`ORACLE_SID`、`ORACLE_HOME` 和巡检开关键名。`DB_INTERACTIVE_LOGIN=on` 时运行时隐藏输入；关闭时优先使用 Wallet 别名，否则使用 OS 认证。命令行仍可用 `-InteractiveLogin` 临时覆盖。
