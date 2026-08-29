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

把整个 `collector-windows` 目录复制到目标 Windows Oracle 服务器，使用 Windows PowerShell 5.1 运行。完整主机和安全巡检建议以管理员身份执行；数据库 OS 认证账号应属于本机 `ORA_DBA` 组。

```powershell
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Host
powershell -ExecutionPolicy Bypass -File .\OraSentry.ps1 -Database
```

配置文件不得保存数据库明文密码。可选择 OS 认证、Oracle Wallet 或 `-InteractiveLogin` 运行时隐藏输入。
