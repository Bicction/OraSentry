# OraSentry v4.3

Oracle 主机、数据库与安全巡检工具。项目采用离线两段式架构：Linux Oracle
服务器运行 `collector-linux`，Windows Oracle 服务器运行 `collector-windows` 生成采集包，Windows 或 Python 环境运行 `reporter`
生成 HTML、DOCX 和多系统汇总报告。

## v4.3 重点

- 新增原生 Windows PowerShell 5.1 Collector，覆盖 Windows 主机性能、服务、事件日志、ACL、Oracle 数据库与安全巡检。
- Linux 采集端更名为 `collector-linux`，统一入口为 `OraSentry.sh`；Windows 入口为 `OraSentry.ps1`。
- Linux 与 Windows 均生成 `host_check_<hostname>_<timestamp>.tar.gz` 和 `db_check_<SID>_<timestamp>.tar.gz`。
- 采集协议升级为 `schema_version=4.3`，通过 `platform=linux/windows` 分流；报告端继续兼容所有 4.x 包。
- 禁止在配置中保存 `DB_USER/DB_PASS` 明文认证，支持 OS 认证、运行时隐藏输入和 Oracle Wallet。
- SQL 文本和 AWR 采集默认关闭，需在对应平台配置中显式启用。
- 打包阶段只生成 tar.gz 采集包，并将其标记为机密运维数据。
- 报告端自动清理解压临时目录，不删除用户已有 JSON 或 `.gitkeep`。
- 主机包与数据库包始终分别生成报告，Oracle 报告不包含主机巡检项。
- 健康评分采用适用检查项归一化加权；风险状态与数据可信度独立展示。
- Python 与 PyInstaller 依赖固定版本，Windows EXE 带版本资源并提供签名建议。
- HTML/Word 巡检项均展示用途说明；Word 静态目录带准确页码且不依赖外部域更新。

## 快速入口

- Linux 采集端：[collector-linux/README.md](collector-linux/README.md)
- Windows 采集端：[collector-windows/README.md](collector-windows/README.md)
- 报告端说明：[reporter/README.md](reporter/README.md)
- v4.3 升级说明：[MIGRATION-v4.3.md](MIGRATION-v4.3.md)
- v4.2 升级说明：[MIGRATION-v4.2.md](MIGRATION-v4.2.md)
- v4.0 升级说明：[MIGRATION-v4.1.md](MIGRATION-v4.1.md)
- 安全边界：[SECURITY.md](SECURITY.md)
- 变更记录：[CHANGELOG.md](CHANGELOG.md)

## 验证

```powershell
python -m unittest discover -s collector-linux\tests -v
python -m unittest discover -s collector-windows\tests -v
python -m unittest discover -s reporter\tests -v
```

Linux 上的 `collector-linux` 测试会额外执行所有 Shell 文件的 `bash -n` 语法检查；Windows 测试会校验 PowerShell 语法、UTF-8 BOM 和原生 tar.gz 兼容性。
