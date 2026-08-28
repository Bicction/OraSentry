# Oracle Inspector v4.2

Oracle 主机、数据库与安全巡检工具。项目采用离线两段式架构：Linux/Oracle
服务器运行 `collector` 生成采集包，Windows 或 Python 环境运行 `reporter`
生成 HTML、DOCX 和多系统汇总报告。

## v4.2 重点

- 禁止在配置中保存 `DB_USER/DB_PASS` 明文认证，支持 OS 认证、运行时隐藏输入和 Oracle Wallet。
- 采集协议升级为 `schema_version=4.2`，报告端继续兼容同一主版本的4.x采集包。
- SQL 文本和 AWR 采集默认关闭，需在 `collector/conf/check.conf` 显式启用。
- 采集包附带 SHA-256 校验文件，并标记为机密运维数据。
- 报告端自动清理解压临时目录，不删除用户已有 JSON 或 `.gitkeep`。
- 主机包与数据库包始终分别生成报告，Oracle 报告不包含主机巡检项。
- 健康评分采用适用检查项归一化加权；风险状态与数据可信度独立展示。
- Python 与 PyInstaller 依赖固定版本，Windows EXE 带版本资源并提供签名建议。
- HTML/Word 巡检项均展示用途说明；Word 静态目录带准确页码且不依赖外部域更新。

## 快速入口

- 采集端说明：[collector/README.md](collector/README.md)
- 报告端说明：[reporter/README.md](reporter/README.md)
- v4.1 升级说明：[MIGRATION-v4.2.md](MIGRATION-v4.2.md)
- v4.0 升级说明：[MIGRATION-v4.1.md](MIGRATION-v4.1.md)
- 安全边界：[SECURITY.md](SECURITY.md)
- 变更记录：[CHANGELOG.md](CHANGELOG.md)

## 验证

```powershell
python -m unittest discover -s collector\tests -v
python -m unittest discover -s reporter\tests -v
```

Linux 上的 collector 测试会额外执行所有 Shell 文件的 `bash -n` 语法检查。
