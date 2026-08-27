# Oracle 巡检数据收集端 v4.2

该目录是可独立上传到 Oracle Linux 服务器的收集程序，不依赖报告端或 Python。

## 目录

```text
collector/
├── main.sh                 # 按当前用户自动分发
├── main_host.sh            # root：主机巡检
├── main_db.sh              # oracle：数据库与安全巡检
├── conf/check.conf         # 收集配置
├── lib/                    # 收集实现
├── tests/                  # 静态回归测试
└── output/raw/             # 原始数据与 tar.gz（运行时生成）
```

## 环境要求

- RHEL、CentOS 或 Oracle Linux
- Bash 4+
- Oracle 11g 至 23ai
- 数据库巡检需要 `sqlplus`
- 主机巡检建议使用 root，数据库巡检必须使用 oracle 用户

## 使用

可按需修改 `conf/check.conf`。默认使用操作系统中的 `ORACLE_SID`、`ORACLE_HOME` 和 `/ as sysdba` 认证。v4.2 禁止 `DB_USER/DB_PASS` 明文认证；如需无密码远程别名，请使用 Oracle Wallet 的 `DB_WALLET_ALIAS`。

```bash
cd /path/to/collector

# root 用户收集主机数据
./main_host.sh

# oracle 用户收集数据库和安全数据
su - oracle -c "cd /path/to/collector && ./main_db.sh"
```

也可以让统一入口按当前用户自动选择：

```bash
./main.sh
./main.sh --host
./main.sh --db
```

默认输出：

```text
output/raw/host_check_<timestamp>.tar.gz
output/raw/db_check_<SID>_<timestamp>.tar.gz
```

每个压缩包旁会生成同名 `.sha256` 校验文件。采集包属于机密运维数据，应通过受控通道传输并按组织策略设置保留期。

将上述压缩包拷贝到 Windows 的 `reporter` 目录，通过 `OracleReport.exe` 或 Python 生成报告。收集端不需要、也不会调用报告端代码。

## 配置与输出

- `RAW_DATA_DIR` 相对于 `collector` 根目录；也可以填写绝对路径。
- root 首次创建共享输出目录时，会为 oracle 用户设置可写的组权限。
- 每次收集都会生成 `env.info`、`collection_manifest.tsv` 和 `collect.log`。
- `env.info` 包含 `schema_version=4.2`、采集器版本和数据分类。
- 单项失败会记录到清单并使主程序返回非零退出码，但仍保留并打包已收集的数据。
- `CHECK_AWR` 和 `COLLECT_SQL_TEXT` 默认关闭；启用前需确认授权和数据处理要求。
- 实例状态通过 `GV$INSTANCE` 采集全部实例；Alert Log 仍只读取当前 `ORACLE_SID` 对应物理日志的最后 100000 行，并在其中提取最近30天内容及实际首末时间。

## 验证

```bash
bash -n main.sh main_host.sh main_db.sh lib/*.sh
python3 -m unittest discover -s tests -v
```
