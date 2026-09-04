# Oracle 巡检报告生成端 v4.3

该目录是可独立复制到 Windows 的报告程序。它读取 `collector-linux` 或 `collector-windows` 生成的 tar.gz，根据包内 `platform` 解析，进行阈值判定并同步输出 HTML 与 Word（DOCX）报告。

## 目录

```text
reporter/
├── requirements.txt               # 源码运行依赖
├── requirements-build.txt         # Windows 构建依赖
├── src/                           # Python 业务源码
│   ├── gui.py                     # 图形界面入口
│   ├── report_gen.py              # 命令行与共用生成逻辑
│   ├── docx_gen.py                # 企业级 Word 报告渲染器
│   ├── summary_gen.py             # 多份报告汇总摘要
│   ├── config.py                  # 报告阈值
│   └── parser/                    # 主机、数据库、安全解析器
├── resources/templates/           # HTML 报告模板
├── tools/                         # Windows exe 构建
├── tests/                         # Python 回归测试
├── output/raw/                    # 可放入收集包
├── output/report/                 # 默认报告输出
└── dist/OracleReport.exe          # 执行构建后生成
```

## Windows 图形界面

双击 `dist/OracleReport.exe`：

1. 添加 `host_check_*.tar.gz` 和/或 `db_check_<SID>_*.tar.gz`；可以点击“添加采集包”，也可以把采集包或包含采集包的文件夹直接拖入数据列表。
2. 在“项目名称”中填写报告封面标识；默认是 `ORACLE INSPECTION REPORT`，留空也会恢复为该默认值。
3. 选择报告目录或文件名；留空时自动写入 exe 旁的 `output/report/`。数据库包命名为 `Oracle巡检报告_<SID>_<日期>`，主机包命名为 `主机巡检报告_<主机名>_<日期>`。
4. “生成总结”默认不勾选；勾选后会在每份 HTML 与 Word 详细报告的“总结”章节自动生成总体结论、重点问题和处置建议，不勾选时该章节留空。
5. 默认勾选“生成汇总摘要”。一次生成两份及以上 Oracle 报告时，会额外输出 `Oracle巡检汇总摘要_<日期>`；该选项与单份报告的“生成总结”相互独立，主机报告不参与汇总摘要。
6. 点击“生成巡检报告”。生成期间使用圆形状态图标且保持普通鼠标指针；如需中止，可点击“停止生成”，程序会在安全检查点停止并保留此前完整生成的报告。
7. 程序会生成同名 `.html` 和 `.docx`，不会删除报告目录中原有的 `.json`、`.gitkeep` 或其他旁路文件。
8. 完成后可分别打开 HTML、Word、汇总摘要或所在文件夹。

同时选择主机包和数据库包时，会分别生成主机报告与 Oracle 报告。主机报告只包含主机巡检项，Oracle 报告只包含数据库、CDB/PDB、RAC 和安全巡检项，二者不会合并。目标电脑不需要安装 Python。

## Python 方式

需要 Python 3.8+。首次运行先安装 Word 报告依赖：

```powershell
python -m pip install -r requirements.txt

# 图形界面
python src\gui.py

# 单个收集包
python src\report_gen.py output\raw\db_check_orcl_20260820_120000.tar.gz

# 同时输入主机包与数据库包，分别生成两份报告
python src\report_gen.py output\raw\host_check_20260820_120000.tar.gz `
  output\raw\db_check_orcl_20260820_120000.tar.gz `
  -o output\report

# 多套数据库：各出一份 Oracle 详细报告，并默认再生成汇总摘要
python src\report_gen.py db_orcl.tar.gz db_prod.tar.gz
python src\report_gen.py db_orcl.tar.gz db_prod.tar.gz --no-summary

# 自动填写每份详细报告末尾的“总结”章节
python src\report_gen.py db_orcl.tar.gz --generate-summary
```

不指定 `-o` 时，源码模式默认输出到 `reporter/output/report/`。数据库报告使用 `Oracle巡检报告_<SID>_<YYYYMMDD>`，主机报告使用 `主机巡检报告_<主机名>_<YYYYMMDD>`。无论 GUI、命令行还是 `OracleReport.exe`，都会走同一命名逻辑并同步生成同名 HTML 和 DOCX。`--generate-summary` 用于填写每份详细报告末尾的“总结”章节，默认关闭。两份及以上 Oracle 报告时，额外生成 `Oracle巡检汇总摘要_<YYYYMMDD>`，可用 `--no-summary` 关闭。

健康评分按适用检查项的业务权重归一化计算：正常项不产生风险损失，警告项消耗
三分之一权重，严重项消耗全部权重。采集完整性、按配置未启用和架构不适用项不参与
健康分；报告另外展示总体风险状态和数据可信度。多系统汇总使用相同的加权分子、分母，
不再使用正常项比例作为另一套评分。

## 汇总摘要报告结构

两份及以上 Oracle 报告生成完成后，程序把数据库系统执行摘要合并为一份管理层报告；主机报告不混入 Oracle 汇总摘要：

- 封面给出覆盖范围、整体健康评分、风险等级与报告编号。
- 执行摘要用文字说明本期结论，并列出优先关注系统。
- 系统健康一览、评分排名与分类统计用于横向对比。
- 跨系统共性风险列出同一检查项在两套及以上系统出现警告或严重的情况。
- 汇总待处理事项按严重优先，并附分系统摘要、结论建议和签批栏。

## Word 报告结构

- 第 1 页为正式封面，展示主机、IP、SID、巡检时间、健康评分与总体状态，不再保留开头空白页。
- 正式封面的项目名称可在图形界面中自定义，默认是 `ORACLE INSPECTION REPORT`；该位置固定使用宋体且不使用斜体。
- 正文页脚同步显示图形界面填写的项目名称及当前页码。
- 正文包含执行摘要、可点击的静态目录、待处理事项以及全部巡检章节；不插入“章节索引”，目录无需更新域即可显示。
- 分类使用一级标题，每个巡检项目使用二级标题，检查说明、整改建议和巡检明细使用三级标题。
- HTML 中的数据表、柱形图、百分比图、列表和备注会转换为 Word 原生表格或可视化内容。
- Word 中文字体使用宋体（SimSun），英文与数字使用 Times New Roman。
- 每次生成都会校验 Word 中的巡检项数量，防止漏项。
- 最后一章固定为“总结”；“生成总结”未勾选时正文为空，勾选后自动填写总体结论、重点问题和处置建议。

## 构建 Windows exe

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_windows.ps1
```

Windows 环境安装 Microsoft Word 时，报告器会在后台调用 Word 分页引擎，将静态目录的内部书签页码写入并锁定；目录不使用 TOC 域，不会创建外部文件引用。

构建产物为 `dist/OracleReport.exe`。构建脚本会安装 `python-docx`、`lxml` 和 PyInstaller；最终用户不需要安装 Python 或 Office 组件即可生成 DOCX。

构建同时生成 `OracleReport.exe.sha256`，EXE 内含 4.3.7.0 版本资源。正式分发前，建议使用组织的代码签名证书和 Windows SDK `signtool.exe` 执行 Authenticode 签名。

Windows 第二期增量指标包括网络质量、终端防护、高权限组、系统审计、锁页与大页配置、Oracle 配置 ACL 和 Windows Failover Cluster。旧包缺少增量文件显示 INFO，已登记的执行失败或部分采集显示 UNKNOWN；已过滤且不影响SQL结果的环境提示保持 INFO。部分失败仍保留已观测到的风险，同时由采集完整性降低数据可信度。规则与适用边界见 [Windows 第二期说明](../doc/WINDOWS-PHASE2.md)。

## 测试

```powershell
python -m unittest discover -s tests -v
python -m compileall -q src
```

## 数据边界

报告端不读取任何 Collector 源码。双方唯一契约是收集包内部的：

- `env.info`
- `collection_manifest.tsv`
- `host/`
- `db/`
- `security/`

报告端接受无协议字段的 v4.0 包以及 `schema_version=4.x` 的包；其他主版本会明确拒绝。
