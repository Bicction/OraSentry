# Oracle 巡检报告生成端 v4.4

该目录是可独立复制到 Windows 的报告程序。它读取 `collector-linux` 或 `collector-windows` 生成的 tar.gz，根据包内 `platform` 解析，进行阈值判定并同步输出 HTML 与 Word（DOCX）报告。

数据库报告会自动生成独立的 Data Guard / Active Data Guard 章节。`PHYSICAL STANDBY + READ ONLY WITH APPLY` 识别为 ADG 实时查询运行特征；该结果用于运行状态巡检，不代表 Oracle 许可证合规结论。默认传输/应用延迟阈值为 5 分钟警告、30 分钟严重，指标停滞阈值为 5 分钟警告、15 分钟严重，可在 `src/config.py` 调整。

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
└── dist/                          # 两种发布包及 SHA256
    ├── OracleReport.exe           # 单文件便携版（旋转启动页）
    ├── OracleReport-FastStart/     # 快速启动目录版
    └── OracleReport-FastStart.zip # 目录版完整分发包
```

## Windows 图形界面

推荐解压 `dist/OracleReport-FastStart.zip`，双击文件夹内的 `OracleReport.exe`。
必须保留同目录的 `_internal` 文件夹；可为 EXE 创建桌面快捷方式。目录版只需解压一次，
日常启动不再重复释放运行环境。也可直接使用 `dist/OracleReport.exe` 单文件便携版，
解包时显示 OraSentry 品牌页和旋转指示，主窗口就绪后自动切换。

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
- 大明细表使用批量格式生成并支持中止。默认不调用本机 Word 后台分页，目录保持可点击跳转；需要目录页码时，可在 Word 中全选后按 F9 更新。
- Word 中文字体使用宋体（SimSun），英文与数字使用 Times New Roman。
- 每次生成都会校验 Word 中的巡检项数量，防止漏项。
- 最后一章固定为“总结”；“生成总结”未勾选时正文为空，勾选后自动填写总体结论、重点问题和处置建议。

## 构建 Windows exe

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_windows.ps1

# 指定已有 Python；依赖已安装时可跳过联网安装
powershell -ExecutionPolicy Bypass -File tools\build_windows.ps1 -PythonExe C:\Python312\python.exe -SkipInstall
```

Windows 环境安装 Microsoft Word 时，报告器会在后台调用 Word 分页引擎，将静态目录的内部书签页码写入并锁定；目录不使用 TOC 域，不会创建外部文件引用。

一次构建生成单文件版、快速启动目录版及 ZIP。默认关闭 UPX；`-UseUpx` 仅用于安装了
`upx.exe` 的构建环境做对照实验，可用 `-DistDirectory` 指定独立输出目录。
源码运行要求 Python 3.8+；使用当前固定依赖构建推荐 Python 3.12/3.13 和 Tcl/Tk 8.6。
构建脚本会安装 `python-docx`、`lxml`、拖放库、PyInstaller 和构建图片所用的 Pillow；
最终用户不需要安装 Python 或 Office 组件即可生成 DOCX。

构建会先在临时目录验证两个 EXE 的 GUI、拖放、压缩词典及 HTML/DOCX/汇总报告，
通过后才替换正式产物。之前的 EXE、目录版及 ZIP 保存在 `build/release-backups/`；
不清空 `dist`，其他文件保持原位。验收日志保存在 `build/release-verification/`。

启动优化包括：只打包目标 Windows 架构的拖放组件；将离线词典打包为 `catalog.json.gz`，
首次使用词典时才在内存解压；评分模块不再间接提前导入业务解析器。启动页运行于单文件
父进程，不占用主窗口事件循环，不设置人为等待时长。目录版不加载启动页。

启动性能复测（会自动启动、关闭程序；不要在正在处理报告的实例上执行）：

```powershell
python tools/benchmark_startup.py dist/OracleReport.exe --output build/verification/portable-startup.json --runs 5 --require-splash
python tools/benchmark_startup.py dist/OracleReport-FastStart/OracleReport.exe --output build/verification/folder-startup.json --runs 5
```

计时从创建进程开始，到启动页绘制/主界面就绪为止，原始分阶段记录保存在输出 JSON 旁。
该测试不清理系统缓存，也不修改杀软设置；首次启动和后续启动数据应分别阅读。
显式执行 `OracleReport.exe --verify-package <结果JSON路径>` 可检查打包完整性，测试数据
自动清理，仅保留结果 JSON；不访问真实数据库或用户采集数据。

构建同时生成 `OracleReport.exe.sha256`，EXE 内含 4.4.0.0 版本资源。正式分发前，建议使用组织的代码签名证书和 Windows SDK `signtool.exe` 执行 Authenticode 签名。

## Alert 事件诊断第三版（4.4）

正常添加数据库采集包并生成报告即可使用。在 HTML 的“Alert Log”明细或 Word
同名章节查看事件统计、中文含义、候选原因、人工排查步骤、处理建议和原始证据。
内置知识库包含 5386 个 ORA/TNS/KUP 词条，其中 5357 个为 ORA；源码文件为 `resources/ora/catalog.json`，
构建时压缩为 `catalog.json.gz` 随程序打包，源码仍维护 JSON；使用时不需要联网，
也不会执行诊断 SQL 或修复命令。

其中 329 个高频词条保留精细中文含义和专项处置；其余扩展词条的编号与官方短消息来自
Oracle Database 21c 官方错误手册，并按故障域给出保守的中文排查模板。报告会降低模板词条的
置信度，避免把通用建议当成已经确认的根因。应用自定义的 `ORA-20000` 至 `ORA-20999` 不按
Oracle 内置错误解释，仍由应用代码和消息正文决定。

- 优先分析 `alert_log_30days.txt`，缺失时兼容两列、五列、九列的历史明细及纯错误文件。
- 多行错误栈归并为事件；重复事件按代码、内部错误首参数、实例及相关对象分组，保留发生次数。
- `ORA-06512` 等伴随码不独立累计；正常 `Time Critical priority` 和 `ERROR(s)` 表头不计为告警。
- Redo 文件打开、QOPatch 长记录、PGA 软断言有组合诊断；其他已知代码提供通用排查，未知/自定义错误明确标注待核实。
- 状态由已观察到的错误影响决定，实例终止证据提高优先级；不再按关键词达到 5/20 行直接定级。旧关键词行数作为核对信息保留。
- 毫秒/时区保留，历史采集包沿用采集窗口，不用运行报告的当前日期重新筛选。
- 缺失、乱码、截断及并发交错会标注“证据有限”，不会凭日志推断当前已恢复或仍然中断。
- 原文读取上限 64 MiB；超限保留尾部并提示。单事件限制 256 行、每行 8192 字符、256 个不同代码，截断明确展示。
- 报告概览最多展示 50 组，详细排查展开优先级最高的 12 组；其余仍计入统计并提示查看原文。

第三版按常见 Alert 与运维故障域扩充，并保留 Oracle 官方英文消息用于复核；尚未建立全量 ORA 索引、逐版本补丁规则、客户覆盖文件或独立 GUI
词典查询入口。`ORA-00600/07445` 等须继续结合完整 trace 和精确版本核实；复杂并发日志的
事件边界属于启发式归并。Windows 旧采集端造成的乱码无法恢复，上限截断标记也可能不准确，
报告会提示核查源日志。这一版不改变采集协议。

Windows 第二期增量指标包括网络质量、终端防护、高权限组、系统审计、锁页与大页配置和 Windows Failover Cluster。旧包缺少增量文件显示 INFO，已登记的执行失败或部分采集显示 UNKNOWN；已过滤且不影响SQL结果的环境提示保持 INFO。部分失败仍保留已观测到的风险，同时由采集完整性降低数据可信度。规则与适用边界见 [Windows 第二期说明](../doc/WINDOWS-PHASE2.md)。

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

独立的 Oracle 配置 ACL 巡检项已移除；旧采集包中的 `oracle_config_acl.txt` 及对应执行清单记录不再参与报告或采集完整性判定。

## RAC Data Guard 应用检查

物理备库按集群应用进程判定，并展示实际应用主机及实例。Linux/Windows 采集器保留本地进程，同时新增带 INST_ID 和采集时间的集群进程、指标及当前实例上下文；11g/12.1 使用 GV$MANAGED_STANDBY，新版按能力选择 GV$DATAGUARD_PROCESS。集群进程查询通过左连接记录无进程的实例，并用完成标记及实例覆盖检查区分空结果与采集失败。

本实例没有 MRP 而其他实例应用正常时不告警；集群确认无应用进程才报告集群应用停止。旧 RAC 包仅有本地数据时，READ ONLY WITH APPLY 显示信息及待确认说明，其余证据不足显示未知；不跨时间拼接其他采集包推断正常。应用延迟优先读取实际应用实例，结合采集时间、TIME_COMPUTED 和 DATUM_TIME 检查新鲜度，保留延迟超限、Gap 和应用错误告警。

## PDB 打开模式与数据库角色

PDB 检查复用 dataguard_identity.txt 或旧包 database_status.txt 中的数据库角色，不需要重新采集即可修正已有物理备库报告。PHYSICAL STANDBY 的 READ ONLY 正常，READ WRITE 等不符模式提示警告并要求核对角色/采集一致性；不要求 PDB 显示 CDB 层面的 READ ONLY WITH APPLY。PRIMARY、SNAPSHOT STANDBY、LOGICAL STANDBY 的 READ WRITE 正常，其 READ ONLY 显示信息并按业务用途确认。PDB$SEED 保留独立规则，MOUNTED 保持原先接受策略。角色缺失或两份角色数据冲突时不默认按主库判断，显示未知。HTML、Word、评分和汇总均使用同一判定结果。

## HTML 导航一致性

左侧菜单、巡检目录和正文共用同一稳定排序：概览项优先，其后按数据异常、严重、警告、正常、信息排列，系统日志保持末尾；同等级保持采集原始顺序。待处理面板仍按严重度排列，其链接使用相同的唯一锚点映射。同名及符号归一化后同名的项目分别生成唯一锚点。无待处理事项时显示明确的空状态。滚动高亮按正文位置更新，支持中文锚点、浏览器前进/后退以及目录和待处理链接；菜单自动跟随只滚动侧栏。汇总报告复用相同的导航行为。
