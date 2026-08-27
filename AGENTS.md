# Repository instructions

- 每次完成代码修改后，都必须运行相关测试并重新构建 `reporter/dist/OracleReport.exe`。
- Windows EXE 必须通过 `reporter/tools/build_windows.ps1` 构建，并同步更新 `reporter/dist/OracleReport.exe.sha256`。
- 交付前必须确认 EXE 的修改时间晚于本次源码修改，并使用实际采集包验证受影响的报告逻辑。
