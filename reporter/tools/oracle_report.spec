# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec：Windows 单文件、无控制台巡检报告生成器。

路径相对于本 spec 所在的 tools/ 目录。
"""
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hidden_imports = (
    collect_submodules("parser")
    + collect_submodules("docx")
    + collect_submodules("tkinterdnd2")
    + ["config", "report_gen", "docx_gen", "inspection_summary", "summary_gen", "lxml.html", "lxml.etree"]
)
dnd_datas = collect_data_files("tkinterdnd2")

a = Analysis(
    ["../gui.py"],
    pathex=[".."],
    binaries=[],
    datas=[("../templates/html_template.html", "templates")] + dnd_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="OracleReport",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version="version_info.txt",
)
