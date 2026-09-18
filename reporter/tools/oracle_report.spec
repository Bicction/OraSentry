# -*- mode: python ; coding: utf-8 -*-
"""Build portable and fast-start releases from the same dependency analysis."""
import os
import platform
import struct
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

tools_dir = Path(SPECPATH)
project = tools_dir.parent
sys.path.insert(0, str(tools_dir))
from startup_assets import AnimatedSplash, prepare_assets

assets = prepare_assets(project, Path(workpath) / "startup-assets")
use_upx = os.environ.get("ORASENTRY_BUILD_UPX", "0") == "1"
debug_bootloader = os.environ.get("ORASENTRY_DEBUG_BOOTLOADER", "0") == "1"
machine = os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine()).lower()
if machine in ("arm64", "aarch64"):
    dnd_platform = "win-arm64"
else:
    dnd_platform = "win-x64" if struct.calcsize("P") == 8 else "win-x86"
dnd_datas = collect_data_files("tkinterdnd2", includes=["tkdnd/" + dnd_platform + "/*"])
if not dnd_datas:
    raise RuntimeError("Missing tkinterdnd2 resources for " + dnd_platform)

a = Analysis(
    [str(project / "src" / "launcher.py")],
    pathex=[str(project / "src")],
    binaries=[],
    datas=[
        (str(project / "resources/templates/html_template.html"), "resources/templates"),
        (str(assets / "catalog.json.gz"), "resources/ora"),
    ] + dnd_datas,
    hiddenimports=["parser.host_parser", "parser.db_parser", "parser.security_parser"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
# Hooks may collect additional platform files. Filter both final TOCs.
def required_dnd(entry):
    parts = entry[0].replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[:2] == ["tkinterdnd2", "tkdnd"]:
        return parts[2] == dnd_platform
    return True

a.binaries = [entry for entry in a.binaries if required_dnd(entry)]
a.datas = [entry for entry in a.datas if required_dnd(entry)]
pyz = PYZ(a.pure)
splash = AnimatedSplash(
    str(assets / "splash.png"), binaries=a.binaries, datas=a.datas,
    text_pos=(68, 235), text_size=11, text_color="#b8cbe0",
    text_font="{Microsoft YaHei UI}", text_default="正在启动…",
    always_on_top=False, center="active", minify_script=False,
)
common = dict(
    name="OracleReport", debug=debug_bootloader, bootloader_ignore_signals=False,
    strip=False, upx=use_upx, console=debug_bootloader,
    disable_windowed_traceback=False, version=str(tools_dir / "version_info.txt"),
)
portable = EXE(pyz, a.scripts, splash, splash.binaries, a.binaries, a.datas, [], **common)
# Onedir uses only the application Tk interpreter, avoiding splash focus issues.
folder_exe = EXE(pyz, a.scripts, [], exclude_binaries=True, **common)
folder = COLLECT(folder_exe, a.binaries, a.datas, strip=False, upx=use_upx,
                 name="OracleReport-FastStart")
