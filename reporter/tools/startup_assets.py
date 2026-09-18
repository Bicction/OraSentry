"""Build-time assets. Pillow and PyInstaller are not application dependencies."""
import gzip
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from PyInstaller.building.splash import Splash


def prepare_assets(project, destination):
    destination.mkdir(parents=True, exist_ok=True)
    original = (project / "resources/ora/catalog.json").read_bytes()
    (destination / "catalog.json.gz").write_bytes(gzip.compress(original, compresslevel=9, mtime=0))
    scale = 2
    canvas = Image.new("RGB", (560 * scale, 300 * scale), "#102a43")
    draw = ImageDraw.Draw(canvas)
    font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"

    def font(size, bold=False, chinese=False):
        name = ("msyhbd.ttc" if bold else "msyh.ttc") if chinese else ("segoeuib.ttf" if bold else "segoeui.ttf")
        return ImageFont.truetype(str(font_dir / name), size * scale)

    def label(x, y, text, size, color, bold=False, chinese=False):
        draw.text((x * scale, y * scale), text, font=font(size, bold, chinese), fill=color)

    draw.rectangle((0, 0, 560 * scale - 1, 300 * scale - 1), outline="#30516d", width=2)
    draw.rectangle((0, 0, 560 * scale, 4 * scale), fill="#3b82f6")
    draw.rounded_rectangle((36 * scale, 39 * scale, 92 * scale, 95 * scale), radius=12 * scale, fill="#2563eb")
    label(49, 48, "OI", 26, "white", bold=True)
    label(111, 34, "OraSentry", 32, "#ffffff", bold=True)
    label(114, 80, "ORACLE INSPECTION", 10, "#93b9da")
    label(36, 125, "让每一次巡检，都清晰可见", 20, "#f1f5f9", bold=True, chinese=True)
    label(36, 164, "离线分析 · HTML / Word 报告", 12, "#93b9da", chinese=True)
    draw.line((36 * scale, 202 * scale, 524 * scale, 202 * scale), fill="#30516d", width=scale)
    label(36, 265, "Oracle 自动化巡检", 10, "#789bb8", chinese=True)
    label(455, 265, "VERSION 4.4", 9, "#789bb8")
    canvas.resize((560, 300), Image.Resampling.LANCZOS).save(destination / "splash.png")
    return destination


class AnimatedSplash(Splash):
    """Pinned-version extension: animation runs in the bootloader Tcl loop."""

    def generate_script(self):
        script = super().generate_script()
        script += r'''
proc canvas_text_update {canvas tag _var - -} {
    upvar $_var value
    if {[string match "正在*" $value]} {
        $canvas itemconfigure $tag -text $value
    } else {
        $canvas itemconfigure $tag -text "正在准备运行环境…"
    }
}
wm title . "OraSentry 正在启动"
.root.canvas create oval 37 218 53 234 -outline "#30516d" -width 2
.root.canvas create arc 37 218 53 234 -style arc -outline "#60a5fa" -width 3 -extent 100 -tags spinner
set orasentry_angle 0
proc orasentry_tick {} {
    global orasentry_angle
    set orasentry_angle [expr {($orasentry_angle - 24) % 360}]
    .root.canvas itemconfigure spinner -start $orasentry_angle
    after 70 orasentry_tick
}
orasentry_tick
set status_text "正在准备运行环境…"
proc orasentry_splash_ready {} {
    if {![winfo ismapped .]} {
        after 10 orasentry_splash_ready
        return
    }
    if {[info exists ::env(ORASENTRY_STARTUP_TRACE)]} {
        catch {
            set stream [open $::env(ORASENTRY_STARTUP_TRACE) a]
            puts $stream [format {{"stage":"splash_shown","timestamp_ms":%s}} [clock milliseconds]]
            close $stream
        }
    }
}
after idle orasentry_splash_ready
'''
        # PyInstaller 6.22.2 SplashWriter records len(str) but writes UTF-8 bytes.
        # Escape our quoted Chinese strings for Tcl so byte/character lengths match.
        script = "".join(char if ord(char) < 128 else "\\u%04x" % ord(char) for char in script)
        Path(self.script_name).write_text(script, encoding="utf-8")
        return script
