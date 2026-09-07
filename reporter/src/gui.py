#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle 巡检报告生成器 - Windows 企业级图形界面。"""
import datetime
import os
import sys
import threading
import traceback
import webbrowser
from pathlib import Path

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    sys.path.insert(0, sys._MEIPASS)
else:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import COPY, DND_FILES, TkinterDnD
except ImportError:  # 源码环境未安装拖放扩展时仍可使用文件选择器。
    COPY = "copy"
    DND_FILES = None
    TkinterDnD = None

from config import REPORT_CONFIG
from scoring import calculate_score_breakdown, score_band


COLORS = {
    "bg": "#eef2f7",
    "surface": "#ffffff",
    "surface_alt": "#f8fafc",
    "navy": "#102a43",
    "navy_light": "#1b4168",
    "border": "#d8e1eb",
    "text": "#172b4d",
    "muted": "#64748b",
    "primary": "#2563eb",
    "primary_hover": "#1d4ed8",
    "primary_soft": "#eff6ff",
    "success": "#059669",
    "warning": "#d97706",
    "danger": "#dc2626",
    "log_bg": "#0f1f33",
    "log_text": "#cbd5e1",
}


def _enable_windows_dpi():
    if sys.platform != "win32":
        return
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            from ctypes import windll
            windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _open_path(path):
    if not path:
        return
    if sys.platform == "win32":
        os.startfile(path)
    else:
        webbrowser.open("file:///" + os.path.abspath(path).replace("\\", "/"))


def add_unique_paths(existing, new_paths):
    """标准化并去重输入路径，返回 (新列表, 新增数量)。"""
    result = list(existing)
    known = {os.path.normcase(os.path.normpath(path)) for path in result}
    added = 0
    for path in new_paths:
        normalized = os.path.normpath(path)
        key = os.path.normcase(normalized)
        if normalized and key not in known:
            result.append(normalized)
            known.add(key)
            added += 1
    return result, added


def filter_dropped_paths(paths):
    """筛选拖入的采集包或目录，返回 (可接收路径, 被拒绝路径)。"""
    accepted = []
    rejected = []
    for raw_path in paths:
        path = os.path.normpath(str(raw_path).strip())
        lower = path.lower()
        supported_archive = lower.endswith(".tar.gz") or lower.endswith(".tgz")
        if path and (os.path.isdir(path) or (os.path.isfile(path) and supported_archive)):
            accepted.append(path)
        elif path:
            rejected.append(path)
    return accepted, rejected


def expand_input_paths(paths):
    """Lightweight input discovery; keep report parsers unloaded at GUI startup."""
    expanded = []
    for path in paths:
        if not path:
            continue
        normalized = os.path.normpath(path)
        if os.path.isdir(normalized) and not os.path.isfile(os.path.join(normalized, "env.info")):
            try:
                names = sorted(os.listdir(normalized))
            except OSError:
                expanded.append(normalized)
                continue
            archives = []
            raw_subdirs = []
            for name in names:
                full = os.path.join(normalized, name)
                lower = name.lower()
                if os.path.isfile(full) and (lower.endswith(".tar.gz") or lower.endswith(".tgz")):
                    archives.append(full)
                elif os.path.isdir(full) and os.path.isfile(os.path.join(full, "env.info")):
                    raw_subdirs.append(full)
            if archives:
                expanded.extend(archives)
                continue
            if len(raw_subdirs) > 1:
                expanded.extend(raw_subdirs)
                continue
        expanded.append(normalized)
    return expanded


def classify_input(path):
    return "数据目录" if os.path.isdir(path) else "采集包"


def normalize_output_selection(path):
    """输出位置只保留文件夹；若误选了报告文件名，则取其父目录。"""
    if not path:
        return ""
    output = Path(path)
    if output.suffix.lower() in {".html", ".htm", ".docx"}:
        output = output.parent
    text = str(output)
    if text in ("", "."):
        return ""
    return os.path.normpath(text)


def score_tone(score, has_score=True):
    return {
        "OK": "success", "WARN": "warning", "CRIT": "danger", "UNKNOWN": "muted",
    }[score_band(score, has_score)]


def result_tone(counts, confidence="完整"):
    """界面颜色表达风险状态，而不是把健康分误当成最高风险。"""
    if counts.get("CRIT"):
        return "danger"
    if counts.get("WARN"):
        return "warning"
    if confidence != "完整":
        return "muted"
    return "success"


# 1080p 上够放下全部功能按钮；小屏由 choose_window_geometry 再收缩。
PREFERRED_WINDOW = (1180, 820)
MIN_WINDOW = (980, 700)


def choose_window_geometry(need_w, need_h, screen_w, screen_h,
                           preferred=PREFERRED_WINDOW, minimum=MIN_WINDOW):
    """按控件需求与屏幕工作区选择默认窗口位置和大小。"""
    pref_w, pref_h = preferred
    min_w, min_h = minimum
    # 预留标题栏、任务栏和边距，避免窗口超出可见区域。
    max_w = max(640, int(screen_w) - 48)
    max_h = max(520, int(screen_h) - 88)
    width = min(max(int(need_w), pref_w, min_w), max_w)
    height = min(max(int(need_h), pref_h, min_h), max_h)
    x = max(0, (int(screen_w) - width) // 2)
    y = max(0, (int(screen_h) - height) // 5)
    return width, height, x, y


class CheckMarkBox(tk.Frame):
    """方框 + 对勾的勾选控件，避免 ttk 选中后显示成 X。"""

    def __init__(self, parent, text, variable, **kwargs):
        surface = parent.cget("bg")
        super().__init__(parent, bg=surface, **kwargs)
        self.variable = variable
        self.surface = surface
        self._enabled = True
        self.box = tk.Label(
            self, text="", width=2, relief=tk.SOLID, bd=1,
            bg="#ffffff", fg=COLORS["success"],
            font=("Segoe UI", 11, "bold"), cursor="hand2",
        )
        self.box.pack(side=tk.LEFT)
        self.caption = tk.Label(
            self, text=text, bg=surface, fg=COLORS["text"],
            font=("Segoe UI", 9), cursor="hand2",
        )
        self.caption.pack(side=tk.LEFT, padx=(7, 0))
        for widget in (self, self.box, self.caption):
            widget.bind("<Button-1>", self._on_click)
        self.variable.trace_add("write", lambda *_args: self._refresh())
        self._refresh()

    def _on_click(self, _event=None):
        if self._enabled:
            self.variable.set(not bool(self.variable.get()))

    def _refresh(self):
        if self.variable.get():
            self.box.configure(text="✓", bg="#ecfdf5", fg=COLORS["success"])
        else:
            self.box.configure(text="", bg="#ffffff", fg=COLORS["muted"])

    def configure(self, cnf=None, **kwargs):
        kwargs = dict(cnf or {}, **kwargs)
        if "state" in kwargs:
            state = kwargs.pop("state")
            self._enabled = str(state) != str(tk.DISABLED)
            cursor = "arrow" if not self._enabled else "hand2"
            dim = COLORS["muted"] if not self._enabled else COLORS["text"]
            self.box.configure(cursor=cursor)
            self.caption.configure(cursor=cursor, fg=dim)
        if kwargs:
            super().configure(**kwargs)

    config = configure


class ReportApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OraSentry Oracle自动化巡检 v4.4")
        self.root.configure(bg=COLORS["bg"])

        self.input_paths = []
        self.last_html = None
        self.last_docx = None
        self.last_summary_html = None
        self.last_summary_docx = None
        self.last_output_dir = None
        self.busy = False
        self.cancel_event = threading.Event()
        self._spinner_job = None
        self._spinner_index = 0
        self._input_controls = []

        self._build_style()
        self._build_ui()
        self._setup_drag_and_drop()
        self._bind_shortcuts()
        self._fit_window()
        self._log("请选择主机巡检包和/或数据库巡检包，可一次添加多个压缩包。")
        self._log("host_check 与 db_check 始终分别生成主机报告和 Oracle 报告，不会混合巡检项。")

    def _build_style(self):
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.root.option_add("*Font", ("Segoe UI", 10))
        style.configure(
            "TEntry", padding=(9, 7), relief="flat",
            fieldbackground="#ffffff", foreground=COLORS["text"],
            bordercolor=COLORS["border"], lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
        )
        style.map(
            "TEntry",
            bordercolor=[("focus", COLORS["primary"])],
            lightcolor=[("focus", COLORS["primary"])],
            darkcolor=[("focus", COLORS["primary"])],
        )
        style.configure(
            "Treeview", rowheight=31, font=("Segoe UI", 9),
            background=COLORS["surface"], fieldbackground=COLORS["surface"],
            foreground=COLORS["text"], bordercolor=COLORS["border"], relief="flat",
        )
        style.configure(
            "Treeview.Heading", font=("Segoe UI", 9, "bold"),
            background="#f1f5f9", foreground="#334155", relief="flat",
            padding=(8, 7),
        )
        style.map("Treeview", background=[("selected", COLORS["primary_soft"])],
                  foreground=[("selected", COLORS["text"])])
        style.configure(
            "Primary.TButton", font=("Segoe UI", 10, "bold"),
            padding=(18, 11), background=COLORS["primary"], foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", COLORS["primary_hover"]), ("disabled", "#9fb3cc")],
            foreground=[("disabled", "#edf2f7")],
        )
        style.configure(
            "Secondary.TButton", font=("Segoe UI", 9),
            padding=(11, 8), background="#f1f5f9", foreground=COLORS["text"],
            bordercolor=COLORS["border"],
        )
        style.map("Secondary.TButton", background=[("active", "#e2e8f0")])
        style.configure(
            "Danger.TButton", font=("Segoe UI", 9),
            padding=(10, 8), background="#fff1f2", foreground=COLORS["danger"],
            bordercolor="#fecdd3",
        )
        style.map("Danger.TButton", background=[("active", "#ffe4e6")])
        style.configure(
            "Stop.TButton", font=("Segoe UI", 9, "bold"),
            padding=(12, 7), background=COLORS["danger"], foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Stop.TButton",
            background=[("active", "#b91c1c"), ("disabled", "#cbd5e1")],
            foreground=[("disabled", "#f8fafc")],
        )
        style.configure(
            "Report.Horizontal.TProgressbar",
            troughcolor="#dbeafe", background=COLORS["primary"], thickness=6,
        )

    def _card(self, parent, row, step, title, subtitle=None, weight=0):
        parent.grid_rowconfigure(row, weight=weight)
        card = tk.Frame(
            parent, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1, bd=0,
        )
        card.grid(row=row, column=0, sticky="nsew", pady=(0, 10))
        card.grid_columnconfigure(1, weight=1)
        badge = tk.Label(
            card, text=str(step), bg=COLORS["primary"], fg="#ffffff",
            font=("Segoe UI", 10, "bold"), width=2, height=1,
        )
        badge.grid(row=0, column=0, padx=(15, 10), pady=(12, 9), sticky="nw")
        header = tk.Frame(card, bg=COLORS["surface"])
        header.grid(row=0, column=1, padx=(0, 15), pady=(10, 8), sticky="ew")
        tk.Label(
            header, text=title, bg=COLORS["surface"], fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        if subtitle:
            tk.Label(
                header, text=subtitle, bg=COLORS["surface"], fg=COLORS["muted"],
                font=("Segoe UI", 8),
            ).pack(anchor="w", pady=(2, 0))
        body = tk.Frame(card, bg=COLORS["surface"])
        body.grid(row=1, column=0, columnspan=2, padx=15, pady=(0, 13), sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        return body

    def _build_ui(self):
        container = tk.Frame(self.root, bg=COLORS["bg"])
        container.pack(fill=tk.BOTH, expand=True, padx=18, pady=16)
        self._container = container
        container.grid_columnconfigure(0, weight=3)
        container.grid_columnconfigure(1, weight=2)
        container.grid_rowconfigure(1, weight=5)
        container.grid_rowconfigure(2, weight=2)

        # 深色品牌栏强化应用身份，并把版本和运行状态放到视线右上角。
        header = tk.Frame(container, bg=COLORS["navy"], bd=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        header.grid_columnconfigure(1, weight=1)
        mark = tk.Label(
            header, text="OI", bg=COLORS["primary"], fg="#ffffff",
            font=("Segoe UI", 14, "bold"), width=3, height=2,
        )
        mark.grid(row=0, column=0, rowspan=2, padx=(16, 12), pady=13)
        tk.Label(
            header, text="OraSentry 自动化巡检",
            bg=COLORS["navy"], fg="#ffffff",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=1, sticky="sw", pady=(12, 0))
        tk.Label(
            header, text="导入采集数据，生成HTML和Word报告",
            bg=COLORS["navy"], fg="#b8cbe0", font=("Segoe UI", 9),
        ).grid(row=1, column=1, sticky="nw", pady=(2, 12))
        version = tk.Label(
            header, text="VERSION 4.4", bg=COLORS["navy_light"], fg="#dbeafe",
            font=("Segoe UI", 8, "bold"), padx=12, pady=6,
        )
        version.grid(row=0, column=2, rowspan=2, padx=16)

        # 左侧：数据源工作区。
        source = tk.Frame(
            container, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        source.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        source.grid_columnconfigure(0, weight=1)
        source.grid_rowconfigure(2, weight=1)
        source_header = tk.Frame(source, bg=COLORS["surface"])
        source_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        tk.Label(
            source_header, text="1", bg=COLORS["primary_soft"], fg=COLORS["primary"],
            font=("Segoe UI", 9, "bold"), width=2, pady=3,
        ).pack(side=tk.LEFT)
        tk.Label(
            source_header, text="选择巡检数据", bg=COLORS["surface"],
            fg=COLORS["text"], font=("Segoe UI", 12, "bold"),
        ).pack(side=tk.LEFT, padx=(9, 0))
        self.input_count_var = tk.StringVar(value="0 项")
        tk.Label(
            source_header, textvariable=self.input_count_var,
            bg="#f1f5f9", fg=COLORS["muted"], font=("Segoe UI", 8, "bold"),
            padx=9, pady=4,
        ).pack(side=tk.RIGHT)

        toolbar = tk.Frame(source, bg=COLORS["surface"])
        toolbar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 9))
        self.add_file_btn = ttk.Button(
            toolbar, text="＋ 添加采集包", style="Primary.TButton", command=self.add_files,
        )
        self.add_dir_btn = ttk.Button(
            toolbar, text="添加数据目录", style="Secondary.TButton", command=self.add_folder,
        )
        self.remove_btn = ttk.Button(
            toolbar, text="移除选中", style="Secondary.TButton", command=self.remove_selected,
        )
        self.clear_btn = ttk.Button(
            toolbar, text="清空", style="Danger.TButton", command=self.clear_inputs,
        )
        self.add_file_btn.pack(side=tk.LEFT, padx=(0, 7))
        self.add_dir_btn.pack(side=tk.LEFT, padx=(0, 7))
        self.remove_btn.pack(side=tk.LEFT, padx=(0, 7))
        self.clear_btn.pack(side=tk.LEFT)

        tree_wrap = tk.Frame(source, bg=COLORS["surface"])
        tree_wrap.grid(row=2, column=0, sticky="nsew", padx=16)
        tree_wrap.grid_rowconfigure(0, weight=1)
        tree_wrap.grid_columnconfigure(0, weight=1)
        self.input_tree = ttk.Treeview(
            tree_wrap, columns=("type", "name", "path"), show="headings",
            selectmode="extended", height=9,
        )
        self.input_tree.heading("type", text="类型")
        self.input_tree.heading("name", text="文件或目录")
        self.input_tree.heading("path", text="完整路径")
        self.input_tree.column("type", width=82, minwidth=70, stretch=False)
        self.input_tree.column("name", width=210, minwidth=140)
        self.input_tree.column("path", width=420, minwidth=240)
        tree_scroll = ttk.Scrollbar(tree_wrap, orient=tk.VERTICAL, command=self.input_tree.yview)
        self.input_tree.configure(yscrollcommand=tree_scroll.set)
        self.input_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.drop_hint = tk.Label(
            tree_wrap,
            text="拖放采集包至此处",
            bg="#ffffff", fg=COLORS["primary"],
            font=("Segoe UI", 11, "bold"), justify=tk.CENTER,
            padx=24, pady=16, cursor="hand2",
            highlightbackground="#bfdbfe", highlightthickness=1,
        )
        self.drop_hint.bind("<Button-1>", lambda _event: self.add_files())
        self.drop_hint.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(
            source,
            text="可拖入多个采集包或文件夹；主机报告与 Oracle 报告会自动分开生成。按 Delete 可移除选中项。",
            bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 8),
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(9, 13))

        # 右侧：项目、输出与生成结果，按操作顺序自上而下排列。
        right = tk.Frame(container, bg=COLORS["bg"])
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)

        settings = tk.Frame(
            right, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        settings.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        settings.grid_columnconfigure(0, weight=1)
        settings_head = tk.Frame(settings, bg=COLORS["surface"])
        settings_head.grid(row=0, column=0, sticky="ew", padx=15, pady=(13, 8))
        tk.Label(
            settings_head, text="2", bg=COLORS["primary_soft"], fg=COLORS["primary"],
            font=("Segoe UI", 9, "bold"), width=2, pady=3,
        ).pack(side=tk.LEFT)
        tk.Label(
            settings_head, text="项目与输出", bg=COLORS["surface"],
            fg=COLORS["text"], font=("Segoe UI", 12, "bold"),
        ).pack(side=tk.LEFT, padx=(9, 0))

        form = tk.Frame(settings, bg=COLORS["surface"])
        form.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 14))
        form.grid_columnconfigure(0, weight=1)
        tk.Label(
            form, text="项目名称", bg=COLORS["surface"], fg="#334155",
            font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=0, sticky="w")
        self.project_name_var = tk.StringVar(value=REPORT_CONFIG["project_name"])
        self.project_name_entry = ttk.Entry(
            form, textvariable=self.project_name_var, font=("Segoe UI", 9)
        )
        self.project_name_entry.grid(row=1, column=0, sticky="ew", pady=(5, 3))
        tk.Label(
            form, text="显示在巡检报告封面；留空时使用默认名称。",
            bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 8),
        ).grid(row=2, column=0, sticky="w")
        tk.Label(
            form, text="输出文件夹", bg=COLORS["surface"], fg="#334155",
            font=("Segoe UI", 9, "bold"),
        ).grid(row=3, column=0, sticky="w", pady=(10, 0))
        output_row = tk.Frame(form, bg=COLORS["surface"])
        output_row.grid(row=4, column=0, sticky="ew", pady=(5, 0))
        output_row.grid_columnconfigure(0, weight=1)
        self.output_var = tk.StringVar()
        self.output_entry = ttk.Entry(output_row, textvariable=self.output_var, font=("Segoe UI", 9))
        self.output_entry.grid(row=0, column=0, sticky="ew")
        self.browse_btn = ttk.Button(
            output_row, text="浏览…", style="Secondary.TButton", command=self.browse_output,
        )
        self.browse_btn.grid(row=0, column=1, padx=(7, 0))

        formats = tk.Frame(form, bg=COLORS["surface"])
        formats.grid(row=5, column=0, sticky="w", pady=(11, 0))
        self.write_html_var = tk.BooleanVar(value=True)
        self.write_docx_var = tk.BooleanVar(value=True)
        self.write_summary_var = tk.BooleanVar(value=True)
        self.generate_summary_var = tk.BooleanVar(value=False)
        self.html_check = CheckMarkBox(formats, "HTML", self.write_html_var)
        self.docx_check = CheckMarkBox(formats, "Word", self.write_docx_var)
        self.summary_check = CheckMarkBox(formats, "汇总摘要", self.write_summary_var)
        self.generate_summary_check = CheckMarkBox(
            formats, "生成总结", self.generate_summary_var
        )
        self.html_check.pack(side=tk.LEFT)
        self.docx_check.pack(side=tk.LEFT, padx=(16, 0))
        self.summary_check.pack(side=tk.LEFT, padx=(16, 0))
        self.generate_summary_check.pack(side=tk.LEFT, padx=(16, 0))

        action = tk.Frame(
            right, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        action.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        action.grid_columnconfigure(0, weight=1)
        tk.Label(
            action, text="3  生成报告", bg=COLORS["surface"], fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=15, pady=(12, 8))
        self.generate_btn = ttk.Button(
            action, text="生成巡检报告  →", style="Primary.TButton", command=self.generate,
        )
        self.generate_btn.grid(row=1, column=0, sticky="ew", padx=15)
        activity = tk.Frame(action, bg=COLORS["surface"])
        activity.grid(row=2, column=0, sticky="ew", padx=15, pady=(8, 5))
        activity.grid_columnconfigure(1, weight=1)
        self.activity_icon = tk.Label(
            activity, text="○", bg=COLORS["surface"], fg=COLORS["muted"],
            font=("Segoe UI Symbol", 14, "bold"), width=2,
        )
        self.activity_icon.grid(row=0, column=0, sticky="w")
        self.activity_var = tk.StringVar(value="等待生成")
        tk.Label(
            activity, textvariable=self.activity_var, bg=COLORS["surface"],
            fg=COLORS["muted"], font=("Segoe UI", 8), anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(3, 8))
        self.stop_btn = ttk.Button(
            activity, text="停止生成", style="Stop.TButton",
            command=self.stop_generation, state=tk.DISABLED,
        )
        self.stop_btn.grid(row=0, column=2, sticky="e")
        tk.Label(
            action, text="快捷键：F5 或 Ctrl+G", bg=COLORS["surface"],
            fg=COLORS["muted"], font=("Segoe UI", 8),
        ).grid(row=3, column=0, sticky="e", padx=15, pady=(0, 10))

        result = tk.Frame(
            right, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        result.grid(row=2, column=0, sticky="nsew")
        result.grid_columnconfigure(0, weight=1)
        tk.Label(
            result, text="最近一次生成", bg=COLORS["surface"], fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=15, pady=(12, 7))
        self.summary_frame = tk.Frame(result, bg=COLORS["primary_soft"])
        self.summary_frame.grid(row=1, column=0, sticky="ew", padx=15)
        self.summary_frame.grid_columnconfigure(1, weight=1)
        self.score_var = tk.StringVar(value="—")
        self.counts_var = tk.StringVar(value="尚未生成报告")
        self.env_var = tk.StringVar(value="主机 —    数据库 —")
        self.result_path_var = tk.StringVar(value="生成完成后将在此显示文件")
        self.score_label = tk.Label(
            self.summary_frame, textvariable=self.score_var, bg=COLORS["primary_soft"],
            fg=COLORS["primary"], font=("Segoe UI", 20, "bold"), width=7,
        )
        self.score_label.grid(row=0, column=0, rowspan=3, padx=(8, 10), pady=8)
        tk.Label(
            self.summary_frame, textvariable=self.counts_var, bg=COLORS["primary_soft"],
            fg=COLORS["text"], font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=1, sticky="w", pady=(8, 1))
        tk.Label(
            self.summary_frame, textvariable=self.env_var, bg=COLORS["primary_soft"],
            fg=COLORS["muted"], font=("Segoe UI", 8),
        ).grid(row=1, column=1, sticky="w")
        tk.Label(
            self.summary_frame, textvariable=self.result_path_var, bg=COLORS["primary_soft"],
            fg=COLORS["muted"], font=("Segoe UI", 8), anchor="w", wraplength=300,
        ).grid(row=2, column=1, sticky="ew", pady=(1, 8), padx=(0, 8))

        controls = tk.Frame(result, bg=COLORS["surface"])
        controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(9, 13))
        for column in range(3):
            controls.grid_columnconfigure(column, weight=1, uniform="openbtns")
        self.open_report_btn = ttk.Button(
            controls, text="打开 HTML", style="Secondary.TButton",
            command=self.open_report, state=tk.DISABLED,
        )
        self.open_word_btn = ttk.Button(
            controls, text="打开 Word", style="Secondary.TButton",
            command=self.open_word, state=tk.DISABLED,
        )
        self.open_folder_btn = ttk.Button(
            controls, text="打开文件夹", style="Secondary.TButton",
            command=self.open_folder, state=tk.DISABLED,
        )
        self.open_summary_html_btn = ttk.Button(
            controls, text="汇总 HTML", style="Secondary.TButton",
            command=self.open_summary_html, state=tk.DISABLED,
        )
        self.open_summary_word_btn = ttk.Button(
            controls, text="汇总 Word", style="Secondary.TButton",
            command=self.open_summary_word, state=tk.DISABLED,
        )
        self.open_report_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.open_word_btn.grid(row=0, column=1, sticky="ew", padx=5)
        self.open_folder_btn.grid(row=0, column=2, sticky="ew", padx=(5, 0))
        self.open_summary_html_btn.grid(row=1, column=0, sticky="ew", padx=(0, 5), pady=(6, 0))
        self.open_summary_word_btn.grid(row=1, column=1, sticky="ew", padx=5, pady=(6, 0))
        self._action_controls = controls

        # 底部日志保留完整诊断能力，但降低其默认视觉权重。
        log_card = tk.Frame(
            container, bg=COLORS["surface"], highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        log_card.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(10, 8))
        log_card.grid_rowconfigure(1, weight=1)
        log_card.grid_columnconfigure(0, weight=1)
        log_header = tk.Frame(log_card, bg=COLORS["surface"])
        log_header.grid(row=0, column=0, sticky="ew", padx=13, pady=(8, 5))
        tk.Label(
            log_header, text="运行日志", bg=COLORS["surface"],
            fg=COLORS["text"], font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            log_header, text="生成过程与错误详情", bg=COLORS["surface"],
            fg=COLORS["muted"], font=("Segoe UI", 8),
        ).pack(side=tk.LEFT, padx=(9, 0))
        ttk.Button(
            log_header, text="清空", style="Secondary.TButton", command=self.clear_log,
        ).pack(side=tk.RIGHT)
        log_wrap = tk.Frame(log_card, bg=COLORS["surface"])
        log_wrap.grid(row=1, column=0, sticky="nsew", padx=13, pady=(0, 10))
        log_wrap.grid_rowconfigure(0, weight=1)
        log_wrap.grid_columnconfigure(0, weight=1)
        self.log = tk.Text(
            log_wrap, height=5, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 8), bg=COLORS["log_bg"], fg=COLORS["log_text"],
            insertbackground="#ffffff", relief=tk.FLAT, padx=10, pady=8,
        )
        log_scroll = ttk.Scrollbar(log_wrap, orient=tk.VERTICAL, command=self.log.yview)
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log.tag_configure("info", foreground=COLORS["log_text"])
        self.log.tag_configure("ok", foreground="#6ee7b7")
        self.log.tag_configure("warn", foreground="#fbbf24")
        self.log.tag_configure("error", foreground="#fda4af")

        status_bar = tk.Frame(container, bg=COLORS["bg"])
        status_bar.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.status_dot = tk.Label(
            status_bar, text="●", bg=COLORS["bg"], fg=COLORS["success"],
            font=("Segoe UI", 9),
        )
        self.status_dot.pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(
            status_bar, textvariable=self.status_var, bg=COLORS["bg"],
            fg=COLORS["muted"], font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=(4, 0))
        self.status_detail_var = tk.StringVar(value="已选择 0 项")
        tk.Label(
            status_bar, textvariable=self.status_detail_var, bg=COLORS["bg"],
            fg=COLORS["muted"], font=("Segoe UI", 8),
        ).pack(side=tk.RIGHT)

        self._input_controls = [
            self.input_tree, self.add_file_btn, self.add_dir_btn,
            self.remove_btn, self.clear_btn, self.project_name_entry,
            self.output_entry, self.browse_btn, self.html_check,
            self.docx_check, self.summary_check, self.generate_summary_check,
        ]

    def _bind_shortcuts(self):
        self.root.bind("<Delete>", lambda _event: self.remove_selected())
        self.root.bind("<F5>", lambda _event: self.generate())
        self.root.bind("<Control-g>", lambda _event: self.generate())
        self.root.bind("<Control-G>", lambda _event: self.generate())

    def _setup_drag_and_drop(self):
        """把数据列表注册为系统文件拖放目标。"""
        self.drag_drop_enabled = False
        if DND_FILES is None or not hasattr(self.input_tree, "drop_target_register"):
            self._log("当前运行环境未加载拖放组件，仍可使用“添加采集包”。", "warn")
            return
        try:
            for widget in (self.input_tree, self.drop_hint):
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<DropEnter>>", self._on_drop_enter)
                widget.dnd_bind("<<DropLeave>>", self._on_drop_leave)
                widget.dnd_bind("<<Drop>>", self._on_drop)
            self.drag_drop_enabled = True
        except (tk.TclError, RuntimeError) as exc:
            self._log(f"拖放组件初始化失败，仍可使用文件选择器：{exc}", "warn")

    def _show_drop_hint(self, active=False):
        if active:
            self.drop_hint.configure(
                text="松开鼠标即可添加",
                bg=COLORS["primary_soft"], fg=COLORS["primary_hover"],
                highlightbackground=COLORS["primary"],
            )
            self.drop_hint.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        elif self.input_paths:
            self.drop_hint.place_forget()
        else:
            self.drop_hint.configure(
                text="拖放采集包到这里",
                #bg="#ffffff", fg=COLORS["primary"],
                bg="#ffffff", fg="#95bbda",
                highlightbackground="#bfdbfe",
            )
            self.drop_hint.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def _on_drop_enter(self, _event):
        self._show_drop_hint(active=True)
        return COPY

    def _on_drop_leave(self, _event):
        self._show_drop_hint(active=False)
        return COPY

    def _on_drop(self, event):
        self._show_drop_hint(active=False)
        if self.busy:
            self._log("报告生成期间暂不接受新的拖放文件。", "warn")
            return COPY
        try:
            dropped = list(self.root.tk.splitlist(event.data))
        except (tk.TclError, TypeError):
            dropped = [str(getattr(event, "data", ""))]
        accepted, rejected = filter_dropped_paths(dropped)
        expanded = expand_input_paths(accepted)
        self.input_paths, added = add_unique_paths(self.input_paths, expanded)
        if added:
            self._refresh_input_tree()
            self._log(f"已通过拖放添加 {added} 个采集包或目录。", "ok")
        if rejected:
            self._log(
                "已忽略不支持的拖入项（仅支持 .tar.gz、.tgz 或文件夹）："
                + "；".join(rejected),
                "warn",
            )
        if not added and not rejected:
            self._log("拖入项已存在于列表中。", "info")
        self._show_drop_hint(active=False)
        return COPY

    def _fit_window(self):
        """按控件实际占用和屏幕大小设置默认窗口，避免每次手动拉伸。"""
        self.root.update_idletasks()
        extra_w, extra_h = 36, 48
        need_w = self._container.winfo_reqwidth() + extra_w
        need_h = self._container.winfo_reqheight() + extra_h
        if getattr(self, "_action_controls", None) is not None:
            need_w = max(need_w, self._action_controls.winfo_reqwidth() + 80)
        screen_w = max(self.root.winfo_screenwidth(), 800)
        screen_h = max(self.root.winfo_screenheight(), 600)
        width, height, x, y = choose_window_geometry(need_w, need_h, screen_w, screen_h)
        min_w = min(MIN_WINDOW[0], width)
        min_h = min(MIN_WINDOW[1], height)
        self.root.minsize(min_w, min_h)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _refresh_input_tree(self):
        for item in self.input_tree.get_children():
            self.input_tree.delete(item)
        for index, path in enumerate(self.input_paths):
            self.input_tree.insert(
                "", tk.END, iid=str(index),
                values=(classify_input(path), os.path.basename(path) or path, path),
            )
        text = f"已选择 {len(self.input_paths)} 项"
        self.input_count_var.set(text)
        self.status_detail_var.set(text)
        self._show_drop_hint(active=False)

    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="选择巡检采集包",
            filetypes=[("采集包", "*.gz;*.tgz"), ("所有文件", "*.*")],
        )
        self.input_paths, added = add_unique_paths(self.input_paths, paths)
        if added:
            self._refresh_input_tree()
            self._log(f"已添加 {added} 个采集包。", "ok")

    def add_folder(self):
        path = filedialog.askdirectory(title="选择采集数据目录或压缩包所在文件夹")
        if not path:
            return
        expanded = expand_input_paths([path])
        self.input_paths, added = add_unique_paths(self.input_paths, expanded)
        if added:
            self._refresh_input_tree()
            if len(expanded) > 1:
                self._log(f"已从文件夹展开并添加 {added} 个采集包：{path}", "ok")
            else:
                self._log(f"已添加数据目录：{path}", "ok")

    def remove_selected(self):
        selected = sorted(
            (int(item) for item in self.input_tree.selection()), reverse=True
        )
        for index in selected:
            if 0 <= index < len(self.input_paths):
                del self.input_paths[index]
        if selected:
            self._refresh_input_tree()
            self._log(f"已移除 {len(selected)} 项。", "info")

    def clear_inputs(self):
        if self.input_paths:
            self.input_paths.clear()
            self._refresh_input_tree()
            self._log("已清空巡检数据列表。", "info")

    def browse_output(self):
        initial = self.output_var.get().strip()
        if initial and os.path.isdir(initial):
            initialdir = initial
        elif initial:
            initialdir = os.path.dirname(initial)
        elif self.input_paths:
            first = self.input_paths[0]
            initialdir = first if os.path.isdir(first) else os.path.dirname(first)
        else:
            initialdir = ""
        path = filedialog.askdirectory(
            title="选择报告输出文件夹",
            initialdir=initialdir or None,
        )
        if path:
            self.output_var.set(normalize_output_selection(path))

    def _log(self, message, level="info"):
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, f"[{stamp}] {message}\n", level)
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def clear_log(self):
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)

    def _set_status(self, text, tone="success", detail=None):
        self.status_var.set(text)
        self.status_dot.configure(fg=COLORS.get(tone, COLORS["muted"]))
        if detail is not None:
            self.status_detail_var.set(detail)

    def _set_busy(self, busy):
        self.busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for control in self._input_controls:
            if isinstance(control, ttk.Treeview):
                control.state(["disabled"] if busy else ["!disabled"])
                continue
            try:
                control.configure(state=state)
            except tk.TclError:
                pass
        self.generate_btn.configure(state=state)
        if busy:
            self.stop_btn.configure(state=tk.NORMAL)
            self.activity_var.set("正在解析巡检数据")
            self._spinner_index = 0
            self._animate_spinner()
            self.root.configure(cursor="")
            self._set_status("正在生成报告…", "primary", "正在解析巡检数据")
        else:
            if self._spinner_job is not None:
                try:
                    self.root.after_cancel(self._spinner_job)
                except tk.TclError:
                    pass
                self._spinner_job = None
            self.stop_btn.configure(state=tk.DISABLED)
            self.activity_icon.configure(text="○", fg=COLORS["muted"])
            self.activity_var.set("等待生成")
            self.root.configure(cursor="")
            self._set_status("就绪", "success")

    def _animate_spinner(self):
        """使用圆形图标表达运行状态，避免传统来回滚动方块。"""
        if not self.busy:
            self._spinner_job = None
            return
        if self.cancel_event.is_set():
            self.activity_icon.configure(text="◎", fg=COLORS["warning"])
        else:
            symbols = ("◐", "◓", "◑", "◒")
            self.activity_icon.configure(
                text=symbols[self._spinner_index % len(symbols)],
                fg=COLORS["primary"],
            )
            self._spinner_index += 1
        self._spinner_job = self.root.after(140, self._animate_spinner)

    def stop_generation(self):
        """请求工作线程在最近的安全检查点停止。"""
        if not self.busy or self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.stop_btn.configure(state=tk.DISABLED)
        self.activity_var.set("正在安全停止，请稍候…")
        self._set_status("正在停止…", "warning", "已完成的报告将保留")
        self._log("已请求停止生成；正在完成当前安全步骤。", "warn")

    def generate(self):
        if self.busy:
            return
        if not self.input_paths:
            messagebox.showwarning("缺少输入", "请先添加至少一个采集包或采集目录。")
            return
        expanded = expand_input_paths(list(self.input_paths))
        if not expanded:
            messagebox.showwarning("缺少输入", "请先添加至少一个采集包或采集目录。")
            return
        missing = [path for path in expanded if not os.path.exists(path)]
        if missing:
            messagebox.showerror("文件不存在", "以下路径不存在:\n" + "\n".join(missing))
            return
        write_html = bool(self.write_html_var.get())
        write_docx = bool(self.write_docx_var.get())
        write_summary = bool(self.write_summary_var.get())
        generate_summary_content = bool(self.generate_summary_var.get())
        project_name = self.project_name_var.get().strip() or REPORT_CONFIG["project_name"]
        self.project_name_var.set(project_name)
        if not write_html and not write_docx:
            messagebox.showwarning("未选择格式", "请至少勾选 HTML 或 Word。")
            return

        output_dir = normalize_output_selection(self.output_var.get().strip()) or None
        if output_dir:
            self.output_var.set(output_dir)
        for button in (
            self.open_report_btn, self.open_word_btn,
            self.open_summary_html_btn, self.open_summary_word_btn,
            self.open_folder_btn,
        ):
            button.configure(state=tk.DISABLED)
        self.last_html = None
        self.last_docx = None
        self.last_summary_html = None
        self.last_summary_docx = None
        self.last_output_dir = None
        self.cancel_event.clear()
        self._set_busy(True)
        self._log("开始生成巡检报告…", "info")
        for path in expanded:
            self._log(f"输入：{path}", "info")
        self._log(
            f"输出文件夹：{output_dir}" if output_dir else "输出文件夹：默认 output/report",
            "info",
        )
        self._log(f"项目名称：{project_name}", "info")
        formats = []
        if write_html:
            formats.append("HTML")
        if write_docx:
            formats.append("Word")
        if write_summary:
            formats.append("汇总摘要")
        if generate_summary_content:
            formats.append("生成总结")
        self._log("将生成：" + "、".join(formats), "info")
        threading.Thread(
            target=self._run_build,
            args=(expanded, output_dir, write_html, write_docx, write_summary,
                  generate_summary_content, project_name),
            daemon=True,
        ).start()

    def _on_progress(self, index, total, label):
        if self.cancel_event.is_set():
            return
        self.activity_var.set(f"正在生成第 {index}/{total} 份")
        self._set_status(f"正在生成 {index}/{total}", "primary", label)
        self._log(f"正在生成第 {index}/{total} 份：{label}", "info")

    def _run_build(self, input_paths, output_dir, write_html, write_docx,
                   write_summary, generate_summary_content, project_name):
        try:
            # Report parsers and the large offline ORA catalog are loaded only
            # after the user starts generation, and on the worker thread.
            from report_gen import ReportBuildError, build_reports
        except Exception:
            detail = traceback.format_exc()
            self.root.after(0, lambda value=detail: self._on_error(value))
            return

        try:
            def progress(index, total, label):
                self.root.after(
                    0,
                    lambda i=index, n=total, text=label: self._on_progress(i, n, text),
                )

            batch = build_reports(
                input_paths, output_dir,
                write_html=write_html, write_docx=write_docx,
                write_summary=write_summary,
                generate_summary_content=generate_summary_content,
                progress=progress,
                project_name=project_name,
                cancel_check=self.cancel_event.is_set,
            )
            if batch.cancelled:
                self.root.after(0, lambda value=batch: self._on_cancelled(value))
            else:
                self.root.after(0, lambda value=batch: self._on_success(value))
        except (ReportBuildError, ValueError) as exc:
            message = str(exc)
            self.root.after(0, lambda value=message: self._on_error(value))
        except Exception:
            detail = traceback.format_exc()
            self.root.after(0, lambda value=detail: self._on_error(value))

    def _on_success(self, batch):
        reports = batch.reports
        last = reports[-1]
        self.last_html = next((item.html for item in reversed(reports) if item.html), None)
        self.last_docx = next((item.docx for item in reversed(reports) if item.docx), None)
        self.last_summary_html = batch.summary_html
        self.last_summary_docx = batch.summary_docx
        result_file = (
            self.last_summary_html or self.last_html
            or self.last_summary_docx or self.last_docx
        )
        self.last_output_dir = os.path.dirname(os.path.abspath(result_file)) if result_file else ""
        if self.last_output_dir:
            self.output_var.set(self.last_output_dir)
        if len(reports) == 1:
            hostname = last.env_info.get("hostname", "N/A")
            sid = last.env_info.get("oracle_sid", "N/A")
            score_breakdown = calculate_score_breakdown(last.results)
            confidence = score_breakdown.confidence
            self.score_var.set(f"{last.health_score}/100")
            self.counts_var.set(
                f"正常 {last.counts['OK']}    警告 {last.counts['WARN']}    "
                f"严重 {last.counts['CRIT']}    信息 {last.counts.get('INFO', 0)}    "
                f"可信度 {confidence}"
            )
            self.env_var.set(f"主机 {hostname}    数据库 {sid}")
            generated = [
                os.path.basename(path)
                for path in (last.html, last.docx)
                if path
            ]
            self.result_path_var.set(
                "、".join(generated) if generated else self.last_output_dir
            )
            self.score_label.configure(
                fg=COLORS[score_tone(last.health_score, score_breakdown.possible > 0)]
            )
        else:
            self.score_var.set(f"{len(reports)}份")
            extra = "，已合并汇总摘要" if (batch.summary_html or batch.summary_docx) else ""
            self.counts_var.set(f"已批量生成 {len(reports)} 份巡检报告{extra}")
            self.env_var.set("按主机/数据库自动分组")
            self.result_path_var.set(self.last_output_dir)
            self.score_label.configure(fg=COLORS["primary"])
        self._set_busy(False)
        self.open_report_btn.configure(
            state=tk.NORMAL if self.last_html else tk.DISABLED
        )
        self.open_word_btn.configure(
            state=tk.NORMAL if self.last_docx else tk.DISABLED
        )
        self.open_summary_html_btn.configure(
            state=tk.NORMAL if self.last_summary_html else tk.DISABLED
        )
        self.open_summary_word_btn.configure(
            state=tk.NORMAL if self.last_summary_docx else tk.DISABLED
        )
        self.open_folder_btn.configure(
            state=tk.NORMAL if self.last_output_dir else tk.DISABLED
        )
        self._set_status(
            "生成完成", "success",
            "完成时间 " + datetime.datetime.now().strftime("%H:%M:%S"),
        )
        for item in reports:
            hostname = item.env_info.get("hostname", "N/A")
            sid = item.env_info.get("oracle_sid", "N/A")
            self._log(
                f"完成：主机 {hostname} / SID {sid}，评分 {item.health_score}/100",
                "ok",
            )
            if item.html:
                self._log(f"HTML 报告：{item.html}", "ok")
            if item.docx:
                self._log(f"Word 报告：{item.docx}", "ok")
        if batch.summary_html:
            self._log(f"汇总摘要 HTML：{batch.summary_html}", "ok")
        if batch.summary_docx:
            self._log(f"汇总摘要 Word：{batch.summary_docx}", "ok")
        elif len(reports) == 1:
            self._log("仅一份巡检报告，未生成汇总摘要。", "info")
        for label, message in batch.errors:
            self._log(f"失败：{label}：{message}", "error")
        lines = [
            f"已生成 {len(reports)} 份巡检报告。",
            f"输出目录：{self.last_output_dir}",
        ]
        if len(reports) == 1:
            lines.append(f"健康评分：{last.health_score}/100")
            if last.html:
                lines.append(f"HTML：{last.html}")
            if last.docx:
                lines.append(f"Word：{last.docx}")
        else:
            lines.append("每套采集包对应一份 HTML/Word 报告。")
        if batch.summary_html:
            lines.append(f"汇总摘要 HTML：{batch.summary_html}")
        if batch.summary_docx:
            lines.append(f"汇总摘要 Word：{batch.summary_docx}")
        if batch.errors:
            lines.append(f"另有 {len(batch.errors)} 份生成失败，详见运行日志。")
            messagebox.showwarning("部分完成", "\n".join(lines))
        else:
            messagebox.showinfo("生成完成", "\n".join(lines))

    def _on_cancelled(self, batch):
        """展示安全停止结果；已经完整生成的报告继续可打开。"""
        reports = batch.reports
        self.last_html = next((item.html for item in reversed(reports) if item.html), None)
        self.last_docx = next((item.docx for item in reversed(reports) if item.docx), None)
        self.last_summary_html = batch.summary_html
        self.last_summary_docx = batch.summary_docx
        result_file = self.last_html or self.last_docx
        self.last_output_dir = (
            os.path.dirname(os.path.abspath(result_file)) if result_file else ""
        )
        if self.last_output_dir:
            self.output_var.set(self.last_output_dir)

        if reports:
            last = reports[-1]
            if len(reports) == 1:
                score_breakdown = calculate_score_breakdown(last.results)
                confidence = score_breakdown.confidence
                self.score_var.set(f"{last.health_score}/100")
                self.counts_var.set(
                    f"已保留 1 份结果：正常 {last.counts['OK']}    "
                    f"警告 {last.counts['WARN']}    严重 {last.counts['CRIT']}    "
                    f"可信度 {confidence}"
                )
                self.env_var.set(
                    f"主机 {last.env_info.get('hostname', 'N/A')}    "
                    f"数据库 {last.env_info.get('oracle_sid', 'N/A')}"
                )
                self.score_label.configure(
                    fg=COLORS[score_tone(last.health_score, score_breakdown.possible > 0)]
                )
            else:
                self.score_var.set(f"{len(reports)}份")
                self.counts_var.set(f"停止前已保留 {len(reports)} 份报告结果")
                self.env_var.set("未开始的报告已取消")
                self.score_label.configure(fg=COLORS["warning"])
            self.result_path_var.set(self.last_output_dir)
        else:
            self.score_var.set("—")
            self.counts_var.set("生成已停止，尚无完整报告")
            self.env_var.set("未完成的报告未计入生成结果")
            self.result_path_var.set("可重新点击“生成巡检报告”")
            self.score_label.configure(fg=COLORS["muted"])

        self._set_busy(False)
        self.open_report_btn.configure(
            state=tk.NORMAL if self.last_html else tk.DISABLED
        )
        self.open_word_btn.configure(
            state=tk.NORMAL if self.last_docx else tk.DISABLED
        )
        self.open_summary_html_btn.configure(state=tk.DISABLED)
        self.open_summary_word_btn.configure(state=tk.DISABLED)
        self.open_folder_btn.configure(
            state=tk.NORMAL if self.last_output_dir else tk.DISABLED
        )
        self._set_status(
            "已停止生成", "warning",
            f"已保留 {len(reports)} 份报告结果",
        )
        self._log(
            f"生成已安全停止；停止前保留 {len(reports)} 份报告结果。",
            "warn",
        )
        for item in reports:
            if item.html:
                self._log(f"已保留 HTML 报告：{item.html}", "ok")
            if item.docx:
                self._log(f"已保留 Word 报告：{item.docx}", "ok")
        messagebox.showinfo(
            "已停止生成",
            f"生成任务已停止。\n已保留报告结果：{len(reports)} 份。"
            + (f"\n输出目录：{self.last_output_dir}" if self.last_output_dir else ""),
        )

    def _on_error(self, message):
        self._set_busy(False)
        self._set_status("生成失败", "danger", "请查看运行日志")
        self._log("报告生成失败。", "error")
        self._log(message, "error")
        messagebox.showerror(
            "生成失败", message[-2000:] if len(message) > 2000 else message
        )

    def open_report(self):
        if self.last_html and os.path.isfile(self.last_html):
            webbrowser.open(self.last_html)
        else:
            messagebox.showwarning("无法打开", "HTML 报告不存在或已被移动。")

    def open_word(self):
        if self.last_docx and os.path.isfile(self.last_docx):
            _open_path(self.last_docx)
        else:
            messagebox.showwarning("无法打开", "Word 报告不存在或已被移动。")

    def open_summary_html(self):
        if self.last_summary_html and os.path.isfile(self.last_summary_html):
            webbrowser.open(self.last_summary_html)
        else:
            messagebox.showwarning("无法打开", "汇总摘要 HTML 不存在。至少两份 Oracle 报告并勾选“生成汇总摘要”后才会生成。")

    def open_summary_word(self):
        if self.last_summary_docx and os.path.isfile(self.last_summary_docx):
            _open_path(self.last_summary_docx)
        else:
            messagebox.showwarning("无法打开", "汇总摘要 Word 不存在。至少两份 Oracle 报告并勾选“生成汇总摘要”后才会生成。")

    def open_folder(self):
        folder = self.last_output_dir
        if not folder:
            for path in (
                self.last_summary_html, self.last_html,
                self.last_summary_docx, self.last_docx,
            ):
                if path:
                    folder = os.path.dirname(os.path.abspath(path))
                    break
        if folder and os.path.isdir(folder):
            _open_path(folder)
        else:
            messagebox.showwarning("无法打开", "还没有生成报告。")


def main():
    _enable_windows_dpi()
    if TkinterDnD is not None:
        try:
            root = TkinterDnD.Tk()
        except (tk.TclError, RuntimeError):
            root = tk.Tk()
    else:
        root = tk.Tk()
    ReportApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
