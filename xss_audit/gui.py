from __future__ import annotations

import os
import queue
import threading
import time
import json
from pathlib import Path
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__
from .ai import DEFAULT_BASE_URL, review, validate_endpoint
from .scanner import LAYERS, scan, write_report
from .importer import import_github
from .state import STATUSES, StateStore
from .i18n import canonical, normalize, tr


class UiVar(tk.StringVar):
    """Localized display with canonical Python values for filters and state."""
    def __init__(self, master, language, value=""):
        self.language = language
        self.raw = value
        self.display = ""
        super().__init__(master=master, value=value)
        self.set(value)

    def set(self, value):
        self.raw = str(value)
        self.display = tr(self.raw, self.language())
        super().set(self.display)

    def get(self):
        displayed = super().get()
        return self.raw if displayed == self.display else canonical(displayed)

    def retranslate(self):
        self.set(self.get())


class AuditApp:
    def __init__(self, root: tk.Tk, state_dir=None, language=None):
        self.root = root
        self.result = None
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.store = StateStore(state_dir)
        self.import_info = {}
        self.import_root = ""
        try:
            preferences = self.store.preferences()
            preference_error = ""
        except (OSError, ValueError) as error:
            preferences = {}
            preference_error = str(error)
        self.language = normalize(language or preferences.get("language", "en"))
        self.ui_vars = []
        root.title(f"XSS Audit Desktop · {__version__}")
        width = max(900, min(1120, root.winfo_screenwidth() - 60))
        height = max(680, min(820, root.winfo_screenheight() - 80))
        root.geometry(f"{width}x{height}")
        root.minsize(900, 680)
        root.configure(bg="#f3f5f9")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f5f9")
        style.configure("TLabel", background="#f3f5f9", font=("Microsoft YaHei UI", 10))
        style.configure("TButton", font=("Microsoft YaHei UI", 10), padding=(12, 7))
        style.configure("Accent.TButton", background="#245bd8", foreground="white")
        style.map("Accent.TButton", background=[("active", "#1848b3"), ("disabled", "#9caac4")])
        style.configure("Treeview", rowheight=30, font=("Microsoft YaHei UI", 10))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"))
        header = tk.Frame(root, bg="#152640", padx=20, pady=12)
        header.pack(fill="x")
        language_box = tk.Frame(header, bg="#152640")
        language_box.pack(side="right", anchor="n")
        tk.Label(language_box, text="Language / 语言", fg="white", bg="#152640").pack(anchor="e")
        self.language_choice = tk.StringVar(value="简体中文" if self.language == "zh-CN" else "English")
        self.language_combo = ttk.Combobox(language_box, textvariable=self.language_choice, values=["English", "简体中文"], state="readonly", width=13)
        self.language_combo.pack(pady=5)
        self.language_combo.bind("<<ComboboxSelected>>", lambda _: self.set_language(self.language_choice.get()))
        tk.Label(header, text="XSS AUDIT", fg="white", bg="#152640", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(header, text="代码审计工作台  /  AST 数据流线索  /  GitHub 导入  /  AI 复核", fg="#bbd0f1", bg="#152640", font=("Microsoft YaHei UI", 11)).pack(anchor="w", pady=(4, 0))
        body = ttk.Frame(root, padding=14)
        body.pack(fill="both", expand=True)
        pathrow = ttk.Frame(body)
        pathrow.pack(fill="x")
        self.path = tk.StringVar()
        self.path_entry = ttk.Entry(pathrow, textvariable=self.path, font=("Microsoft YaHei UI", 11))
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.choose_button = ttk.Button(pathrow, text="本地目录", command=self.choose)
        self.choose_button.pack(side="left", padx=(10, 0))
        self.import_button = ttk.Button(pathrow, text="导入 GitHub", command=self.import_dialog)
        self.import_button.pack(side="left", padx=(10, 0))
        self.scan_button = ttk.Button(pathrow, text="开始扫描", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(10, 0))
        self.cancel_button = ttk.Button(pathrow, text="取消", state="disabled", command=self.cancel.set)
        self.cancel_button.pack(side="left", padx=(10, 0))
        metrics = ttk.Frame(body)
        metrics.pack(fill="x", pady=(12, 0))
        self.metrics = []
        for title in ("扫描文件", "全部线索", "高优先复核", "已复核"):
            variable = self.ui_var(title + "  0")
            self.metrics.append(variable)
            ttk.Label(metrics, textvariable=variable, foreground="#245bd8", font=("Microsoft YaHei UI", 12, "bold")).pack(side="left", padx=(0, 35))
        self.status = self.ui_var(preference_error or "选择本地目录或导入公开 GitHub 仓库。扫描不执行项目文件。")
        ttk.Label(body, textvariable=self.status, wraplength=1040).pack(fill="x", pady=(12, 6))
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 12))
        ttk.Label(body, text="启发式搜索 + 可选 AI 复核 · 零匹配不代表安全 · 基于 songjianyang/xss-audit（MIT）", foreground="#566478").pack(side="bottom", anchor="w", pady=(8, 0))
        notebook = ttk.Notebook(body)
        notebook.pack(fill="both", expand=True)
        local = ttk.Frame(notebook, padding=10)
        ai_tab = ttk.Frame(notebook, padding=10)
        scope_tab = ttk.Frame(notebook, padding=10)
        notebook.add(local, text="  本地扫描  ")
        notebook.add(ai_tab, text="  AI 辅助审计  ")
        notebook.add(scope_tab, text="  扫描范围与解析说明  ")
        self.scope_text = ScrolledText(scope_tab, font=("Microsoft YaHei UI", 10), wrap="word", relief="flat", padx=12, pady=12)
        self.scope_text.pack(fill="both", expand=True)
        self.set_text(self.scope_text, "扫描后显示语言统计、导入来源、类别覆盖、跳过项和 AST 解析说明。")
        toolbar = ttk.Frame(local)
        toolbar.pack(fill="x", pady=(0, 8))
        self.category = self.ui_var("全部类别")
        categories = ["全部类别"] + [f"{n}. {name}" for n, name in LAYERS.items()]
        combo = ttk.Combobox(toolbar, textvariable=self.category, values=categories, state="readonly", width=22)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _: self.refresh())
        self.priority = self.ui_var("全部优先级")
        priority = ttk.Combobox(toolbar, textvariable=self.priority, values=["全部优先级", "高", "中", "信息"], state="readonly", width=11)
        priority.pack(side="left", padx=8)
        priority.bind("<<ComboboxSelected>>", lambda _: self.refresh())
        self.search = tk.StringVar()
        ttk.Label(toolbar, text="搜索").pack(side="left", padx=(0, 5))
        ttk.Entry(toolbar, textvariable=self.search, width=20).pack(side="left", fill="x", expand=True)
        self.search.trace_add("write", lambda *_: self.refresh())
        self.export_button = ttk.Button(toolbar, text="导出报告", state="disabled", command=self.export)
        self.export_button.pack(side="right")
        table_frame = ttk.Frame(local)
        table_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table_frame, columns=("priority", "category", "path", "line", "status"), show="headings", height=4)
        for name, title, width in [("priority", "复核优先级", 90), ("category", "规则", 260), ("path", "文件", 340), ("line", "行号", 60), ("status", "状态", 100)]:
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, minwidth=50)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        horizontal = ttk.Scrollbar(local, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=horizontal.set)
        self.tree.pack(fill="both", expand=True)
        horizontal.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self.show_match)
        ttk.Label(local, text="代码与复核建议").pack(anchor="w", pady=(10, 5))
        self.detail = ScrolledText(local, height=4, font=("Consolas", 10), wrap="word", relief="flat", padx=10, pady=10)
        self.detail.pack(fill="x")
        review_row = ttk.Frame(local)
        review_row.pack(fill="x", pady=(8, 0))
        self.review_status = self.ui_var(STATUSES[0])
        ttk.Combobox(review_row, textvariable=self.review_status, values=STATUSES, state="readonly", width=12).pack(side="left")
        self.review_note = tk.StringVar()
        ttk.Label(review_row, text="备注").pack(side="left", padx=(8, 0))
        ttk.Entry(review_row, textvariable=self.review_note).pack(side="left", fill="x", expand=True, padx=8)
        self.review_button = ttk.Button(review_row, text="保存复核标记", command=self.save_review, state="disabled")
        self.review_button.pack(side="right")
        self.set_text(self.detail, "扫描完成后选择一条线索查看代码位置。所有规则匹配均需人工复核。")
        config = ttk.Frame(ai_tab)
        config.pack(fill="x")
        self.base_url = tk.StringVar(value=preferences.get("base_url", os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL)))
        self.model = tk.StringVar(value=preferences.get("model", os.environ.get("XSS_AUDIT_MODEL", "")))
        self.api_key = tk.StringVar()
        self.api_format = tk.StringVar(value=preferences.get("api_format", "responses"))
        fields = [("API Base URL", self.base_url), ("模型名称", self.model), ("API Key（留空读取环境变量）", self.api_key)]
        for row, (label, variable) in enumerate(fields):
            ttk.Label(config, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(config, textvariable=variable, show="*" if row == 2 else "", width=60)
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=4)
        config.columnconfigure(1, weight=1)
        ttk.Label(config, text="接口格式").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Combobox(config, textvariable=self.api_format, values=["responses", "chat"], state="readonly").grid(row=3, column=1, sticky="w", padx=(12, 0), pady=4)
        ttk.Label(ai_tab, text="优先选择有数据流证据的完整文件；最多约 18 万字符。已识别的凭据值会遮蔽，但仍需核查敏感信息。\n发送前审核范围，可能产生 API 费用。密钥仅在内存中使用；AI 不执行代码或动态验证。", wraplength=980).pack(anchor="w", pady=10)
        ai_actions = ttk.Frame(ai_tab)
        ai_actions.pack(fill="x", pady=(0, 10))
        self.ai_button = ttk.Button(ai_actions, text="审核范围并开始 AI 审计", command=self.start_ai, state="disabled", style="Accent.TButton")
        self.ai_button.pack(side="left")
        self.ai_export = ttk.Button(ai_actions, text="导出合并报告", command=self.export, state="disabled")
        self.ai_export.pack(side="left", padx=10)
        ttk.Button(ai_actions, text="保存接口设置（不含密钥）", command=self.save_preferences).pack(side="right")
        self.ai_text = ScrolledText(ai_tab, height=6, font=("Microsoft YaHei UI", 10), wrap="word", relief="flat", padx=12, pady=12)
        self.ai_text.pack(fill="both", expand=True)
        self.set_text(self.ai_text, "尚未运行 AI 审计。可配置支持 Responses 或 Chat Completions 的接口。")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.localize(root)
        root.after(100, self.poll)

    def tr(self, text):
        return tr(text, self.language)

    def ui_var(self, value):
        variable = UiVar(self.root, lambda: self.language, value)
        self.ui_vars.append(variable)
        return variable

    def localize(self, widget):
        if "text" in widget.keys() and not ("textvariable" in widget.keys() and widget.cget("textvariable")):
            if not hasattr(widget, "_original_text"):
                widget._original_text = widget.cget("text")
            widget.configure(text=self.tr(widget._original_text))
        if isinstance(widget, ttk.Combobox):
            if not hasattr(widget, "_original_values"):
                widget._original_values = tuple(widget.cget("values"))
            widget.configure(values=[self.tr(value) for value in widget._original_values])
        if isinstance(widget, ttk.Notebook):
            if not hasattr(widget, "_original_tabs"):
                widget._original_tabs = [(tab, widget.tab(tab, "text")) for tab in widget.tabs()]
            for tab, title in widget._original_tabs:
                widget.tab(tab, text=self.tr(title))
        if isinstance(widget, ttk.Treeview):
            if not hasattr(widget, "_original_headings"):
                widget._original_headings = {column: widget.heading(column, "text") for column in widget.cget("columns")}
            for column, title in widget._original_headings.items():
                widget.heading(column, text=self.tr(title))
        if isinstance(widget, tk.Toplevel):
            if not hasattr(widget, "_original_title"):
                widget._original_title = widget.title()
            widget.title(self.tr(widget._original_title))
        for child in widget.winfo_children():
            self.localize(child)

    def set_language(self, language):
        if self.busy:
            self.language_choice.set("简体中文" if self.language == "zh-CN" else "English")
            return
        self.language = normalize(language)
        self.language_choice.set("简体中文" if self.language == "zh-CN" else "English")
        for variable in self.ui_vars:
            variable.retranslate()
        self.localize(self.root)
        if self.result:
            self.result.language = self.language
            self.refresh()
            self.show_scope()
            self.show_match()
        else:
            self.set_text(self.scope_text, "扫描后显示语言统计、导入来源、类别覆盖、跳过项和 AST 解析说明。")
            self.set_text(self.detail, "扫描完成后选择一条线索查看代码位置。所有规则匹配均需人工复核。")
        if not self.result or not self.result.ai_report:
            self.set_text(self.ai_text, "尚未运行 AI 审计。可配置支持 Responses 或 Chat Completions 的接口。")
        try:
            self.store.save_preferences(language=self.language, base_url=self.base_url.get(), model=self.model.get(), api_format=self.api_format.get())
        except (OSError, ValueError) as error:
            self.error("保存失败", str(error))

    def error(self, title, message):
        messagebox.showerror(self.tr(title), self.tr(message))

    def set_text(self, widget, text, translate=True):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", self.tr(text) if translate else text)
        widget.configure(state="disabled")

    def choose(self):
        path = filedialog.askdirectory(title=self.tr("选择需要审计的本地代码文件夹"))
        if path:
            self.path.set(path)

    def import_dialog(self):
        if self.busy:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("导入公开 GitHub 仓库")
        dialog.geometry("640x280")
        dialog.transient(self.root)
        dialog.grab_set()
        form = ttk.Frame(dialog, padding=18)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="仓库首页链接，或 owner/repository").pack(anchor="w")
        repository = tk.StringVar()
        ttk.Entry(form, textvariable=repository, width=65).pack(fill="x", pady=8)
        ttk.Label(form, text="Ref（可选：分支、标签、commit；留空使用默认分支）").pack(anchor="w")
        ref = tk.StringVar()
        ttk.Entry(form, textvariable=ref).pack(fill="x", pady=8)
        ttk.Label(form, text="下载公开源码快照到本机应用数据目录；不执行代码、不安装项目依赖。", wraplength=590).pack(anchor="w", pady=5)

        def confirmed():
            value, revision = repository.get(), ref.get()
            dialog.destroy()
            self.cancel.clear()
            self.set_busy(True)
            self.status.set("开始导入 GitHub…")

            def worker():
                try:
                    imported = import_github(value, revision, cancel=self.cancel,
                        progress=lambda text: self.events.put(("message", text)))
                    self.events.put(("imported", imported))
                except Exception as error:
                    self.events.put(("error", str(error)))
            threading.Thread(target=worker, daemon=True).start()
        ttk.Button(form, text="导入并扫描", style="Accent.TButton", command=confirmed).pack(anchor="e", pady=8)
        self.localize(dialog)

    def save_preferences(self):
        try:
            base = validate_endpoint(self.base_url.get())
            self.store.save_preferences(base_url=base, model=self.model.get(), api_format=self.api_format.get(), language=self.language)
            self.status.set("接口设置已保存在本机。API Key 未保存。")
        except (OSError, ValueError) as error:
            self.error("保存失败", str(error))

    def save_review(self):
        selected = self.tree.selection()
        if self.busy or not selected or not self.result:
            return
        item = self.result.matches[int(selected[0])]
        old = item.status, item.note
        item.status = self.review_status.get() if self.review_status.get() in STATUSES else STATUSES[0]
        item.note = self.review_note.get()[:1000]
        try:
            self.store.save_review(self.result)
            self.refresh()
            self.status.set("复核标记已保存；相同路径 / 规则 / 代码的线索将在下次扫描时恢复状态。")
        except (OSError, ValueError) as error:
            item.status, item.note = old
            self.error("保存失败", str(error))

    def set_busy(self, busy, ai=False):
        self.busy = busy
        self.language_combo.configure(state="disabled" if busy else "readonly")
        self.scan_button.configure(state="disabled" if busy else "normal")
        self.choose_button.configure(state="disabled" if busy else "normal")
        self.import_button.configure(state="disabled" if busy else "normal")
        self.review_button.configure(state="normal" if not busy and self.tree.selection() else "disabled")
        self.path_entry.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy and not ai else "disabled")
        for button in (self.export_button, self.ai_export):
            button.configure(state="normal" if not busy and self.result else "disabled")
        valid = self.result and not self.result.cancelled and not self.result.truncated and self.result.sources
        self.ai_button.configure(state="normal" if not busy and valid else "disabled")
        self.progress.start(12) if busy else self.progress.stop()

    def start_scan(self):
        if self.busy:
            return
        path = self.path.get().strip()
        if not path:
            messagebox.showinfo(self.tr("选择文件夹"), self.tr("请先选择代码文件夹。"))
            return
        self.cancel.clear()
        self.result = None
        self.refresh()
        self.set_text(self.detail, "正在扫描，完成后可选择线索查看代码上下文和证据。")
        self.set_text(self.ai_text, "新扫描已开始；之前的 AI 结果已清除。")
        self.set_busy(True)
        self.status.set("正在本地扫描…")
        import_info = self.import_info if str(Path(path).resolve()) == self.import_root else {}

        def worker():
            last_update = 0.0

            def progress(path):
                nonlocal last_update
                if time.monotonic() - last_update > .1:
                    self.events.put(("progress", path))
                    last_update = time.monotonic()
            try:
                result = scan(path, cancel=self.cancel, progress=progress, collect_source=True)
                result.language = self.language
                result.import_metadata = import_info
                try:
                    self.store.apply(result)
                except (OSError, ValueError) as error:
                    result.analysis_notes.append({"path": "本机复核记录", "reason": str(error)})
                self.events.put(("scan", result))
            except Exception as error:
                self.events.put(("error", str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def start_ai(self):
        if self.busy or not self.result:
            return
        key = self.api_key.get().strip() or os.environ.get("OPENAI_API_KEY", "")
        model = self.model.get().strip()
        try:
            base = validate_endpoint(self.base_url.get())
            if not key or not model:
                raise ValueError("请填写 API Key 和模型名称（或设置对应环境变量）。")
        except ValueError as error:
            self.error("AI 配置", str(error))
            return
        files = "\n".join(item["path"] for item in self.result.sources)
        dialog = tk.Toplevel(self.root)
        dialog.title("确认 AI 发送范围")
        dialog.geometry("760x520")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text=self.tr(f"接口：{base}\n模型：{model}\n将发送 {len(self.result.sources)} 个完整源文件；预算外 {len(self.result.ai_omitted)} 个。\n请核查下方文件列表。发送后可能产生 API 费用，接收方按其政策处理代码。"), wraplength=720, padding=15).pack(fill="x")
        preview = ScrolledText(dialog, wrap="word", font=("Consolas", 10))
        preview.pack(fill="both", expand=True, padx=15)
        self.set_text(preview, "项目：" + self.result.root + "\n\n将发送：\n" + files + "\n\n预算外未发送：\n" + "\n".join(self.result.ai_omitted))
        api_format = self.api_format.get()

        def confirmed():
            dialog.destroy()
            self.set_busy(True, ai=True)
            self.status.set("AI 正在审计所选范围…请求最多等待 180 秒。")
            result = self.result

            def worker():
                try:
                    review(result, key, model, base, api_format, language=self.language)
                    self.events.put(("ai", None))
                except Exception as error:
                    self.events.put(("error", str(error)))
            threading.Thread(target=worker, daemon=True).start()
        ttk.Button(dialog, text="确认发送并审计", command=confirmed).pack(pady=15)
        self.localize(dialog)

    def show_scope(self):
        from .reports import localized_metadata
        if not self.result:
            return
        value = self.result
        notes = lambda rows: [{"path": row["path"], "reason": self.tr(row["reason"])} for row in rows]
        scope = {self.tr("扫描目录"): value.root, self.tr("导入来源"): localized_metadata(value.import_metadata, self.language),
                 self.tr("语言统计"): value.languages, self.tr("AST 说明"): notes(value.analysis_notes),
                 self.tr("跳过项"): notes(value.skipped), self.tr("类别"): {self.tr(name): sum(m.layer == n for m in value.matches) for n, name in LAYERS.items()}}
        self.set_text(self.scope_text, json.dumps(scope, ensure_ascii=False, indent=2))

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    self.status.set("扫描中：" + value)
                elif kind == "message":
                    self.status.set(value)
                elif kind == "imported":
                    path, self.import_info = value
                    self.import_root = str(path.resolve())
                    self.path.set(str(path))
                    self.set_busy(False)
                    self.start_scan()
                elif kind == "scan":
                    self.result = value
                    self.refresh()
                    self.set_busy(False)
                    self.show_scope()
                    state = "已取消，结果不完整" if value.cancelled else "达到上限，结果不完整" if value.truncated else "完成，部分 AST 未完成" if value.ast_incomplete else "完成"
                    self.status.set(f"{state} · {value.files_scanned} 个文件 · {len(value.matches)} 条待确认线索 · {len(value.skipped)} 项未读取 / 排除")
                elif kind == "ai":
                    self.set_busy(False)
                    self.set_text(self.ai_text, self.result.ai_report, translate=False)
                    self.status.set("AI 审计完成，结果尚需人工确认。可导出合并报告。")
                elif kind == "error":
                    self.set_busy(False)
                    self.status.set("操作失败；已有本地扫描结果可导出。")
                    self.error("操作失败", value)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def refresh(self):
        selected_rows = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        if not self.result:
            for variable, title in zip(self.metrics, ("扫描文件", "全部线索", "高优先复核", "已复核")):
                variable.set(title + "  0")
            self.review_button.configure(state="disabled")
            return
        values = (self.result.files_scanned, len(self.result.matches), sum(m.priority == "高" and m.status == STATUSES[0] for m in self.result.matches), sum(m.status != STATUSES[0] for m in self.result.matches))
        for variable, title, value in zip(self.metrics, ("扫描文件", "全部线索", "高优先复核", "已复核"), values):
            variable.set(f"{title}  {value}")
        selected = self.category.get()
        layer = None if selected == "全部类别" else int(selected.split(".")[0])
        priority, search = self.priority.get(), self.search.get().strip().lower()
        ordered = sorted(enumerate(self.result.matches), key=lambda pair: ({"高": 0, "中": 1, "信息": 2}[pair[1].priority], pair[1].path, pair[1].line))
        for index, match in ordered:
            haystack = " ".join((match.path, match.rule, self.tr(match.rule), match.snippet, match.cwe, match.status, self.tr(match.status), match.note)).lower()
            if (layer is None or match.layer == layer) and (priority == "全部优先级" or match.priority == priority) and (not search or search in haystack):
                self.tree.insert("", "end", iid=str(index), values=(self.tr(match.priority), self.tr(match.rule), match.path, match.line, self.tr(match.status)))
        if selected_rows and self.tree.exists(selected_rows[0]):
            self.tree.selection_set(selected_rows[0])

    def show_match(self, _=None):
        selected = self.tree.selection()
        if selected and self.result:
            item = self.result.matches[int(selected[0])]
            self.review_status.set(item.status)
            self.review_note.set(item.note)
            self.review_button.configure(state="disabled" if self.busy else "normal")
            evidence = "\n".join(item.evidence) or "尚无完整数据流证据，请人工追踪。"
            evidence = "\n".join(self.tr(line) for line in item.evidence) or self.tr("尚无完整数据流证据，请人工追踪。")
            self.set_text(self.detail, f"{item.path}:{item.line}:{item.column} · {item.rule_id} · {item.cwe}\n{self.tr('优先级')} {self.tr(item.priority)} · {self.tr(item.confidence)}\n\n{item.context or item.snippet}\n\n{evidence}\n\n{self.tr('建议')}：{self.tr(item.recommendation)}")

    def export(self):
        if not self.result or self.busy:
            return
        path = filedialog.asksaveasfilename(title=self.tr("导出完整报告（包含所有类别，当前筛选仅影响界面）"), initialfile=f"xss-audit-report-{datetime.now():%Y%m%d-%H%M%S}.html", defaultextension=".html", filetypes=[(self.tr("HTML 离线报告"), "*.html"), (self.tr("Markdown 报告"), "*.md"), (self.tr("JSON 报告"), "*.json"), ("SARIF 2.1.0", "*.sarif")])
        if path:
            try:
                fmt = {".json": "json", ".html": "html", ".sarif": "sarif"}.get(Path(path).suffix.lower(), "markdown")
                write_report(self.result, path, fmt, overwrite=True, language=self.language)
                self.status.set("报告已导出：" + path)
            except OSError as error:
                self.error("导出失败", str(error))

    def close(self):
        self.cancel.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
