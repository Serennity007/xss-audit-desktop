from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__
from .ai import DEFAULT_BASE_URL, review, validate_endpoint
from .scanner import LAYERS, scan, write_report


class AuditApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.result = None
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
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
        tk.Label(header, text="XSS AUDIT", fg="white", bg="#152640", font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(header, text="本地代码审计助手  /  14 类规则  /  可选 AI 复核", fg="#bbd0f1", bg="#152640", font=("Microsoft YaHei UI", 11)).pack(anchor="w", pady=(4, 0))
        body = ttk.Frame(root, padding=14)
        body.pack(fill="both", expand=True)
        pathrow = ttk.Frame(body)
        pathrow.pack(fill="x")
        self.path = tk.StringVar()
        self.path_entry = ttk.Entry(pathrow, textvariable=self.path, font=("Microsoft YaHei UI", 11))
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.choose_button = ttk.Button(pathrow, text="选择代码文件夹", command=self.choose)
        self.choose_button.pack(side="left", padx=(10, 0))
        self.scan_button = ttk.Button(pathrow, text="开始本地扫描", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(10, 0))
        self.cancel_button = ttk.Button(pathrow, text="取消", state="disabled", command=self.cancel.set)
        self.cancel_button.pack(side="left", padx=(10, 0))
        self.status = tk.StringVar(value="请选择本地项目。普通扫描离线运行，不修改或执行项目代码。")
        ttk.Label(body, textvariable=self.status, wraplength=1040).pack(fill="x", pady=(12, 6))
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 12))
        ttk.Label(body, text="启发式搜索 + 可选 AI 复核 · 零匹配不代表安全 · 基于 songjianyang/xss-audit（MIT）", foreground="#566478").pack(side="bottom", anchor="w", pady=(8, 0))
        notebook = ttk.Notebook(body)
        notebook.pack(fill="both", expand=True)
        local = ttk.Frame(notebook, padding=10)
        ai_tab = ttk.Frame(notebook, padding=10)
        notebook.add(local, text="  本地扫描  ")
        notebook.add(ai_tab, text="  AI 辅助审计  ")
        toolbar = ttk.Frame(local)
        toolbar.pack(fill="x", pady=(0, 8))
        self.category = tk.StringVar(value="全部类别")
        categories = ["全部类别"] + [f"{n}. {name}" for n, name in LAYERS.items()]
        combo = ttk.Combobox(toolbar, textvariable=self.category, values=categories, state="readonly", width=29)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _: self.refresh())
        self.export_button = ttk.Button(toolbar, text="导出 Markdown / JSON", state="disabled", command=self.export)
        self.export_button.pack(side="right")
        table_frame = ttk.Frame(local)
        table_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table_frame, columns=("category", "path", "line", "status"), show="headings", height=5)
        for name, title, width in [("category", "规则类别", 230), ("path", "文件", 430), ("line", "行号", 65), ("status", "状态", 120)]:
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
        self.set_text(self.detail, "扫描完成后选择一条线索查看代码位置。所有规则匹配均需人工复核。")
        config = ttk.Frame(ai_tab)
        config.pack(fill="x")
        self.base_url = tk.StringVar(value=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL))
        self.model = tk.StringVar(value=os.environ.get("XSS_AUDIT_MODEL", ""))
        self.api_key = tk.StringVar()
        self.api_format = tk.StringVar(value="responses")
        fields = [("API Base URL", self.base_url), ("模型名称", self.model), ("API Key（留空读取环境变量）", self.api_key)]
        for row, (label, variable) in enumerate(fields):
            ttk.Label(config, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(config, textvariable=variable, show="*" if row == 2 else "", width=60)
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=4)
        config.columnconfigure(1, weight=1)
        ttk.Label(config, text="接口格式").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Combobox(config, textvariable=self.api_format, values=["responses", "chat"], state="readonly").grid(row=3, column=1, sticky="w", padx=(12, 0), pady=4)
        ttk.Label(ai_tab, text="先完成本地扫描，再审核发送范围。AI 会发送完整源文件，可能包含敏感信息并产生 API 费用。\n密钥仅在内存中使用；最多发送约 18 万字符，报告记录未发送文件。AI 不执行代码或动态验证。", wraplength=980).pack(anchor="w", pady=10)
        ai_actions = ttk.Frame(ai_tab)
        ai_actions.pack(fill="x", pady=(0, 10))
        self.ai_button = ttk.Button(ai_actions, text="审核范围并开始 AI 审计", command=self.start_ai, state="disabled", style="Accent.TButton")
        self.ai_button.pack(side="left")
        self.ai_export = ttk.Button(ai_actions, text="导出合并报告", command=self.export, state="disabled")
        self.ai_export.pack(side="left", padx=10)
        self.ai_text = ScrolledText(ai_tab, height=6, font=("Microsoft YaHei UI", 10), wrap="word", relief="flat", padx=12, pady=12)
        self.ai_text.pack(fill="both", expand=True)
        self.set_text(self.ai_text, "尚未运行 AI 审计。可配置支持 Responses 或 Chat Completions 的接口。")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)

    @staticmethod
    def set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def choose(self):
        path = filedialog.askdirectory(title="选择需要审计的本地代码文件夹")
        if path:
            self.path.set(path)

    def set_busy(self, busy, ai=False):
        self.busy = busy
        self.scan_button.configure(state="disabled" if busy else "normal")
        self.choose_button.configure(state="disabled" if busy else "normal")
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
            messagebox.showinfo("选择文件夹", "请先选择代码文件夹。")
            return
        self.cancel.clear()
        self.result = None
        self.refresh()
        self.set_text(self.ai_text, "新扫描已开始；之前的 AI 结果已清除。")
        self.set_busy(True)
        self.status.set("正在本地扫描…")

        def worker():
            last_update = 0.0

            def progress(path):
                nonlocal last_update
                if time.monotonic() - last_update > .1:
                    self.events.put(("progress", path))
                    last_update = time.monotonic()
            try:
                self.events.put(("scan", scan(path, cancel=self.cancel, progress=progress, collect_source=True)))
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
            messagebox.showerror("AI 配置", str(error))
            return
        files = "\n".join(item["path"] for item in self.result.sources)
        dialog = tk.Toplevel(self.root)
        dialog.title("确认 AI 发送范围")
        dialog.geometry("760x520")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text=f"接口：{base}\n模型：{model}\n将发送 {len(self.result.sources)} 个完整源文件；预算外 {len(self.result.ai_omitted)} 个。\n请核查下方文件列表。发送后可能产生 API 费用，接收方按其政策处理代码。", wraplength=720, padding=15).pack(fill="x")
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
                    review(result, key, model, base, api_format)
                    self.events.put(("ai", None))
                except Exception as error:
                    self.events.put(("error", str(error)))
            threading.Thread(target=worker, daemon=True).start()
        ttk.Button(dialog, text="确认发送并审计", command=confirmed).pack(pady=15)

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    self.status.set("扫描中：" + value)
                elif kind == "scan":
                    self.result = value
                    self.refresh()
                    self.set_busy(False)
                    state = "已取消，结果不完整" if value.cancelled else "达到上限，结果不完整" if value.truncated else "完成"
                    self.status.set(f"{state} · {value.files_scanned} 个文件 · {len(value.matches)} 条待确认线索 · {len(value.skipped)} 项未读取 / 排除")
                elif kind == "ai":
                    self.set_busy(False)
                    self.set_text(self.ai_text, self.result.ai_report)
                    self.status.set("AI 审计完成，结果尚需人工确认。可导出合并报告。")
                elif kind == "error":
                    self.set_busy(False)
                    self.status.set("操作失败；已有本地扫描结果可导出。")
                    messagebox.showerror("操作失败", value)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        if not self.result:
            return
        selected = self.category.get()
        layer = None if selected == "全部类别" else int(selected.split(".")[0])
        for index, match in enumerate(self.result.matches):
            if layer is None or match.layer == layer:
                self.tree.insert("", "end", iid=str(index), values=(f"{match.layer}. {LAYERS[match.layer]}", match.path, match.line, match.status))

    def show_match(self, _=None):
        selected = self.tree.selection()
        if selected and self.result:
            item = self.result.matches[int(selected[0])]
            self.set_text(self.detail, f"{item.path}:{item.line}:{item.column}\n{item.rule} · {item.status}\n\n{item.snippet}\n\n复核输入来源、数据流、最终输出上下文及校验 / 净化。规则匹配不等于漏洞。")

    def export(self):
        if not self.result or self.busy:
            return
        path = filedialog.asksaveasfilename(title="导出报告", initialfile=f"xss-audit-report-{datetime.now():%Y%m%d-%H%M%S}.md", defaultextension=".md", filetypes=[("Markdown 报告", "*.md"), ("JSON 报告", "*.json")])
        if path:
            try:
                write_report(self.result, path, "json" if path.lower().endswith(".json") else "markdown", overwrite=True)
                self.status.set("报告已导出：" + path)
            except OSError as error:
                messagebox.showerror("导出失败", str(error))

    def close(self):
        self.cancel.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
