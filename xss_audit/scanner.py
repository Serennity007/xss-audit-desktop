"""Bounded, read-only heuristic search. Matches are never confirmed vulnerabilities."""
from __future__ import annotations

import bisect
import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

LAYERS = {
    1: "DOM / HTML 注入", 2: "属性与事件处理器", 3: "URL 与导航",
    4: "配置与脚本内 JSON", 5: "Props 展开与组件", 6: "不可信数据源与消息",
    7: "原型污染链", 8: "JavaScript 执行", 9: "CSS 与样式",
    10: "SVG / MathML / XML", 11: "Markdown 与净化器", 12: "框架渲染与信任绕过",
    13: "Trusted Types 与 CSP", 14: "框架绑定与模板编译",
}

# Broad review signals deliberately include safe uses. No source-to-sink claim is made.
RULES = [
    (1, "HTML 写入 / 解析", r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|setHTMLUnsafe|DOMParser|createContextualFragment|attachShadow)\b|document\s*\.\s*(?:write|writeln)\s*\("),
    (2, "动态属性 / 事件", r"\bsetAttribute(?:NS)?\s*\(|\bon[a-z]+\s*=|\b(?:href|src|srcdoc|action|formaction|poster)\s*=\s*[\{]"),
    (3, "导航 / URL 值", r"\b(?:window\s*\.\s*open|location\s*\.\s*(?:assign|replace)|(?:history|router)\s*\.\s*(?:pushState|replaceState|push|replace|navigate))\s*\(|\b(?:location(?:\s*\.\s*href)?|href|src|action|formAction)\s*=|(?:javascript|vbscript|data|blob|file):"),
    (3, "URL 校验复核", r"\b(?:hostname|protocol|URLSearchParams)\b|\.\s*(?:includes|startsWith)\s*\(\s*['\"]https?"),
    (4, "脚本数据 / 内容配置", r"__INITIAL_STATE__|__NEXT_DATA__|__NUXT__|__APOLLO_STATE__|JSON\s*\.\s*stringify\s*\(|application/ld\+json|<script\b|\b(?:html|template|linkExpression)\s*:"),
    (5, "Props 转发", r"\{\s*\.\.\.\s*\w+|\b(?:createElement|cloneElement)\s*\("),
    (6, "外部输入 / 消息", r"\b(?:URLSearchParams|localStorage|sessionStorage|indexedDB|postMessage|BroadcastChannel|MessageChannel)\b|document\s*\.\s*(?:cookie|referrer)|\.\s*(?:json|text)\s*\(\s*\)|addEventListener\s*\(\s*['\"]message['\"]"),
    (7, "对象合并 / 原型", r"__proto__|\b(?:deepmerge|defaultsDeep|cloneDeep|merge|extend)\s*\(|Object\s*\.\s*assign\s*\(|\[\s*['\"]constructor['\"]\s*\]"),
    (8, "动态执行", r"\b(?:eval|Function|importScripts)\s*\(|\b(?:setTimeout|setInterval)\s*\(\s*['\"`]|createObjectURL\s*\(|createElement\s*\(\s*['\"]script['\"]|\bnew\s+(?:Worker|SharedWorker|Blob)\s*\("),
    (9, "样式字符串 / 外部样式", r"\b(?:cssText|setProperty|insertRule)\b|\b(?:styled|css)\s*`|@import\b|\b(?:url|expression)\s*\(|\bbehavior\s*:"),
    (10, "外来命名空间", r"<(?:svg|math|foreignObject|annotation-xml)\b|xlink:href|\b(?:createElementNS|setAttributeNS)\s*\(|\bon(?:begin|end|repeat)\s*="),
    (11, "净化 / Markdown / 二次解析", r"\b(?:DOMPurify|sanitizeHtml|sanitize-html|marked|markdown-it|remark|rehype|showdown|sanitize|ALLOW_DATA_ATTR|FORBID_ATTR|ALLOWED_ATTR|ALLOWED_TAGS|ADD_ATTR|USE_PROFILES)\b"),
    (12, "框架原始 HTML / 信任绕过", r"\bv-html\b|\bbypassSecurityTrust\w*|\bDomSanitizer\b|\{@html\b|\bunsafeHTML\b|\[innerHTML\]"),
    (13, "浏览器防护配置", r"\btrustedTypes\b|\bcreatePolicy\s*\(|Content-Security-Policy|require-trusted-types-for|trusted-types|unsafe-inline|unsafe-eval"),
    (14, "绑定 / 模板解释", r"\b(?:data-bind|data-win-bind|data-win-control|ng-bind-html|ng-bind-html-unsafe|x-html|x-data|x-init)\b|\bx-(?:on|bind):|\bko\s*\.\s*(?:applyBindings\w*|bindingHandlers)|\bWinJS\s*\.|\$compile\s*\(|\$sce\s*\.|\b(?:SafeString|htmlSafe|controlsDescendantBindings|parseBindingsString)\b|\{\{\{"),
]
COMPILED = [(layer, title, re.compile(pattern, re.I)) for layer, title, pattern in RULES]
EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte", ".astro", ".mdx", ".css", ".scss", ".svg", ".xml", ".json", ".hbs", ".handlebars", ".ejs", ".njk"}
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".nuxt", ".venv", "venv", "__pycache__", ".idea", ".vscode"}
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_FILES = 10000
MAX_MATCHES = 10000
AI_CHAR_BUDGET = 180000


@dataclass
class Match:
    path: str
    line: int
    column: int
    layer: int
    rule: str
    snippet: str
    status: str = "待人工确认"


@dataclass
class ScanResult:
    root: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    files_scanned: int = 0
    bytes_scanned: int = 0
    matches: list[Match] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    cancelled: bool = False
    truncated: bool = False
    ai_report: str = ""
    ai_metadata: dict = field(default_factory=dict)
    sources: list[dict] = field(default_factory=list, repr=False)
    ai_omitted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("sources")  # Never dump entire source files into JSON reports.
        data["layers"] = {str(k): {"name": v, "matches": sum(m.layer == k for m in self.matches)} for k, v in LAYERS.items()}
        data["limitations"] = "启发式匹配，不进行完整数据流分析；零匹配不代表安全。AI 结论也需要人工复核。"
        data["excluded_directories"] = sorted(EXCLUDED_DIRS)
        return data


def scan(root: str | Path, cancel: threading.Event | None = None,
         progress: Callable[[str], None] | None = None, collect_source: bool = False) -> ScanResult:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("请选择代码文件夹。")
    result = ScanResult(str(base))
    ai_chars = 0

    def skip(path: str, reason: str) -> None:
        result.skipped.append({"path": path, "reason": reason})

    def walk_error(error: OSError) -> None:
        skip(str(error.filename), f"目录无法读取：{error.strerror}")

    for directory, dirs, files in os.walk(base, followlinks=False, onerror=walk_error):
        allowed = []
        for name in sorted(dirs):
            child = Path(directory) / name
            if name.lower() in EXCLUDED_DIRS or child.is_symlink() or getattr(child, "is_junction", lambda: False)():
                skip(child.relative_to(base).as_posix() + "/", "依赖 / 生成目录 / 链接目录")
            else:
                allowed.append(name)
        dirs[:] = allowed
        for name in sorted(files):
            if cancel and cancel.is_set():
                result.cancelled = True
                return result
            path = Path(directory) / name
            rel = path.relative_to(base).as_posix()
            if path.suffix.lower() not in EXTENSIONS or name.endswith((".min.js", ".min.css")):
                skip(rel, "不支持的格式 / 压缩文件")
                continue
            if result.files_scanned >= MAX_FILES or result.bytes_scanned >= MAX_TOTAL_BYTES or len(result.matches) >= MAX_MATCHES:
                skip(rel, "达到扫描上限；此文件及剩余目录未扫描")
                result.truncated = True
                return result
            try:
                if path.is_symlink() or not path.resolve().is_relative_to(base):
                    skip(rel, "符号链接 / 范围外文件")
                    continue
                with path.open("rb") as stream:
                    raw = stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    skip(rel, "文件大于 1 MiB")
                    continue
                if b"\x00" in raw:
                    skip(rel, "二进制 / 非 UTF-8 文件")
                    continue
                content = raw.decode("utf-8-sig")
            except (OSError, UnicodeError) as error:
                skip(rel, f"读取失败：{type(error).__name__}")
                continue
            if result.bytes_scanned + len(raw) > MAX_TOTAL_BYTES:
                result.truncated = True
                skip(rel, "达到总读取字节上限；此文件及剩余目录未扫描")
                return result
            result.files_scanned += 1
            result.bytes_scanned += len(raw)
            if progress:
                progress(rel)
            if collect_source:
                # Complete files only: never imply that a truncated file was reviewed.
                if ai_chars + len(content) + len(rel) + 100 <= AI_CHAR_BUDGET:
                    result.sources.append({"path": rel, "content": content})
                    ai_chars += len(content) + len(rel) + 100
                else:
                    result.ai_omitted.append(rel)
            starts = [0] + [m.end() for m in re.finditer("\n", content)]
            lines = content.splitlines()
            for layer, title, regex in COMPILED:
                seen = set()
                for match in regex.finditer(content):
                    line_index = bisect.bisect_right(starts, match.start()) - 1
                    if line_index in seen:
                        continue
                    seen.add(line_index)
                    snippet = lines[line_index].strip()[:300] if line_index < len(lines) else ""
                    result.matches.append(Match(rel, line_index + 1, match.start() - starts[line_index] + 1, layer, title, snippet))
                    if len(result.matches) >= MAX_MATCHES:
                        result.truncated = True
                        skip(rel, "达到 10000 条匹配上限；当前文件和后续文件不完整")
                        return result
    return result


def fenced(text: str) -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def markdown(result: ScanResult) -> str:
    status = "已取消，结果不完整" if result.cancelled else "达到上限，结果不完整" if result.truncated else "扫描完成"
    parts = ["# XSS Audit 报告", f"时间（UTC）：{result.created_at}", "扫描目录：", fenced(result.root),
             f"状态：{status}。扫描 {result.files_scanned} 个文件，{len(result.matches)} 条待人工确认线索。",
             "启发式搜索不进行完整数据流分析。所有匹配均不是已确认漏洞；零匹配不代表安全。安全的调用、注释和字符串也可能匹配。AI 结果为未验证模型输出。",
             "## 14 类规则覆盖", "| 类别 | 匹配数 |", "| --- | ---: |"]
    for layer, name in LAYERS.items():
        parts.append(f"| {layer}. {name} | {sum(m.layer == layer for m in result.matches)} |")
    parts.append("\n## 待人工确认")
    for index, match in enumerate(result.matches, 1):
        parts.extend([f"### {index}. 第 {match.layer} 类：{match.rule}",
                      fenced(f"{match.path}:{match.line}:{match.column}"), fenced(match.snippet),
                      "复核：追踪输入来源 → 数据流 → 最终输出位置；检查对应上下文的校验 / 净化、执行时机和可利用性。"])
    parts.extend(["## 排除与未读取", "默认排除目录：" + ", ".join(sorted(EXCLUDED_DIRS)),
                  "仅处理支持的文本扩展名；单文件上限 1 MiB、最多 10000 个文件 / 100 MiB / 10000 条匹配。读取 UTF-8；不跟随链接。不会执行项目文件。"])
    for item in result.skipped:
        parts.append(fenced(f"{item['path']} — {item['reason']}"))
    if result.ai_report or result.ai_metadata:
        parts.extend(["## AI 辅助审计（未验证）", "请求与实际发送范围：", fenced(json.dumps(result.ai_metadata, ensure_ascii=False, indent=2)),
                      "因上下文预算未发送：", fenced("\n".join(result.ai_omitted) or "无"), result.ai_report])
    parts.extend(["## 来源", "衍生自 https://github.com/songjianyang/xss-audit ，保留 MIT 许可与原始 SKILL.md。"])
    return "\n\n".join(parts) + "\n"


def write_report(result: ScanResult, target: str | Path, fmt: str = "markdown", overwrite: bool = False) -> Path:
    path = Path(target).expanduser().resolve()
    text = json.dumps(result.to_dict(), ensure_ascii=False, indent=2) if fmt == "json" else markdown(result)
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    return path
