"""Bounded, read-only heuristic search. Matches are never confirmed vulnerabilities."""
from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .analysis import analyze
from .secrets import redact, secret_locations
from .i18n import normalize, tr

LAYERS = {
    1: "DOM / HTML 注入", 2: "属性与事件处理器", 3: "URL 与导航",
    4: "配置与脚本内 JSON", 5: "Props 展开与组件", 6: "不可信数据源与消息",
    7: "原型污染链", 8: "JavaScript 执行", 9: "CSS 与样式",
    10: "SVG / MathML / XML", 11: "Markdown 与净化器", 12: "框架渲染与信任绕过",
    13: "Trusted Types 与 CSP", 14: "框架绑定与模板编译",
    15: "SQL 查询构造", 16: "Shell 命令执行", 17: "文件路径与遍历",
    18: "服务端请求 / SSRF", 19: "不安全反序列化", 20: "疑似硬编码凭据",
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
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte", ".astro", ".mdx", ".css", ".scss", ".svg", ".xml", ".json", ".hbs", ".handlebars", ".ejs", ".njk"}
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".nuxt", ".venv", "venv", "__pycache__", ".idea", ".vscode"}
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_FILES = 10000
MAX_MATCHES = 10000
AI_CHAR_BUDGET = 180000


def is_link(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


@dataclass
class Match:
    path: str
    line: int
    column: int
    layer: int
    rule: str
    snippet: str
    status: str = "待人工确认"
    rule_id: str = ""
    priority: str = "信息"
    confidence: str = "语法信号"
    cwe: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = "追踪输入来源与最终输出，核查对应上下文的校验和净化。"
    context: str = ""
    fingerprint: str = ""
    note: str = ""


@dataclass
class ScanResult:
    root: str
    language: str = "en"
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
    analysis_notes: list[dict] = field(default_factory=list)
    languages: dict = field(default_factory=dict)
    import_metadata: dict = field(default_factory=dict)
    report_filters: dict = field(default_factory=dict)

    @property
    def ast_incomplete(self):
        return any(note.get("path") != "本机复核记录" for note in self.analysis_notes)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("sources")  # Never dump entire source files into JSON reports.
        data["ast_incomplete"] = self.ast_incomplete
        data["layers"] = {str(k): {"name": v, "matches": sum(m.layer == k for m in self.matches)} for k, v in LAYERS.items()}
        data["limitations"] = "规则搜索 + 有限 AST 数据流线索；不进行完整跨文件分析。优先级是复核顺序，不是已确认漏洞等级。零匹配不代表安全。"
        data["excluded_directories"] = sorted(EXCLUDED_DIRS)
        return data


def scan(root: str | Path, cancel: threading.Event | None = None,
         progress: Callable[[str], None] | None = None, collect_source: bool = False) -> ScanResult:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("请选择代码文件夹。")
    result = ScanResult(str(base))

    def skip(path: str, reason: str) -> None:
        result.skipped.append({"path": path, "reason": reason})

    def walk_error(error: OSError) -> None:
        skip(str(error.filename), f"目录无法读取：{error.strerror}")

    for directory, dirs, files in os.walk(base, followlinks=False, onerror=walk_error):
        allowed = []
        for name in sorted(dirs):
            child = Path(directory) / name
            if name.lower() in EXCLUDED_DIRS or is_link(child):
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
                if is_link(path) or not path.resolve().is_relative_to(base):
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
            suffix = path.suffix.lower()
            result.languages[suffix] = result.languages.get(suffix, 0) + 1
            starts = [0] + [m.end() for m in re.finditer("\n", content)]
            lines = content.splitlines()
            file_matches = []
            def add(item):
                neighborhood = "\n".join(line.strip() for line in lines[max(0, item.line - 3):item.line + 2])
                item.fingerprint = hashlib.sha256((rel + "\0" + item.rule_id + "\0" + neighborhood).encode()).hexdigest()[:32]
                item.snippet = redact(item.snippet)
                item.context = redact("\n".join(f"{i + 1:>5} {'>' if i + 1 == item.line else ' '} {lines[i]}" for i in range(max(0, item.line - 4), min(len(lines), item.line + 3))))[:4000]
                item.evidence = [redact(value) for value in item.evidence]
                result.matches.append(item)
                file_matches.append(item)

            found, notes = analyze(content, suffix)
            result.analysis_notes.extend({"path": rel, "reason": note} for note in notes)
            for evidence in found:
                if len(result.matches) >= MAX_MATCHES:
                    break
                add(Match(path=rel, **evidence))
            for start, end in secret_locations(content):
                if len(result.matches) >= MAX_MATCHES:
                    break
                line = bisect.bisect_right(starts, start)
                add(Match(rel, line, start - starts[line - 1] + 1, 20, "疑似硬编码凭据", lines[line - 1].strip()[:300],
                    rule_id="SECRET-LITERAL", priority="中", confidence="凭据格式 / 命名信号", cwe="CWE-798",
                    evidence=["命中凭据格式或敏感变量名；无法判断是否为真实有效凭据。显示与 AI 发送时遮蔽识别出的值。"],
                    recommendation="若为有效凭据，请撤销 / 轮换并使用环境变量或秘密存储；仅删除源码不足以撤销已泄露值。"))
            for layer, title, regex in COMPILED:
                seen = set()
                for match in regex.finditer(content):
                    line_index = bisect.bisect_right(starts, match.start()) - 1
                    if line_index in seen:
                        continue
                    seen.add(line_index)
                    if len(result.matches) >= MAX_MATCHES:
                        result.truncated = True
                        skip(rel, "达到 10000 条匹配上限；当前文件和后续文件不完整")
                        return result
                    snippet = lines[line_index].strip()[:300] if line_index < len(lines) else ""
                    if not any(m.line == line_index + 1 and m.layer == layer and m.confidence.startswith("AST") for m in file_matches):
                        priority = "中" if layer in {1, 8, 12, 14} else "信息"
                        add(Match(rel, line_index + 1, match.start() - starts[line_index] + 1, layer, title, snippet,
                                  rule_id=f"XSS-L{layer:02d}", priority=priority, cwe="CWE-79" if layer != 7 else "CWE-1321"))
            if collect_source:
                rank = 0 if any(m.priority == "高" for m in file_matches) else 1 if file_matches else 2
                candidates = [*result.sources, {"path": rel, "content": content, "_rank": rank}]
                result.sources = []
                used = 0
                for candidate in sorted(candidates, key=lambda c: (c.get("_rank", 2), c["path"])):
                    size = len(candidate["content"]) + len(candidate["path"]) + 100
                    if used + size <= AI_CHAR_BUDGET:
                        result.sources.append(candidate)
                        used += size
                    elif candidate["path"] not in result.ai_omitted:
                        result.ai_omitted.append(candidate["path"])
            if len(result.matches) >= MAX_MATCHES:
                result.truncated = True
                skip(rel, "达到匹配上限；后续范围未扫描")
                return result
    return result


def fenced(text: str) -> str:
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def markdown(result: ScanResult, language=None) -> str:
    from .reports import localized_metadata
    language = normalize(language or result.language)
    t = lambda text: tr(text, language)
    status = "已取消，结果不完整" if result.cancelled else "达到上限，结果不完整" if result.truncated else "扫描完成，部分 AST 未完成" if result.ast_incomplete else "扫描完成"
    summary = (f"Status: {t(status)}. {result.files_scanned} files scanned; {len(result.matches)} unverified review signals." if language == "en" else f"状态：{status}。扫描 {result.files_scanned} 个文件，{len(result.matches)} 条待人工确认线索。")
    parts = [t("# XSS Audit 报告"), f"{t('时间（UTC）')}: {result.created_at}", t("扫描目录："), fenced(result.root), summary,
             t("规则搜索与有限 AST 数据流分析不构成完整审计。优先级表示复核顺序，所有自动匹配均需人工确认；零匹配不代表安全。"),
             t("## 规则类别覆盖"), t("| 类别 | 匹配数 |"), "| --- | ---: |"]
    for layer, name in LAYERS.items():
        parts.append(f"| {layer}. {t(name)} | {sum(m.layer == layer for m in result.matches)} |")
    parts.append(t("\n## 待人工确认"))
    for index, match in enumerate(result.matches, 1):
        title = f"### {index}. {t(LAYERS[match.layer])}: {t(match.rule)}" if language == "en" else f"### {index}. 第 {match.layer} 类：{match.rule}"
        parts.extend([title,
                      f"{t('复核优先级')}: {t(match.priority)}; {t('状态')}: {t(match.status)}; {t('证据')}: {t(match.confidence)}; {match.cwe}",
                      fenced(f"{match.path}:{match.line}:{match.column}"), fenced(match.snippet),
                      fenced("\n".join(t(step) for step in match.evidence)) if match.evidence else t("尚无完整数据流证据。"),
                      t("建议") + ": " + t(match.recommendation), t("复核备注") + ": " + (match.note or t("无"))])
    if result.import_metadata:
        parts.extend([t("## 导入来源"), fenced(json.dumps(localized_metadata(result.import_metadata, language), ensure_ascii=False, indent=2))])
    if result.report_filters:
        parts.extend([t("## 报告筛选条件"), fenced(json.dumps(result.report_filters, ensure_ascii=False, indent=2))])
    if result.analysis_notes:
        parts.extend([t("## AST 未完成 / 解析说明"), fenced(json.dumps(localized_metadata(result.analysis_notes, language), ensure_ascii=False, indent=2))])
    parts.extend([t("## 排除与未读取"), t("默认排除目录：") + ", ".join(sorted(EXCLUDED_DIRS)),
                  t("仅处理支持的文本扩展名；单文件上限 1 MiB、最多 10000 个文件 / 100 MiB / 10000 条匹配。读取 UTF-8；不跟随链接。不会执行项目文件。")])
    for item in result.skipped:
        parts.append(fenced(f"{item['path']} — {t(item['reason'])}"))
    if result.ai_report or result.ai_metadata:
        parts.extend([t("## AI 辅助审计（未验证）"), t("请求与实际发送范围："), fenced(json.dumps(localized_metadata(result.ai_metadata, language), ensure_ascii=False, indent=2)),
                      t("因上下文预算未发送："), fenced("\n".join(result.ai_omitted) or t("无")), result.ai_report])
    parts.extend([t("## 来源"), t("衍生自 https://github.com/songjianyang/xss-audit ，保留 MIT 许可与原始 SKILL.md。")])
    return "\n\n".join(parts) + "\n"


def write_report(result: ScanResult, target: str | Path, fmt: str = "markdown", overwrite: bool = False, language=None) -> Path:
    language = normalize(language or result.language)
    path = Path(target).expanduser().resolve()
    if fmt in {"html", "sarif"}:
        from .reports import html_report, sarif
        text = html_report(result, language) if fmt == "html" else json.dumps(sarif(result, language), ensure_ascii=False, indent=2)
    elif fmt in {"markdown", "json"}:
        from .reports import localized_dict
        text = json.dumps(localized_dict(result, language), ensure_ascii=False, indent=2) if fmt == "json" else markdown(result, language)
    else:
        raise ValueError("不支持的报告格式。")
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    return path
