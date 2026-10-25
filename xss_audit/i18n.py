"""English/Chinese presentation; analysis identities remain language-independent."""
from __future__ import annotations

import re

LANGUAGES = ("en", "zh-CN")
EN = {
    "界面和报告语言（默认英语）": "Interface and report language (default: English)",
    "高": "High", "中": "Medium", "信息": "Info", "待人工确认": "Needs review",
    "确认风险": "Confirmed risk", "误报": "False positive", "已修复": "Fixed", "无": "None",
    "扫描文件": "Files scanned", "全部线索": "Review signals", "高优先复核": "High priority pending", "已复核": "Reviewed",
    "本地目录": "Local folder", "导入 GitHub": "Import GitHub", "开始扫描": "Start scan", "取消": "Cancel",
    "本地扫描": "Local scan", "AI 辅助审计": "AI review", "扫描范围与解析说明": "Scope and analysis notes",
    "全部类别": "All categories", "全部优先级": "All priorities", "导出报告": "Export report",
    "复核优先级": "Review priority", "规则": "Rule", "文件": "File", "行号": "Line", "状态": "Status",
    "保存复核标记": "Save review", "模型名称": "Model", "API Key（留空读取环境变量）": "API key (or environment variable)",
    "审核范围并开始 AI 审计": "Review scope and start AI", "导出合并报告": "Export combined report",
    "选择需要审计的本地代码文件夹": "Select a local source folder", "导入公开 GitHub 仓库": "Import a public GitHub repository",
    "选择本地目录或导入公开 GitHub 仓库。扫描不执行项目文件。": "Select a folder or import a public GitHub repository. Project files are never executed.",
    "扫描后显示语言统计、导入来源、类别覆盖、跳过项和 AST 解析说明。": "After scanning: language counts, import provenance, category coverage, exclusions and AST notes.",
    "扫描完成后选择一条线索查看代码位置。所有规则匹配均需人工复核。": "Select a signal after scanning to inspect its location. All automatic matches require human review.",
    "尚未运行 AI 审计。可配置支持 Responses 或 Chat Completions 的接口。": "AI review has not run. Configure a Responses or Chat Completions compatible endpoint.",
    "正在扫描，完成后可选择线索查看代码上下文和证据。": "Scanning. Select a signal when finished to inspect context and evidence.",
    "新扫描已开始；之前的 AI 结果已清除。": "A new scan has started. Previous AI results have been cleared.",
    "正在本地扫描…": "Scanning local files…", "确认 AI 发送范围": "Confirm AI source scope",
    "开始导入 GitHub…": "Starting GitHub import…", "保存失败": "Save failed", "选择文件夹": "Select a folder",
    "请先选择代码文件夹。": "Select a source folder first.", "请选择代码文件夹。": "Select a source folder.",
    "AI 正在审计所选范围…请求最多等待 180 秒。": "AI review is running… A request can take up to 180 seconds.",
    "接口设置已保存在本机。API Key 未保存。": "Endpoint preferences saved locally. The API key was not saved.",
    "复核标记已保存；相同路径 / 规则 / 代码的线索将在下次扫描时恢复状态。": "Review saved. The same path, rule and nearby code will restore this decision on a later scan.",
    "请填写 API Key 和模型名称（或设置对应环境变量）。": "Enter an API key and model, or set their environment variables.",
    "AI 配置": "AI configuration", "搜索": "Search", "代码与复核建议": "Code and review guidance", "备注": "Note",
    "接口格式": "API format", "保存接口设置（不含密钥）": "Save settings (no key)",
    "代码审计工作台  /  AST 数据流线索  /  GitHub 导入  /  AI 复核": "Code review workbench  /  AST flow evidence  /  GitHub import  /  AI review",
    "启发式搜索 + 可选 AI 复核 · 零匹配不代表安全 · 基于 songjianyang/xss-audit（MIT）": "Heuristic search + optional AI review · No matches is not proof of safety · Based on songjianyang/xss-audit (MIT)",
    "优先选择有数据流证据的完整文件；最多约 18 万字符。已识别的凭据值会遮蔽，但仍需核查敏感信息。\n发送前审核范围，可能产生 API 费用。密钥仅在内存中使用；AI 不执行代码或动态验证。": "Prioritizes complete files with flow evidence, up to about 180,000 characters. Recognized credentials are masked, but sensitive data still needs review.\nCheck the scope before sending; API charges may apply. The key stays in memory. AI does not execute or dynamically verify code.",
    "仓库首页链接，或 owner/repository": "Repository homepage URL, or owner/repository",
    "Ref（可选：分支、标签、commit；留空使用默认分支）": "Ref (optional: branch, tag or commit; blank uses the default branch)",
    "下载公开源码快照到本机应用数据目录；不执行代码、不安装项目依赖。": "Downloads a public snapshot to local app data. Does not execute code or install project dependencies.",
    "导入并扫描": "Import and scan", "确认发送并审计": "Send source and review",
    "HTML 离线报告": "Offline HTML report", "Markdown 报告": "Markdown report", "JSON 报告": "JSON report",
    "导出完整报告（包含所有类别，当前筛选仅影响界面）": "Export full report (all categories; screen filters do not apply)",
    "导出失败": "Export failed", "操作失败": "Operation failed",
    "操作失败；已有本地扫描结果可导出。": "Operation failed. Existing local results can still be exported.",
    "AI 审计完成，结果尚需人工确认。可导出合并报告。": "AI review finished. Human verification is still required. You can export the combined report.",
    "扫描目录": "Source folder", "导入来源": "Import provenance", "语言统计": "Language counts", "AST 说明": "AST notes", "跳过项": "Skipped items", "类别": "Category",
    "已取消，结果不完整": "Cancelled; incomplete results", "达到上限，结果不完整": "Limit reached; incomplete results",
    "完成，部分 AST 未完成": "Finished; some AST analysis incomplete", "完成": "Finished",
    "扫描完成，部分 AST 未完成": "Scan finished; some AST analysis incomplete", "扫描完成": "Scan complete", "结果不完整": "Incomplete results",
    "DOM / HTML 注入": "DOM / HTML injection", "属性与事件处理器": "Attributes and event handlers", "URL 与导航": "URLs and navigation",
    "配置与脚本内 JSON": "Configuration and JSON in scripts", "Props 展开与组件": "Props spreading and components",
    "不可信数据源与消息": "Untrusted sources and messaging", "原型污染链": "Prototype pollution chains", "JavaScript 执行": "JavaScript execution",
    "CSS 与样式": "CSS and styles", "Markdown 与净化器": "Markdown and sanitizers", "框架渲染与信任绕过": "Framework rendering and trust bypasses",
    "Trusted Types 与 CSP": "Trusted Types and CSP", "框架绑定与模板编译": "Framework binding and template compilation",
    "SQL 查询构造": "SQL query construction", "Shell 命令执行": "Shell command execution", "文件路径与遍历": "File paths and traversal",
    "服务端请求 / SSRF": "Server-side requests / SSRF", "不安全反序列化": "Unsafe deserialization", "疑似硬编码凭据": "Possible hardcoded credentials",
    "语法信号": "Syntax signal", "HTML 写入 / 解析": "HTML writes / parsing", "动态属性 / 事件": "Dynamic attributes / events",
    "导航 / URL 值": "Navigation / URL values", "URL 校验复核": "URL validation review", "脚本数据 / 内容配置": "Script data / content configuration",
    "Props 转发": "Props forwarding", "外部输入 / 消息": "External input / messages", "对象合并 / 原型": "Object merging / prototypes",
    "动态执行": "Dynamic execution", "样式字符串 / 外部样式": "Style strings / external styles", "外来命名空间": "Foreign namespaces",
    "净化 / Markdown / 二次解析": "Sanitization / Markdown / reparsing", "框架原始 HTML / 信任绕过": "Framework raw HTML / trust bypasses",
    "浏览器防护配置": "Browser defense configuration", "绑定 / 模板解释": "Binding / template interpretation",
    "AST 可见数据流（待复核）": "AST-visible flow (unverified)", "凭据格式 / 命名信号": "Credential format / naming signal",
    "外部输入到 React 原始 HTML": "External input to React raw HTML", "外部输入到 HTML 写入": "External input to an HTML write",
    "外部输入到 HTML 插入": "External input to HTML insertion", "外部输入到动态代码执行": "External input to dynamic code execution",
    "外部输入到动态执行": "External input to dynamic execution", "外部输入到计时器参数": "External input to a timer argument",
    "外部输入到 Shell 命令": "External input to a shell command", "外部输入到 SQL 语句构造": "External input to SQL statement construction",
    "外部输入到文件路径": "External input to a file path", "外部输入到服务端请求": "External input to a server-side request",
    "外部输入到模板 / 信任绕过": "External input to templates / trust bypasses", "外部输入到反序列化": "External input to deserialization",
    "外部输入到 URL 属性 / 导航": "External input to a URL attribute / navigation", "外部输入到浏览器导航": "External input to browser navigation",
    "优先使用普通 JSX 文本；富文本需要最终 HTML 净化。": "Prefer ordinary JSX text. Rich text requires sanitization at the final HTML output.",
    "使用 textContent；需要富文本时在最终 HTML 输出前采用可信净化器。": "Use textContent. If rich text is required, sanitize with a trusted sanitizer immediately before final HTML output.",
    "避免动态执行外部字符串，改用显式分派或数据解析。": "Avoid executing external strings. Use explicit dispatch or data parsing.",
    "传递函数回调，避免外部字符串作为执行内容。": "Pass a function callback instead of executing an external string.",
    "移除 eval / exec，使用显式数据解析和允许操作列表。": "Remove eval / exec. Use explicit data parsing and an allowlist of operations.",
    "使用参数数组和 shell=False；对每个参数做业务约束。": "Use an argument array with shell=False and validate each argument for its business purpose.",
    "使用数据库参数绑定，不拼接外部输入到 SQL 字符串。": "Bind database parameters instead of concatenating external input into SQL strings.",
    "解析规范路径后检查允许根目录；避免仅用字符串前缀校验。": "Resolve the canonical path and enforce an allowed root directory; do not rely only on string prefixes.",
    "限制协议、目标和重定向；结合网络出口限制与解析结果检查。": "Restrict schemes, destinations and redirects, and combine parsed-destination checks with network egress controls.",
    "固定模板源码，通过参数传入数据并保持上下文转义。": "Keep template source fixed. Pass data as parameters and retain context-appropriate escaping.",
    "使用安全数据格式与安全解析器，避免对不可信内容反序列化对象。": "Use safe data formats and parsers. Do not deserialize objects from untrusted content.",
    "基于 URL 解析后的协议与业务允许域名进行校验；核查最终元素上下文。": "Validate the parsed URL scheme and allowed business domains, and inspect the final element context.",
    "校验解析后的协议、域名和具体导航上下文。": "Validate the parsed scheme, hostname and actual navigation context.",
    "采用安全文本 API，或在正确上下文进行最终净化。": "Use safe text APIs, or sanitize the final value for the correct output context.",
    "追踪输入来源与最终输出，核查对应上下文的校验和净化。": "Trace the source to the final output and check context-appropriate validation and sanitization.",
    "仅当前函数 / 文件的保守传播；未证明可利用性。": "Conservative propagation in the current function / file only; exploitability has not been established.",
    "命中凭据格式或敏感变量名；无法判断是否为真实有效凭据。显示与 AI 发送时遮蔽识别出的值。": "Matched a credential format or sensitive variable name; validity is unknown. Recognized values are masked in display and AI requests.",
    "若为有效凭据，请撤销 / 轮换并使用环境变量或秘密存储；仅删除源码不足以撤销已泄露值。": "If valid, revoke or rotate the credential and use environment variables or secret storage. Removing source code alone does not revoke an exposed value.",
    "尚无完整数据流证据，请人工追踪。": "No complete flow evidence is available. Trace it manually.", "尚无完整数据流证据。": "No complete flow evidence is available.",
    "AST 分析达到深度 / 节点上限；该文件的语法树分析不完整。": "AST depth / node budget reached; analysis of this file is incomplete.",
    "解析包含语法错误，AST 结果可能不完整。": "The parse contains syntax errors; AST results may be incomplete.",
    "AST 证据达到单文件 1000 条上限，结果可能不完整。": "The per-file limit of 1,000 AST findings was reached; results may be incomplete.",
    "AST 依赖缺失，当前文件仅执行规则搜索。": "AST dependencies are missing; only pattern search ran on this file.",
    "依赖 / 生成目录 / 链接目录": "Dependency / generated / linked directory", "不支持的格式 / 压缩文件": "Unsupported format / minified file",
    "达到扫描上限；此文件及剩余目录未扫描": "Scan limit reached; this file and remaining directories were not scanned",
    "达到总读取字节上限；此文件及剩余目录未扫描": "Total byte limit reached; this file and remaining directories were not scanned",
    "达到匹配上限；后续范围未扫描": "Match limit reached; the remaining scope was not scanned",
    "达到 10000 条匹配上限；当前文件和后续文件不完整": "The 10,000-match limit was reached; this file and later files are incomplete",
    "符号链接 / 范围外文件": "Symbolic link / out-of-scope file", "文件大于 1 MiB": "File exceeds 1 MiB", "二进制 / 非 UTF-8 文件": "Binary / non-UTF-8 file",
    "本机复核记录": "Local review records", "本地复核记录过大，未加载。": "Local review records are too large and were not loaded.",
    "复核记录超过 2 MiB，请减少或缩短备注。": "Review records exceed 2 MiB. Remove or shorten notes.",
    "本地复核记录格式错误。": "Invalid local review-record format.",
    "本地复核记录损坏，未加载；源代码扫描结果仍可使用。": "Local review records are corrupt and were not loaded. Source scan results are still available.",
    "API Base URL 必须包含主机，且不能带账号、查询参数或片段。": "The API base URL needs a host and must not contain credentials, a query or a fragment.",
    "远程 AI 接口必须使用 HTTPS；本机接口可使用 HTTP。": "Remote AI endpoints require HTTPS. Localhost endpoints may use HTTP.",
    "AI 审计需要 API Key 和模型名称。": "AI review requires an API key and model name.",
    "API Key 格式无效：请移除空格、换行或非 ASCII 字符。": "Invalid API key format: remove whitespace, newlines or non-ASCII characters.",
    "不支持的 AI API 格式。": "Unsupported AI API format.",
    "本地扫描不完整，请缩小范围并重新扫描后再运行 AI。": "The local scan is incomplete. Narrow the scope and rescan before AI review.",
    "没有可发送的完整源文件；请缩小扫描目录。": "No complete source file fits the sending scope. Choose a smaller source folder.",
    "AI 响应过大，已拒绝。": "The AI response exceeded the size limit and was rejected.",
    "AI 接口返回格式不兼容。": "The AI response format is incompatible.",
    "AI 没有返回文本，可能拒绝了请求或接口格式不兼容。": "AI returned no text. The request may have been refused, or the endpoint format may be incompatible.",
    "AI 连接失败或超时；检查网络和接口地址。": "AI connection failed or timed out. Check the network and endpoint URL.",
    "AI 未完整完成响应（可能达到输出上限），请缩小审计范围。": "AI did not finish the response, possibly due to an output limit. Narrow the review scope.",
    "AI 响应未正常完成，请缩小范围。": "The AI response did not complete normally. Narrow the scope.",
    "优先 AST 高优先级文件，再按规则线索与文件名选择完整文件；预算 180000 字符。": "Complete files are selected by AST priority, then pattern evidence and filename; budget: 180,000 characters.",
    "未执行代码；未独立验证 AI 结论；仅审核已发送文件。": "No code was executed. AI conclusions were not independently verified. Only sent files were reviewed.",
    "请输入 https://github.com/作者/仓库 或 作者/仓库。": "Enter https://github.com/owner/repository or owner/repository.",
    "仅支持 github.com 仓库首页；分支 / 标签请在 Ref 栏填写。": "Use a github.com repository homepage; specify branches / tags in the Ref field.",
    "GitHub 仓库地址不合法。": "Invalid GitHub repository URL.", "解压目录必须为空。": "The extraction directory must be empty.",
    "Ref 长度或格式不合法。": "Invalid ref format or length.", "导入目录校验失败。": "Import directory validation failed.",
    "已拒绝 GitHub 以外的下载重定向。": "A download redirect outside GitHub was rejected.",
    "仓库压缩包超过文件数量 / 解压大小限制。": "The archive exceeds the file-count / extracted-size limit.",
    "正在下载 GitHub 源码快照…": "Downloading a GitHub source snapshot…", "正在检查压缩包并解压…": "Checking and extracting the archive…",
    "源码快照；不包括 Git 历史、子模块内容或 Git LFS 对象。未执行项目文件。": "Source snapshot only: excludes Git history, submodule contents and Git LFS objects. No project files were executed.",
    "压缩包含不安全路径、特殊文件或超大文件。": "The archive contains unsafe paths, special files or oversized members.",
    "已拒绝范围外解压路径。": "An out-of-scope extraction path was rejected.",
    "压缩包含重复 / 大小写冲突路径。": "The archive contains duplicate / case-colliding paths.",
    "导入已取消。": "Import cancelled.", "压缩包文件大小不一致。": "Archive member size mismatch.", "默认分支": "Default branch",
    "GitHub 下载 / 解压失败；检查网络、磁盘空间与压缩包格式。": "GitHub download / extraction failed. Check the network, disk space and archive format.",
    "下载超过 60 MiB 限制，请下载后选择较小的子目录。": "The download exceeds 60 MiB. Download it separately and choose a smaller subdirectory.",
    "压缩包实际解压大小超过限制。": "The actual extracted size exceeds the limit.",
    "XSS 静态审计助手；匹配结果需人工确认。": "XSS static review assistant. Matches require human verification.",
    "本地代码文件夹": "Local source folder", "下载并审计公开 GitHub 仓库，例如 owner/repository": "Download and review a public GitHub repository, e.g. owner/repository",
    "GitHub 分支、标签或 commit；默认使用仓库默认分支": "GitHub branch, tag or commit; defaults to the repository's default branch",
    "GitHub 导入的存放目录；默认使用本机应用数据目录": "Directory for GitHub imports; defaults to local app data",
    "报告路径（默认带时间戳，不覆盖已有文件）": "Report path (timestamped by default; existing files are not overwritten)",
    "报告与 fail-on-match 的最低复核优先级": "Minimum review priority for export and fail-on-match",
    "不导出已标记为误报 / 已修复的线索": "Exclude signals marked false positive / fixed",
    "不读取本机保存的复核状态": "Ignore locally saved review decisions",
    "明确同意发送已纳入范围的源代码到 AI 接口；可能产生 API 费用": "Explicitly opt in to sending scoped source to AI; API charges may apply",
    "AI 模型名称": "AI model name", "有待确认线索时返回 1；默认完成时返回 0": "Return 1 when review signals exist; default completion returns 0",
    "请提供本地代码文件夹或 --repo，二者选择一项。": "Provide exactly one local source folder or --repo.",
    "--ref / --destination 仅与 --repo 一起使用。": "--ref / --destination require --repo.",
    "扫描不完整，请缩小范围。": "The scan is incomplete. Narrow the scope.", "扫描已中断。": "Scan interrupted.",
    "规则搜索 + 有限 AST 数据流线索；不进行完整跨文件分析。优先级是复核顺序，不是已确认漏洞等级。零匹配不代表安全。": "Pattern search and limited AST flow evidence; no complete cross-file analysis. Priority is review order, not a confirmed vulnerability severity. No matches is not proof of safety.",
    "规则搜索与有限 AST 数据流分析不构成完整审计。优先级表示复核顺序，所有自动匹配均需人工确认；零匹配不代表安全。": "Pattern search and limited AST flow analysis are not a complete audit. Priority is review order. All automatic matches require human verification; no matches is not proof of safety.",
    "优先级表示复核顺序，不是已确认漏洞等级。有限 AST 分析不解析完整跨文件调用链；零匹配不代表安全。识别出的敏感值已尽力遮蔽，分享前仍需检查。": "Priority indicates review order, not confirmed severity. Limited AST analysis does not resolve complete cross-file call chains. No matches is not proof of safety. Recognized sensitive values are masked; check the report before sharing.",
    "未记录 AST 解析错误。未支持语言仍仅执行规则搜索。": "No AST parse errors were recorded. Unsupported languages still use pattern search only.",
    "无跳过项": "No skipped items", "不支持的报告格式。": "Unsupported report format.",
    "仅处理支持的文本扩展名；单文件上限 1 MiB、最多 10000 个文件 / 100 MiB / 10000 条匹配。读取 UTF-8；不跟随链接。不会执行项目文件。": "Supported text extensions only. Limits: 1 MiB per file, 10,000 files / 100 MiB / 10,000 matches. UTF-8 only; links are not followed. Project files are not executed.",
    "用户标记为误报": "Marked false positive by the user",
    "查看数据流证据和建议": "Inspect flow evidence and guidance", "范围与未读取 / AST 解析说明": "Scope, exclusions and AST notes",
    "未发现匹配线索。请结合扫描范围与解析说明评估。": "No review signals matched. Evaluate this together with the scope and analysis notes.",
    "审计报告": "Audit report", "代码审计报告": "Code review report", "优先级": "priority", "复核备注": "Review note", "建议": "Guidance",
    "搜索文件、规则、证据或代码": "Search files, rules, evidence or code",
    "单文件 1 MiB；最多 10000 文件 / 100 MiB / 10000 线索。不执行项目代码。": "Limits: 1 MiB per file; 10,000 files / 100 MiB / 10,000 signals. Project code is not executed.",
    "基于 songjianyang/xss-audit（MIT）。本报告可离线打开，无外部资源请求。": "Based on songjianyang/xss-audit (MIT). This report works offline and requests no external resources.",
    "AI 辅助审计 · 未独立验证": "AI review · not independently verified",
    "# XSS Audit 报告": "# XSS Audit report", "## 规则类别覆盖": "## Category coverage", "| 类别 | 匹配数 |": "| Category | Matches |",
    "## 待人工确认": "## Signals requiring review", "## 排除与未读取": "## Exclusions and unread files", "## 来源": "## Attribution",
    "## 导入来源": "## Import provenance", "## 报告筛选条件": "## Report filters", "## AST 未完成 / 解析说明": "## Incomplete AST analysis / parse notes",
    "## AI 辅助审计（未验证）": "## AI review (unverified)", "扫描目录：": "Source folder:", "默认排除目录：": "Excluded directories:",
    "请求与实际发送范围：": "Request and actual source scope:", "因上下文预算未发送：": "Not sent due to the context budget:",
    "衍生自 https://github.com/songjianyang/xss-audit ，保留 MIT 许可与原始 SKILL.md。": "Derived from https://github.com/songjianyang/xss-audit; retains the MIT license and original SKILL.md.",
    "接口": "Endpoint", "模型": "Model", "项目": "Project", "将发送": "Files to send", "预算外未发送": "Outside the budget",
    "时间（UTC）": "Time (UTC)", "证据": "Evidence", "匹配数": "Matches", "状态：": "Status:",
}

# Numeric placeholders are presentation-only; captured paths/code are never evaluated.
TEMPLATES = {
    "L{0}: 潜在外部输入 {1}": "L{0}: potentially external input {1}",
    "L{0}: 到达 {1}": "L{0}: reaches {1}",
    "L{0}: 赋值给 {1}": "L{0}: assigned to {1}",
    "L{0}: HTML 净化调用（配置和版本仍需复核）": "L{0}: HTML sanitizer call (configuration and version still need review)",
    "AST 分析不完整：{0}": "AST analysis incomplete: {0}",
    "读取失败：{0}": "Read failed: {0}", "目录无法读取：{0}": "Cannot read directory: {0}",
    "扫描 {0} 个文件，{1} 条待确认线索。报告：{2}": "Files scanned: {0}; review signals: {1}. Report: {2}",
    "AI 将发送 {0} 个完整文件；预算外 {1} 个。": "Complete files to send: {0}; outside the budget: {1}.",
    "AI 失败，本地报告已保留：{0}": "AI failed; the local report was retained: {0}",
    "复核记录未加载：{0}": "Review records were not loaded: {0}", "错误：{0}": "Error: {0}",
    "扫描中：{0}": "Scanning: {0}", "报告已导出：{0}": "Report exported: {0}",
    "{0} · {1} 个文件 · {2} 条待确认线索 · {3} 项未读取 / 排除": "{0} · {1} files · {2} review signals · {3} unread / excluded items",
    "AI 接口 HTTP {0}；检查接口、权限、额度和模型名称。": "AI endpoint HTTP {0}; check the endpoint, permissions, quota and model name.",
    "GitHub 下载失败（HTTP {0}）；核查仓库 / Ref 是否公开存在，或稍后重试限流。": "GitHub download failed (HTTP {0}); check the public repository / ref, or retry later after rate limiting.",
    "接口：{0}\n模型：{1}\n将发送 {2} 个完整源文件；预算外 {3} 个。\n请核查下方文件列表。发送后可能产生 API 费用，接收方按其政策处理代码。": "Endpoint: {0}\nModel: {1}\nSending {2} complete source files; {3} files are outside the budget.\nCheck the list below. API charges may apply, and the recipient handles code under its own policies.",
    "项目：{0}\n\n将发送：\n{1}\n\n预算外未发送：\n{2}": "Project: {0}\n\nFiles to send:\n{1}\n\nOutside the budget:\n{2}",
}
_PATTERNS = []
_RECURSIVE = {
    "AST 分析不完整：{0}": {0}, "AI 失败，本地报告已保留：{0}": {0},
    "复核记录未加载：{0}": {0}, "错误：{0}": {0},
    "{0} · {1} 个文件 · {2} 条待确认线索 · {3} 项未读取 / 排除": {0},
}
for original, english in TEMPLATES.items():
    pieces = re.split(r"(\{\d+\})", original)
    pattern = "".join(f"(?P<p{part[1:-1]}>.*?)" if re.fullmatch(r"\{\d+\}", part) else re.escape(part) for part in pieces)
    _PATTERNS.append((re.compile("^" + pattern + "$", re.S), english, _RECURSIVE.get(original, set())))


def normalize(language):
    return "zh-CN" if str(language).lower().replace("_", "-") in {"zh", "zh-cn", "简体中文"} else "en"


def tr(text, language="en", _depth=0):
    text = str(text)
    if normalize(language) == "zh-CN" or _depth > 6:
        return text
    if text in EN:
        return EN[text]
    stripped = text.strip()
    if stripped in EN:
        return text[:len(text)-len(text.lstrip())] + EN[stripped] + text[len(text.rstrip()):]
    category = re.fullmatch(r"(\d+\.\s+)(.+)", text)
    if category and category[2] in EN:
        return category[1] + EN[category[2]]
    metric = re.fullmatch(r"(扫描文件|全部线索|高优先复核|已复核)  (\d+)", text)
    if metric:
        return EN[metric[1]] + "  " + metric[2]
    for regex, english, recursive in _PATTERNS:
        match = regex.fullmatch(text)
        if match:
            values = {int(key[1:]): tr(value, language, _depth+1) if int(key[1:]) in recursive else value for key,value in match.groupdict().items()}
            return english.format(*(values[i] for i in range(len(values))))
    return text


_REVERSE = {value:key for key,value in EN.items()}


def canonical(text):
    return _REVERSE.get(str(text), str(text))


