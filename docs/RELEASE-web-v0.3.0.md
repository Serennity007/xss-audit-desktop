# XSS Audit Studio web 0.3.0 — offline project workflows

[Open the public workbench](https://serennity007.github.io/xss-audit-desktop/)

- **Import a project ZIP locally.** Validate archive metadata, apply project scope, inflate accepted source in a disposable Worker and check size/CRC. Preserve skipped paths and the current project on failures or superseded jobs.
- **Resume with project snapshots.** Explicitly download full source, saved review notes, scope, skipped paths and an optional baseline. Restore, analyze again and attach only matching decisions. Imported judgments carry visible provenance and are not automatically written to the browser's saved-review library.
- **Search source across loaded files.** Literal text search, original line/column navigation, optional ASCII case sensitivity and a 200-row limit. This is source navigation; analysis still has the documented local-flow limits.
- **Review filtered signals in batches.** Confirm the current count/status, preserve saved notes and update only the selected filtered IDs. Full report exports retain all signals.

All runtime processing remains browser-local. JSON, Markdown, offline HTML, CSV and SARIF remain available. The UI is English/Simplified Chinese. Workbench 0.3.0 retains AST engine 0.2.0, preserving its full-baseline and finding-ID compatibility. Windows v0.4.0 executables are unchanged.

Limits: regular Store/Deflate ZIPs up to 20 MiB compressed / 5,000 entries, with at most 100 accepted sources / 256 KiB each / 5 MiB total. Unsupported encryption, split/ZIP64 archives, links and non-UTF-8/ASCII names produce explicit failures. Skipped contents are not inflated or CRC-checked. Project snapshots are up to 32 MiB and contain full source; they are not encrypted or signed. Inspect sensitive content and imported judgments before sharing or relying on them.

Validation: 56 source checks passed; 8 built-artifact DOM/Worker checks passed. The latter execute the actual bundled Worker through Node worker threads with explicit DOM/platform shims. Native browser layout, permissions, file pickers, downloads and new screenshots were not independently reverified in this run. This preview does not establish detection precision/recall or exploitability. [Verification receipt](https://github.com/Serennity007/xss-audit-desktop/blob/main/docs/verification/web-0.3.0-local.json).

The static ZIP includes all seven deployable files and runtime license notices; the source ZIP comes from the release's exact Git commit. SHA-256 checksums accompany both. Retain upstream MIT attribution and bundled dependency notices, including fflate.

## 中文

网页 0.3.0 新增四项完整流程：离线 ZIP 项目导入、含完整源码的快照保存／恢复、跨文件字面搜索定位、当前筛选结果批量复核。源码仍在浏览器本地处理，无需账号或 API Key。

快照包含完整源码和已保存备注，请检查后分享；恢复判断由文件提供，须重新分析并按身份匹配，不自动保存到本机复核库。ZIP 在 Worker 内校验和解压，失败或过期任务保留现有项目。批量操作需确认数量与状态，不修改源码，导出仍保留全量线索。

56 项源码检查与 8 项构建产物 DOM／Worker 检查通过；本轮未重新独立验收真实浏览器布局、权限、文件选择框与下载行为。保留 0.2.0 AST 引擎和基线兼容性，Windows 0.4.0 程序未改动。自动线索仍需人工复核，不代表已证实漏洞。
