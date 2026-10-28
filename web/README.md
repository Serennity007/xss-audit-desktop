# XSS Audit Studio — browser workbench

[English](#run-and-deploy) · [简体中文](#中文)

A static web application for browser-local review of JS, TS, JSX and TSX. Source files are parsed in a disposable Web Worker; no analysis server, account, API key or external network requests are needed at runtime.

## Run and deploy

Use Node.js 22.18+ (tested with 24.18.0):

```powershell
cd web
npm ci
npm test
npm run build
npm run preview
```

The preview binds only to http://127.0.0.1:4178. It is a local preview, not a public experience link. Serve over HTTP on loopback or HTTPS when deployed; opening index.html with file:// is not supported because module Workers and cryptographic APIs require appropriate browser contexts.

Deploy the **contents** of web/dist as a static website, preserving index.html, app.js, worker.js, style.css and the license files in the same directory. No Python server or secrets are needed. Keep same-origin module Workers enabled. Host headers must not contradict the page CSP. The application works at a subdirectory URL as well as a domain root. Refreshing is not dependent on client routing.

The runtime CSP blocks outbound connections. Downloaded HTML reports have a separate CSP that also blocks scripts. The build includes dependency code and notices locally; there are no CDN dependencies or remote fonts.

## Delivered behavior

- Paste/edit source, rename and add/remove files, import multiple UTF-8 files, and load synthetic samples.
- Babel AST parsing with bounded local propagation: selected URL/storage/request/message inputs, assignment/string composition, HTML writes, selected navigation and execution calls, and React raw HTML output.
- Separate broad pattern matches for HTML, URL, execution, sanitizers and messaging.
- Evidence locations, source context, priority/keyword filters and explicit parse/coverage notes.
- Manual pending/confirmed-risk/false-positive/fixed decisions, notes and single-signal copy with a manual fallback.
- JSON, Markdown and standalone offline HTML export of all results, not only the current filter.
- Simplified Chinese default, English switch and responsive desktop/mobile layouts.
- A disposable Worker with termination on cancel, timeout or input change; late results cannot replace a newer run.

## Data and review identities

Source is kept only in page memory and cleared when the page is closed or reloaded. Closing the page does not erase downloaded reports.

Only review decisions, user notes, timestamps and SHA-256 identities are stored under the origin-local key xss-audit-studio.reviews.v1. At most the 500 most recently saved records are retained. Identity includes engine version, path, full-file content digest and finding location, so any source change invalidates saved decisions for that file. Storage failures are visible; the page-session decision remains available. Records are not synchronized across devices. Use Clear local reviews to remove them.

Reports include selected code contexts, file paths and review notes, but do not embed whole uploaded files by default. Review reports before sharing. Source snippets, notes and HTML-like filenames are rendered as text, never as active markup.

## Limits and analysis boundaries

- 100 files; 256 KiB per file; 5 MiB total; 2,000 project signals; 1,000 signals per file; 40,000 traversal steps and depth 80 per file; 10 seconds per analysis job.
- UTF-8/BOM only. Empty/duplicate filenames, binary content and size excesses produce errors. Import failures preserve the current project.
- Standalone JS/TS/JSX/TSX/MJS/CJS only. Python, HTML, framework templates and embedded component scripts are not analyzed. Unsupported files appear in coverage notes.
- No complete cross-file or interprocedural analysis, precise control-flow/type/alias resolution, object-field tracking, async timing or framework lifecycle modeling. Function and block scoping are bounded approximations; var hoisting and custom abstractions can produce misses or false positives. Unknown call arguments propagate conservatively.
- A recognized sanitizer lowers HTML-flow priority but never proves safety; URL flow is still reviewed. Pattern matches can occur in comments, safe code and string literals.
- Raw strings in notes/source are not executed. No project installation, eval, imported code execution, dependency advisory lookup, GitHub import, AI calls or automatic patching is implemented in this web version.
- Zero matches is not proof of safety. Unit and UI tests verify behavior, not detection accuracy. Browser and Python desktop engines have different coverage and review identity formats; do not interchange their baseline reports.

## Provenance

This MIT-licensed web application extends Serennity007/xss-audit-desktop, which derives from songjianyang/xss-audit. Retain ../LICENSE and ../NOTICE.md. Browser AST parsing uses @babel/parser and its MIT-licensed dependencies; the build copies their notices to dist. The upstream author has not endorsed this derivative.

## 中文

本版已实现浏览器本地的 JS／TS／JSX／TSX 审查工作台，提供示例、多文件导入、代码编辑、有限 AST 数据流证据、普通规则匹配、人工复核、复制与 JSON／Markdown／离线 HTML 导出。默认中文，可切换英文。

按上面的命令安装、测试、构建。将 web/dist 内的全部文件部署到支持 HTTPS 和同源模块 Worker 的静态网站。文件须保持同目录，不需要服务端、数据库或 API Key。localhost 是本机预览，不是参赛公开链接。

源码默认仅在当前页面内存中，不上传、不持久保存。浏览器只保存最近最多 500 条复核判断、备注及摘要身份；修改文件任何内容后，该文件的旧判断不再自动恢复。关闭页面后需要重新导入源码。导出的报告包含代码上下文与备注，分享前请自行检查。

当前网页版与桌面引擎覆盖不同，不支持 Python、模板脚本提取、完整跨文件分析、GitHub 导入或 AI 审查。解析失败、上限和不支持文件会显示为覆盖缺口。不会执行上传代码，示例也只作为文本解析。自动结果是待复核线索，测试通过不代表已验证检测准确率。

WorkBuddy 参赛需由 WorkBuddy 实际发布，并验证其生成的公开体验链接包含有效 sharecode；本构建不会生成或猜测参赛链接。参赛应用链接和本次创作对话链接应分别获取。
