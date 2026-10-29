# XSS Audit Studio — browser workbench

[English](#run-and-deploy) · [简体中文](#中文)

A static web application for browser-local review of JS, TS, JSX and TSX, with limited inline-script extraction from HTML, Vue and Svelte. Source files are parsed in a disposable Web Worker; no analysis server, account, API key or external network requests are needed at runtime.

## Run and deploy

Use Node.js 22.18+ within the 22.x line, or 24.11+ (tested with 24.18.0):

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

- Paste/edit source, rename and add/remove files, import UTF-8 files or a complete selected folder, and load basic or component synthetic examples. Folder paths are relative to the selected root.
- Explicit case-sensitive include/exclude patterns, dependency/build exclusions, import-time skipped-path inventory and per-file analysis coverage.
- Babel AST parsing with bounded local propagation (each inline script is analyzed independently): selected URL/storage/request/message inputs, assignment/string composition, HTML writes, selected navigation and execution calls, and React raw HTML output.
- Separate broad pattern matches for HTML, URL, execution, sanitizers and messaging.
- Evidence locations, source context, priority, category, evidence mode, review status, current-file, keyword and baseline-state filters and explicit parse/coverage notes.
- Manual pending/confirmed-risk/false-positive/fixed decisions, notes and single-signal copy with a manual fallback.
- JSON, readable Markdown, standalone offline HTML, CSV and SARIF 2.1.0 exports of all results, including effective scope, import inventory, coverage and comparison. UI filters never narrow an export. CSV protects formula-leading cells; SARIF distinguishes review priority from unverified exploitability.
- Conservative baseline comparison: keep the current complete result, or import a full compatible JSON report. Changed-file signals are new; missing observations never automatically become fixed.
- Local/reassigned sanitizer names cannot lower HTML-flow priority just because they have a recognized name.
- Simplified Chinese default, English switch and responsive desktop/mobile layouts.
- A disposable Worker with termination on cancel, timeout or input change; late results cannot replace a newer run.

## Data and review identities

Source, scope settings, import inventories and baseline data are kept only in page memory and cleared when the page is closed or reloaded. Closing the page does not erase downloaded reports.

Only saved review decisions, user notes, timestamps and SHA-256 identities are stored under the origin-local key xss-audit-studio.reviews.v1. At most the 500 most recently saved records are retained. Identity includes engine version, path, full-file content digest and finding location, so any source change invalidates saved decisions for that file. Storage failures are visible; the page-session decision remains available. Records are not synchronized across devices. Use Clear local reviews to remove them.

Reports include selected code contexts, file paths and review notes, but do not embed whole uploaded files by default. Review reports before sharing. Source snippets, notes and HTML-like filenames are rendered as text, never as active markup.

## Limits and analysis boundaries

- Finding context is capped at 4,096 characters; source/assignment labels at 120 and sink labels at 240. Shortened text is flagged in the UI and all reports; full files remain in the in-memory editor.
- 100 files; 256 KiB per file; 5 MiB total; 2,000 project signals; 1,000 signals per file; 40,000 traversal steps and depth 80 per file; 10 seconds per analysis job.
- UTF-8/BOM only. Empty/duplicate filenames, binary content and size excesses produce errors. Import failures preserve the current project.
- JS/TS/JSX/TSX/MJS/CJS plus limited inline scripts in .html/.htm/.vue/.svelte. parse5 extracts HTML script nodes; Babel parses supported JS/TS syntax with original line/column coordinates. This is not a Vue/Svelte compiler. Component extraction only handles root script nodes, HTML excludes inert template contents. External scripts are never fetched; JSON scripts, unknown languages and unclosed blocks are reported. Up to 16 blocks/file. Scripts are independent: module/instance sharing, cross-script flow, HTML attributes, Vue directives, Svelte expressions, custom preprocessors and framework compilation are not modeled. Every extracted file carries an explicit template coverage gap; such incomplete reports cannot be baselines. Python is unsupported.
- No complete cross-file or interprocedural analysis, precise control-flow/type/alias resolution, object-field tracking, async timing or framework lifecycle modeling. Function and block scoping are bounded approximations; var hoisting and custom abstractions can produce misses or false positives. Unknown call arguments propagate conservatively.
- A recognized sanitizer lowers HTML-flow priority but never proves safety; URL flow is still reviewed. Pattern matches can occur in comments, safe code and string literals. Sanitizer recognition is a bounded approximation, not package/version verification; selected local bindings and overwrites prevent inappropriate downgrades.
- Raw strings in notes/source are not executed. No project installation, eval, imported code execution, dependency advisory lookup, GitHub import, AI calls or automatic patching is implemented in this web version.
- Zero matches is not proof of safety. Unit and UI tests verify behavior, not detection accuracy. Browser and Python desktop engines have different coverage and review identity formats; do not interchange their baseline reports. Engine 0.2.0 changes review identities, so 0.1.0 decisions are retained in storage but not applied to new findings.

## Provenance

This MIT-licensed web application extends Serennity007/xss-audit-desktop, which derives from songjianyang/xss-audit. Retain ../LICENSE and ../NOTICE.md. Browser parsing uses @babel/parser and parse5 (MIT), plus their dependencies including entities (BSD-2-Clause); the build copies their notices to dist. The upstream author has not endorsed this derivative.

## Project scope and comparisons

The default scope includes `**/*` and excludes node_modules, vendor, .git, dist, build, coverage, .next, .nuxt and `*.min.js` at any depth. Patterns are case-sensitive and relative, with `/` separators. `*` and `?` stay within a path segment; `**` is a complete segment matching zero or more segments. Exclusion wins. Up to 24 patterns/list and 200 characters/pattern; no negation, character classes, braces, whitespace, backslashes or .gitignore interpretation.

Folder import replaces the open in-memory source project after confirmation; file import adds to it. Both honor current scope. Imports inspect at most 5,000 entries, read only supported in-scope sources, and apply the 100-file/5-MiB limits to accepted sources. Invalid UTF-8, binary content, duplicate names and size failures preserve the old project. An import finishing after a source/scope change is discarded. Skipped paths are kept in memory and exported (the UI lists the first 100). Changing scope after import cannot recover unread files: re-import the folder. Folder selection may be unavailable in some browsers; use multifile import there. ZIP and GitHub online import are not implemented.

To compare revisions, analyze a complete JS/TS project, use **Use current result as baseline** (or download its full JSON), edit or re-import the next snapshot, and analyze again. Choose a baseline from the same engine version. Incomplete/filtered/foreign reports and JSON larger than 16 MiB are rejected. Validation also checks unique IDs, normalized paths, source hashes and declared budgets. Baselines restore no decisions from imported JSON. Scope changes and current coverage failures are disclosed.

Comparison uses the entire file digest and each signal ID: even a distant comment change makes that file's signals new. This deliberately requires fresh review and is not semantic change detection. Not-observed entries may reflect deletion, changes, scope or incomplete analysis; they never imply a verified fix. Baselines stay only in page memory. Downloads can contain source context, notes, paths and hashes: inspect before sharing.

CSV has a consistent `record_type` column: `signal` rows contain findings; `metadata` rows carry scope, coverage and comparison. It is UTF-8 with BOM. SARIF uses warning/note presentation levels, explicit unverified-exploitability properties, code-flow locations, review states and baseline states; importing into a third-party platform is not independently certified.

## Public website and updating

[Open the public workbench](https://serennity007.github.io/xss-audit-desktop/) — **web 0.2.0**, independently hosted on GitHub Pages. On 2026-10-29 the public site completed the synthetic example (2 files / 6 signals / 3 high-priority signals), followed by an identical-baseline comparison (0 new / 6 unchanged / 0 not observed). See the [public deployment receipt](../docs/verification/web-0.2.0-public.json). This address does not depend on WorkBuddy.

To republish this repository with an already authenticated GitHub CLI and repository administration access, run from `web/`:

```powershell
npm run build
node scripts/deploy-pages.mjs
node scripts/deploy-pages.mjs --publish
```

The first deployment command only previews the files and hashes. `--publish` pushes the seven built static files, `.nojekyll` and `deployment.json` to `gh-pages`, without switching or staging the source checkout or force-pushing. It configures branch-based Pages only when no Pages configuration exists; an existing different source is preserved and reported. Wait for GitHub's Pages build to finish before checking the public address. Source changes require a new build and deployment; publishing a release alone does not update the website.

See [release changes](CHANGELOG.md) and [local 0.2.0 verification](../docs/verification/web-0.2.0-local.json). HTTPS deployment needs no analysis server or runtime network connection. The build versions asset URLs and bundles the parsers only into the Worker. The earlier [WorkBuddy preview](https://xss-audit-studio.app.workbuddy.host/?sharecode=JHJQZE62LQ) remains a separate **0.1.0** deployment; it was not updated in this release. [WorkBuddy handoff](WORKBUDDY.md) is optional if a submission specifically requires that host or a sharecode. The application link and creation-conversation link are distinct.

## 中文

0.2.0 提供目录／多文件导入、明确的包含与排除规则、跳过清单、逐文件覆盖、JS／TS 局部 AST 证据，以及 HTML／Vue／Svelte 的有限内联脚本提取。组件模板、框架语义和跨脚本传播未覆盖，会明确显示缺口。默认中文，可切换英文。

可按优先级、类别、证据方式、复核状态、当前文件、关键词和基线状态组合筛选。支持单项／全部复制、人工复核与五种导出：JSON、Markdown、离线 HTML、CSV、SARIF。导出包含全量结果与范围说明。CSV 防公式注入，HTML 转义源码和备注并禁用脚本。

基线对比只接收当前网页引擎的完整 JSON；整文件摘要变化后保守按新增线索处理。“本次未观察到”不表示已修复，不会自动改人工判断。组件文件因为存在模板覆盖缺口，当前不能用于建立完整基线。旧网页版本和桌面报告不能混用。

按上方命令构建，将 web/dist 全部文件部署到 HTTPS 静态网站。目录导入会替换当前页面项目，文件导入会追加；依赖和构建目录默认跳过，不读取被跳过文件的内容。改变范围后需重新导入才能恢复未读取的文件。源码、基线和导入清单仅保留在页面内存；本机存储只保存最多 500 条复核判断、备注、时间和摘要。没有 ZIP／GitHub 在线导入、Python、完整跨文件分析、AI 审查或动态验证，不会运行用户代码。

当前主站为 [GitHub Pages 网页版](https://serennity007.github.io/xss-audit-desktop/)，已部署 0.2.0 并实际跑通样例与基线对比。按上方命令预览部署清单，再使用 `--publish` 更新 `gh-pages`；不会切换源码分支或强制推送。GitHub Pages 构建完成后才会更新线上内容。

旧 WorkBuddy 站点独立保留在 0.1.0，本次未操作。如活动明确要求 WorkBuddy 发布和 sharecode，再按可选交接文档操作；普通公开使用直接打开 GitHub Pages 即可。参赛应用链接与创作对话分享链接需分别获取。
