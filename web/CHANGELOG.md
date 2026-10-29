# Browser release history

## 0.3.0 — 2026-10-29

Complete offline project handoffs and repeatable review tasks; retain AST engine 0.2.0 identities and baselines.

- Add bounded local ZIP import in a disposable Worker, including path/link/collision/header checks, declared/actual inflation limits and CRC-32 verification of accepted sources. Keep scope exclusions and skipped inventory. Reject unsupported archive formats explicitly.
- Download/restore a full-source project snapshot with saved decisions, scope, skipped paths and an optional complete baseline. Restored decisions require a fresh identity match, remain session-local until saved and carry imported provenance in evidence/reports. Full-source download is explicitly disclosed and confirmed.
- Search literal text across loaded files, navigate to original lines/columns, select ASCII case handling and bound results to 200 rows. This is text navigation, not cross-file flow analysis.
- Apply a manually confirmed review status only to current filtered IDs, preserving saved notes. Export continues to include all signals. Stale IDs are rejected before mutation.
- Add source and built-bundle DOM integration using real Node-backed analysis/import Workers, covering restoration, batch scope, cancellation, superseded imports and language switches. This does not replace native-browser, layout, permission or file-dialog verification.
- Bundle fflate 0.8.3 (MIT) locally in the Worker; no runtime network requests. LinkeDOM is a development-only DOM test dependency.
- Add packaging of the static build, exact committed source archive and checksums. Windows v0.4.0 binaries are unchanged.

中文：新增离线 ZIP、源码快照、跨文件字面搜索与批量复核；现有 0.2.0 引擎身份和基线继续兼容。快照含完整源码，恢复记录标注来源，仍需重新分析和人工复核。

## 0.2.0 — 2026-10-29

Turn the single-run browser workbench into a repeatable project review workflow.

- Folder import keeps relative paths, skips dependency/build directories before reading content, and exports the skipped-path inventory. Failed or superseded imports preserve the current project.
- Explicit bounded include/exclude patterns, effective scope and per-file completion records. Finding limits keep the remaining files visible as unprocessed.
- Limited HTML/Vue/Svelte inline JS/TS extraction preserves original positions. External/JSON/unsupported/unclosed scripts and unmodeled templates remain explicit coverage gaps. No user source is executed.
- Combined priority, category, evidence, saved-status, current-file, keyword and comparison filters, plus per-file signal counts and a keyboard analysis shortcut.
- Full JSON baselines distinguish new/unchanged/not-observed signals without auto-fixing anything. Source and baseline data stay in memory; incomplete or incompatible baselines are rejected.
- CSV with formula protection, SARIF 2.1.0 with flow locations, more readable Markdown, and existing JSON/offline HTML. All five formats retain full scope and coverage regardless of UI filters.
- Bounded finding excerpts prevent long minified lines/identifiers from expanding every result into a whole-file copy; truncation is disclosed in the UI and exports.
- Static computed property names are recognized. Local or overwritten sanitizer names cannot lower priority solely by name. Recognition is still a limited approximation, not proof of safe output.
- Babel/parse5 parsing is confined to the disposable Worker; the smaller UI bundle and versioned asset URLs improve initial load and update behavior.
- Added regression tests for imports, bounds, original coordinates, sanitizer shadowing, conservative comparisons, exports and filters. See the verification receipt for observed checks and exclusions.

Engine identities change in this release. Old local decisions are retained but not attached to 0.2.0 signals. The WorkBuddy 0.1.0 public preview requires a separate redeployment. Windows v0.3.0 executables are unchanged.

## 中文

0.2.0 新增项目目录导入与范围控制、HTML／Vue／Svelte 内联脚本审查、组合筛选、前后版本对比，以及 CSV／SARIF 导出。保留逐文件覆盖和被跳过文件清单；未再观察到的线索不会自动标成修复。

该版本仍是有限静态复核工具，不证明可利用性和检测准确率，不完整覆盖模板、跨文件或框架生命周期。新版部署包需要在 WorkBuddy 重新发布，原 Windows EXE 不受此次更新影响。
