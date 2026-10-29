# Changelog

Release dates below use Asia/Shanghai. Downloadable binaries remain versioned separately from documentation updates on `main`.

## [0.4.0](https://github.com/Serennity007/xss-audit-desktop/releases/tag/v0.4.0) · 2026-10-29

### Windows desktop and CLI

- Package the previously source-only project configuration, per-file coverage, conservative baselines and retained review history in both Windows executables.
- Add `.xss-audit.toml` include/exclude scope and resource budgets, CLI `--config` / `--allow-partial`, and explicit coverage failures. Strict incomplete scans preserve reports and return 2.
- Compare complete JSON baselines in the desktop or with CLI `--baseline` / `--only-new`. Distinguish new, unchanged and no-longer-observed signals; missing signals never automatically become fixed. Incomplete/filtered baselines are rejected.
- Preserve distinct source snapshots and duplicate finding instances in saved review history. Add a desktop review-status filter and invalidate old decisions when full-file evidence changes.
- Add selected HTML `srcdoc` and jQuery setters, static Python import aliases and context expressions. Locally overridden sanitizer names no longer suppress HTML evidence automatically.
- Skip marked generated audit reports on subsequent source scans.
- Identify version 0.4.0 in Windows file properties. Bundle bilingual usage/configuration guides, example configuration, release notes, licenses and inert fixtures.
- Record 148 local regression checks (145 passed, 3 skipped for Windows symlink permission) and 17 checks of the actual frozen CLI. These verify implementation, not detection precision/recall.

### Independently deployed browser workbench

- Publish [web 0.2.0 on GitHub Pages](https://serennity007.github.io/xss-audit-desktop/) with a bounded static-only deployment script and a SHA-256 deployment manifest. Basic live-site analysis and baseline comparison were observed.
- Browser features and limits are versioned separately in the [web changelog](web/CHANGELOG.md). The earlier WorkBuddy deployment was not updated.

### Python-source research tools

- Include a repository-auditor robustness platform: unchanged-source context pairs, external oracle labels, bounded multi-file agent transcripts, strict JSON actions, exposed-line evidence checks, balanced repeated trials and separate detection/localization/evidence regression proxies.
- Run through `python -m xss_audit.research_cli`; this is not an additional frozen Windows entrypoint. Scripted synthetic demonstrations are separate from live-model results. No measured real-model performance or paper novelty is claimed. See [English](docs/ROBUSTNESS.en.md) / [中文](docs/ROBUSTNESS.zh-CN.md).

Details: [release notes](docs/RELEASE-v0.4.0.md) · [verification](docs/verification/v0.4.0-local.json) · [scan configuration](docs/SCAN-CONFIG.en.md).

## [0.3.0](https://github.com/Serennity007/xss-audit-desktop/releases/tag/v0.3.0) · 2026-10-26

- Add English and Simplified Chinese to the same Windows desktop and CLI executables; default to English.
- Localize CLI help, interface text, Markdown/HTML output and SARIF messages; request the selected AI-response language.
- Preserve canonical identifiers, saved-review compatibility, source snippets, paths, notes and existing AI output.
- Provide English-default documentation, Chinese guides and bilingual example reports.

Detailed changes and boundaries: [v0.3.0 release notes](docs/RELEASE-v0.3.0.md).

## [0.2.0](https://github.com/Serennity007/xss-audit-desktop/releases/tag/v0.2.0) · 2026-10-25

Introduce limited AST evidence, public GitHub import and the review workbench. See the linked release for its original notes and assets.

## [0.1.0](https://github.com/Serennity007/xss-audit-desktop/releases/tag/v0.1.0) · 2026-10-25

First published desktop, CLI and optional AI-review release derived from the upstream audit Skill. See the linked release for its original notes and assets.

## 中文说明

上方日期按北京时间记录。`main` 中的文档和维护规范更新不代表发布了新的二进制；当前 Windows 软件正式版本为 `v0.4.0`，网页独立版本为 `0.2.0`。可通过对应 Release 查看各版本原始说明、程序与校验文件。
