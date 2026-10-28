# Changelog

Release dates below use Asia/Shanghai. Downloadable binaries remain versioned separately from documentation updates on `main`.

## Unreleased

- Add shared `.xss-audit.toml` scan scope, include/exclude globs and resource budgets, with CLI `--config` and `--allow-partial` controls.
- Record per-file analysis depth and coverage failures in desktop and exported reports. Strict CLI scans return 2 for unreadable/oversized supported source and projects without readable source.
- Recognize generated JSON/HTML audit reports so repeated scans do not report their own output as application code.
- Keep review decisions across snapshots and independent windows; separate duplicate finding instances and invalidate decisions when source-file evidence changes. Preserve unambiguous legacy review records.
- Add a desktop review-status filter.
- Extend HTML flow evidence to `srcdoc` and direct jQuery HTML setters; resolve static Python import aliases and analyze `with` / `async with` context expressions. Locally overridden sanitizer names no longer suppress HTML evidence.
- Add focused regressions for scan configuration, repeated exports, coverage policy, review history and the added analyzer models. See [scan configuration](docs/SCAN-CONFIG.en.md) / [扫描配置](docs/SCAN-CONFIG.zh-CN.md).

- Refresh the English-default README and Chinese edition with a product banner, download links, a source example and task-oriented navigation.
- Retain detailed usage in separate English and Chinese guides.
- Add contribution and security-reporting policies, structured issue forms, a pull-request checklist and a documentation index.
- Publish a local verification record with actual test outcomes, skipped checks and portable-CLI smoke results. See [verification](docs/VERIFICATION.md).

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

上方日期按北京时间记录。`main` 中的文档和维护规范更新不代表发布了新的二进制；当前软件正式版本仍为 `v0.3.0`。可通过对应 Release 查看各版本原始说明、程序与校验文件。
