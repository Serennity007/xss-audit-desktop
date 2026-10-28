# Changelog

Release dates below use Asia/Shanghai. Downloadable binaries remain versioned separately from documentation updates on `main`.

## Unreleased

- Add a browser-local bilingual JS/TS/JSX/TSX workbench in web/, with bounded Babel AST evidence, pattern review, disposable analysis Workers, file editing/import, persisted review decisions and three offline report formats. Includes static build and WorkBuddy deployment handoff; no public deployment is claimed.

- Add desktop baseline comparison and a new-signals view, CLI --baseline / --only-new, and comparison metadata in JSON, Markdown, HTML and SARIF. Missing signals are not classified as fixed; incomplete and filtered baselines are rejected. Available from source; not included in v0.3.0 binaries.

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
