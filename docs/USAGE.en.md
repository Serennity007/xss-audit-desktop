[English](USAGE.en.md) · [简体中文](USAGE.zh-CN.md) · [Project home](../README.md)

# XSS Audit Desktop: detailed usage

A code-review workbench with a **Windows desktop app, CLI, public GitHub imports, limited AST flow evidence and optional AI review**.

Derived from [songjianyang/xss-audit](https://github.com/songjianyang/xss-audit), an MIT-licensed audit Skill. This independent derivative adds executable software and retains the [original playbook](../SKILL.md), [license](../LICENSE) and [upstream README](UPSTREAM-README.md). It is not endorsed by the upstream author.

> Automatic matches are review signals. High / Medium / Info indicate review order, not confirmed vulnerability severity. Limited AST analysis does not cover complete cross-file call chains. No matches is not proof of safety; AI conclusions also require human verification.

## Download

Download `XSS-Audit-v0.3.0-windows-x64.zip` from [Releases](https://github.com/Serennity007/xss-audit-desktop/releases/latest), then extract it:

- **XSS-Audit-Desktop.exe:** select a local folder or import a public GitHub repository, scan, inspect context/evidence, save review decisions and export a report.
- **xss-audit-cli.exe:** terminal, batch and CI entry point.
- **AI review:** included in both programs; bring your own API key. No third executable is needed.

The Windows x64 executables require no Python installation. They target Windows 10/11 and were checked on Windows 11 x64. There is no installer, code signature or automatic updater. Compare `Get-FileHash -Algorithm SHA256 filename` with `SHA256SUMS.txt`.

The ZIP includes the two executables, English/Chinese guides, licenses, a deliberately risky synthetic project under `examples/demo-project/`, and English/Chinese example reports. Do not execute or deploy the synthetic project.

## English and Chinese

English is the default. The desktop language selector switches between **English** and **简体中文** and saves the choice locally. The CLI selects its interface and report language with `--lang en` or `--lang zh-CN` (or `XSS_AUDIT_LANG`). AI requests ask for the selected language.

Source code, paths, user notes, identifiers and existing model output remain verbatim. Switching languages does not call AI or rewrite an earlier AI response. JSON/SARIF preserve the existing canonical priority/status values for compatibility and add localized display labels. See [language coverage](LANGUAGES.md).

## Capabilities

| Capability | Current implementation |
| --- | --- |
| Public GitHub import | Repository URL or `owner/repository`, optional branch/tag/commit; Git is not required |
| JavaScript / TypeScript / TSX | Tree-sitter parsing; partial source → variable → HTML / URL / dynamic-execution evidence |
| Python | AST evidence for selected SQL construction, shell, file path, SSRF, deserialization and template paths |
| Review workbench | Summary counts, category/priority/search filters, code context, evidence and guidance |
| Triage | Needs review, confirmed risk, false positive and fixed decisions with locally saved notes |
| Export | Markdown, JSON, offline searchable HTML and SARIF 2.1.0 |
| AI scope protection | Prioritizes complete files with evidence and masks recognized credentials; records actual scope and omitted files |

## CLI examples

```powershell
.\xss-audit-cli.exe "D:\projects\web-app" --format html -o "D:\reports\audit.html"
.\xss-audit-cli.exe "D:\projects\web-app" --lang zh-CN --format markdown -o "D:\reports\audit-zh.md"
.\xss-audit-cli.exe --repo "owner/repository" --ref "main" --lang en --format sarif -o "D:\reports\audit.sarif"
.\xss-audit-cli.exe "D:\projects\web-app" --min-priority high --ignore-reviewed --fail-on-match
.\xss-audit-cli.exe --help
```

The output directory must exist. Without `-o`, the CLI creates a timestamped report in the selected format and never overwrites an existing file. Exit codes: `0` complete; `1` signals exist with `--fail-on-match`; `2` error or incomplete scan/AST analysis; `130` interrupted. Exit code `1` does not establish a vulnerability.

`--no-saved-review` ignores local triage records; `--destination` selects an import directory. Desktop filters affect the view while export includes all signals. CLI priority/review filters affect exported results and are recorded in the report. The former Chinese priority arguments remain accepted for compatibility.

## GitHub snapshots and local state

Import accepts public `github.com` repository homepages or `owner/repository`; provide the ref separately. It uses GitHub's ZIP archive API without an account token. Snapshots exclude Git history, submodule contents and LFS object payloads. HTTPS redirects are restricted to official GitHub hosts.

Limits: 60 MiB compressed, 250 MiB extracted, 15,000 archive entries and 20 MiB per archive member. Extraction rejects out-of-scope paths, links, device names and case collisions. Project files are not executed and project dependencies are not installed.

Windows data lives under `%LOCALAPPDATA%\XSSAudit`: `imports` holds downloaded source and `state` holds review records and non-secret preferences. Imports are not automatically deleted. The API key is never persisted. Review identities use the project, rule, path and nearby-code digest; distant semantic changes may not invalidate a saved decision, so old decisions still need review. Records are not synchronized across machines.

## Optional AI review

Supports Responses and Chat Completions compatible endpoints. The default API base URL is `https://api.openai.com/v1`; choose a model available to your account. Endpoint compatibility, access and billing depend on the provider.

Desktop: complete a local scan, fill in the endpoint/model/key, choose **Review scope and start AI**, inspect the actual file list and confirm sending.

CLI: configure your own `OPENAI_API_KEY` and `XSS_AUDIT_MODEL`, then explicitly opt in:

```powershell
# Configure your own OPENAI_API_KEY and XSS_AUDIT_MODEL first.
.\xss-audit-cli.exe "D:\projects\web-app" --ai --lang en -o "D:\reports\ai-review.md"
.\xss-audit-cli.exe "D:\projects\web-app" --ai --lang zh-CN --api-format chat --base-url "https://your-provider.example/v1" --model "your-model"
```

`--ai` consents to sending scoped source files to the selected endpoint; API charges may apply. Recognized credential prefixes and selected sensitive assignments are masked, but unknown secrets may still be sent. Inspect sensitive content yourself. Remote endpoints require HTTPS; localhost may use HTTP. AI requests do not follow redirects or grant model execution tools. Responses requests use `store: false`, which does not guarantee the provider retains no data.

The source budget is about **180,000 characters**, prioritizing AST evidence, then pattern signals and filename. Only complete files fit; omissions are listed. The original 14-layer playbook and Python review requirements are supplied, but the client does not automatically batch or fetch more files. It does not claim whole-repository coverage. Timeout is 180 seconds; closing the application cannot retract a sent request or cancel provider charges.

Implementation follows [official OpenAI Responses documentation](https://developers.openai.com/api/docs/guides/migrate-to-responses?api-mode=responses). Protocol and language instructions are tested with a local mock service; no paid production model integration or audit-quality benchmark has been performed.

## Detection boundaries

The original 14 XSS categories are retained, with SQL, shell, path, SSRF, deserialization and credential review categories added: 20 total. Analysis depth differs by language/category; see [analysis boundaries](ANALYSIS.en.md).

- AST covers standalone Python, JS/JSX/MJS/CJS and TS/TSX files. Vue/Svelte/Astro/MDX and templates currently use pattern search only.
- Pattern search can match safe code, comments and strings. AST propagation is limited and conservative, without complete cross-file/cross-function analysis or exploitability proof. No automatic dependency-advisory lookup is performed.
- Recognized HTML sanitization does not establish URL, JavaScript or CSS safety, and sanitizer configuration/version still requires review.
- Reads UTF-8 / UTF-8 BOM only. Default exclusions include dependencies, generated output, caches and editor directories; minified JS/CSS and linked/reparse directories are skipped.
- Local scan limits: 1 MiB per file, 10,000 files, 100 MiB and 10,000 matches. Limits and parse failures are recorded; narrow the scope when incomplete.
- Exported reports contain paths and snippets. Best-effort masking is not a guarantee that all secrets were identified.

## Run from source

Python 3.11+ is required. The GUI additionally needs Tkinter (normally included with the official Windows Python installer). The CLI does not require Tkinter.

```powershell
python -m pip install .
python desktop.py
python -m xss_audit "D:\projects\web-app" --lang en
python -m unittest discover -s tests -v
xss-audit --version
```

The source CLI can run on other Python 3.11+ systems; published binaries currently target Windows x64.

## Build and release

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/build_release.py
```

`release/v0.3.0/` contains the two EXEs, portable ZIP and SHA-256 checksums; earlier version directories remain available. Parser notices are included in [THIRD-PARTY-NOTICES.txt](../THIRD-PARTY-NOTICES.txt). Packaging uses [PyInstaller](https://pyinstaller.org/en/stable/usage.html); indirect build dependencies are not fully locked, so byte-for-byte reproducibility is not claimed.

Optional Actions templates live in `docs/workflows/`. They are not enabled because the current GitHub credential lacks `workflow` scope. Local builds and validation are used for this release.

## License

[MIT](../LICENSE). Attribution and derivative scope are in [NOTICE.md](../NOTICE.md). Review code you own or are authorized to assess.
