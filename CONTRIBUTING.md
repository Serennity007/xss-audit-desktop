[English](CONTRIBUTING.md) · [简体中文](docs/CONTRIBUTING.zh-CN.md)

# Contributing

Thank you for helping improve XSS Audit Desktop. You can contribute a minimal parser case, reduce a false positive, clarify evidence, improve a report or correct a translation.

## Choose the right channel

| What you found | Where to send it |
| --- | --- |
| A reproducible application bug | [Bug report](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=bug_report.yml) |
| A signal that appears incorrect or a missed case | [Detection feedback](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=detection_feedback.yml) |
| A workflow the app could support better | [Feature request](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=feature_request.yml) |
| A vulnerability in this application | Follow [SECURITY.md](SECURITY.md); keep sensitive details out of public issues. |

English and Simplified Chinese are welcome. Share synthetic or sanitized examples that you have permission to disclose. Remove credentials, private repository content and confidential report excerpts.

## Set up a development environment

Python 3.11+ is required. On Windows, from your clone:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m xss_audit examples/demo-project --no-saved-review --lang en
```

The GUI needs Tkinter and a usable display. Some GUI tests skip when that environment is unavailable; include skipped tests in your validation notes. The sample project contains deliberately risky source for static inspection. Do not execute it.

## Make a reviewable change

- Keep a pull request focused on one problem and explain the observable behavior before and after the change.
- For scanner changes, include a small risky case and a nearby safe comparison when applicable. Assert the evidence, location and scope that matter, rather than only a finding count.
- Preserve rule identifiers, fingerprints and canonical status values unless the change includes a compatibility plan for saved reviews and exports.
- Keep user-facing English and Chinese text aligned. Source code, paths, identifiers and existing AI output should retain their original content.
- For report or AI changes, check HTML escaping, secret handling and the recorded source scope. Use local mock endpoints in tests; do not require a paid account or real credentials.
- Retain upstream attribution and add third-party notices when introducing a dependency. Explain why the dependency is needed.

## Before opening a pull request

Run the relevant regression tests and the complete suite when your change affects shared scanning, reports, imports, AI transport or localization. Report the exact commands, results and skips. If you changed documentation, check relative links and use the documented CLI examples.

Describe what remains untested. Claims about better detection need reproducible examples; passing unit tests does not establish precision, recall or exploitability. Use [the analysis boundary document](docs/ANALYSIS.en.md) to keep feature descriptions aligned with the implementation.

The maintainer will assess the change, compatibility and verification evidence before merging. Discuss large changes before investing in an implementation. Keep feedback specific to the code and treat contributors respectfully.

## License

Contributions are distributed under the repository's [MIT License](LICENSE). Preserve the [upstream attribution](NOTICE.md) and applicable third-party notices.
