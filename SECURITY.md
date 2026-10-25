[English](SECURITY.md) · [简体中文](docs/SECURITY.zh-CN.md)

# Security policy

## Report a vulnerability privately

Use **[GitHub private vulnerability reporting](https://github.com/Serennity007/xss-audit-desktop/security/advisories/new)** for a suspected vulnerability in XSS Audit Desktop itself. This keeps the initial report between you and the repository maintainers.

Include the affected version or source commit, operating system, entrypoint, minimal reproduction, expected security boundary, observed behavior and impact. Use a synthetic project or archive when possible. Remove real credentials and unrelated private data.

Relevant examples include archive extraction escaping its destination, unexpected execution of imported code, credential disclosure, or an export that allows unintended active content. Explain the conditions needed to reproduce the behavior; do not test against systems you do not own or have permission to assess.

Unsafe audit instructions, malicious repository content, accidental private data, unintended file reads and source transmission without opt-in are also in scope.

Coordinate disclosure through the private report while the maintainer investigates. Response time depends on maintainer availability; a minimal reproduction helps assessment. No bug-bounty program is offered by this repository.

## Version policy

Start with the **latest published release**, currently `v0.3.0`, or identify the exact source commit. For historical `v0.1.x` / `v0.2.x` reports, check whether the issue reproduces in the latest release. This policy does not promise backports or a fixed support period. See [release history](CHANGELOG.md).

## Detection feedback is a different report

A scanner match in a project you examine is not evidence that XSS Audit Desktop itself is vulnerable. Report vulnerabilities in other projects to their maintainers using their disclosure process. For sanitized false-positive or missed-pattern examples, use [detection feedback](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=detection_feedback.yml).

## Handling source code

Local scans read source files without executing project code or installing project dependencies. GitHub import downloads public repository snapshots. Optional AI review sends the selected source scope to the configured provider only after the desktop confirmation or explicit CLI `--ai` option.

Review source and reports before sharing them. Best-effort credential masking is incomplete. The app does not persist the API key, but provider billing, access and retention remain provider-controlled. Read the [detailed guide](docs/USAGE.en.md#optional-ai-review) and [analysis boundaries](docs/ANALYSIS.en.md).
