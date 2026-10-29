# Verification records

Current browser workbench: [0.3.0 verification](verification/web-0.3.0-local.json) — source checks and built-bundle DOM/Worker integration; native-browser layout/permissions/file pickers were not retested in this run. The earlier public-browser record below remains historical.

Current Windows release: [Windows v0.4.0 verification](verification/v0.4.0-local.json) — 148 regression tests (145 passed, 3 skipped) and 17 frozen-CLI checks; desktop launch and synthetic scan observed. [Public web 0.2.0 deployment](verification/web-0.2.0-public.json) records the independent GitHub Pages build and basic live-browser flow. [Web local verification](verification/web-0.2.0-local.json) covers the broader browser acceptance checks.

当前版本验证：Windows v0.4.0 的 148 项回归检查中 145 通过、3 项因本机符号链接权限跳过，打包 CLI 的 17 项检查通过；桌面已实际启动并扫描合成样例。公开网页独立部署至 GitHub Pages，基本分析与基线对比已实测。以下保留 v0.3.0 原始记录，便于区分版本与验证范围。

# Historical local verification · v0.3.0

This is a local implementation check of the existing application and portable CLI. The [machine-readable receipt](verification/v0.3.0-local.json) records the observation time, source commit, runtime/test Git trees, environment and commands. The [test log](verification/v0.3.0-tests.txt) retains individual outcomes; machine-local project and temporary-directory prefixes are replaced with placeholders.

## Observed results

| Check | Result |
| --- | --- |
| Unit/regression suite | **43 passed, 1 skipped**, 0 failures, 0 errors; 44 tests discovered. |
| Desktop event loop | Scan, filtering, details, saved review and four export formats passed in the GUI regression test. |
| Desktop language handling | English/Chinese switching and saved-review preservation passed in the localization test. |
| Portable CLI | **8 checks passed**: English and Chinese × Markdown, JSON, HTML and SARIF. |
| Synthetic input | 2 files, 11 review signals in each JSON smoke result; AST analysis reported complete for this fixture. |
| Release files | Local portable CLI, desktop EXE and ZIP match the v0.3.0 checksum list; exact hashes are in the receipt. |

`test_audit.AuditTests.test_symlink_is_not_followed` skipped because this Windows session lacked permission to create a symbolic link. That specific test remains unverified in this run. The GUI tests did not skip.

Console messages such as “file exists,” missing AI credentials and incomplete scan appear in tests that exercise those failure paths; the test log reports their assertions separately. No paid model or third-party project was used for these checks.

## Reproduce the checks

From the project clone, create an isolated Python 3.11+ environment and install the package before running the suite:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

To check the downloaded portable program, run from the extracted release ZIP:

```powershell
New-Item -ItemType Directory -Force .\verification-output | Out-Null
.\xss-audit-cli.exe .\examples\demo-project --no-saved-review --lang en --format json -o .\verification-output\demo.en.json
.\xss-audit-cli.exe .\examples\demo-project --no-saved-review --lang zh-CN --format sarif -o .\verification-output\demo.zh-CN.sarif
Get-FileHash -Algorithm SHA256 .\xss-audit-cli.exe
```

Use a fresh output filename for each run: the application refuses to overwrite reports. Compare downloads against the release's `SHA256SUMS.txt`. The synthetic source is for scanning, not execution.

## Scope of this evidence

These results show specific behavior in the recorded Windows/Python environment. They do not establish detection precision/recall, exploitability, whole-repository coverage, paid-provider compatibility or equivalent results on macOS/Linux. The source-tree identifiers let readers distinguish this snapshot from later code changes.

The workflow YAML files under `docs/workflows/` are **templates, not active hosted CI**. The publishing credential used for this release lacks GitHub `workflow` scope. This record is not a CI status, signed build attestation or byte-for-byte reproducibility claim. Hashes establish consistency with the referenced release files, not publisher identity or source-to-binary provenance.

See [analysis boundaries](ANALYSIS.en.md), [language coverage](LANGUAGES.md) and the [changelog](../CHANGELOG.md).

## 中文

本次本地验证发现 44 项测试：**43 项通过、1 项跳过，失败和错误均为 0**。跳过项是 `test_symlink_is_not_followed`，原因是当前 Windows 会话无创建符号链接权限；GUI 扫描、筛选、详情、复核记录、导出及中英切换测试均已通过。

便携 CLI 另外完成 **8 组检查**：中英两种语言分别导出 Markdown、JSON、HTML、SARIF。构造输入为 2 个文件，两种 JSON 输出各有 11 条复核线索，此样例未报告 AST 不完整。发布文件与本地 v0.3.0 校验清单一致。

[JSON 记录](verification/v0.3.0-local.json)包含实际时点、环境、源码和测试树标识；[测试日志](verification/v0.3.0-tests.txt)保留逐项结果，并去掉本机目录前缀。它们属于本地实现验证，不是托管 CI、签名构建证明或检测质量评测，也不能证明可利用性或完整覆盖。未在本次验证中执行 macOS／Linux，也未使用付费真实模型。
