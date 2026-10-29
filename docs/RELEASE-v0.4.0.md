# XSS Audit 0.4.0 — repeatable desktop reviews

The Windows desktop and CLI now package the previously source-only project configuration, coverage records, conservative baselines and retained review history. Both executables support English and Simplified Chinese.

- Use `.xss-audit.toml` to declare includes, excludes and scan budgets. Both entrypoints load the selected project's configuration. Effective scope and per-file analysis depth travel with reports.
- In the desktop, scan a project, export its full JSON report, then use **Compare baseline** against a later scan. Filter the view to new signals. CLI supports `--baseline` and `--only-new`.
- Baseline matching uses paths, rules, signal fingerprints and source-file hashes. Missing observations never automatically become fixed; source changes conservatively require fresh review. Incomplete/filtered baselines are rejected, and current coverage failures/scope changes are disclosed.
- Review history retains decisions for distinct source snapshots and duplicate occurrences. Status filtering and independent-window saves are integrated.
- Added HTML `srcdoc`/direct jQuery setter evidence, selected Python import-alias models, and conservative handling of locally overridden sanitizer names. Coverage remains bounded and category-dependent.
- Generated reports no longer get analyzed as application source on repeat scans. Strict CLI scans keep their report but return 2 on incomplete analysis; `--allow-partial` explicitly changes that exit policy.
- Windows file properties now identify the product and 0.4.0 version. The ZIP includes bilingual usage/configuration guides and an example configuration, alongside licenses and inert fixtures.

## Run

Extract `XSS-Audit-v0.4.0-windows-x64.zip`, then run `XSS-Audit-Desktop.exe`, or use `xss-audit-cli.exe` from a terminal. Python is bundled. Verify the files against `SHA256SUMS.txt`.

```powershell
.\xss-audit-cli.exe D:\project --no-saved-review --format json -o baseline.json
.\xss-audit-cli.exe D:\project --baseline baseline.json --only-new --no-saved-review --format json -o current.json
```

Keep the baseline/output outside the scanned project when practical. Output paths must be new: reports are not silently overwritten. Do not run the deliberately risky sample application.

The [public browser application](https://serennity007.github.io/xss-audit-desktop/) is versioned separately (web 0.2.0) and independently hosted on GitHub Pages. Browser and desktop engines have different formats and coverage; do not interchange baselines. The source repository also contains a Python repository-agent research harness; it is not an additional packaged Windows entrypoint or measured live-model result.

Validation: 148 local regression checks (145 passed, 3 skipped for Windows symlink permission), plus 17 checks of the actual frozen CLI, including both languages and four report formats. The frozen desktop launched and scanned the inert demo (2 files / 11 signals). The native baseline-picker flow was not completed after the UI automation connection became unavailable; baseline behavior passed in the CLI and regression checks. [Verification receipt](https://github.com/Serennity007/xss-audit-desktop/blob/main/docs/verification/v0.4.0-local.json).

These are review signals, not verified vulnerabilities. This release does not establish detection precision/recall, complete interprocedural/interfile coverage or paid-model compatibility. Optional AI sends only after explicit user action and needs your own endpoint/key. Windows 10/11 x64 portable binaries are unsigned, with no installer or automatic updater; other OS binaries are not claimed.

## 中文

0.4.0 把已完成的项目配置、逐文件覆盖、基线对比和复核历史打入 Windows 桌面版／CLI。两份 EXE 均支持英语与简体中文，默认英语。

可通过 `.xss-audit.toml` 控制项目范围和预算，按复核状态筛选，保存完整 JSON 作为基线，再对比后续扫描。未再观察到的线索不会自动标记修复，文件内容变化后保守要求重新复核。配置、覆盖缺口和比较说明随报告导出。

新版增加 Windows 文件版本信息，便携包补齐中英文使用／配置文档和示例配置。[网页 0.2.0](https://serennity007.github.io/xss-audit-desktop/) 已独立上线 GitHub Pages，覆盖和基线格式与桌面版不同；科研评测工具仍从 Python 源码运行，未据此宣称真实模型能力。

验证：148 项回归检查中 145 通过、3 项因 Windows 符号链接权限跳过；打包 CLI 的 17 项检查全部通过。桌面 EXE 已启动并扫描合成样例。桌面基线文件选择尚未完成时自动化连接中断，该界面步骤未计为通过；CLI 基线及相关回归检查已通过。

下载 ZIP，校验后解压运行桌面程序或 CLI，不需要安装 Python。自动线索仍需人工确认；Windows x64 便携程序没有代码签名、安装器和自动更新，AI 需主动启用及自备接口密钥。
