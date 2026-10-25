# XSS Audit v0.3.0 — English / 简体中文

## English

The Windows desktop app and CLI now support English and Simplified Chinese in the **same executables**. English is the default.

- Switch language in the desktop selector; the choice is saved locally. Scanning/requesting disables switching until the operation finishes.
- Use `--lang en` / `--lang zh-CN` for CLI help, diagnostics, Markdown/HTML reports and SARIF messages. AI requests ask for that language.
- Rule IDs, finding fingerprints and existing review decisions remain compatible. JSON/SARIF retain canonical status fields and add localized labels.
- Paths, source snippets, user notes and existing model output remain verbatim; language switching never silently resends code to AI.
- `README.md` is English by default, with `README.zh-CN.md`, a language-coverage guide, English/Chinese analysis notes and example reports.

Download `XSS-Audit-v0.3.0-windows-x64.zip`, extract it and run `XSS-Audit-Desktop.exe`. `xss-audit-cli.exe` is the terminal entry. Neither needs Python installed. Verify downloads with `SHA256SUMS.txt`.

These are unverified review signals, not confirmed vulnerabilities. Analysis remains limited; masking is best-effort. AI requires your own endpoint/key and has only been tested with mock responses, not a paid production model. Windows x64 only; no installer, signature or automatic updater. Original upstream instructions and historical material retain their original language.

## 简体中文

Windows 桌面版和命令行版现在由**同一份可执行文件**支持英语与简体中文，默认英语。

- 桌面右上角切换语言并保存本机偏好；扫描或请求中暂不切换。
- CLI 用 `--lang en`／`--lang zh-CN` 选择提示、Markdown/HTML 报告与 SARIF 消息语言；AI 请求同步指定语言。
- 规则 ID、指纹和已有复核记录保持兼容；JSON/SARIF 保留原始状态字段并增加显示标签。
- 路径、代码、用户备注和已有模型文本保持原样，切换语言不会暗中重新发送代码给 AI。
- 默认 README 改为英语，保留中文指南，补充语言范围说明、中英文分析文档及示例报告。

下载 `XSS-Audit-v0.3.0-windows-x64.zip`，解压运行 `XSS-Audit-Desktop.exe`；终端入口为 `xss-audit-cli.exe`。无需安装 Python。附件校验值见 `SHA256SUMS.txt`。

检测结果仍是待复核线索，不是已证实漏洞。分析范围有限，敏感值遮蔽不保证完整；AI 需要自配接口与密钥，仅完成模拟接口测试，尚未付费真实模型联调。当前仅提供 Windows x64，无安装器、签名或自动更新。原始上游指令与历史资料保留原文。
