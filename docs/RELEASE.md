## XSS Audit v0.1.0

首个 Windows x64 便携版：桌面、命令行及内置 AI 辅助审计。

### 下载

- `XSS-Audit-v0.1.0-windows-x64.zip`：推荐，含两种 EXE、说明、MIT 许可和上游审计规则。
- `XSS-Audit-Desktop.exe`：中文界面，选择文件夹扫描，按类别查看线索，导出 Markdown / JSON。
- `xss-audit-cli.exe`：终端与 CI 使用，`--help` 查看参数。
- `SHA256SUMS.txt`：附件 SHA-256 校验值。

两个程序均内置 AI；配置自己的 API Key、Base URL、模型名，选择 Responses 或 Chat Completions 格式。无需第三个 EXE。

### 已知限制

- 本地扫描为 14 类正则启发式线索，不做完整数据流分析或确认漏洞。零匹配不代表安全。
- AI 需要配置接口与额度，会发送所选代码，最多约 18 万字符，报告列出未发送文件。AI 结论未独立验证。
- AI 协议通过模拟服务测试，未进行真实付费模型联调；审计质量未经基准评测。
- 仅支持 UTF-8，排除依赖 / 生成目录，单文件 1 MiB、总计 100 MiB / 10000 文件 / 10000 线索上限。
- Windows x64 便携程序，无安装器、签名和自动更新。

独立衍生自 [songjianyang/xss-audit](https://github.com/songjianyang/xss-audit)，保留 MIT 许可与上游原文。
