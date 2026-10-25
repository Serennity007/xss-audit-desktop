## XSS Audit v0.2.0

Windows x64 桌面版与 CLI 全面升级；两个版本均内置可选 AI 辅助审计。

### 新增

- 直接导入公开 GitHub 仓库，支持默认分支及指定分支 / 标签 / commit，无需安装 Git。
- JS / JSX / TS / TSX 使用 Tree-sitter，Python 使用 AST，追踪部分常见输入到危险位置的路径。
- 原 14 类 XSS 线索之外，增加 SQL、Shell、文件路径、SSRF、反序列化与凭据复核类别。
- 统计概览、优先级与关键词筛选、上下文、来源 / 传播 / 调用证据及修复建议。
- 本地保存误报、确认风险、已修复等标记与备注，再次扫描恢复相同线索的记录。
- 新增可离线搜索的 HTML 报告和 SARIF 2.1.0；保留 Markdown / JSON。
- AI 优先收录有证据的文件，对识别出的凭据尽力遮蔽；可保存不含密钥的接口配置。
- ZIP 附带合成示例项目和离线示例报告。

### 下载

- `XSS-Audit-v0.2.0-windows-x64.zip`：推荐，含两种 EXE、说明、示例、第三方 MIT 许可和原始规则。
- `XSS-Audit-Desktop.exe`：中文审计工作台。
- `xss-audit-cli.exe`：终端与 CI 使用，`--help` 查看参数。
- `SHA256SUMS.txt`：附件 SHA-256 校验值。

两个程序均内置 AI；配置自己的 API Key、Base URL、模型名，选择 Responses 或 Chat Completions 格式。无需第三个 EXE。

### 已知限制

- 优先级是人工复核顺序，不是已证实漏洞等级。规则与有限 AST 分析不覆盖完整跨文件 / 跨函数链。零匹配不代表安全。
- AI 需要配置接口与额度，会发送所选代码，最多约 18 万字符，报告列出未发送文件。AI 结论未独立验证。
- AI 协议通过模拟服务测试，未进行真实付费模型联调；审计质量未经基准评测。
- 遮蔽不能保证识别所有秘密；代码发送和分享报告前仍需检查。复核记录依据邻近代码摘要，不能替代语义差异审计。
- 仅支持 UTF-8，排除依赖 / 生成目录，单文件 1 MiB、总计 100 MiB / 10000 文件 / 10000 线索上限。
- Windows x64 便携程序，无安装器、签名和自动更新。
- 当前登录权限不含 `workflow`，自动构建工作流以 `docs/workflows/` 模板提供，尚未启用。

独立衍生自 [songjianyang/xss-audit](https://github.com/songjianyang/xss-audit)，保留 MIT 许可与上游原文。
