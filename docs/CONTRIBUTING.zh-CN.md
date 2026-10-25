[English](../CONTRIBUTING.md) · [简体中文](CONTRIBUTING.zh-CN.md)

# 贡献指南

欢迎补充最小解析案例、减少误报、改进证据解释、完善报告或修正翻译。

## 反馈入口

| 问题 | 入口 |
| --- | --- |
| 可复现的软件错误 | [Bug 报告](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=bug_report.yml) |
| 疑似误报或漏报 | [检测反馈](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=detection_feedback.yml) |
| 工作流或功能建议 | [功能建议](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=feature_request.yml) |
| 本软件自身的安全漏洞 | 遵循[安全报告政策](SECURITY.zh-CN.md)，不要公开敏感细节。 |

接受英语和简体中文反馈。请提供有权公开的构造或去敏示例，移除密钥、私有仓库源码与保密报告片段。

## 开发环境

需要 Python 3.11+。在 Windows 克隆目录运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m xss_audit examples/demo-project --no-saved-review --lang zh-CN
```

GUI 需要 Tkinter 和可用显示环境。部分 GUI 测试可能因环境条件跳过，请在验证记录中如实说明。示例项目刻意包含风险代码，仅用于静态检查，不要执行。

## 提交可审查的修改

- 一个 Pull Request 聚焦一个问题，说明修改前后可以观察到的行为。
- 修改扫描逻辑时，尽量同时提供最小风险案例和安全对照；断言有意义的证据、位置和范围，不只比较线索数量。
- 保持规则 ID、指纹和原始状态值兼容；需要调整时，说明已有复核记录和导出格式如何迁移。
- 用户可见的中英文字保持对应；源码、路径、标识及已有 AI 文本保留原内容。
- 修改报告或 AI 传输时，检查 HTML 转义、敏感值处理和实际发送范围；使用本地模拟接口测试，不依赖付费账户或真实密钥。
- 保留上游署名；引入依赖时说明用途并补充第三方许可。

## 提交前验证

运行相关回归测试。涉及共享扫描、报告、导入、AI 传输或本地化时，运行完整测试；提供实际命令、结果和跳过项。文档修改应检查相对链接并试用写出的 CLI 示例。

说明尚未验证的部分。检测改进需要可复现案例，单元测试通过不能证明精确率、召回率或可利用性。功能描述应符合[分析边界](ANALYSIS.md)。

维护者会审查修改、兼容性和验证证据。较大的变更建议先讨论使用场景；交流时聚焦代码，尊重贡献者。

## 许可

贡献沿用仓库的 [MIT 许可](../LICENSE)，保留[上游署名](../NOTICE.md)及适用的第三方许可。
