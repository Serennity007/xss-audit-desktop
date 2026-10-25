# Language coverage / 语言范围

## English

English is the default README and application language. The same desktop and CLI executables support English and Simplified Chinese; separate language-specific EXEs are not required.

- Desktop: select **English** or **简体中文** at the top right. The choice persists in non-secret local preferences. Switching is disabled during an active scan/request.
- CLI: `--lang en` / `--lang zh-CN`, or `XSS_AUDIT_LANG`. Human-facing descriptions, diagnostics, Markdown/HTML reports and SARIF messages use that language.
- AI: the prompt requests the selected language, recorded in request metadata. Model compliance is not guaranteed. Existing model output is not automatically translated or sent again.
- Analysis rule IDs, fingerprints and stored review decisions do not change with the display language. JSON/SARIF retain the previous canonical priority/status fields and add localized labels.
- Source snippets, paths, user notes, branch names and external/system messages are not rewritten. Such data can contain either language even in an English report.
- Original upstream Skill instructions and some historical documents remain as supplied. Chinese analysis documentation is retained; an English counterpart is provided.

## 简体中文

README 和应用默认使用英语。同一份桌面 EXE 和命令行 EXE 均支持英语与简体中文，无需按语言分别下载。

- 桌面版右上角选择语言并保存在本机；扫描或请求进行中不切换。
- 命令行使用 `--lang en`／`--lang zh-CN` 或 `XSS_AUDIT_LANG`；提示、Markdown/HTML 报告和 SARIF 消息随语言变化。
- AI 请求指定所选语言并记录在元数据中，但不保证模型遵从；已有模型文本不会自动重译或再次发送。
- 规则 ID、指纹和复核记录保持一致；JSON/SARIF 保留原有状态字段，另提供本地化显示标签。
- 源代码、路径、用户备注、分支名称及外部系统消息不改写，因此英语报告中仍可能出现原始中文数据。
- 原始上游 Skill 指令和历史资料保留原文；分析边界文档另附英语版本。
