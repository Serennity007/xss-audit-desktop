[English](README.md) · [简体中文](README.zh-CN.md)

<p align="center">
  <img src=".github/cover.svg" alt="XSS Audit Desktop：源码安全审查、AST 证据、人工复核与报告导出" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Serennity007/xss-audit-desktop/releases/latest"><img alt="最新发布" src="https://img.shields.io/github/v/release/Serennity007/xss-audit-desktop?style=flat-square&amp;color=147d78"></a>
  <img alt="Windows 10 / 11 x64" src="https://img.shields.io/badge/Desktop-Windows%2010%20%2F%2011%20x64-147d78?style=flat-square">
  <img alt="英语与简体中文" src="https://img.shields.io/badge/Language-English%20%2F%20简体中文-147d78?style=flat-square">
  <a href="LICENSE"><img alt="MIT 许可" src="https://img.shields.io/badge/License-MIT-147d78?style=flat-square"></a>
</p>

# XSS Audit Desktop

新增[浏览器工作台](web/README.md#中文)：本地分析 JS／TS／JSX／TSX，查看证据、保存人工复核并导出 JSON／Markdown／离线 HTML。可构建为静态网站，覆盖范围与桌面版不同。[WorkBuddy 发布交接](web/WORKBUDDY.md)。目前尚未发布公开网页链接。

源码新增：桌面与 CLI 已支持基线对比，区分新增、持续出现和本次未再观察到的线索，见[使用说明](docs/USAGE.zh-CN.md#扫描基线对比未发布源码功能)。此改动尚未包含在已发布的 v0.3.0 EXE 中。后续扩展及验收条件见[优化路线](docs/ROADMAP.md#中文)。

**在同一个工作台查看源码上下文、数据流证据与人工复核记录。**

选择本地项目，或导入公开 GitHub 仓库，审查 JavaScript、TypeScript 与 Python 中的安全线索，保存判断，再导出可搜索的 HTML 或 SARIF 报告。桌面版用于交互复核，命令行版用于重复检查和批处理。

本地静态扫描无需 API Key。需要 AI 辅助时，再使用自己的接口、模型和密钥启用。

`main` 的功能更新现已支持项目扫描配置、逐文件覆盖说明、跨快照复核记录保留及状态筛选，并补充部分 HTML / Python 数据流模型。[配置与行为变化](docs/SCAN-CONFIG.zh-CN.md)包含使用方法及复核记录兼容说明；下方 v0.3.0 下载仍是已发布的旧版二进制。

源码另提供[仓库级审计鲁棒性研究平台](docs/ROBUSTNESS.zh-CN.md)：构建源码不变、README 上下文不同的实验对，记录受控多文件审计轨迹，并分别分析检出、定位和证据退化。可运行 `python -m xss_audit.research_cli demo --output D:\audit-research\demo --offline-demo` 查看合成演示；演示使用脚本响应，不代表真实模型效果。

**[下载 Windows 版](https://github.com/Serennity007/xss-audit-desktop/releases/latest)** · [试用示例](#先用附带示例体验) · [文档导航](docs/README.md) · [验证记录](docs/VERIFICATION.md#中文) · [参与贡献](docs/CONTRIBUTING.zh-CN.md)

## 下载即用

下载 **[XSS-Audit-v0.3.0-windows-x64.zip](https://github.com/Serennity007/xss-audit-desktop/releases/download/v0.3.0/XSS-Audit-v0.3.0-windows-x64.zip)**，解压后选择入口：

| 程序 | 用途 |
| --- | --- |
| **`XSS-Audit-Desktop.exe`** | 导入项目、扫描、检查上下文和证据、保存复核标记、导出报告。 |
| **`xss-audit-cli.exe`** | 在终端、批处理任务或 CI 脚本中审查本地项目或公开仓库。 |

两个程序均支持英语与简体中文，**无需预装 Python**。ZIP 另附说明、许可证、构造的审计示例和示例报告；AI 审核内置于两个程序中。

当前二进制面向 Windows 10/11 x64，已在 Windows 11 x64 验证。发布形式为便携 EXE，暂未提供安装器、代码签名或自动更新器。可用 `Get-FileHash -Algorithm SHA256` 对照发布页的 `SHA256SUMS.txt` 核验文件。源码运行需要 Python 3.11+；macOS／Linux 二进制尚未发布。

## 能用它完成什么

| 能力 | 实际使用方式 |
| --- | --- |
| **导入公开 GitHub 代码** | 输入仓库链接或 `owner/repository`，可指定分支、标签或 commit；无需安装 Git。 |
| **查看 AST 数据流线索** | 核对特定输入如何经过变量和字符串构造，到达 HTML、导航、动态执行及支持的 Python 调用；证据包含来源行和有界传播步骤。 |
| **审查多类风险写法** | 保留原 14 类 XSS 规则，增加 SQL 构造、Shell 执行、文件路径、SSRF、反序列化与凭据，共 20 个复核类别；各语言、类别的分析深度不同。 |
| **在上下文中复核** | 按优先级、类别、关键词筛选，查看代码及解释；标记待确认、确认风险、误报或已修复，并在本机保存备注。 |
| **交付可复查报告** | 导出 Markdown、JSON、离线可搜索 HTML 或 SARIF 2.1.0，保留线索、覆盖说明和复核上下文。 |
| **自行决定 AI 发送范围** | 桌面发送前检查实际纳入的完整文件列表；优先选择有证据的文件并记录遗漏，对识别出的凭据值尽力遮蔽。 |

### 一次审查的路径

1. **选定代码**：打开本地目录，或导入指定 ref 的公开仓库快照。
2. **检查线索**：核对类别、优先级、上下文和可用 AST 证据；查看跳过项、读取和解析失败，明确覆盖范围。
3. **保存判断**：记录复核状态与备注；相关代码变化后重新检查已有标记。
4. **导出结果**：分享离线报告、保存 JSON，或在兼容流程中使用 SARIF。需要第二遍阅读时，再对选定源码启用 AI。

## 先用附带示例体验

在桌面版选择 ZIP 内的 `examples/demo-project/` 扫描。也可查看[中文 HTML 示例](examples/demo-report.zh-CN.html)、[英文 HTML 示例](examples/demo-report.html)和 [Markdown 示例](examples/sample-report.md)，了解报告格式。

TypeScript 示例刻意保留了下面这条风险路径：

```tsx
const text: string = new URLSearchParams(window.location.search).get("q") ?? "";
const html = "<p>" + text + "</p>";
document.querySelector("#unsafe-preview")!.innerHTML = html;
```

复核时，把查询参数输入、字符串拼接和 HTML 写入放在一起检查。同一文件包含 `textContent` 对照，特定 AST HTML 写入规则会区分文本输出与 HTML sink；Python 示例另有参数绑定 SQL 的对照。

**示例是刻意构造的风险代码，只用于扫描，请勿运行或部署。** 实际应用中的输入约束、输出上下文和可利用性需要人工确认。

## 命令行使用

在解压目录运行，先创建报告目录：

```powershell
New-Item -ItemType Directory -Force .\reports | Out-Null

# 本地项目 → 中文离线 HTML
.\xss-audit-cli.exe "D:\projects\web-app" --lang zh-CN --format html -o ".\reports\audit.html"

# 指定 ref 的公开仓库 → SARIF
.\xss-audit-cli.exe --repo "owner/repository" --ref "main" --lang zh-CN --format sarif -o ".\reports\audit.sarif"

# 只检查高优先级且未标记为误报／已修复的线索
.\xss-audit-cli.exe "D:\projects\web-app" --min-priority high --ignore-reviewed --fail-on-match

.\xss-audit-cli.exe --lang zh-CN --help
```

不指定 `-o` 时，程序按所选格式生成带时间戳的报告，不覆盖已有文件。CLI 筛选影响导出和匹配门禁；桌面筛选只影响视图，桌面导出仍包含全部线索。

| 退出码 | 含义 |
| --- | --- |
| `0` | 完成。 |
| `1` | 使用 `--fail-on-match`，且筛选后仍有匹配线索；表示需要复核，不代表已证实漏洞数量。 |
| `2` | 错误或扫描／AST 分析不完整，需检查覆盖说明。 |
| `130` | 用户中断。 |

## 可选 AI 辅助审查

使用自己的凭据连接 Responses 或 Chat Completions 兼容接口。桌面版先展示纳入的源码文件列表，再由你确认发送；CLI 用 `--ai` 显式同意发送该范围：

```powershell
# 先配置自己的 OPENAI_API_KEY 与 XSS_AUDIT_MODEL
.\xss-audit-cli.exe "D:\projects\web-app" --ai --lang zh-CN -o ".\reports\ai-review.md"
```

源码预算约 **18 万字符**，只纳入完整文件，优先处理 AST 证据和规则线索，并列出预算外文件。请求包含原始审计手册与 Python 复核要求，不自动补读剩余仓库或分批追加请求。

应用不会保存 API Key。凭据遮蔽不能识别所有秘密，发送前仍需检查源码范围；接口访问、计费和数据保留由服务商决定。AI 传输与语言行为已用本地模拟服务验证，尚未进行付费模型联调或审计质量基准评测。[AI 参数与数据处理 →](docs/USAGE.zh-CN.md#ai-辅助审计)

## 分析覆盖与结果解释

| 输入 | 当前分析方式 |
| --- | --- |
| 独立 JS／JSX／MJS／CJS | 规则搜索与有限 Tree-sitter 数据流分析。 |
| 独立 TS／TSX | 规则搜索与有限 Tree-sitter 数据流分析。 |
| Python | 规则搜索与特定 Python 标准库 AST 数据流分析。 |
| Vue／Svelte／Astro／MDX、HTML 和支持的模板 | 规则搜索，暂不提取嵌入脚本执行 AST 分析。 |
| 支持的样式文件、SVG／XML 和 JSON | 适用的规则搜索，与源码 AST 的深度不同。 |

“高／中／信息”表示**人工复核优先级**。自动线索需要人工确认；引擎不提供完整跨文件／跨函数分析、依赖漏洞公告查询或可利用性证明，零匹配也不能证明安全。

扫描器读取 UTF-8／UTF-8 BOM，跳过常见依赖、产物、缓存和压缩文件；报告会说明上限、读取失败与解析失败。可查阅[具体分析边界](docs/ANALYSIS.md)及[详细范围与存储说明](docs/USAGE.zh-CN.md)。

## 中英双语

默认英语，通过桌面选择器或 CLI `--lang en`／`--lang zh-CN` 切换界面与报告语言；AI 请求同步指定语言。代码、路径、用户备注及已有 AI 文本保持原样，JSON／SARIF 保留原始标识并增加本地化显示字段。[语言范围说明 →](docs/LANGUAGES.md)

## 开发与贡献

由 [Serennity007](https://github.com/Serennity007) 维护。[本地验证记录](docs/VERIFICATION.md#中文)列明 **43 项测试通过、1 项跳过**，另有 **8 组便携 CLI 导出检查**通过，并说明跳过原因，区分本地验证、托管 CI 与检测质量评测。

```powershell
git clone https://github.com/Serennity007/xss-audit-desktop.git
cd xss-audit-desktop
python -m pip install .
python desktop.py
python -m xss_audit "examples/demo-project" --lang zh-CN
python -m unittest discover -s tests -v
```

需要 Python 3.11+；GUI 另需 Tkinter，CLI 不需要。源码 CLI 可在其他提供 Python 3.11+ 的系统运行。源码安装、导入控制、本机存储、构建步骤及工作流模板状态见[详细指南](docs/USAGE.zh-CN.md)。

反馈问题时，请附版本、语言、相关覆盖说明及去敏后的最小示例。欢迎改进解析案例、证据可读性、误报处理、报告和翻译。可提交 [Issue](https://github.com/Serennity007/xss-audit-desktop/issues) 或 Pull Request，分享前移除密钥与私有源码。

**[贡献指南](docs/CONTRIBUTING.zh-CN.md)** · [检测反馈](https://github.com/Serennity007/xss-audit-desktop/issues/new?template=detection_feedback.yml) · [安全政策](docs/SECURITY.zh-CN.md) · [版本记录](CHANGELOG.md)

本软件自身的漏洞请使用[私密漏洞报告](https://github.com/Serennity007/xss-audit-desktop/security/advisories/new)；去敏后的软件问题、检测反馈与工作流建议可走公开表单。

## 致谢与许可

本项目独立衍生自 **[songjianyang/xss-audit](https://github.com/songjianyang/xss-audit)**，原项目是 MIT 许可的审计 Skill。本仓库新增桌面软件、CLI、扫描器、有限 AST 分析、可选 AI 传输与打包，保留[原始规则](SKILL.md)、[上游 README](docs/UPSTREAM-README.md)及署名；原作者未为本衍生项目背书。

[MIT 许可](LICENSE) · [来源署名](NOTICE.md) · [解析器许可](THIRD-PARTY-NOTICES.txt) · [v0.3.0 发布说明](docs/RELEASE-v0.3.0.md)

请审查自己拥有或获得授权的代码。
