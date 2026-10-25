[English](USAGE.en.md) · [简体中文](USAGE.zh-CN.md) · [项目首页](../README.zh-CN.md)

# XSS Audit Desktop：详细使用指南

中英双语代码审计工作台，提供 **Windows 桌面版、命令行版、GitHub 导入、AST 数据流线索与可选 AI 辅助审计**。

基于 [songjianyang/xss-audit](https://github.com/songjianyang/xss-audit) 的 MIT 审计规则开发。原项目是 AI Skill；本仓库新增独立运行的软件，保留 [SKILL.md](../SKILL.md)、[许可](../LICENSE) 和[原 README](UPSTREAM-README.md)。本项目为独立衍生项目，未经原作者背书。

> 自动结果是待确认线索。“高 / 中 / 信息”表示人工复核优先级，不是已证实漏洞等级。有限 AST 分析不覆盖完整跨文件调用链，零匹配不代表安全。AI 结果同样需要人工复核。

## v0.3 中英双语

界面默认英语，可在右上角选择简体中文；语言选择会保存在本机。命令行使用 `--lang en` 或 `--lang zh-CN`；报告和 AI 请求跟随所选语言。源代码、路径、用户备注和已有 AI 文本保持原样。JSON/SARIF 保留既有状态字段，另提供本地化显示标签。

## 检测与复核能力

| 能力 | 当前实现 |
| --- | --- |
| GitHub 仓库导入 | 粘贴公开仓库链接，可指定分支 / 标签 / commit；无需安装 Git |
| JavaScript / TypeScript / TSX | Tree-sitter 语法树，常见输入 → 变量 → HTML / URL / 动态执行线索 |
| Python | AST 追踪 SQL 构造、Shell 执行、文件路径、SSRF、反序列化和模板等常见路径 |
| 复核工作台 | 概览统计、优先级 / 类别 / 关键词筛选、上下文、证据和建议 |
| 误报与处理记录 | 标记待确认 / 确认风险 / 误报 / 已修复，保存备注并在再次扫描时恢复 |
| 报告 | Markdown、JSON、可离线搜索的 HTML、SARIF 2.1.0 |
| AI 输入保护 | 优先选择有证据的完整文件，遮蔽识别出的凭据值，保留发送范围与遗漏记录 |

随 ZIP 附带 `examples/demo-project/` 合成示例与 `examples/demo-report.html`。可以先打开示例报告了解如何复核；示例故意包含风险写法，请勿执行或部署。

## 下载与运行

从 [Releases](https://github.com/Serennity007/xss-audit-desktop/releases/latest) 下载 `XSS-Audit-v0.3.0-windows-x64.zip` 并解压：

- **XSS-Audit-Desktop.exe**：打开桌面界面，可切换简体中文；选择本地目录或导入 GitHub → 扫描 → 查看上下文和证据 → 保存复核标记 → 导出报告。
- **xss-audit-cli.exe**：在 PowerShell / 终端运行，用于批处理和 CI。
- **AI 辅助审计**：两个版本均内置，通过自己的 API Key 启用，无需第三个程序。

也可直接下载单独 EXE；ZIP 另附说明、原始规则与许可证。当前二进制面向 Windows 10/11 x64，使用 Windows 11 x64 验证；无需预装 Python。无安装器、代码签名或自动更新器。可用 `Get-FileHash -Algorithm SHA256 文件名` 对照 `SHA256SUMS.txt` 检查下载文件。

## 命令行

```powershell
.\xss-audit-cli.exe "D:\projects\my-web-app" -o "D:\reports\audit.md"
.\xss-audit-cli.exe "D:\projects\my-web-app" --format json -o "D:\reports\audit.json"
.\xss-audit-cli.exe "D:\projects\my-web-app" --fail-on-match
.\xss-audit-cli.exe --help

# 公开 GitHub 仓库，Ref 可不填
.\xss-audit-cli.exe --repo "owner/repository" --ref "main" --format html -o "D:\reports\audit.html"
.\xss-audit-cli.exe "D:\projects\my-web-app" --format sarif -o "D:\reports\audit.sarif"
.\xss-audit-cli.exe "D:\projects\my-web-app" --min-priority 高 --ignore-reviewed --fail-on-match
```

输出目录需要已存在。默认按所选格式输出带时间戳的报告，不覆盖已有报告。退出码：`0` 完成；`1` 启用 `--fail-on-match` 且有待确认线索；`2` 错误或扫描不完整；`130` 用户中断。`1` 不表示已确认漏洞。

CLI 可用 `--no-saved-review` 忽略本机复核记录，`--destination` 指定 GitHub 快照存放位置。桌面筛选仅影响界面，导出完整结果；CLI 的 `--min-priority` / `--ignore-reviewed` 会筛选导出内容，报告记录筛选条件。

## GitHub 导入与复核记录

仅支持公开 `github.com` 仓库首页或 `owner/repository`；分支、标签或 commit 单独填写。使用 GitHub 官方 ZIP archive 接口，不使用账号令牌，不需要 Git，不获取 Git 历史、子模块内容或 LFS 实体文件。下载只允许 GitHub 官方主机的 HTTPS 重定向。压缩下载上限 60 MiB，解压总量 250 MiB / 15000 项 / 单文件 20 MiB，拒绝越界路径、链接、设备文件和大小写冲突。

默认本地数据目录为 Windows `%LOCALAPPDATA%\XSSAudit`：`imports` 保存导入源码，`state` 保存复核标记及接口设置。缓存不会自动删除，可按界面显示路径自行管理。API Key 不保存。复核身份由项目、规则、路径及邻近代码摘要确定；更远处的语义改动可能不使标记失效，重新审计时应复核旧标记。不同机器不自动同步复核记录。

## AI 辅助审计

支持 Responses API 和 Chat Completions 兼容接口。默认 API Base URL 为 `https://api.openai.com/v1`。模型名由使用者填写，需有对应权限和额度；服务商决定接口兼容性。

桌面版：先本地扫描，在 AI 页填写接口、模型和密钥，点击“审核范围并开始 AI 审计”，核对实际发送文件列表再发送。结果可合并导出。

命令行：设置自己的 `OPENAI_API_KEY` 与 `XSS_AUDIT_MODEL` 环境变量，再显式使用 `--ai`：

```powershell
# 请先在当前环境配置自己的 OPENAI_API_KEY 和 XSS_AUDIT_MODEL
.\xss-audit-cli.exe "D:\projects\my-web-app" --ai -o "D:\reports\ai-audit.md"

# 兼容 Chat Completions 的服务：使用服务方提供的地址与模型名
.\xss-audit-cli.exe "D:\projects\my-web-app" --ai --api-format chat --base-url "https://your-provider.example/v1" --model "your-model"
```

`--ai` 表示同意将纳入范围的完整源文件发送到指定接口，可能产生 API 费用。请先选择可分享的目录。常见凭据前缀和敏感变量名对应的字符串会尽力遮蔽，但不保证识别所有秘密，未知格式的密钥仍可能发送。接口密钥不写入配置、日志或报告；远程接口要求 HTTPS，本机模型可用 `http://localhost:端口/v1`。不跟随重定向，不给模型执行工具。Responses 请求设置 `store: false`，但这不保证服务方不保留数据，需核对服务方政策。

AI 上下文预算为约 **18 万字符**，优先选择 AST 高优先级文件，再选择有规则线索的文件；只发送完整文件，预算外文件在报告中列出。传入原始 14 层规则与 Python 风险复核要求，不自动分批或补读其他文件，不声称完整仓库审计。单次请求超时 180 秒；关闭程序不能撤回已发送请求或取消服务方计费。

实现依据 [OpenAI 官方 Responses 文档](https://developers.openai.com/api/docs/guides/migrate-to-responses?api-mode=responses)。协议使用模拟 HTTP 服务验证；发布前未使用真实付费模型联调，审计质量未经基准评测。

## 规则与扫描范围

原始 14 类 XSS 线索继续保留；另增加 SQL 构造、Shell、路径、SSRF、反序列化与凭据，共 20 个复核类别。不同语言和类别的分析深度不同，详见 [分析边界](ANALYSIS.md)。

本地引擎结合正则搜索与有限语法树分析。不等同于完整执行原 Skill 的人工步骤，也不自动查询依赖公告或验证可利用性。正则可命中安全调用、注释和字符串；AST 保守传播也可能产生误报或漏报。HTML 净化不能代表 URL、JS、CSS 上下文安全。

- 支持 Python、JS/JSX/TS/TSX/MJS/CJS、HTML、Vue、Svelte、Astro、MDX、CSS/SCSS、SVG/XML、JSON、HBS/Handlebars/EJS/NJK。AST 仅覆盖独立 JS / TS / JSX / TSX / Python 源文件，框架单文件组件与模板仍执行规则搜索。
- 排除 `.git`、`node_modules`、`vendor`、`dist`、`build`、`coverage`、`.next`、`.nuxt`、Python 虚拟环境、缓存和编辑器目录；跳过 `.min.js` / `.min.css`。
- 仅读取 UTF-8 / UTF-8 BOM；不跟随符号链接与 junction，不加载依赖或执行项目代码。
- 单文件最多 1 MiB；最多 10000 文件、100 MiB 和 10000 条匹配。到达上限标为不完整，需缩小范围。
- 报告列出排除和读取失败原因；达到全局上限后不继续遍历剩余范围。报告含路径和代码片段，公开前请检查敏感内容。

## 源码运行

需要 Python 3.11+，桌面版还需要 Tkinter（Windows 官方 Python 通常自带）。

```powershell
python -m pip install .
python desktop.py
python -m xss_audit "D:\projects\my-web-app"
python -m unittest discover -s tests -v

# 安装后也可使用命令入口
xss-audit --version
```

源码 CLI 可在其他有 Python 3.11+ 的系统运行，当前仅提供 Windows x64 二进制。

## 构建与发布

在 Windows x64 的干净环境中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/build_release.py
```

`release/v0.3.0/` 包含桌面 EXE、CLI EXE、ZIP 和 SHA-256 文件，旧版本产物保留。打包包含三种 Tree-sitter 组件及 MIT 许可，见 [第三方声明](../THIRD-PARTY-NOTICES.txt)。使用 [PyInstaller](https://pyinstaller.org/en/stable/usage.html)；工具版本固定，间接构建依赖未全锁定，二进制不保证逐字节可复现。

`docs/workflows/` 附带两个可选 GitHub Actions 模板：`Verify` 测试与验证安装，`Build Windows Release` 构建并发布标签版本。首次发布使用本机构建与测试的产物。当前凭据缺少 GitHub `workflow` 权限，模板尚未启用；之后可用有该权限的凭据将模板复制至 `.github/workflows/` 再提交。不同构建环境的产物可能不同，以 Release 校验文件为准。

## 许可

[MIT](../LICENSE)。版权与来源见 [NOTICE.md](../NOTICE.md)。仅审计自己拥有或获授权的代码。
