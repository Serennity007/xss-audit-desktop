# XSS Audit Desktop

中文 XSS 代码审计助手，提供 **Windows 桌面版、命令行版、可选 AI 辅助审计**。

基于 [songjianyang/xss-audit](https://github.com/songjianyang/xss-audit) 的 MIT 审计规则开发。原项目是 AI Skill；本仓库新增独立运行的软件，保留 [SKILL.md](SKILL.md)、[许可](LICENSE) 和[原 README](docs/UPSTREAM-README.md)。本项目为独立衍生项目，未经原作者背书。

> 规则匹配是待确认线索。软件不做完整跨文件数据流分析，也不执行代码或验证漏洞可利用性。零匹配不代表安全。AI 结果同样需要人工复核。

## 下载与运行

从 [Releases](https://github.com/Serennity007/xss-audit-desktop/releases/latest) 下载 `XSS-Audit-v0.1.0-windows-x64.zip` 并解压：

- **XSS-Audit-Desktop.exe**：双击打开中文界面；选择代码文件夹 → 本地扫描 → 查看代码线索 → 导出 Markdown / JSON。
- **xss-audit-cli.exe**：在 PowerShell / 终端运行，用于批处理和 CI。
- **AI 辅助审计**：两个版本均内置，通过自己的 API Key 启用，无需第三个程序。

也可直接下载单独 EXE；ZIP 另附说明、原始规则与许可证。当前二进制面向 Windows 10/11 x64，使用 Windows 11 x64 验证；无需预装 Python。无安装器、代码签名或自动更新器。可用 `Get-FileHash -Algorithm SHA256 文件名` 对照 `SHA256SUMS.txt` 检查下载文件。

## 命令行

```powershell
.\xss-audit-cli.exe "D:\projects\my-web-app" -o "D:\reports\audit.md"
.\xss-audit-cli.exe "D:\projects\my-web-app" --format json -o "D:\reports\audit.json"
.\xss-audit-cli.exe "D:\projects\my-web-app" --fail-on-match
.\xss-audit-cli.exe --help
```

输出目录需要已存在。默认输出带时间戳的 Markdown 报告，不覆盖已有报告。退出码：`0` 完成；`1` 启用 `--fail-on-match` 且有待确认线索；`2` 错误或扫描不完整；`130` 用户中断。`1` 不表示已确认漏洞。

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

`--ai` 表示同意将纳入范围的完整源文件发送到指定接口，可能产生 API 费用。请先选择可分享的目录。软件不做完整秘密检测或自动脱敏；JSON 配置及代码中的密钥也可能发送。密钥不写入配置、日志或报告；远程接口要求 HTTPS，本机模型可用 `http://localhost:端口/v1`。不跟随重定向，不给模型执行工具。Responses 请求设置 `store: false`，但这不保证服务方不保留数据，需核对服务方政策。

AI 上下文预算为约 **18 万字符**，只收录预算容纳的完整文件；未发送文件在报告中列出。传入原始 14 层规则，不自动分批或补读其他文件，不声称完整仓库审计。单次请求超时 180 秒；关闭程序不能撤回已发送请求或取消服务方计费。

实现依据 [OpenAI 官方 Responses 文档](https://developers.openai.com/api/docs/guides/migrate-to-responses?api-mode=responses)。协议使用模拟 HTTP 服务验证；发布前未使用真实付费模型联调，审计质量未经基准评测。

## 规则与扫描范围

14 类线索：DOM/HTML、属性与事件、URL 导航、脚本 JSON、Props、外部输入与消息、原型污染、动态执行、CSS、SVG/MathML/XML、Markdown/净化器、框架信任绕过、Trusted Types/CSP、框架绑定与模板编译。

本地引擎为正则启发式搜索，覆盖上述类别的常见 API 与语法，不等同于完整执行原 Skill 的人工步骤。安全调用、注释、字符串也可能匹配；不会推断完整来源、净化正确性或可利用性，不自动查依赖公告，不为匹配赋已确认漏洞等级。

- 支持 JS/JSX/TS/TSX/MJS/CJS、HTML、Vue、Svelte、Astro、MDX、CSS/SCSS、SVG/XML、JSON、HBS/Handlebars/EJS/NJK。
- 排除 `.git`、`node_modules`、`vendor`、`dist`、`build`、`coverage`、`.next`、`.nuxt`、Python 虚拟环境、缓存和编辑器目录；跳过 `.min.js` / `.min.css`。
- 仅读取 UTF-8 / UTF-8 BOM；不跟随符号链接与 junction，不加载依赖或执行项目代码。
- 单文件最多 1 MiB；最多 10000 文件、100 MiB 和 10000 条匹配。到达上限标为不完整，需缩小范围。
- 报告列出排除和读取失败原因；达到全局上限后不继续遍历剩余范围。报告含路径和代码片段，公开前请检查敏感内容。

## 源码运行

需要 Python 3.11+，桌面版还需要 Tkinter（Windows 官方 Python 通常自带）。

```powershell
python desktop.py
python -m xss_audit "D:\projects\my-web-app"
python -m unittest discover -s tests -v

# 可选：安装命令入口
python -m pip install .
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

`release/` 包含桌面 EXE、CLI EXE、ZIP 和 SHA-256 文件。使用 [PyInstaller](https://pyinstaller.org/en/stable/usage.html)；工具版本固定，间接构建依赖未全锁定，二进制不保证逐字节可复现。

`docs/workflows/` 附带两个可选 GitHub Actions 模板：`Verify` 测试与验证安装，`Build Windows Release` 构建并发布标签版本。首次发布使用本机构建与测试的产物。当前凭据缺少 GitHub `workflow` 权限，模板尚未启用；之后可用有该权限的凭据将模板复制至 `.github/workflows/` 再提交。不同构建环境的产物可能不同，以 Release 校验文件为准。

## 许可

[MIT](LICENSE)。版权与来源见 [NOTICE.md](NOTICE.md)。仅审计自己拥有或获授权的代码。
