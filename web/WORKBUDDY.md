# WorkBuddy handoff / 网页发布交接

请使用现有 web/ 目录继续开发和发布 XSS Audit Studio，不要把真实分析替换为假数据或静态展示页。

1. 阅读 web/README.md、项目 LICENSE 和 NOTICE.md，保留上游及依赖署名。
2. 检查当前部署环境。已有静态构建输出 web/dist/；如需重新构建，在 web/ 下执行 npm ci、npm test、npm run build。
3. 将 dist/ 内文件作为网站根目录发布，保留 app.js 与 worker.js 的相对位置。确保 HTTPS、同源模块 Worker 和浏览器 SHA-256 可用。
4. 不需要 Python、数据库、API Key 或源码上传服务。保留浏览器本地分析和当前隐私说明，不增加追踪。
5. 实际验证基础及组件示例、目录／多文件导入、排除及跳过清单、编辑重扫、证据定位、复核记录、组合筛选、中英切换、复制及 JSON／Markdown／HTML／CSV／SARIF 五种导出；检查桌面及手机布局。
6. 对照 README 的实际范围，不宣称 Python、完整跨文件分析、AI 或 GitHub 导入已实现。
7. 通过 WorkBuddy 真实发布，提供保留有效 sharecode 的完整体验链接，并用未登录浏览器验证；不要拿 localhost、GitHub Release 或 GhostTrack 链接代替。
8. 应用体验链接与本次 WorkBuddy 创作对话分享链接分别提供。不要代填个人信息、勾选授权或提交报名。
9. 本轮版本为 0.2.0。在现有 XSS 应用中替换全部部署文件并重新发布，优先保留现有应用地址与有效 sharecode。不要重新部署成 GhostTrack。不要仅更新 index.html 或让旧 Worker 与新页面混用。
10. 验证版本对比：基础示例分析后设为基线，改掉一个 innerHTML 写入并重扫。应显示新增／不变／本次未观察到，且未观察到不自动成为已修复。组件模板覆盖不完整，因此组件报告当前不能设为完整基线。
11. 本项目提供新的构建和验证记录，不会自动更新 WorkBuddy。请将实际发布后的页面、版本文字、样例结果和未登录访问作为部署依据，不复用旧验收表冒充新版验收。

现有公开应用地址（0.1.0 来源，新版须重新发布）：https://xss-audit-studio.app.workbuddy.host/?sharecode=JHJQZE62LQ

新版构建包：GitHub `web-v0.2.0` Release 的 `XSS-Audit-Studio-web-0.2.0.zip`。将包内文件直接作为静态根目录；若从完整源码包构建，保持 `web/` 与仓库根的许可文件相对位置。

## 作品宣言

这个 1024，我做了一个代码安全审查工作台，让开发者沿着源码证据发现线索、记录判断并导出报告。

## 作品介绍草稿（按最终发布验收核对）

XSS Audit Studio 面向开发者、学生与代码审查者，可载入样例、粘贴代码或导入项目目录，在浏览器本地查看 JS／TS 风险线索、源码位置与有限数据流证据，并提取 HTML／Vue／Svelte 内联脚本。用户可组合筛选、记录复核判断、对比前后版本，导出 JSON、Markdown、离线 HTML、CSV 或 SARIF 报告。界面支持中英切换与手机使用，无需登录或 API Key。源码不运行、不上传；模板与跨文件等未覆盖范围明确标出，自动线索仍需人工确认。本作品基于开源项目扩展并保留来源署名，请以最终发布站点验收为准。
