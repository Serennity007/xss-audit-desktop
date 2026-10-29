# Functional roadmap

This is a development sequence, not a claim that the listed capabilities exist. Published binaries remain v0.3.0. Scope each increment around a complete, verifiable user task.

## Delivered source and browser increments

Integrated upstream development commits f495a3a, 011f642 and 3eb4908: scan configuration, per-file coverage, review history/status filtering, HTML/Python analysis improvements and a paired repository-auditor robustness research harness. These remain source features, not new published Windows binaries or measured live-model research results.

Browser 0.2.0 is implemented in web/: folder/multifile import, bounded include/exclude scope and import inventory, local JS/TS AST review, limited HTML/Vue/Svelte inline scripts, combined triage filters, conservative baselines, and JSON/Markdown/HTML/CSV/SARIF exports. Browser and desktop coverage differ. WorkBuddy has a separately deployed 0.1.0 public preview; publishing the 0.2.0 repository package does not update that site. See web/README.md and web/WORKBUDDY.md.

Baseline comparison is available in the desktop and CLI. Export a full JSON report, scan a comparable project snapshot, then compare. Reports preserve new/unchanged identities and locations no longer observed. The desktop has a new-signals view; CLI supports baseline-aware matching gates. Missing signals never automatically become fixed. Identity is based on path, rule and nearby code, not semantic equivalence. See the English and Chinese usage guides for limits.

## Next increments

| Order | User outcome | Required proof |
| --- | --- | --- |
| 1 | Experience a browser workbench without installation | Synthetic sample and user files use the same real analyzer; review and offline exports work anonymously; mobile and keyboard flows pass; source processing/storage is disclosed. |
| 2 | Extend the existing project scope controls | Existing TOML include/exclude configuration and budgets are integrated. Any further ignore-file support must have predictable precedence and report effective scope. |
| 3 | Extend embedded framework review | Limited root-script extraction now retains original coordinates and isolated parse failures. Further framework support needs compiler-aware template semantics and independent cases; extraction alone does not establish it. |
| 4 | Trace selected cross-file paths | Resolve a declared subset of imports and function calls with explicit budgets; distinguish unsupported/dynamic paths; validate positive and negative cases without claiming full repository analysis. |
| 5 | Compare branches and PRs | Record exact base/head revisions; preserve evidence outside edited lines where relevant; explicitly identify new signals without equating disappearance to a fix. |
| 6 | Check dependency advisories | Cover declared lockfile ecosystems and resolved versions; show source/date, affected range, unavailable lookups and limits; do not infer reachability from an advisory alone. |
| 7 | Review proposed fixes | Generate a reviewable patch with evidence and limitations; verify unchanged intent and relevant regressions; no unattended application or execution of imported projects. |
| 8 | Extend the integrated audit-agent research harness | The paired-trial runner and observable traces exist. Next validate independent real-world cases and live-model runs, with budget-matched controls and separate detection/evidence outcomes. |
| 9 | Share reviews across users | Define authentication, project permissions, data retention/deletion and audit history before hosting private code or adding persistent team storage. |
| 10 | Improve distribution | Build and test each claimed OS/architecture; provide checksums and license notices; enable real CI with the required credential scope, then document actual results. |

## Stop conditions

- New rules or languages require independent positive and negative samples; more matches alone are not better detection.
- Keep engine coverage, human decisions, optional AI interpretation and runtime verification distinct.
- Treat dependency/plugin installation and analysis of untrusted source as separate activities. Static review must not execute imported code.
- Release only completed increments with tests and current docs. Do not add usable-looking placeholders or speculative accuracy figures.
- Research evaluation features are not evidence of novelty or publication readiness; compare with related work independently.

## 中文

本文件是开发顺序，不代表所有功能已实现。公开二进制仍为 v0.3.0。

本地源码已补齐桌面、CLI 和四种报告的基线对比，并合入远端的项目配置、覆盖说明、复核历史和仓库审计鲁棒性评测工具。基线按路径、规则、线索身份和源文件摘要比较，不证明语义等价，不把未再观察到的线索当成已修复。网页 0.2.0 已补齐目录导入、范围、有限组件脚本、组合筛选、基线和五种导出；WorkBuddy 已有 0.1.0 公开预览，新版仍需重新部署。科研工具未据此宣称真实模型性能或论文创新。

后续按完整用户流程推进：

1. 网页版实际体验：本地分析、源码阅读、人工复核、离线导出、手机与键盘操作。
2. 项目配置：包含／排除规则、可解释的扫描范围及跳过说明。
3. 框架支持：组件脚本提取、原始行号、解析失败说明。
4. 有界跨文件分析：明确支持的导入和调用、预算及未覆盖路径。
5. PR／分支对比：固定 base/head 版本，保留必要上下文和证据。
6. 依赖公告：实际版本、公告来源、更新时间、查询失败及可达性限制。
7. 修复建议：可审查补丁及回归验证，不自动执行导入项目。
8. 科研评测：工具轨迹、真实标签、漏洞／修复对照、重复实验和成本统计。
9. 团队协作：权限、数据保留与删除、可审计的复核历史。
10. 分发维护：实际测试的多平台构建、CI、校验文件及版本说明。

每一步都需要独立验收。规则数量增加、界面丰富或测试通过，不能替代检测质量评测，也不能据此宣称学术创新。
