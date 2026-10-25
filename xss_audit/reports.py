"""Offline HTML and SARIF 2.1.0. All project/model text is treated as data."""
from __future__ import annotations

import html
import json
from urllib.parse import quote

from . import __version__


def html_report(result):
    escape = lambda value: html.escape(str(value), quote=True)
    cards = "".join(f'<div class="card"><b>{escape(value)}</b><span>{escape(label)}</span></div>' for label, value in [
        ("扫描文件", result.files_scanned), ("全部线索", len(result.matches)), ("高优先复核", sum(m.priority == "高" and m.status == "待人工确认" for m in result.matches)),
        ("已复核", sum(m.status != "待人工确认" for m in result.matches))])
    findings = []
    for match in sorted(result.matches, key=lambda m: ({"高": 0, "中": 1, "信息": 2}.get(m.priority, 3), m.path, m.line)):
        evidence = "\n".join(match.evidence) or "尚无完整数据流证据，请人工追踪。"
        findings.append(f'''<article class="finding" data-priority="{escape(match.priority)}">
<div class="meta"><span class="badge">{escape(match.priority)}优先级</span> {escape(match.rule_id)} · {escape(match.cwe)} · {escape(match.status)}</div>
<h2>{escape(match.rule)}</h2><p class="location">{escape(match.path)}:{match.line}:{match.column}</p>
<p>{escape(match.confidence)}</p><pre>{escape(match.context or match.snippet)}</pre>
<details><summary>查看数据流证据和建议</summary><pre>{escape(evidence)}</pre><p>{escape(match.recommendation)}</p><p>复核备注：{escape(match.note or '无')}</p></details></article>''')
    state = "结果不完整" if result.truncated or result.cancelled else "扫描完成，部分 AST 未完成" if result.ast_incomplete else "扫描完成"
    notes = "\n".join(f"{item['path']} — {item['reason']}" for item in result.analysis_notes)
    skipped = "\n".join(f"{item['path']} — {item['reason']}" for item in result.skipped)
    ai = f'<section><h2>AI 辅助审计 · 未独立验证</h2><pre>{escape(result.ai_report)}</pre></section>' if result.ai_report else ""
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>XSS Audit {escape(__version__)} · 审计报告</title><style>
:root{{font-family:Segoe UI,Microsoft YaHei,sans-serif;color:#17263b;background:#f2f5fa}}body{{max-width:1100px;margin:0 auto;padding:32px}}header{{background:#142743;color:white;border-radius:18px;padding:30px}}h1{{margin:0 0 12px}}p{{line-height:1.6;overflow-wrap:anywhere}}.muted{{color:#bfd2ee}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}.card{{background:white;border:1px solid #dce4ef;border-radius:12px;padding:20px}}.card b{{display:block;font-size:30px;color:#245bd8}}.card span{{color:#54647a}}.filters{{display:flex;gap:12px;margin:22px 0;flex-wrap:wrap}}input,select{{padding:12px;border:1px solid #c3cee0;border-radius:8px;font:inherit}}input{{flex:1;min-width:200px}}.finding,section{{background:white;padding:24px;border:1px solid #dce4ef;border-radius:12px;margin:14px 0}}h2{{font-size:19px;margin:14px 0 8px}}.meta,.location{{color:#53647b;font-size:14px}}.badge{{color:#245bd8;background:#edf3ff;border-radius:5px;padding:5px 8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fb;border-radius:8px;padding:16px;font:13px/1.7 Consolas,monospace}}summary{{cursor:pointer;color:#245bd8}}[hidden]{{display:none!important}}@media(max-width:650px){{body{{padding:12px}}.cards{{grid-template-columns:repeat(2,1fr)}}}}@media print{{.filters{{display:none}}article{{break-inside:avoid}}body{{padding:0}}}}
</style></head><body><header><h1>XSS AUDIT · 代码审计报告</h1><p class="muted">v{escape(__version__)} · {escape(result.created_at)} · {escape(state)}</p><p>{escape(result.root)}</p></header>
<div class="cards">{cards}</div><p>优先级表示复核顺序，不是已确认漏洞等级。有限 AST 分析不解析完整跨文件调用链；零匹配不代表安全。识别出的敏感值已尽力遮蔽，分享前仍需检查。</p>
<div class="filters"><input id="search" placeholder="搜索文件、规则、证据或代码" aria-label="搜索"><select id="priority"><option value="">全部优先级</option><option>高</option><option>中</option><option>信息</option></select><span id="count"></span></div>
<main>{''.join(findings) or '<section>未发现匹配线索。请结合扫描范围与解析说明评估。</section>'}</main>{ai}
<section><details><summary>范围与未读取 / AST 解析说明</summary><pre>{escape(json.dumps({'import': result.import_metadata, 'report_filters': result.report_filters, 'AI_scope': result.ai_metadata}, ensure_ascii=False, indent=2))}</pre><pre>{escape(notes or '未记录 AST 解析错误。未支持语言仍仅执行规则搜索。')}</pre><pre>{escape(skipped or '无跳过项')}</pre><p>单文件 1 MiB；最多 10000 文件 / 100 MiB / 10000 线索。不执行项目代码。</p></details></section>
<footer>基于 songjianyang/xss-audit（MIT）。本报告可离线打开，无外部资源请求。</footer><script>
const search=document.getElementById('search'), priority=document.getElementById('priority');
function filter(){{let count=0;document.querySelectorAll('.finding').forEach(item=>{{const show=(!priority.value||item.dataset.priority===priority.value)&&item.textContent.toLowerCase().includes(search.value.toLowerCase());item.hidden=!show;if(show)count++;}});document.getElementById('count').textContent='显示 '+count+' 条';}}search.addEventListener('input',filter);priority.addEventListener('change',filter);filter();
</script></body></html>'''


def sarif(result):
    rules = {}
    results = []
    for match in result.matches:
        rule_id = match.rule_id or f"XSS-L{match.layer:02d}"
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": match.rule},
            "help": {"text": match.recommendation}, "properties": {"tags": ["security", match.cwe] if match.cwe else ["security"]}})
        def location(line):
            return {"physicalLocation": {"artifactLocation": {"uri": quote(match.path, safe="/")}, "region": {"startLine": max(1, line)}}}
        item = {"ruleId": rule_id, "level": "warning" if match.priority in {"高", "中"} else "note",
                "message": {"text": f"{match.rule}；复核优先级 {match.priority}；{match.confidence}。{match.recommendation}"},
                "locations": [location(match.line)], "partialFingerprints": {"reviewIdentity/v1": match.fingerprint},
                "properties": {"reviewStatus": match.status, "reviewNote": match.note, "priority": match.priority,
                               "evidence": match.evidence, "unverified": True}}
        if match.status == "误报":
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": match.note or "用户标记为误报"}]
        results.append(item)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "XSS Audit Desktop", "version": __version__, "informationUri": "https://github.com/Serennity007/xss-audit-desktop", "rules": list(rules.values())}},
        "results": results, "invocations": [{"executionSuccessful": not (result.cancelled or result.truncated or result.analysis_notes)}],
        "properties": {"limitations": "Review signals only; no exploitability proof or complete interprocedural analysis.", "analysisNotes": result.analysis_notes}}]}
