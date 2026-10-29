import { translate } from './i18n.js';
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function signalText(f, language) {
  const t = k => translate(language, k);
  const evidence = f.mode === 'ast' ? [t('source') + ': L' + f.source.line + ' ' + f.source.text, ...f.steps.map(s => t('assignment') + ': L' + s.line + ' ' + s.text), t('sink') + ': L' + f.sink.line + ' ' + f.sink.text, ...(f.sanitized ? [t('sanitized')] : [])] : [t('evidenceMissing')];
  if (f.context_truncated || f.evidence_truncated) evidence.push(t('excerptTruncated'));
  return [t(f.category) + ' · ' + f.rule, f.path + ':' + f.line + ':' + f.column, t(f.mode) + ' · ' + t(f.priority), t('status') + ': ' + t(f.status), ...(f.baseline_state ? [t('baseline') + ': ' + t(f.baseline_state)] : []), ...evidence, t('guidance') + ': ' + t(f.mode === 'pattern' ? 'patternFix' : f.category + 'Fix'), f.context, t('notes') + ': ' + f.note].join('\n');
}
export function reportText(result, language) {
  const t = k => translate(language, k);
  return ['# ' + t('report'), result.created_at + ' · ' + result.engine, t('reportNote'), t('boundary'), t('reportScope'), JSON.stringify({files:result.files, scope:result.scope, import_inventory:result.import_inventory}, null, 2), ...(result.comparison ? [t('baselineNotice'), JSON.stringify(result.comparison, null, 2)] : []), t('scope'), ...result.notes.map(n => n.path + ': ' + t(n.code) + (n.line ? ' L' + n.line : '')), ...result.findings.map(f => '\n---\n' + signalText(f, language))].join('\n\n');
}
export function csvCell(value) {
  let text = String(value ?? '');
  if (/^[\x00-\x20]*[=+@-]|^[\t\r\n]/.test(text) || /^[=+@-]/.test(text.trimStart())) text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
function sarifReport(result, language) {
  const t = key => translate(language, key), rules = [...new Map(result.findings.map(f => [f.rule, f])).values()];
  const location = (f, line = f.line, column = f.column) => ({physicalLocation:{artifactLocation:{uri:f.path.split('/').map(encodeURIComponent).join('/')}, region:{startLine:line, startColumn:column}}});
  return {$schema:'https://json.schemastore.org/sarif-2.1.0.json', version:'2.1.0', runs:[{
    tool:{driver:{name:'XSS Audit Studio', version:result.engine.split('/')[1], informationUri:'https://github.com/Serennity007/xss-audit-desktop', rules:rules.map(f => ({id:f.rule, name:f.rule, shortDescription:{text:t(f.category)}, fullDescription:{text:t(f.mode === 'pattern' ? 'patternFix' : f.category + 'Fix')}}))}},
    invocations:[{executionSuccessful:!result.incomplete, toolExecutionNotifications:result.notes.map(n=>({level:'warning', message:{text:n.path + ': ' + t(n.code)}}))}],
    results:result.findings.map(f=>({ruleId:f.rule, level:f.priority === 'info' ? 'note' : 'warning', message:{text:signalText(f,language)}, locations:[location(f)], partialFingerprints:{'xssAuditIdentity/v2':f.id}, properties:{reviewPriority:f.priority, reviewStatus:f.status, note:f.note, evidenceMode:f.mode, exploitability:'unverified'}, ...(f.baseline_state ? {baselineState:f.baseline_state} : {}), ...(f.mode === 'ast' ? {codeFlows:[{threadFlows:[{locations:[{line:f.source.line, text:f.source.text}, ...f.steps, {line:f.sink.line, text:f.sink.text}].map(s=>({location:{...location(f,s.line,1), message:{text:s.text}}}))}]}]} : {})})),
    properties:{notice:t('reportNote'), limitations:t('boundary'), scope:result.scope, files:result.files, importInventory:result.import_inventory || [], comparison:result.comparison || null, exportScope:'all-results', sourceExecuted:false}
  }]};
}
export function exportReport(result, language, format) {
  const t = k => translate(language, k);
  const data = { ...result, language, limitations: t('boundary'), export_scope: 'all-results', notice: t('reportNote') };
  if (format === 'json') return { text: JSON.stringify(data, null, 2), type:'application/json', extension:'json' };
  if (format === 'sarif') return {text:JSON.stringify(sarifReport(result,language),null,2), type:'application/sarif+json', extension:'sarif'};
  if (format === 'csv') {
    const fields = ['record_type','path','line','column','rule','category','priority','mode','status','note','baseline_state','context','metadata_key','metadata_value'];
    const records = result.findings.map(f=>({...f,record_type:'signal'}));
    for (const [key,value] of [['engine',result.engine], ['created_at',result.created_at], ['notice',t('reportNote')], ['limitations',t('boundary')], ['scope',JSON.stringify(result.scope)], ['coverage',JSON.stringify({incomplete:result.incomplete,files:result.files,notes:result.notes,import_inventory:result.import_inventory})], ['comparison',JSON.stringify(result.comparison || null)]]) records.push({record_type:'metadata',metadata_key:key,metadata_value:value});
    const rows = [fields, ...records.map(record=>fields.map(key=>record[key]))];
    return {text:'\uFEFF' + rows.map(row=>row.map(csvCell).join(',')).join('\r\n'), type:'text/csv', extension:'csv'};
  }
  if (format === 'markdown') {
    const fenced = contents => {
      const fence = '`'.repeat(Math.max(3, ...[...contents.matchAll(/`+/g)].map(m=>m[0].length + 1)));
      return fence + '\n' + contents + '\n' + fence;
    };
    const sections = ['# ' + t('report'), t('reportNote'), t('boundary'), t('reportScope'), fenced(result.created_at + ' · ' + result.engine), '## ' + t('scope'), fenced(JSON.stringify({files:result.files,scope:result.scope,import_inventory:result.import_inventory,incomplete:result.incomplete,notes:result.notes},null,2))];
    if (result.comparison) sections.push('## ' + t('baseline'), t('baselineNotice'), fenced(JSON.stringify(result.comparison,null,2)));
    result.findings.forEach((f,index)=>sections.push('## ' + (index + 1) + '. ' + t(f.category), fenced(signalText(f,language))));
    return {text:sections.join('\n\n') + '\n',type:'text/markdown',extension:'md'};
  }
  if (format !== 'html') throw Error('format');
  const e = escapeHTML;
  const sections = result.findings.map(f => '<article><h2>' + e(t(f.category)) + '</h2><pre>' + e(signalText(f, language)) + '</pre></article>').join('');
  return { text: '<!doctype html><html lang="' + (language === 'zh' ? 'zh-CN' : 'en') + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>' + e(t('report')) + '</title><style>body{max-width:960px;margin:40px auto;padding:20px;background:#10191e;color:#dfebe9;font:16px/1.7 system-ui}article{border:1px solid #33454c;padding:20px;margin:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.8 monospace}h1,h2{color:#80e5c6}</style></head><body><h1>' + e(t('report')) + '</h1><p>' + e(result.created_at + ' · ' + result.engine) + '</p><p>' + e(t('reportNote')) + '</p><p>' + e(t('boundary')) + '</p><h2>' + e(t('scope')) + '</h2><pre>' + e(JSON.stringify({ files:result.files, scope:result.scope, import_inventory:result.import_inventory, incomplete:result.incomplete, notes:result.notes.map(n => ({...n, explanation:t(n.code)})) }, null, 2)) + '</pre>' + (result.comparison ? '<h2>' + e(t('baseline')) + '</h2><p>' + e(t('baselineNotice')) + '</p><pre>' + e(JSON.stringify(result.comparison,null,2)) + '</pre>' : '') + sections + '<footer>' + e(t('attribution')) + '</footer></body></html>', type:'text/html', extension:'html' };
}
