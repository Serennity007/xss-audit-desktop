import { translate } from './i18n.js';
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function signalText(f, language) {
  const t = k => translate(language, k);
  const evidence = f.mode === 'ast' ? [t('source') + ': L' + f.source.line + ' ' + f.source.text, ...f.steps.map(s => t('assignment') + ': L' + s.line + ' ' + s.text), t('sink') + ': L' + f.sink.line + ' ' + f.sink.text, ...(f.sanitized ? [t('sanitized')] : [])] : [t('evidenceMissing')];
  return [t(f.category) + ' · ' + f.rule, f.path + ':' + f.line + ':' + f.column, t(f.mode) + ' · ' + t(f.priority), t('status') + ': ' + t(f.status), ...evidence, t('guidance') + ': ' + t(f.mode === 'pattern' ? 'patternFix' : f.category + 'Fix'), f.context, t('notes') + ': ' + f.note].join('\n');
}
export function reportText(result, language) {
  const t = k => translate(language, k);
  return ['# ' + t('report'), result.created_at + ' · ' + result.engine, t('reportNote'), t('boundary'), t('reportScope'), JSON.stringify(result.files, null, 2), t('scope'), ...result.notes.map(n => n.path + ': ' + t(n.code) + (n.line ? ' L' + n.line : '')), ...result.findings.map(f => '\n---\n' + signalText(f, language))].join('\n\n');
}
export function exportReport(result, language, format) {
  const t = k => translate(language, k);
  const data = { ...result, language, limitations: t('boundary'), export_scope: 'all-results', notice: t('reportNote') };
  if (format === 'json') return { text: JSON.stringify(data, null, 2), type:'application/json', extension:'json' };
  if (format === 'markdown') {
    const contents = reportText(result, language);
    const longest = Math.max(3, ...[...contents.matchAll(/`+/g)].map(m => m[0].length + 1));
    const fence = '`'.repeat(longest);
    return { text: '# ' + t('report') + '\n\n' + fence + '\n' + contents + '\n' + fence + '\n', type:'text/markdown', extension:'md' };
  }
  if (format !== 'html') throw Error('format');
  const e = escapeHTML;
  const sections = result.findings.map(f => '<article><h2>' + e(t(f.category)) + '</h2><pre>' + e(signalText(f, language)) + '</pre></article>').join('');
  return { text: '<!doctype html><html lang="' + (language === 'zh' ? 'zh-CN' : 'en') + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>' + e(t('report')) + '</title><style>body{max-width:960px;margin:40px auto;padding:20px;background:#10191e;color:#dfebe9;font:16px/1.7 system-ui}article{border:1px solid #33454c;padding:20px;margin:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.8 monospace}h1,h2{color:#80e5c6}</style></head><body><h1>' + e(t('report')) + '</h1><p>' + e(result.created_at + ' · ' + result.engine) + '</p><p>' + e(t('reportNote')) + '</p><p>' + e(t('boundary')) + '</p><h2>' + e(t('scope')) + '</h2><pre>' + e(JSON.stringify({ files:result.files, incomplete:result.incomplete, notes:result.notes.map(n => ({...n, explanation:t(n.code)})) }, null, 2)) + '</pre>' + sections + '<footer>' + e(t('attribution')) + '</footer></body></html>', type:'text/html', extension:'html' };
}
