import { parse } from '@babel/parser';
import { DEFAULT_SCOPE, scopeReason, validateScope } from './scope.js';
import { extractScripts } from './components.js';

import { LIMITS, validateFiles } from './inputs.js';
import { ENGINE } from './version.js';
export { LIMITS, validateFiles, ENGINE };
const sourcePattern = /^(?:(?:window|document)\.)?location\.(?:hash|search|href)$|^document\.(?:cookie|referrer)$|^(?:req|request)\.(?:query|params|body)(?:\.|\[|$)|^(?:e|ev|event)\.data(?:\.|\[|$)|\.target\.value$/;
const supported = /\.(js|jsx|ts|tsx|mjs|cjs)$/i;
const patterns = [
  ['HTML-PATTERN', 'html', /\b(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\.write)\b/g],
  ['URL-PATTERN', 'url', /\b(?:window\.open|location\.(?:assign|replace)|href|src|action)\b/g],
  ['CODE-PATTERN', 'code', /\b(?:eval|Function|setTimeout|setInterval)\s*\(/g],
  ['SANITIZER-PATTERN', 'sanitizer', /\b(?:DOMPurify|sanitizeHtml|sanitize|ALLOW_DATA_ATTR|ALLOWED_TAGS)\b/g],
  ['MESSAGE-PATTERN', 'message', /\b(?:postMessage|BroadcastChannel|MessageChannel)\b/g]
];
const combine = (...groups) => [...new Map(groups.flat().map(f => [JSON.stringify(f), f])).values()].slice(0, 4);
const keys = node => Object.entries(node).filter(([key, value]) => !['loc', 'tokens', 'comments', 'extra', 'leadingComments', 'trailingComments', 'innerComments'].includes(key) && value && typeof value === 'object').flatMap(([, value]) => Array.isArray(value) ? value : [value]).filter(v => v?.type);
function contextAt(lines, line, column) {
  const previous = lines.slice(Math.max(0,line - 4),line - 1), full = [...previous,...lines.slice(line - 1,line + 3)].join('\n');
  const focus = previous.reduce((sum,s)=>sum + s.length + 1,0) + column - 1;
  const start = full.length > 4096 ? Math.max(0,focus - 1600) : 0;
  return {context:full.slice(start,start + 4096),context_truncated:full.length > 4096};
}
function names(node) {
  if (!node) return [];
  if (node.type === 'Identifier') return [node.name];
  if (node.type === 'ObjectProperty') return names(node.value);
  if (node.type === 'AssignmentPattern') return names(node.left);
  return keys(node).flatMap(names);
}

export function inspectFile(file, extension) {
  if (!extension && /\.(?:vue|svelte|html?)$/i.test(file.path)) {
    const extracted = extractScripts(file), findings = [], notes = [...extracted.notes];
    for (const block of extracted.blocks) {
      const scanned = inspectFile(block, block.extension);
      // Use original file context rather than padded extraction text.
      const lines = file.content.split(/\r?\n/);
      findings.push(...scanned.findings.map(f => ({...f, ...contextAt(lines,f.line,f.column)})));
      notes.push(...scanned.notes);
      if (findings.length >= 1000) { findings.length = 1000; notes.push({path:file.path, code:'findingBudget'}); break; }
    }
    return {findings, notes, analyzed: extracted.blocks.length > 0, blocks: extracted.blocks.length};
  }
  const findings = [], notes = [], lines = file.content.split(/\r?\n/);
  const text = node => node ? file.content.slice(node.start, node.end) : '';
  const name = node => {
    if (!node) return '';
    if (node.type === 'Identifier') return node.name;
    if (['MemberExpression', 'OptionalMemberExpression'].includes(node.type)) {
      const property = node.computed ? (node.property.type === 'StringLiteral' ? node.property.value : null) : node.property.name;
      if (property !== null && property !== undefined) return name(node.object) + '.' + property;
    }
    return text(node).replace(/\s/g, '');
  };
  let visited = 0;
  const modifiedSanitizers = new Set();
  const seen = new Set();
  function emit(flows, node, category, sink) {
    for (const flow of flows) {
      const key = [node.start, category, flow.line, flow.source].join(':');
      if (seen.has(key)) continue;
      if (findings.length >= 1000) throw Error('findingBudget');
      seen.add(key);
      findings.push({ path: file.path, line: node.loc.start.line, column: node.loc.start.column + 1, rule: 'JS-' + category.toUpperCase() + '-FLOW', category, priority: category === 'html' && flow.sanitized ? 'medium' : 'high', mode: 'ast', source: { line: flow.line, text: flow.source }, steps: flow.steps, sink: { line: node.loc.start.line, text: sink.slice(0,240) }, sanitized: Boolean(flow.sanitized), evidence_truncated:Boolean(flow.truncated || sink.length > 240), ...contextAt(lines,node.loc.start.line,node.loc.start.column + 1) });
    }
  }
  function walk(node, env, depth = 0) {
    if (!node) return [];
    if (++visited > LIMITS.nodes || depth > LIMITS.depth) throw Error('analysisBudget');
    const type = node.type, line = node.loc?.start.line || 1;
    if (/Literal$/.test(type) || type === 'JSXText' || type.startsWith('Comment')) return [];
    if (type === 'Identifier') return env.get(node.name) || [];
    if (['MemberExpression', 'OptionalMemberExpression'].includes(type) && sourcePattern.test(name(node))) return [{ source: text(node).slice(0, 120), truncated:text(node).length > 120, line, steps: [] }];
    if (['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'TSSatisfiesExpression', 'ParenthesizedExpression'].includes(type)) return walk(node.expression, env, depth + 1);
    if (type.startsWith('TS')) return [];
    if (type === 'ImportDeclaration') {
      for (const specifier of node.specifiers) {
        const local = specifier.local?.name;
        const recognized = specifier.type === 'ImportDefaultSpecifier' && ((local === 'DOMPurify' && ['dompurify','isomorphic-dompurify'].includes(node.source.value)) || (local === 'sanitizeHtml' && node.source.value === 'sanitize-html'));
        if (local && !recognized) env.set(local, []);
      }
      return [];
    }
    if (type === 'Program') {
      // Bind declarations before traversal, including later function declarations.
      for (const statement of node.body) {
        const stmt = statement.declaration || statement;
        if (stmt.type === 'VariableDeclaration') for (const d of stmt.declarations) for (const key of names(d.id)) env.set(key, []);
        if (['FunctionDeclaration','ClassDeclaration'].includes(stmt.type) && stmt.id) env.set(stmt.id.name, []);
      }
      for (const stmt of node.body) walk(stmt,env,depth + 1);
      return [];
    }
    if (type === 'CatchClause') {
      const local = new Map(env);
      for (const key of names(node.param)) local.set(key, []);
      walk(node.body, local, depth + 1); return [];
    }
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod'].includes(type)) {
      const local = new Map(env);
      for (const param of node.params || []) for (const key of names(param)) local.set(key, []);
      if (node.id) local.set(node.id.name, []);
      walk(node.body, local, depth + 1); return [];
    }
    if (type === 'BlockStatement') {
      const local = new Map(env), declared = new Set();
      for (const stmt of node.body) {
        if (stmt.type === 'VariableDeclaration') for (const decl of stmt.declarations) for (const key of names(decl.id)) declared.add(key);
        if (stmt.type === 'FunctionDeclaration' && stmt.id) declared.add(stmt.id.name);
      }
      // Hoisted/shadowed names must not inherit outside taint.
      for (const key of declared) local.set(key, []);
      for (const stmt of node.body) walk(stmt, local, depth + 1);
      for (const key of env.keys()) if (!declared.has(key)) env.set(key, local.get(key) || []);
      return [];
    }
    if (type === 'IfStatement' || type === 'ConditionalExpression') {
      walk(node.test, env, depth + 1);
      const left = new Map(env), right = new Map(env);
      const a = walk(node.consequent, left, depth + 1), b = walk(node.alternate, right, depth + 1);
      for (const key of new Set([...left.keys(), ...right.keys()])) env.set(key, combine(left.get(key) || [], right.get(key) || []));
      return combine(a, b);
    }
    if (/^(?:For|While|DoWhile|Switch|Try)/.test(type)) {
      const before = new Map(env);
      for (const child of keys(node)) walk(child, env, depth + 1);
      for (const [key, value] of before) env.set(key, combine(value, env.get(key) || []));
      return [];
    }
    if (type === 'VariableDeclarator') {
      const flows = walk(node.init, env, depth + 1);
      if (node.id.type === 'Identifier') env.set(node.id.name, flows.map(f => ({ ...f, truncated:f.truncated || node.id.name.length > 120, steps: [...f.steps.slice(-4), { line, text: node.id.name.slice(0,120) }] })));
      else { for (const key of names(node.id)) env.set(key, flows); notes.push({ path: file.path, code: 'destructuring' }); }
      return flows;
    }
    if (type === 'AssignmentExpression') {
      let flows = walk(node.right, env, depth + 1);
      if (node.operator !== '=') flows = combine(walk(node.left, env, depth + 1), flows);
      const target = name(node.left);
      if (['DOMPurify','DOMPurify.sanitize','sanitizeHtml'].includes(target)) modifiedSanitizers.add(target.split('.')[0]);
      if (node.left.type === 'Identifier') env.set(node.left.name, flows.map(f => ({ ...f, truncated:f.truncated || node.left.name.length > 120, steps: [...f.steps.slice(-4), { line, text: node.left.name.slice(0,120) }] })));
      else if (/\.(?:innerHTML|outerHTML)$|\[['"](?:innerHTML|outerHTML)['"]\]$/.test(target)) emit(flows, node, 'html', text(node.left));
      else if (/(?:^|\.)location(?:\.href)?$|\.(?:href|src|action)$/.test(target)) emit(flows, node, 'url', text(node.left));
      return flows;
    }
    if (['CallExpression', 'OptionalCallExpression', 'NewExpression'].includes(type)) {
      const callee = name(node.callee), values = (node.arguments || []).map(arg => walk(arg, env, depth + 1));
      const receiver = node.callee?.object ? walk(node.callee.object, env, depth + 1) : [];
      const all = combine(receiver, ...values);
      if (/^(?:window\.)?(?:localStorage|sessionStorage)\.(?:getItem|key)$/.test(callee)) return [{ source: callee, line, steps: [] }];
      if (['DOMPurify.sanitize', 'sanitizeHtml'].includes(callee) && !env.has(callee.split('.')[0]) && !modifiedSanitizers.has(callee.split('.')[0])) return all.map(f => ({ ...f, sanitized: true }));
      if (['eval', 'window.eval', 'Function'].includes(callee)) emit(all, node, 'code', callee);
      else if (['setTimeout', 'setInterval'].includes(callee)) emit(values[0] || [], node, 'code', callee);
      else if (['window.open', 'location.assign', 'location.replace', 'window.location.assign', 'window.location.replace'].includes(callee)) emit(values[0] || [], node, 'url', callee);
      else if (['document.write', 'document.writeln'].includes(callee) || /\.(?:insertAdjacentHTML|setHTMLUnsafe)$/.test(callee)) emit(callee.endsWith('.insertAdjacentHTML') ? values[1] || [] : all, node, 'html', callee);
      return all;
    }
    if (type === 'JSXAttribute' && node.name?.name === 'dangerouslySetInnerHTML') {
      const flows = walk(node.value, env, depth + 1); emit(flows, node, 'html', 'dangerouslySetInnerHTML'); return flows;
    }
    if (type === 'ObjectProperty') return walk(node.value, env, depth + 1);
    return combine(...keys(node).map(child => walk(child, env, depth + 1)));
  }
  if (!extension && !supported.test(file.path)) return { findings: [], notes: [{ path: file.path, code: 'unsupported' }], analyzed: false };
  try {
    const plugins = [];
    const syntax = extension ? '.' + extension : file.path;
    if (/\.tsx?$/i.test(syntax)) plugins.push('typescript');
    if (/\.[jt]sx$/i.test(syntax)) plugins.push('jsx');
    const ast = parse(file.content, { sourceType: 'unambiguous', plugins, errorRecovery: false });
    walk(ast.program, new Map());
  } catch (error) {
    notes.push({ path: file.path, code: ['analysisBudget', 'findingBudget'].includes(error.message) ? error.message : 'parse', line: error.loc?.line || null });
  }
  for (const [rule, category, regex] of patterns) {
    if (findings.length >= 1000) { notes.push({path:file.path,code:'findingBudget'}); break; }
    regex.lastIndex = 0;
    for (const match of file.content.matchAll(regex)) {
      const line = file.content.slice(0, match.index).split('\n').length;
      if (findings.some(f => f.line === line && f.category === category)) continue;
      const column = match.index - file.content.lastIndexOf('\n', match.index - 1);
      findings.push({ path: file.path, line, column, rule, category, priority: 'info', mode: 'pattern', ...contextAt(lines,line,column) });
      if (findings.length >= 1000) { notes.push({ path: file.path, code: 'findingBudget' }); break; }
    }
    if (findings.length >= 1000) break;
  }
  return { findings, notes: [...new Map(notes.map(n => [n.code, n])).values()], analyzed: true };
}

export async function analyzeProject(files, options = {}) {
  validateFiles(files);
  const scope = validateScope(options.scope || DEFAULT_SCOPE), started = performance.now();
  const result = { schema_version:2, engine: ENGINE, created_at: new Date().toISOString(), scope, files: [], findings: [], notes: [], incomplete: false };
  let exhausted = false;
  for (const file of files) {
    const reason = scopeReason(file.path, scope);
    if (reason || exhausted) {
      result.files.push({path:file.path, analyzed:false, reason:reason || 'projectBudget'});
      if (reason === 'unsupported') result.notes.push({path:file.path, code:reason});
      continue;
    }
    const scanned = inspectFile(file);
    const identityCounts = new Map();
    const sourceDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(file.content));
    const sourceHash = [...new Uint8Array(sourceDigest)].map(n => n.toString(16).padStart(2, '0')).join('');
    result.files.push({ path: file.path, analyzed: scanned.analyzed, sha256:sourceHash, complete:scanned.notes.length === 0, ...(scanned.blocks !== undefined ? {blocks:scanned.blocks} : {}) });
    result.notes.push(...scanned.notes);
    for (const finding of scanned.findings) {
      const key = [ENGINE, finding.path, finding.rule, sourceHash, finding.line, finding.column].join('\0');
      const occurrence = identityCounts.get(key) || 0;
      identityCounts.set(key, occurrence + 1);
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key + '\0' + occurrence));
      finding.id = [...new Uint8Array(digest)].map(n => n.toString(16).padStart(2, '0')).join('');
      finding.status = 'pending'; finding.note = '';
      result.findings.push(finding);
      if (result.findings.length >= LIMITS.findings) { result.notes.push({ path: file.path, code: 'projectBudget' }); result.incomplete = true; exhausted = true; break; }
    }
  }
  result.incomplete ||= result.notes.length > 0;
  result.duration_ms = Math.round(performance.now() - started);
  return result;
}
