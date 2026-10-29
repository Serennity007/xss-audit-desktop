import { parseFragment } from 'parse5';

// HTML parsing is inert. Only inline JS/TS blocks are returned; templates are never evaluated.
export function extractScripts(file) {
  const component = /\.(vue|svelte)$/i.test(file.path), notes = [], blocks = [];
  const tree = parseFragment(file.content, { sourceCodeLocationInfo: true });
  let count = 0;
  function visit(node, root = false) {
    if (++count > 20000) throw Error('analysisBudget');
    if (node.tagName === 'script' && (!component || root)) {
      const loc = node.sourceCodeLocation, attrs = Object.fromEntries(node.attrs.map(a => [a.name, a.value]));
      const line = loc?.startLine || 1;
      if ('src' in attrs) { notes.push({path:file.path, code:'externalScript', line}); return; }
      const lang = (attrs.lang || '').toLowerCase(), type = (attrs.type || '').toLowerCase();
      if ((lang && !['js', 'javascript', 'ts', 'typescript', 'jsx', 'tsx'].includes(lang)) || (type && !['module', 'text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(type))) {
        notes.push({path:file.path, code:'nonScript', line}); return;
      }
      if (!loc?.startTag || !loc.endTag) { notes.push({path:file.path, code:'unclosedScript', line}); return; }
      if (blocks.length >= 16) { notes.push({path:file.path, code:'scriptBudget', line}); return; }
      const offset = loc.startTag.endOffset, prefix = file.content.slice(0, offset);
      // Whitespace padding preserves original Babel line/column positions, including same-line tags.
      const padding = prefix.replace(/[^\r\n]/g, ' ');
      blocks.push({ path:file.path, content:padding + file.content.slice(offset, loc.endTag.startOffset), extension: ['ts', 'typescript'].includes(lang) ? 'ts' : lang === 'tsx' ? 'tsx' : lang === 'jsx' ? 'jsx' : 'js', start:offset, end:loc.endTag.startOffset });
      return;
    }
    // Inert <template> content is deliberately excluded, even for plain HTML.
    for (const child of node.childNodes || []) visit(child, node === tree);
  }
  try { visit(tree); } catch { notes.push({path:file.path, code:'analysisBudget'}); }
  notes.push({path:file.path, code:'templateUncovered'});
  if (!blocks.length) notes.push({path:file.path, code:'noInlineScript'});
  return {blocks, notes};
}
