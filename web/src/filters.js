export function filterFindings(result, filters, t) {
  const query = (filters.query || '').toLowerCase();
  return result.findings.filter(f => (!filters.priority || f.priority === filters.priority) && (!filters.category || f.category === filters.category) && (!filters.mode || f.mode === filters.mode) && (!filters.status || f.status === filters.status) && (!filters.baseline || f.baseline_state === filters.baseline) && (!filters.path || f.path === filters.path) && [f.path, f.rule, f.context, t(f.category), f.note].join(' ').toLowerCase().includes(query)).sort((a,b) => ({high:0,medium:1,info:2}[a.priority] - {high:0,medium:1,info:2}[b.priority]) || a.path.localeCompare(b.path) || a.line - b.line || a.column - b.column);
}
