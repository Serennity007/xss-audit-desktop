import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xss_audit.analysis import analyze
from xss_audit.scanner import scan
from xss_audit.secrets import redact


class AnalysisTests(unittest.TestCase):
    def high(self, code, suffix=".js"):
        found, notes = analyze(code, suffix)
        self.assertFalse(notes)
        return found

    def test_js_url_search_params_and_alias_flow(self):
        found = self.high('const q = new URLSearchParams(location.search).get("q");\nconst html = q;\nel.innerHTML = html;')
        self.assertEqual([m["rule_id"] for m in found], ["JS-HTML-FLOW"])
        self.assertEqual(found[0]["line"], 3)
        self.assertIn("location.search", found[0]["evidence"][0])
        self.assertTrue(any("html" in step for step in found[0]["evidence"]))

    def test_js_safe_assignment_comments_and_text_content(self):
        self.assertFalse(self.high('let x = location.hash; x = "fixed"; el.innerHTML = x;'))
        self.assertFalse(self.high('// el.innerHTML = location.hash;\nel.textContent = location.hash;'))
        self.assertFalse(self.high('const x = "literal"; eval(x);'))

    def test_js_function_scopes_and_branches(self):
        self.assertFalse(self.high('const x=location.hash; function safe(x) { el.innerHTML = x; }'))
        found = self.high('let x=location.hash; if (ok) { x="fixed"; } el.innerHTML=x;')
        self.assertEqual(len(found), 1)
        self.assertFalse(self.high('let x=location.hash; if (ok) { x="fixed"; } else { x="also fixed"; } el.innerHTML=x;'))

    def test_tsx_and_typescript(self):
        self.assertEqual(self.high('const q:string=location.hash; const view=<div dangerouslySetInnerHTML={{__html:q}}/>;', '.tsx')[0]['rule_id'], 'JS-HTML-FLOW')
        self.assertEqual(self.high('const q: string=location.hash; window.open(q);', '.ts')[0]['rule_id'], 'JS-URL-FLOW')

    def test_html_sanitizer_does_not_make_navigation_safe(self):
        self.assertFalse(self.high('const x=DOMPurify.sanitize(location.hash); el.innerHTML=x;'))
        found = self.high('const x=DOMPurify.sanitize(location.hash); window.open(x);')
        self.assertEqual(found[0]['rule_id'], 'JS-URL-FLOW')
        # Unknown sanitizer names are not assumed to sanitize HTML.
        self.assertTrue(self.high('el.innerHTML=customSanitize(location.hash);'))

    def test_python_sql_and_parameter_binding(self):
        found = self.high('value=request.args.get("q")\nquery=f"SELECT * FROM t WHERE x={value}"\ncursor.execute(query)', '.py')
        self.assertEqual([m['rule_id'] for m in found], ['PY-SQL-FLOW'])
        self.assertFalse(self.high('value=request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE x=%s", (value,))', '.py'))

    def test_python_shell_and_safe_argument_array(self):
        self.assertEqual(self.high('x=request.args.get("q")\nsubprocess.run(x, shell=True)', '.py')[0]['cwe'], 'CWE-78')
        self.assertFalse(self.high('x=request.args.get("q")\nsubprocess.run(["tool", x], shell=False)', '.py'))

    def test_python_paths_ssrf_deserialization_and_templates(self):
        found = self.high('x=request.args.get("q")\nopen(x)\nrequests.get(x)\npickle.loads(x)\nrender_template_string(x)', '.py')
        self.assertEqual({m['rule_id'] for m in found}, {'PY-PATH-FLOW', 'PY-SSRF-FLOW', 'PY-DESERIALIZE-FLOW', 'PY-TEMPLATE-FLOW'})
        self.assertFalse(self.high('x=request.args.get("q")\nyaml.safe_load(x)', '.py'))
        self.assertFalse(self.high('x=request.args.get("q")\nyaml.load(x, Loader=yaml.SafeLoader)', '.py'))

    def test_python_safe_reassignment_and_scope(self):
        self.assertFalse(self.high('x=request.args.get("q")\nx="fixed"\neval(x)', '.py'))
        self.assertFalse(self.high('x=request.args.get("q")\ndef local(x):\n    eval(x)', '.py'))
        self.assertFalse(self.high('x=request.args.get("q")\nrequests.get("https://example.org", params={"q":x})', '.py'))
        self.assertFalse(self.high('x=request.args.get("q")\nPath(x)', '.py'))
        self.assertTrue(self.high('x=request.args.get("q")\nPath(x).read_text()', '.py'))
        self.assertTrue(self.high('x=request.args.get("q")\nrequests.get(url=x)', '.py'))

    def test_bad_syntax_is_recorded(self):
        self.assertTrue(analyze('def broken(:', '.py')[1])
        self.assertTrue(analyze('const =;', '.ts')[1])

    def test_unicode_columns(self):
        code = 'const q=location.hash; const 汉字="字"; el.innerHTML=q;'
        self.assertEqual(self.high(code)[0]['column'], code.index('el.innerHTML') + 1)

    def test_scanner_redacts_and_prioritizes_ast_files_for_ai(self):
        secret = 'ghp_' + 'A' * 36
        self.assertNotIn(secret, redact(f'const api_key="prefix {secret} suffix";'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'a.js').write_text('const harmless = "' + 'x' * 200 + '";', encoding='utf-8')
            (root/'z.js').write_text('const q=location.hash; el.innerHTML=q;', encoding='utf-8')
            (root/'secrets.json').write_text('{"api_key":"' + secret + '"}', encoding='utf-8')
            with patch('xss_audit.scanner.AI_CHAR_BUDGET', 350):
                result = scan(root, collect_source=True)
            self.assertEqual(result.sources[0]['path'], 'z.js')
            self.assertNotIn(secret, str(result.to_dict()))
            self.assertTrue(any(m.layer == 20 for m in result.matches))
            self.assertIn('a.js', result.ai_omitted)


if __name__ == '__main__':
    unittest.main()
