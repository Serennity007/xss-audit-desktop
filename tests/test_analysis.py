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

    def test_srcdoc_tracks_html_flow_and_preserves_safe_values(self):
        for code in ('frame.srcdoc=location.hash;', 'frame["srcdoc"] = location.hash;'):
            with self.subTest(code=code):
                found = self.high(code)
                self.assertEqual([item['rule_id'] for item in found], ['JS-HTML-FLOW'])
                self.assertIn('location.hash', found[0]['evidence'][0])
        self.assertFalse(self.high('frame.srcdoc="<p>fixed</p>";'))
        self.assertFalse(self.high('frame.srcdoc=DOMPurify.sanitize(location.hash);'))

    def test_jquery_html_only_models_known_factory_setters(self):
        for factory in ('$', 'jQuery'):
            with self.subTest(factory=factory):
                found = self.high(f'{factory}("#output").html(location.hash);')
                self.assertEqual([item['rule_id'] for item in found], ['JS-HTML-FLOW'])
                self.assertFalse(self.high(f'{factory}(location.hash).html();'))
                self.assertFalse(self.high(f'{factory}(location.hash).html("fixed");'))
                self.assertFalse(self.high(f'{factory}("#output").text(location.hash);'))
        self.assertFalse(self.high('view.html(location.hash);'))
        self.assertFalse(self.high('function $(x){return view;} $("#output").html(location.hash);'))
        self.assertFalse(self.high('const $=custom; $("#output").html(location.hash);'))
        self.assertFalse(self.high('$("#output").html(DOMPurify.sanitize(location.hash));'))
        self.assertEqual(self.high('import $ from "jquery"; $("#output").html(location.hash);')[0]['rule_id'], 'JS-HTML-FLOW')
        self.assertFalse(self.high('import $ from "./custom.js"; $("#output").html(location.hash);'))

    def test_local_sanitizer_names_do_not_hide_html_flow(self):
        cases = [
            'function sanitizeHtml(x){return x;} el.innerHTML=sanitizeHtml(location.hash);',
            'el.innerHTML=sanitizeHtml(location.hash); function sanitizeHtml(x){return x;}',
            'const sanitizeHtml=x=>x; el.innerHTML=sanitizeHtml(location.hash);',
            'function render(sanitizeHtml){el.innerHTML=sanitizeHtml(location.hash);}',
            'const DOMPurify={sanitize:x=>x}; el.innerHTML=DOMPurify.sanitize(location.hash);',
            'function render(DOMPurify){el.innerHTML=DOMPurify.sanitize(location.hash);}',
            'function render({DOMPurify}){el.innerHTML=DOMPurify.sanitize(location.hash);}',
            'try {} catch(DOMPurify){el.innerHTML=DOMPurify.sanitize(location.hash);}',
            '({DOMPurify}=custom); el.innerHTML=DOMPurify.sanitize(location.hash);',
            'DOMPurify.sanitize=x=>x; el.innerHTML=DOMPurify.sanitize(location.hash);',
            'DOMPurify["sanitize"]=x=>x; el.innerHTML=DOMPurify.sanitize(location.hash);',
            'import sanitizeHtml from "./custom.js"; el.innerHTML=sanitizeHtml(location.hash);',
            'import DOMPurify from "./custom.js"; el.innerHTML=DOMPurify.sanitize(location.hash);',
        ]
        for code in cases:
            with self.subTest(code=code):
                self.assertEqual([item['rule_id'] for item in self.high(code)], ['JS-HTML-FLOW'])

    def test_real_sanitizer_imports_and_nested_scopes_keep_existing_behavior(self):
        for code in (
            'import DOMPurify from "dompurify"; el.innerHTML=DOMPurify.sanitize(location.hash);',
            'import sanitizeHtml from "sanitize-html"; el.innerHTML=sanitizeHtml(location.hash);',
            'const DOMPurify=require("dompurify"); el.innerHTML=DOMPurify.sanitize(location.hash);',
            'const sanitizeHtml=require("sanitize-html"); el.innerHTML=sanitizeHtml(location.hash);',
            'function local(){const DOMPurify={};} el.innerHTML=DOMPurify.sanitize(location.hash);',
        ):
            with self.subTest(code=code):
                self.assertFalse(self.high(code))
        self.assertTrue(self.high('function require(){return custom;} const DOMPurify=require("dompurify"); el.innerHTML=DOMPurify.sanitize(location.hash);'))

    def test_js_block_bindings_do_not_shadow_outer_sanitizer(self):
        self.assertFalse(self.high('import DOMPurify from "dompurify"; { const DOMPurify=custom; } el.innerHTML=DOMPurify.sanitize(location.hash);'))
        self.assertFalse(self.high('import DOMPurify from "dompurify"; { let DOMPurify=custom; } el.innerHTML=DOMPurify.sanitize(location.hash);'))
        found = self.high('import DOMPurify from "dompurify"; { const DOMPurify=custom; el.innerHTML=DOMPurify.sanitize(location.hash); } el.innerHTML=DOMPurify.sanitize(location.hash);')
        self.assertEqual([item['rule_id'] for item in found], ['JS-HTML-FLOW'])
        self.assertTrue(self.high('import DOMPurify from "dompurify"; { DOMPurify=custom; } el.innerHTML=DOMPurify.sanitize(location.hash);'))
        self.assertTrue(self.high('{ var DOMPurify=custom; } el.innerHTML=DOMPurify.sanitize(location.hash);'))

    def test_python_sql_and_parameter_binding(self):
        found = self.high('value=request.args.get("q")\nquery=f"SELECT * FROM t WHERE x={value}"\ncursor.execute(query)', '.py')
        self.assertEqual([m['rule_id'] for m in found], ['PY-SQL-FLOW'])
        self.assertFalse(self.high('value=request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE x=%s", (value,))', '.py'))

    def test_python_shell_and_safe_argument_array(self):
        self.assertEqual(self.high('x=request.args.get("q")\nsubprocess.run(x, shell=True)', '.py')[0]['cwe'], 'CWE-78')
        self.assertFalse(self.high('x=request.args.get("q")\nsubprocess.run(["tool", x], shell=False)', '.py'))

    def test_python_imported_sink_and_source_aliases(self):
        cases = [
            ('import subprocess as sp\nsp.run(request.args["q"], shell=True)', 'PY-SHELL-FLOW'),
            ('from subprocess import run\nrun(request.args["q"], shell=True)', 'PY-SHELL-FLOW'),
            ('from subprocess import run as launch\nlaunch(request.args["q"], shell=True)', 'PY-SHELL-FLOW'),
            ('from flask import request as r\nfrom os import system as launch\nlaunch(r.args["q"])', 'PY-SHELL-FLOW'),
            ('import requests as client\nclient.get(url=request.args["q"])', 'PY-SSRF-FLOW'),
            ('from urllib.request import urlopen as fetch\nfetch(request.args["q"])', 'PY-SSRF-FLOW'),
            ('from builtins import open as read\nread(request.args["q"])', 'PY-PATH-FLOW'),
            ('from sys import argv as arguments\nopen(arguments[1])', 'PY-PATH-FLOW'),
            ('from flask import render_template_string as render\nrender(request.args["q"])', 'PY-TEMPLATE-FLOW'),
            ('from flask import request as r\nfrom pickle import loads as load\nload(r.get_data())', 'PY-DESERIALIZE-FLOW'),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                self.assertEqual([item['rule_id'] for item in self.high(code, '.py')], [expected])
        self.assertFalse(self.high('from subprocess import run as launch\nlaunch(["tool",request.args["q"]], shell=False)', '.py'))
        self.assertFalse(self.high('from .subprocess import run\nrun(request.args["q"], shell=True)', '.py'))

    def test_python_import_aliases_respect_rebinding_and_function_scopes(self):
        cases = [
            'from subprocess import run\nrun=custom\nrun(request.args["q"],shell=True)',
            'import subprocess as sp\nsp=custom\nsp.run(request.args["q"],shell=True)',
            'from subprocess import run\ndef render(run):\n    run(request.args["q"],shell=True)',
            'from subprocess import run\ndef render():\n    run(request.args["q"],shell=True)\n    run=custom',
            'from subprocess import run\ndef run(x,**kwargs):\n    pass\nrun(request.args["q"],shell=True)',
            'from flask import request as r\nr=custom\neval(r.args["q"])',
            'from subprocess import run\n(run := custom)\nrun(request.args["q"],shell=True)',
            'from subprocess import run\nif flag:\n    run=custom\nelse:\n    run=other\nrun(request.args["q"],shell=True)',
        ]
        for code in cases:
            with self.subTest(code=code):
                self.assertFalse(self.high(code, '.py'))
        found = self.high('from subprocess import run\ndef render(run):\n    run(request.args["q"],shell=True)\nrun(request.args["q"],shell=True)', '.py')
        self.assertEqual([item['line'] for item in found], [4])
        self.assertTrue(self.high('from subprocess import run\nif flag:\n    run=custom\nrun(request.args["q"],shell=True)', '.py'))
        self.assertTrue(self.high('if flag:\n    os=custom\nos.system(request.args["q"])', '.py'))

    def test_python_comprehension_targets_do_not_rebind_function_import(self):
        for expression in ('[subprocess for subprocess in []]', '{subprocess for subprocess in []}', '{subprocess:subprocess for subprocess in []}', '(subprocess for subprocess in [])'):
            with self.subTest(expression=expression):
                code = f'import subprocess\ndef render():\n    unused={expression}\n    subprocess.run(request.args["q"],shell=True)'
                self.assertEqual([item['rule_id'] for item in self.high(code, '.py')], ['PY-SHELL-FLOW'])
        self.assertFalse(self.high('import subprocess\ndef render():\n    for subprocess in []:\n        pass\n    subprocess.run(request.args["q"],shell=True)', '.py'))
        self.assertFalse(self.high('import subprocess\ndef render():\n    unused=[(subprocess := custom) for item in []]\n    subprocess.run(request.args["q"],shell=True)', '.py'))

    def test_python_method_aliases_skip_class_namespace(self):
        code = 'import subprocess\nclass C:\n    subprocess=custom\n    def render(self):\n        subprocess.run(request.args["q"],shell=True)'
        found = self.high(code, '.py')
        self.assertEqual([item['rule_id'] for item in found], ['PY-SHELL-FLOW'])
        self.assertFalse(self.high('import subprocess\nclass C:\n    def render(self, subprocess):\n        subprocess.run(request.args["q"],shell=True)', '.py'))
        self.assertFalse(self.high('class C:\n    import subprocess as local\n    def render(self):\n        local.run(request.args["q"],shell=True)', '.py'))

    def test_python_with_contexts_are_visited_before_body(self):
        cases = [
            ('with open(request.args["p"]) as handle:\n    pass', 1),
            ('async def read():\n    async with open(request.args["p"]) as handle:\n        pass', 2),
            ('from builtins import open as read\nwith read(request.args["p"]) as handle:\n    pass', 2),
        ]
        for code, line in cases:
            with self.subTest(code=code):
                found = self.high(code, '.py')
                self.assertEqual([item['rule_id'] for item in found], ['PY-PATH-FLOW'])
                self.assertEqual(found[0]['line'], line)
        self.assertFalse(self.high('with open("fixed.txt") as handle:\n    pass', '.py'))
        self.assertFalse(self.high('from subprocess import run\nwith context() as run:\n    run(request.args["q"],shell=True)', '.py'))

    def test_python_aliased_safe_loader_identity(self):
        self.assertFalse(self.high('import yaml as y\nfrom yaml import SafeLoader as Loader\ny.load(request.args["q"],Loader=Loader)', '.py'))
        self.assertTrue(self.high('import yaml\nfrom custom import SafeLoader\nyaml.load(request.args["q"],Loader=SafeLoader)', '.py'))
        self.assertTrue(self.high('import yaml\nfrom yaml import SafeLoader\nSafeLoader=custom\nyaml.load(request.args["q"],Loader=SafeLoader)', '.py'))
        self.assertTrue(self.high('SafeLoader=custom\nyaml.load(request.args["q"],Loader=SafeLoader)', '.py'))

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
