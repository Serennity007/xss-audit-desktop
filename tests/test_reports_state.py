import json
import tempfile
import unittest
from pathlib import Path

from xss_audit.reports import html_report, sarif
from xss_audit.scanner import scan, write_report
from xss_audit.state import StateStore


class ReportsStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = self.root/'项目'
        source.mkdir()
        (source/'example.js').write_text('const q=location.hash;\nel.innerHTML=q;\n// </pre><script>alert("report-injection")</script>', encoding='utf-8')
        self.result = scan(source, collect_source=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_html_escapes_code_and_model_output(self):
        self.result.ai_report = '</pre><script>alert("model-injection")</script>'
        text = html_report(self.result)
        self.assertNotIn('<script>alert(', text)
        self.assertIn('&lt;script&gt;alert(', text)
        self.assertIn('Content-Security-Policy', text)
        self.assertNotIn('<script src=', text)
        self.assertIn('AST', text)

    def test_sarif_uses_relative_encoded_paths_and_unverified_results(self):
        self.result.matches[0].path = '中文/example file.js'
        self.result.matches[0].status = '误报'
        data = sarif(self.result)
        self.assertEqual(data['version'], '2.1.0')
        run = data['runs'][0]
        item = run['results'][0]
        self.assertTrue(item['properties']['unverified'])
        self.assertEqual(item['suppressions'][0]['kind'], 'external')
        uri = item['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertIn('%20', uri)
        self.assertNotIn('C:', uri)

    def test_export_all_formats_and_no_overwrite(self):
        for fmt, suffix in [('html','html'), ('sarif','sarif'), ('json','json'), ('markdown','md')]:
            target = self.root/f'report.{suffix}'
            write_report(self.result, target, fmt)
            self.assertTrue(target.stat().st_size > 100)
            with self.assertRaises(FileExistsError):
                write_report(self.result, target, fmt)
        with self.assertRaises(ValueError):
            write_report(self.result, self.root/'bad', 'invalid')

    def test_review_roundtrip_and_changed_code_does_not_inherit(self):
        store = StateStore(self.root/'state')
        match = self.result.matches[0]
        match.status, match.note = '误报', '实际来源已有外部约束，人工确认。'
        store.save_review(self.result)
        fresh = scan(self.result.root)
        store.apply(fresh)
        saved = next(item for item in fresh.matches if item.fingerprint == match.fingerprint)
        self.assertEqual(saved.status, '误报')
        changed = Path(self.result.root)/'example.js'
        changed.write_text('const q=location.search; el.outerHTML=q;', encoding='utf-8')
        fresh = scan(self.result.root)
        store.apply(fresh)
        self.assertTrue(all(m.status == '待人工确认' for m in fresh.matches))

    def test_preferences_never_save_api_key_and_corruption_is_reported(self):
        store = StateStore(self.root/'state')
        store.save_preferences(base_url='https://api.example/v1', model='example-model', api_format='chat', api_key='must-never-be-stored')
        self.assertNotIn('must-never-be-stored', (self.root/'state/preferences.json').read_text())
        self.assertEqual(store.preferences()['api_format'], 'chat')
        (self.root/'state/preferences.json').write_text('not json')
        with self.assertRaises(ValueError):
            store.preferences()


if __name__ == '__main__':
    unittest.main()
