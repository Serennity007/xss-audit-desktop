import contextlib
import io
import json
import re
import tempfile
import tkinter as tk
import unittest
from html.parser import HTMLParser
from pathlib import Path

from xss_audit.ai import review
from xss_audit.cli import main
from xss_audit.gui import AuditApp
from xss_audit.i18n import EN, tr
from xss_audit.reports import html_report, sarif
from xss_audit.scanner import scan, write_report, markdown


class VisibleLabels(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.data = []
    def handle_starttag(self, tag, attrs):
        if tag in ('pre', 'script', 'style'):
            self.hidden += 1
    def handle_endtag(self, tag):
        if tag in ('pre', 'script', 'style'):
            self.hidden -= 1
    def handle_data(self, data):
        if not self.hidden:
            self.data.append(data)


class LocalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base/'source'
        self.source.mkdir()
        (self.source/'code.tsx').write_text('const q=location.hash;\nconst view=<div dangerouslySetInnerHTML={{__html:q}}/>;', encoding='utf-8')
        self.result = scan(self.source, collect_source=True)
    def tearDown(self):
        self.temp.cleanup()

    def test_catalog_and_dynamic_messages(self):
        self.assertEqual(tr('开始扫描'), 'Start scan')
        self.assertEqual(tr('开始扫描','zh-CN'), '开始扫描')
        self.assertEqual(tr('x  高'), 'x  高')
        self.assertEqual(tr('扫描文件  7'), 'Files scanned  7')
        self.assertEqual(tr('L9: 潜在外部输入 location.hash'), 'L9: potentially external input location.hash')
        self.assertEqual(tr('L9: 赋值给 高'), 'L9: assigned to 高')
        self.assertEqual(tr('AI 将发送 2 个完整文件；预算外 1 个。'), 'Complete files to send: 2; outside the budget: 1.')
        self.assertNotRegex(tr('AI 接口 HTTP 401；检查接口、权限、额度和模型名称。'), '[\u4e00-\u9fff]')
        self.assertTrue(all(not re.search('[\u4e00-\u9fff]', value) for value in EN.values()))

    def test_default_html_is_english_and_chinese_is_available(self):
        english = html_report(self.result)
        labels = VisibleLabels()
        labels.feed(english)
        self.assertNotRegex(''.join(labels.data), '[\u4e00-\u9fff]')
        self.assertIn('lang="en"',english)
        chinese = html_report(self.result,'zh-CN')
        self.assertIn('lang="zh-CN"',chinese)
        self.assertIn('代码审计报告',chinese)
        self.assertIn('External input',markdown(self.result,'en'))
        self.assertIn('外部输入',markdown(self.result,'zh-CN'))

    def test_json_state_and_fingerprints_are_language_independent(self):
        outputs=[]
        for lang in ('en','zh-CN'):
            path=self.base/(lang+'.json')
            write_report(self.result,path,'json',language=lang)
            outputs.append(json.loads(path.read_text(encoding='utf-8')))
        self.assertEqual(outputs[0]['matches'][0]['fingerprint'], outputs[1]['matches'][0]['fingerprint'])
        self.assertEqual(outputs[0]['matches'][0]['status'], outputs[1]['matches'][0]['status'])
        self.assertEqual(outputs[0]['matches'][0]['priority_label'],'High')
        self.assertEqual(outputs[1]['matches'][0]['priority_label'],'高')
        self.assertIn('External input',outputs[0]['matches'][0]['rule'])
        self.assertIn('外部输入',outputs[1]['matches'][0]['rule'])

    def test_sarif_rule_ids_and_user_text_are_preserved(self):
        self.result.matches[0].note='用户原始备注'
        en=sarif(self.result,'en')['runs'][0]
        zh=sarif(self.result,'zh-CN')['runs'][0]
        self.assertEqual(en['results'][0]['ruleId'],zh['results'][0]['ruleId'])
        self.assertEqual(en['results'][0]['properties']['reviewNote'],'用户原始备注')
        self.assertNotRegex(en['results'][0]['message']['text'],'[\u4e00-\u9fff]')

    def test_cli_help_in_both_languages(self):
        for language, expected in [('en','Local source folder'),('zh-CN','本地代码文件夹')]:
            output=io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
                main(['--lang',language,'--help'])
            self.assertEqual(caught.exception.code,0)
            self.assertIn(expected,output.getvalue())
            if language=='en':
                self.assertNotRegex(output.getvalue(),'[\u4e00-\u9fff]')

    def test_ai_request_uses_selected_language(self):
        for language, expected in [('en','Write the entire report in English'),('zh-CN','Write the entire report in Simplified Chinese')]:
            def transport(request,timeout):
                self.assertIn(expected,json.loads(request.data)['instructions'])
                return io.BytesIO(b'{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"review"}]}]}')
            review(self.result,'dummy-key','mock-model',transport=transport,language=language)
            self.assertEqual(self.result.ai_metadata['requested_language'],language)

    def test_gui_switches_without_losing_review_state(self):
        try:
            root=tk.Tk()
        except tk.TclError:
            self.skipTest('Tk display unavailable')
        root.withdraw()
        try:
            app=AuditApp(root,state_dir=self.base/'state',language='en')
            self.assertEqual(app.scan_button.cget('text'),'Start scan')
            self.assertEqual(root.globalgetvar(app.category._name),'All categories')
            self.assertEqual(root.globalgetvar(app.priority._name),'All priorities')
            self.assertEqual(root.globalgetvar(app.review_status._name),'Needs review')
            self.assertNotRegex(root.globalgetvar(app.status._name),'[\u4e00-\u9fff]')
            self.assertTrue(all(not re.search('[\u4e00-\u9fff]', root.globalgetvar(var._name)) for var in app.metrics))
            app.result=self.result
            app.refresh()
            row=app.tree.get_children()[0]
            app.tree.selection_set(row)
            app.show_match()
            fingerprint=app.result.matches[int(row)].fingerprint
            root.globalsetvar(app.review_status._name,'False positive')
            app.review_note.set('用户原始备注')
            app.save_review()
            app.set_language('zh-CN')
            self.assertEqual(app.scan_button.cget('text'),'开始扫描')
            self.assertEqual(app.result.matches[int(row)].status,'误报')
            app.set_language('en')
            self.assertEqual(app.scan_button.cget('text'),'Start scan')
            self.assertEqual(app.result.matches[int(row)].fingerprint,fingerprint)
            self.assertEqual(app.result.matches[int(row)].note,'用户原始备注')
            self.assertEqual(app.store.preferences()['language'],'en')
            self.assertNotIn('api_key',app.store.preferences())
            app.search.set('External input')
            self.assertTrue(app.tree.get_children())
        finally:
            root.destroy()


if __name__=='__main__':
    unittest.main()
