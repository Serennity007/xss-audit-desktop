"""Regression checks for repeatable scans, review identities and coverage policy."""
import json
import tempfile
import unittest
from pathlib import Path

from xss_audit.cli import main
from xss_audit.config import ScanConfig
from xss_audit.reports import sarif
from xss_audit.scanner import scan, write_report
from xss_audit.state import StateStore


class ScanWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def source(self, path, content):
        target = self.project / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_report_export_does_not_add_findings_on_next_scan(self):
        self.source("app.js", "eval(input);")
        first = scan(self.project)
        for fmt, suffix in (("json", "json"), ("html", "html"), ("sarif", "sarif"), ("markdown", "md")):
            write_report(first, self.project / ("audit." + suffix), fmt)
        second = scan(self.project)
        self.assertEqual(first.files_scanned, second.files_scanned)
        self.assertEqual([(m.path, m.rule_id) for m in first.matches], [(m.path, m.rule_id) for m in second.matches])
        self.assertTrue(any(item["reason"] == "审计报告产物" for item in second.skipped))

    def test_business_json_with_similar_name_is_not_excluded(self):
        self.source("xss-audit-report.json", '{"code":"eval(input)"}')
        result = scan(self.project)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(result.matches)

    def test_report_header_inside_business_html_string_is_not_an_exclusion(self):
        self.source("page.html", '<script>const text=\'<meta name="generator" content="XSS Audit Desktop">\'; document.write(location.hash);</script>')
        result = scan(self.project)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(result.matches)

    def test_generated_reports_do_not_consume_source_budgets(self):
        self.source("app.json", '{"code":"eval(input)"}')
        config = ScanConfig(max_files=1, max_file_bytes=128)
        first = scan(self.project, config=config)
        self.assertFalse(first.incomplete)
        write_report(first, self.project / "audit.json", "json")
        write_report(first, self.project / "audit.html", "html")
        second = scan(self.project, config=config)
        self.assertFalse(second.incomplete)
        self.assertEqual(second.files_scanned, 1)
        self.assertEqual(len(second.matches), len(first.matches))

    def test_duplicate_instances_keep_separate_review_decisions(self):
        self.source("app.js", "// pad\n// pad\neval(input)\n// pad\n// pad\n\n" * 2)
        result = scan(self.project)
        self.assertEqual(len(result.matches), 2)
        first, second = result.matches
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        first.status, first.note = "误报", "first"
        second.status, second.note = "确认风险", "second"
        store = StateStore(self.base / "state")
        store.save_review(result)
        fresh = scan(self.project)
        store.apply(fresh)
        self.assertEqual([(m.status, m.note) for m in fresh.matches], [("误报", "first"), ("确认风险", "second")])

    def test_source_change_far_from_sink_requires_new_review(self):
        source = self.source("app.js", 'let q="safe";\n' + "// pad\n" * 10 + 'el.innerHTML=q;\n')
        initial = scan(self.project)
        store = StateStore(self.base / "state")
        for item in initial.matches:
            item.status = "误报"
        store.save_review(initial)
        source.write_text('let q=location.hash;\n' + "// pad\n" * 10 + 'el.innerHTML=q;\n', encoding="utf-8")
        fresh = scan(self.project)
        store.apply(fresh)
        self.assertTrue(fresh.matches)
        self.assertTrue(all(item.status == "待人工确认" for item in fresh.matches))

    def test_read_failure_marks_reports_and_cli_incomplete(self):
        (self.project / "invalid.js").write_bytes(b"\xff\xfe")
        result = scan(self.project)
        self.assertTrue(result.incomplete)
        self.assertIn("read_failed", {item["code"] for item in result.coverage_errors})
        self.assertFalse(sarif(result)["runs"][0]["invocations"][0]["executionSuccessful"])
        target = self.base / "strict.json"
        self.assertEqual(main([str(self.project), "--no-saved-review", "--fail-on-match", "--format", "json", "-o", str(target)]), 2)
        self.assertTrue(json.loads(target.read_text(encoding="utf-8"))["incomplete"])
        self.assertEqual(main([str(self.project), "--no-saved-review", "--allow-partial", "--format", "json", "-o", str(self.base / "partial.json")]), 0)

    def test_project_config_controls_scope_and_budget(self):
        self.source("src/app.js", "eval(input)")
        self.source("tests/fixture.js", "eval(input)")
        self.source(".xss-audit.toml", '[scan]\ninclude=["src/**/*.js"]\nmax_matches=1\n')
        result = scan(self.project)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.scan_config["max_matches"], 1)
        self.assertTrue(result.truncated)
        self.assertTrue(all(item.path == "src/app.js" for item in result.matches))

    def test_cli_explicit_configuration_uses_project_relative_paths(self):
        self.source("src/app.js", "eval(input)")
        self.source("tests/fixture.js", "eval(input)")
        self.source("settings.toml", '[scan]\ninclude=["src/**/*.js"]\n')
        output = self.base / "scoped.json"
        self.assertEqual(main([str(self.project), "--config", "settings.toml", "--no-saved-review", "--format", "json", "-o", str(output)]), 0)
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(data["files_scanned"], 1)
        self.assertTrue(all(item["path"] == "src/app.js" for item in data["matches"]))
        (self.project / "invalid.js").write_bytes(b"\xff\xfe")
        self.source("settings.toml", '[scan]\nstrict=false\n')
        partial = self.base / "configured-partial.json"
        self.assertEqual(main([str(self.project), "--config", "settings.toml", "--no-saved-review", "--format", "json", "-o", str(partial)]), 0)
        self.assertTrue(json.loads(partial.read_text(encoding="utf-8"))["incomplete"])

    def test_pattern_only_and_ast_files_have_explicit_coverage(self):
        self.source("App.vue", '<template><div v-html="q"></div></template>')
        self.source("app.js", "const x=1;")
        result = scan(self.project)
        self.assertEqual({item["path"]: item["status"] for item in result.file_coverage}, {"App.vue": "patterns_only", "app.js": "ast_and_patterns"})
        self.assertFalse(result.incomplete)

    def test_empty_project_and_oversize_source_are_incomplete(self):
        self.assertTrue(scan(self.project).incomplete)
        self.source("app.js", "123456")
        result = scan(self.project, config=ScanConfig(max_file_bytes=5))
        self.assertEqual(result.files_scanned, 0)
        self.assertTrue(result.incomplete)
        self.assertIn("file_budget", {item["code"] for item in result.coverage_errors})

    def test_project_configuration_cannot_disable_resource_guardrails(self):
        from xss_audit.config import load_config
        for key in ("max_file_bytes", "max_total_bytes", "max_files", "max_matches"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ScanConfig(**{key: 2 ** 100})
        self.source(".xss-audit.toml", " " * 65537)
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            load_config(self.project)


if __name__ == "__main__":
    unittest.main()
