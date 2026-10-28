import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xss_audit.baseline import compare, load_baseline
from xss_audit.cli import main
from xss_audit.reports import html_report, sarif
from xss_audit.scanner import scan, write_report, markdown


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.code = self.root / "code"
        self.code.mkdir()
        (self.code / "old.js").write_text("const q=location.hash;\nel.innerHTML=q;", encoding="utf-8")
        self.old = scan(self.code)
        self.baseline = self.root / "baseline.json"
        write_report(self.old, self.baseline, "json")

    def test_added_changed_and_unchanged(self):
        data = load_baseline(self.baseline)
        value = compare(scan(self.code), data)
        self.assertEqual(value["new"], 0)
        self.assertEqual(value["unchanged"], len(self.old.matches))
        self.assertFalse(value["not_observed"])
        (self.code / "new.js").write_text("eval(location.hash);", encoding="utf-8")
        fresh = scan(self.code)
        value = compare(fresh, data)
        self.assertGreater(value["new"], 0)
        self.assertEqual(value["unchanged"], len(self.old.matches))
        for match in fresh.matches:
            self.assertEqual(match.baseline_state, "new" if match.path == "new.js" else "unchanged")
        (self.code / "old.js").write_text("el.textContent='constant';", encoding="utf-8")
        value = compare(scan(self.code), data)
        self.assertEqual(len(value["not_observed"]), len(self.old.matches))
        self.assertNotIn("snippet", value["not_observed"][0])

    def test_duplicate_identities_and_review_decisions(self):
        fresh = scan(self.code)
        fresh.matches.append(copy.deepcopy(fresh.matches[0]))
        fresh.matches[-1].status = "误报"
        value = compare(fresh, load_baseline(self.baseline))
        self.assertEqual(value["new"], 1)
        self.assertEqual(fresh.matches[-1].status, "误报")

    def test_reject_incomplete_and_filtered_baselines(self):
        original = json.loads(self.baseline.read_text(encoding="utf-8"))
        for key in ("cancelled", "truncated", "ast_incomplete", "incomplete", "coverage_errors"):
            data = copy.deepcopy(original)
            data[key] = True
            self.baseline.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(self.baseline)
        for filters in ({"only_new": True}, {"ignore_reviewed": True}, {"min_priority": "高"}, {"matches_before_filters": 999}):
            data = copy.deepcopy(original)
            data["report_filters"] = filters
            self.baseline.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(self.baseline)

    def test_source_change_and_legacy_reports_require_new_review(self):
        data = load_baseline(self.baseline)
        (self.code / "old.js").write_text("const q=location.hash;\nel.innerHTML=q;\n// source changed", encoding="utf-8")
        fresh = scan(self.code)
        self.assertEqual(fresh.matches[0].fingerprint, self.old.matches[0].fingerprint)
        self.assertEqual(compare(fresh, data)["unchanged"], 0)
        for row in data["matches"]:
            row.pop("evidence_hash", None)
        self.assertTrue(compare(fresh, data)["baseline_legacy"])

    def test_malformed_and_oversized_input(self):
        original = json.loads(self.baseline.read_text(encoding="utf-8"))
        bad_match = copy.deepcopy(original)
        bad_match["matches"][0]["fingerprint"] = "wrong"
        for data in ([], {}, bad_match, {"root": "x", "matches": [], "files_scanned": 1, "skipped": None}):
            self.baseline.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(self.baseline)
        self.baseline.write_bytes(b"\xff")
        with self.assertRaises(ValueError):
            load_baseline(self.baseline)
        self.baseline.write_text("{}", encoding="utf-8")
        with patch("xss_audit.baseline.MAX_BASELINE_BYTES", 1), self.assertRaises(ValueError):
            load_baseline(self.baseline)

    def test_report_escaping_localization_and_incomplete_current_scan(self):
        fresh = scan(self.code)
        data = load_baseline(self.baseline)
        compare(fresh, data)
        self.assertIn("Baseline comparison", markdown(fresh, "en"))
        self.assertIn("基线对比", markdown(fresh, "zh-CN"))
        self.assertIn("Unchanged signal", html_report(fresh, "en"))
        run = sarif(fresh)["runs"][0]
        self.assertTrue(all(m["baselineState"] == "unchanged" for m in run["results"]))
        data["matches"][0]["path"] = '</pre><script>baseline</script>'
        fresh.cancelled = True
        self.assertTrue(compare(fresh, data)["current_incomplete"])
        text = html_report(fresh, "en")
        self.assertNotIn("<script>baseline", text)
        self.assertIn("&lt;script&gt;baseline", text)

    def test_cli_new_only_gate_and_filtered_baseline_rejection(self):
        def run(output):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return main([str(self.code), "--baseline", str(self.baseline), "--only-new", "--fail-on-match", "--no-saved-review", "--format", "json", "-o", str(output)])
        first = self.root / "first.json"
        self.assertEqual(run(first), 0)
        self.assertEqual(json.loads(first.read_text(encoding="utf-8"))["matches"], [])
        (self.code / "new.js").write_text("eval(location.hash);", encoding="utf-8")
        second = self.root / "second.json"
        self.assertEqual(run(second), 1)
        data = json.loads(second.read_text(encoding="utf-8"))
        self.assertTrue(all(m["path"] == "new.js" for m in data["matches"]))
        self.assertGreater(data["baseline"]["unchanged"], 0)
        with self.assertRaises(ValueError):
            load_baseline(second)

    def test_cli_requires_baseline_and_preserves_incomplete_exit(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main([str(self.code), "--only-new"])
        self.assertEqual(caught.exception.code, 2)
        fresh = scan(self.code)
        fresh.cancelled = True
        with patch("xss_audit.cli.scan", return_value=fresh), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.code), "--baseline", str(self.baseline), "--only-new", "--no-saved-review", "--format", "json", "-o", str(self.root / "cancelled.json")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
