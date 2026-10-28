"""End-to-end research trials with scripted responders and temporary projects."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xss_audit.research_cli import main
from xss_audit.research_runner import OfflineDemoResponder, create_demo, run_pair, validate_pair


class ResearchRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_offline_demo_builds_traces_and_labeled_proxy_report(self):
        result = create_demo(self.root / "demo", offline_demo=True, language="zh-CN")
        report = result["results"]["report"]
        self.assertFalse(report["empirical_model_results"])
        self.assertEqual(report["execution"], "offline_demo")
        trial = report["trials"][0]
        self.assertEqual(trial["runs"]["baseline"]["status"], "completed")
        self.assertEqual(trial["score"]["detection_regression"], {"n": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(trial["score"]["location_regression"]["rate"], None)
        self.assertEqual(trial["runs"]["variant"]["provenance"]["execution"], "offline_demo")
        self.assertNotIn("synthetic-dom-xss", json.dumps(trial["runs"]["baseline"].get("transcript", [])))
        self.assertIn("离线脚本演示", Path(result["results"]["html"]).read_text(encoding="utf-8"))
        case, manifest = validate_pair(result["case"])
        self.assertTrue(manifest["source_byte_identical"])
        self.assertFalse((case / "baseline" / "ground-truth.json").exists())
        self.assertFalse((case / "variant" / "manifest.json").exists())

    def test_balanced_repetition_preserves_denominators_and_execution_order(self):
        demo = create_demo(self.root / "demo")
        result = run_pair(demo["case"], self.root / "runs", OfflineDemoResponder,
                          execution="offline_demo", repeats=2)
        trials = result["report"]["trials"]
        self.assertEqual([trial["execution_order"] for trial in trials], [["baseline", "variant"], ["variant", "baseline"]])
        self.assertEqual(result["report"]["aggregate"]["metrics"]["detection_regression"]["denominator"], 2)
        self.assertEqual(result["report"]["aggregate"]["run_status_counts"], {"completed": 4})

    def test_custom_callback_defaults_to_mock_and_cannot_impersonate_offline_live(self):
        demo = create_demo(self.root / "demo")
        result = run_pair(demo["case"], self.root / "mock", lambda condition: lambda messages: '{"action":"finish","findings":[]}')
        self.assertEqual(result["report"]["execution"], "mock")
        self.assertFalse(result["report"]["empirical_model_results"])
        self.assertIsNone(result["report"]["aggregate"]["metrics"]["detection_regression"]["rate"])
        with self.assertRaisesRegex(ValueError, "provenance"):
            run_pair(demo["case"], self.root / "invalid-live", OfflineDemoResponder, execution="live")

    def test_source_context_and_inventory_tampering_are_rejected(self):
        for name in ("source", "context", "inventory"):
            with self.subTest(name=name):
                demo = create_demo(self.root / name)
                case = Path(demo["case"])
                target = case / "variant" / {"source": "src/view.js", "context": "README.md", "inventory": "extra.js"}[name]
                with target.open("a", encoding="utf-8") as stream:
                    stream.write("\n// altered\n")
                with self.assertRaisesRegex(ValueError, "changed|mismatch"):
                    validate_pair(case)

    def test_mid_trial_mutation_is_retained_as_failed_not_successful(self):
        demo = create_demo(self.root / "demo")
        target = Path(demo["case"]) / "baseline" / "src/view.js"
        def factory(condition):
            def respond(messages):
                target.write_text("// changed during a trial", encoding="utf-8")
                return '{"action":"finish","findings":[]}'
            return respond
        result = run_pair(demo["case"], self.root / "runs", factory)
        self.assertEqual(result["report"]["aggregate"]["run_status_counts"], {"invariance_failed": 2})
        self.assertEqual(result["report"]["aggregate"]["metrics"]["detection_regression"]["denominator"], 0)
        self.assertTrue(Path(result["json"]).exists())

    def test_mid_trial_manifest_and_source_rewrites_cannot_replace_frozen_oracle(self):
        import hashlib
        demo = create_demo(self.root / "demo")
        case = Path(demo["case"])
        manifest_path = case / "manifest.json"
        def factory(condition):
            def respond(messages):
                updated = b"// both copies changed during trial\n"
                for name in ("baseline", "variant"):
                    (case / name / "src/view.js").write_bytes(updated)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                digest = hashlib.sha256(updated).hexdigest()
                manifest["source_hashes"]["src/view.js"] = digest
                for item in manifest["copied"]:
                    if item["path"] == "src/view.js":
                        item["sha256"] = digest
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                return '{"action":"finish","findings":[]}'
            return respond
        result = run_pair(case, self.root / "runs", factory)
        self.assertEqual(result["report"]["aggregate"]["run_status_counts"], {"invariance_failed": 2})
        self.assertEqual(result["report"]["aggregate"]["metrics"]["detection_regression"]["denominator"], 0)

    def test_cli_keeps_ground_truth_outside_audited_project(self):
        project = self.root / "project"
        project.mkdir()
        (project / "view.js").write_text("el.innerHTML=location.hash;", encoding="utf-8")
        truth = project / "truth.json"
        truth.write_text("[]", encoding="utf-8")
        output = self.root / "pair"
        self.assertEqual(main(["prepare", str(project), "--output", str(output), "--ground-truth", str(truth)]), 2)
        self.assertFalse(output.exists())

    def test_cli_live_mode_requires_explicit_ai_and_credentials(self):
        demo = create_demo(self.root / "demo")
        with self.assertRaises(SystemExit):
            main(["run", demo["case"], "--output", str(self.root / "missing-consent")])
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            self.assertEqual(main(["run", demo["case"], "--output", str(self.root / "missing-key"), "--ai", "--model", "mock-model"]), 2)
        self.assertFalse((self.root / "missing-key").exists())

    def test_output_is_never_overwritten_or_created_inside_audited_tree(self):
        demo = create_demo(self.root / "demo")
        with self.assertRaises(ValueError):
            create_demo(self.root / "demo")
        with self.assertRaisesRegex(ValueError, "outside"):
            run_pair(demo["case"], Path(demo["case"]) / "baseline" / "results", OfflineDemoResponder, execution="offline_demo")


if __name__ == "__main__":
    unittest.main()
