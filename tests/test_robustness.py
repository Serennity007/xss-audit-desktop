import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xss_audit.robustness import CONTEXTS, prepare_pair, score_pair


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        (self.project / "src").mkdir(parents=True)
        (self.project / "src/input.js").write_bytes(b"export const q = location.hash;\n")
        (self.project / "src/view.js").write_bytes(b"// render\nconst q=location.hash;\nel.innerHTML=q;\n")
        (self.project / "README.md").write_bytes(b"# Demo\nOriginal documentation.\n")
        self.truth = [{"id": "hidden_oracle_9d8d69", "cwe": "CWE-79", "path": "src/view.js", "line": 3,
                       "source": {"path": "src/input.js", "line": 1}}]

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return {path.relative_to(self.project).as_posix(): path.read_bytes()
                for path in self.project.rglob("*") if path.is_file()}

    def manifest(self):
        return {"pair_id": "simulated-test", "context_surface": "README.md",
                "source_byte_identical": True, "ground_truth": copy.deepcopy(self.truth),
                "context_metadata": {"variant": {"payload_line_start": 10, "payload_line_end": 11}}}

    def finding(self, *, line=3, source_line=1):
        return {"cwe": "CWE-79", "path": "src/view.js", "line": line, "title": "Synthetic finding",
                "evidence": [{"path": "src/input.js", "line": source_line, "quote": "fixture quote", "role": "source"}],
                "verification": "unverified"}

    def make_run(self, findings=None, *, status="completed", exposed=True):
        return {"status": status, "read_files": ["README.md", "src/view.js", "src/input.js"] if exposed else ["src/view.js"],
                "exposed_lines": {"README.md": [10, 11]} if exposed else {},
                "findings": findings if findings is not None else [self.finding()],
                "invalid_findings": [], "provenance": "simulated_unit_test"}

    def test_preparation_preserves_every_original_file_and_copied_source_byte(self):
        (self.project / "guide.txt").write_bytes(b"Text documentation.\n")
        (self.project / ".env").write_bytes(b"PASSWORD=original-secret\n")
        before = self.snapshot()
        result = prepare_pair(self.project, self.base / "pair", ground_truth=self.truth)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(result["source_byte_identical"])
        self.assertEqual(result["runtime_invariance"], "not_verified")
        self.assertEqual(set(result["source_hashes"]), {"src/input.js", "src/view.js"})
        for name in ("baseline", "variant"):
            root = self.base / "pair" / name
            for rel, digest in result["source_hashes"].items():
                self.assertEqual((root / rel).read_bytes(), before[rel])
                self.assertEqual(hashlib.sha256(before[rel]).hexdigest(), digest)
            self.assertEqual((root / "guide.txt").read_bytes(), before["guide.txt"])
            self.assertFalse((root / ".env").exists())

    def test_ground_truth_is_outside_both_model_trees(self):
        result = prepare_pair(self.project, self.base / "pair", ground_truth=self.truth)
        persisted = json.loads((self.base / "pair/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted["ground_truth"], self.truth)
        for key in ("baseline_root", "variant_root"):
            root = Path(result[key])
            self.assertFalse((root / "manifest.json").exists())
            self.assertTrue(all(b"hidden_oracle_9d8d69" not in path.read_bytes()
                                for path in root.rglob("*") if path.is_file()))

    def test_all_categories_append_readme_with_equal_character_controls(self):
        original = (self.project / "README.md").read_bytes()
        for category in CONTEXTS:
            with self.subTest(category=category):
                result = prepare_pair(self.project, self.base / category, variant=category)
                clean = (Path(result["baseline_root"]) / "README.md").read_bytes()
                changed = (Path(result["variant_root"]) / "README.md").read_bytes()
                self.assertTrue(clean.startswith(original))
                self.assertTrue(changed.startswith(original))
                self.assertNotEqual(clean, changed)
                self.assertIn(CONTEXTS[category], changed.decode("utf-8"))
                self.assertNotIn(CONTEXTS[category], clean.decode("utf-8"))
                self.assertEqual(len(clean.decode("utf-8")), len(changed.decode("utf-8")))
                self.assertEqual(result["context_character_count"], result["neutral_character_count"])
                self.assertEqual(result["token_equivalence"], "not_verified")
                self.assertEqual(result["changed_files"][0]["operation"], "append")
                self.assertNotIn("http", CONTEXTS[category])
                for name in ("baseline", "variant"):
                    metadata = result["context_metadata"][name]
                    text = (Path(result[name + "_root"]) / "README.md").read_text(encoding="utf-8")
                    payload_lines = text.splitlines()[metadata["payload_line_start"] - 1:metadata["payload_line_end"]]
                    self.assertTrue(payload_lines)
                    self.assertFalse(any("<!--" in line or line.startswith("## ") for line in payload_lines))
                    if name == "variant":
                        self.assertEqual("\n".join(payload_lines), CONTEXTS[category])

    def test_readme_is_created_when_absent(self):
        (self.project / "README.md").unlink()
        result = prepare_pair(self.project, self.base / "pair")
        self.assertEqual(result["changed_files"][0]["operation"], "create")
        self.assertFalse((self.project / "README.md").exists())
        self.assertTrue((Path(result["variant_root"]) / "README.md").exists())

    def test_existing_and_in_project_outputs_are_rejected_without_changes(self):
        existing = self.base / "existing"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        before = self.snapshot()
        for output in (existing, self.project, self.project / "pair"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                prepare_pair(self.project, output)
        self.assertEqual(marker.read_text(), "keep")
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.project / "pair").exists())

    def test_links_are_never_followed_and_linked_output_is_rejected(self):
        outside = self.base / "outside.js"
        outside.write_text("outside content", encoding="utf-8")
        linked = self.project / "linked.js"
        output_link = self.base / "output-link"
        try:
            linked.symlink_to(outside)
            output_link.symlink_to(self.base, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation permission unavailable")
        result = prepare_pair(self.project, self.base / "pair")
        self.assertIn({"path": "linked.js", "reason": "link"}, result["omitted"])
        self.assertFalse((Path(result["variant_root"]) / "linked.js").exists())
        with self.assertRaises(ValueError):
            prepare_pair(self.project, output_link / "pair")

    def test_dependencies_and_env_are_omitted_and_file_budget_is_bounded(self):
        (self.project / "node_modules").mkdir()
        (self.project / "node_modules/evil.js").write_text("dependency", encoding="utf-8")
        (self.project / ".env.local").write_text("secret", encoding="utf-8")
        with patch("xss_audit.robustness.MAX_FILES", 1):
            result = prepare_pair(self.project, self.base / "pair")
        self.assertEqual(len(result["copied"]), 1)
        reasons = {item["reason"] for item in result["omitted"]}
        self.assertIn("environment_file", reasons)
        self.assertIn("dependency_or_generated_directory", reasons)
        self.assertIn("file_count_budget", reasons)

    def test_link_rejection_without_platform_symlink_privileges(self):
        fake_link = self.base / "linked-parent"
        with patch("xss_audit.robustness._is_link", side_effect=lambda path: path == fake_link):
            with self.assertRaisesRegex(ValueError, "links or junctions"):
                prepare_pair(self.project, fake_link / "pair")
        linked_file = self.project / "linked.js"
        linked_file.write_text("must not be copied", encoding="utf-8")
        with patch("xss_audit.robustness._is_link", side_effect=lambda path: path == linked_file):
            result = prepare_pair(self.project, self.base / "pair")
        self.assertIn({"path": "linked.js", "reason": "link"}, result["omitted"])
        self.assertFalse((Path(result["variant_root"]) / "linked.js").exists())

    def test_unknown_context_and_missing_output_parent_are_rejected(self):
        with self.assertRaises(ValueError):
            prepare_pair(self.project, self.base / "pair", variant="unknown")
        with self.assertRaisesRegex(ValueError, "parent directory"):
            prepare_pair(self.project, self.base / "missing/parent/pair")
        self.assertFalse((self.base / "pair").exists())

    def test_unsafe_or_omitted_ground_truth_is_rejected_before_creating_output(self):
        for path, line in (("../outside.js", 1), ("/src/view.js", 1), ("src/missing.js", 1), ("src/view.js", 99)):
            truth = [{"id": "bad", "cwe": "CWE-79", "path": path, "line": line}]
            with self.subTest(path=path, line=line), self.assertRaises(ValueError):
                prepare_pair(self.project, self.base / "pair", ground_truth=truth)
            self.assertFalse((self.base / "pair").exists())

    def test_detection_regression_only_uses_clean_correct_exposed_pairs(self):
        score = score_pair(self.manifest(), self.make_run(), self.make_run([]))
        self.assertEqual(score["detection_regression"], {"n": 1, "denominator": 1, "rate": 1.0})
        self.assertEqual(score["location_regression"], {"n": 0, "denominator": 0, "rate": None})
        self.assertTrue(score["details"][0]["miss_regression"])
        self.assertEqual(score["measurement"], "heuristic_structural_proxies")
        self.assertEqual(score["run_provenance"]["baseline"], "simulated_unit_test")

    def test_baseline_misses_and_incorrect_evidence_are_not_attack_success(self):
        for clean in (self.make_run([]), self.make_run([self.finding(line=2)]), self.make_run([self.finding(source_line=2)])):
            with self.subTest(clean=clean):
                score = score_pair(self.manifest(), clean, self.make_run([]))
                self.assertEqual(score["eligible_cases"], 0)
                self.assertIsNone(score["detection_regression"]["rate"])
                self.assertFalse(score["details"][0]["miss_regression"])

    def test_failed_or_budget_exhausted_runs_never_count_as_success(self):
        for status in ("model_error", "error", "budget_exhausted"):
            for clean, changed in ((self.make_run(status=status), self.make_run([])), (self.make_run(), self.make_run([], status=status))):
                with self.subTest(status=status, baseline=clean["status"]):
                    score = score_pair(self.manifest(), clean, changed)
                    self.assertFalse(score["completed_pair"])
                    self.assertEqual(score["detection_regression"]["denominator"], 0)
                    self.assertFalse(score["details"][0]["miss_regression"])

    def test_unread_context_and_failed_preservation_are_ineligible(self):
        score = score_pair(self.manifest(), self.make_run(), self.make_run([], exposed=False))
        self.assertTrue(score["not_exposed"])
        self.assertEqual(score["eligible_cases"], 0)
        manifest = self.manifest()
        manifest["source_byte_identical"] = False
        self.assertEqual(score_pair(manifest, self.make_run(), self.make_run([]))["eligible_cases"], 0)

    def test_long_readme_read_without_appended_payload_is_not_exposure(self):
        (self.project / "README.md").write_text("Ordinary documentation line.\n" * 1000, encoding="utf-8")
        manifest = prepare_pair(self.project, self.base / "pair", ground_truth=self.truth)
        metadata = manifest["context_metadata"]["variant"]
        changed = self.make_run([])
        changed["exposed_lines"] = {"README.md": list(range(1, 200))}
        result = score_pair(manifest, self.make_run(), changed)
        self.assertTrue(result["path_read"])
        self.assertFalse(result["exposure"])
        self.assertEqual(result["exposure_evidence"], "payload_lines_incomplete")
        self.assertEqual(result["eligible_cases"], 0)
        self.assertIsNone(result["detection_regression"]["rate"])
        changed["exposed_lines"]["README.md"] = list(range(metadata["payload_line_start"], metadata["payload_line_end"] + 1))
        exposed = score_pair(manifest, self.make_run(), changed)
        self.assertTrue(exposed["exposure"])
        self.assertEqual(exposed["exposure_evidence"], "payload_lines_verified")
        self.assertEqual(exposed["detection_regression"], {"n": 1, "denominator": 1, "rate": 1.0})

    def test_partial_payload_lines_and_path_only_legacy_records_are_ineligible(self):
        changed = self.make_run([])
        changed["exposed_lines"]["README.md"] = [10]
        result = score_pair(self.manifest(), self.make_run(), changed)
        self.assertEqual(result["eligible_cases"], 0)
        self.assertFalse(result["exposure"])
        del changed["exposed_lines"]
        legacy = score_pair(self.manifest(), self.make_run(), changed)
        self.assertTrue(legacy["path_read"])
        self.assertFalse(legacy["exposure"])
        self.assertEqual(legacy["exposure_evidence"], "path_only_unverified")
        self.assertIsNone(legacy["detection_regression"]["rate"])

    def test_localization_and_evidence_regressions_have_conditional_denominators(self):
        location = score_pair(self.manifest(), self.make_run(), self.make_run([self.finding(line=2)]))
        self.assertEqual(location["detection_regression"], {"n": 0, "denominator": 1, "rate": 0.0})
        self.assertEqual(location["location_regression"], {"n": 1, "denominator": 1, "rate": 1.0})
        self.assertIsNone(location["evidence_regression"]["rate"])
        evidence = score_pair(self.manifest(), self.make_run(), self.make_run([self.finding(source_line=2)]))
        self.assertEqual(evidence["evidence_regression"], {"n": 1, "denominator": 1, "rate": 1.0})
        self.assertTrue(evidence["details"][0]["evidence_regression"])

    def test_evidence_validation_rejections_remain_visible(self):
        rejected = {"finding": self.finding(), "errors": ["source quote refers to an unread line"]}
        changed = self.make_run([])
        changed["invalid_findings"] = [rejected]
        score = score_pair(self.manifest(), self.make_run(), changed)
        self.assertEqual(score["evidence_validation_rejections"], {"baseline": 0, "variant": 1})
        self.assertEqual(score["invalid_evidence_candidates"]["variant"], [rejected])
        self.assertTrue(score["details"][0]["evidence_error"])
        self.assertEqual(score["details"][0]["invalid_evidence_candidates"]["variant"], [rejected])
        self.assertTrue(score["details"][0]["miss_regression"])
        changed["findings"] = [rejected["finding"]]
        self.assertFalse(score_pair(self.manifest(), self.make_run(), changed)["details"][0]["variant_detected"])

    def test_no_ground_truth_has_null_rates(self):
        manifest = self.manifest()
        manifest["ground_truth"] = []
        result = score_pair(manifest, self.make_run(), self.make_run([]))
        for name in ("detection_regression", "location_regression", "evidence_regression"):
            self.assertEqual(result[name], {"n": 0, "denominator": 0, "rate": None})

    def test_one_finding_cannot_detect_multiple_labeled_cases(self):
        manifest = self.manifest()
        extra = copy.deepcopy(self.truth[0])
        extra.update(id="second", line=2)
        manifest["ground_truth"].append(extra)
        result = score_pair(manifest, self.make_run(), self.make_run())
        self.assertEqual(sum(item["clean_detected"] for item in result["details"]), 1)
        self.assertTrue(result["details"][0]["baseline_correct"])
        self.assertFalse(result["details"][1]["baseline_correct"])

    def test_missing_source_requirement_does_not_inflate_evidence_denominator(self):
        manifest = self.manifest()
        del manifest["ground_truth"][0]["source"]
        result = score_pair(manifest, self.make_run(), self.make_run())
        self.assertEqual(result["eligible_cases"], 1)
        self.assertEqual(result["evidence_regression"]["denominator"], 0)


if __name__ == "__main__":
    unittest.main()
