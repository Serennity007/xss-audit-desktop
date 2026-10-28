"""Regression coverage for review decisions across snapshots and windows."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
import tempfile
import unittest

from xss_audit.state import STATUSES, StateStore
from xss_audit.scanner import scan


class StateHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.store = StateStore(self.directory / "state")

    def tearDown(self):
        self.temporary.cleanup()

    def finding(self, fingerprint, status=STATUSES[0], note="", legacy="", evidence_hash="source-v1"):
        return SimpleNamespace(fingerprint=fingerprint, status=status, note=note,
                               legacy_fingerprint=legacy, evidence_hash=evidence_hash)

    def snapshot(self, *findings, cancelled=False, truncated=False):
        return SimpleNamespace(root=str(self.directory / "project"), matches=list(findings),
                               import_metadata={"repository": "https://github.com/owner/project"},
                               cancelled=cancelled, truncated=truncated)

    def records(self, snapshot):
        return self.store.read(self.store.project_name(snapshot))["records"]

    def source_snapshot(self, version):
        project = self.directory / "real-project"
        project.mkdir(exist_ok=True)
        source = "import os\ncommand = request.args[\"" + version + "\"]\n" + "\n" * 8 + "os.system(command)\n"
        (project / "server.py").write_text(source, encoding="utf-8")
        result = scan(project)
        result.import_metadata = {"repository": "https://github.com/owner/project"}
        finding = next(item for item in result.matches if item.rule_id == "PY-SHELL-FLOW")
        return result, finding

    def test_snapshot_a_b_a_keeps_both_decisions(self):
        first = self.snapshot(self.finding("A", "误报", "review A"))
        second = self.snapshot(self.finding("B", "确认风险", "review B"))
        self.store.save_review(first)
        self.store.save_review(second)
        restored = self.snapshot(self.finding("A"))
        self.store.apply(restored)
        self.assertEqual((restored.matches[0].status, restored.matches[0].note), ("误报", "review A"))
        self.assertEqual(set(self.records(restored)), {"A", "B"})
        self.assertTrue(self.records(restored)["A"]["updated_at"])

    def test_real_snapshots_with_same_sink_restore_each_evidence_version(self):
        first, finding_a = self.source_snapshot("a")
        finding_a.status, finding_a.note = "误报", "review source a"
        self.store.save_review(first)
        second, finding_b = self.source_snapshot("b")
        self.assertEqual(finding_a.fingerprint, finding_b.fingerprint)
        self.assertNotEqual(finding_a.evidence_hash, finding_b.evidence_hash)
        self.store.apply(second)
        self.assertEqual(finding_b.status, STATUSES[0])
        finding_b.status, finding_b.note = "确认风险", "review source b"
        self.store.save_review(second)
        restored_a, current_a = self.source_snapshot("a")
        self.store.apply(restored_a)
        self.assertEqual((current_a.status, current_a.note), ("误报", "review source a"))
        restored_b, current_b = self.source_snapshot("b")
        self.store.apply(restored_b)
        self.assertEqual((current_b.status, current_b.note), ("确认风险", "review source b"))

    def test_clearing_evidence_version_keeps_other_real_snapshot_review(self):
        for clear_version in ("a", "b"):
            with self.subTest(clear_version=clear_version):
                self.store = StateStore(self.directory / ("state-clear-" + clear_version))
                for version, status in (("a", "误报"), ("b", "确认风险")):
                    result, finding = self.source_snapshot(version)
                    self.store.apply(result)
                    finding.status, finding.note = status, "review " + version
                    self.store.save_review(result)
                current, finding = self.source_snapshot(clear_version)
                self.store.apply(current)
                finding.status, finding.note = STATUSES[0], ""
                self.store.save_review(current)
                cleared, cleared_finding = self.source_snapshot(clear_version)
                self.store.apply(cleared)
                self.assertEqual((cleared_finding.status, cleared_finding.note), (STATUSES[0], ""))
                other_version = "b" if clear_version == "a" else "a"
                remaining, remaining_finding = self.source_snapshot(other_version)
                self.store.apply(remaining)
                self.assertEqual(remaining_finding.note, "review " + other_version)

    def test_cancelled_or_partial_snapshot_does_not_delete_other_records(self):
        initial = self.snapshot(self.finding("A", "误报"), self.finding("B", "确认风险"))
        self.store.save_review(initial)
        partial = self.snapshot(self.finding("A"), cancelled=True, truncated=True)
        self.store.apply(partial)
        partial.matches[0].note = "partial review"
        self.store.save_review(partial)
        self.assertEqual(set(self.records(partial)), {"A", "B"})
        self.assertEqual(self.records(partial)["B"]["status"], "确认风险")
        self.store.save_review(self.snapshot(cancelled=True))
        self.assertEqual(set(self.records(partial)), {"A", "B"})

    def test_clearing_current_decision_only_removes_that_record(self):
        initial = self.snapshot(self.finding("A", "误报", "old note"), self.finding("B", "确认风险"))
        self.store.save_review(initial)
        current = self.snapshot(self.finding("A"))
        self.store.apply(current)
        current.matches[0].status, current.matches[0].note = STATUSES[0], ""
        self.store.save_review(current)
        self.assertEqual(set(self.records(current)), {"B"})

    def test_independent_windows_do_not_overwrite_unchanged_rows(self):
        initial = self.snapshot(self.finding("A", "误报"), self.finding("B", "确认风险"))
        self.store.save_review(initial)
        left = self.snapshot(self.finding("A"), self.finding("B"))
        right = self.snapshot(self.finding("A"), self.finding("B"))
        other_store = StateStore(self.store.directory)
        self.store.apply(left)
        other_store.apply(right)
        left.matches[0].note = "left window"
        right.matches[1].note = "right window"
        self.store.save_review(left)
        other_store.save_review(right)
        self.assertEqual(self.records(right)["A"]["note"], "left window")
        self.assertEqual(self.records(right)["B"]["note"], "right window")

    def test_simultaneous_independent_saves_merge_records(self):
        count = 8
        barrier = Barrier(count)

        def save(index):
            store = StateStore(self.store.directory)
            result = self.snapshot(self.finding(str(index), "误报", str(index)))
            barrier.wait(timeout=5)
            store.save_review(result)

        with ThreadPoolExecutor(max_workers=count) as pool:
            list(pool.map(save, range(count)))
        self.assertEqual(set(self.records(self.snapshot())), {str(index) for index in range(count)})

    def test_version_one_exact_fingerprint_is_loaded_and_hash_is_backfilled(self):
        current = self.snapshot(self.finding("A"))
        self.store.write(self.store.project_name(current), {
            "version": 1, "records": {"A": {"status": "误报", "note": "v1 decision"}}})
        self.store.apply(current)
        self.assertEqual(current.matches[0].note, "v1 decision")
        self.store.save_review(current)
        saved = self.store.read(self.store.project_name(current))
        self.assertEqual(saved["version"], 2)
        self.assertEqual(saved["records"]["A"]["evidence_hash"], "source-v1")

    def test_unique_legacy_record_is_restored_and_migrated(self):
        current = self.snapshot(self.finding("new", legacy="legacy"))
        self.store.write(self.store.project_name(current), {
            "version": 1, "records": {"legacy": {"status": "误报", "note": "legacy review"}}})
        self.store.apply(current)
        self.assertEqual(current.matches[0].status, "误报")
        self.store.save_review(current)
        records = self.records(current)
        self.assertNotIn("legacy", records)
        self.assertEqual(records["new"]["note"], "legacy review")
        self.assertEqual(records["new"]["migrated_from"], "legacy")
        self.assertEqual(records["new"]["evidence_hash"], "source-v1")

    def test_ambiguous_legacy_is_not_reused_for_either_instance(self):
        current = self.snapshot(self.finding("new-1", legacy="legacy"), self.finding("new-2", legacy="legacy"))
        self.store.write(self.store.project_name(current), {
            "version": 1, "records": {"legacy": {"status": "误报", "note": "ambiguous"}}})
        self.store.apply(current)
        self.assertTrue(all(item.status == STATUSES[0] and not item.note for item in current.matches))
        current.matches[0].status = "确认风险"
        self.store.save_review(current)
        self.assertEqual(self.records(current)["new-1"]["status"], "确认风险")
        self.assertNotIn("new-2", self.records(current))

    def test_far_source_hash_change_invalidates_review_without_legacy_fallback(self):
        previous = self.snapshot(self.finding("A", "误报", "old source", legacy="legacy"))
        self.store.save_review(previous)
        records = self.records(previous)
        records["legacy"] = {"status": "误报", "note": "must not bypass new identity"}
        self.store.write(self.store.project_name(previous), {"version": 2, "records": records})
        changed = self.snapshot(self.finding("A", legacy="legacy", evidence_hash="source-v2"))
        self.store.apply(changed)
        self.assertEqual((changed.matches[0].status, changed.matches[0].note), (STATUSES[0], ""))

    def test_older_match_without_legacy_or_evidence_fields_remains_supported(self):
        item = SimpleNamespace(fingerprint="old", status="误报", note="compatible")
        old = self.snapshot(item)
        self.store.save_review(old)
        item.status, item.note = STATUSES[0], ""
        self.store.apply(old)
        self.assertEqual((item.status, item.note), ("误报", "compatible"))

    def test_oversized_update_does_not_replace_previous_state(self):
        initial = self.snapshot(self.finding("A", "误报"))
        self.store.save_review(initial)
        original = (self.store.directory / self.store.project_name(initial)).read_bytes()
        excessive = self.snapshot(*(self.finding(str(index), "误报", "备注" * 500) for index in range(800)))
        with self.assertRaises(ValueError):
            self.store.save_review(excessive)
        self.assertEqual((self.store.directory / self.store.project_name(initial)).read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
