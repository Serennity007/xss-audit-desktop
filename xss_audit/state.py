"""Local review decisions and non-secret preferences. Never persist API keys."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .importer import app_directory

STATUSES = ("待人工确认", "确认风险", "误报", "已修复")


class StateStore:
    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory) if directory else app_directory() / "state"

    def read(self, name):
        path = self.directory / name
        if not path.exists():
            return {}
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("本地复核记录过大，未加载。")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (ValueError, UnicodeError):
            raise ValueError("本地复核记录损坏，未加载；源代码扫描结果仍可使用。") from None

    def write(self, name, data):
        text = json.dumps(data, ensure_ascii=False, indent=2)
        if len(text.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("复核记录超过 2 MiB，请减少或缩短备注。")
        self.directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.directory, suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        try:
            os.replace(temporary, self.directory / name)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def project_name(result):
        identity = result.import_metadata.get("repository") or os.path.normcase(str(Path(result.root).resolve()))
        digest = hashlib.sha256(identity.encode()).hexdigest()[:32]
        return "review-" + digest + ".json"

    @contextmanager
    def _review_lock(self, name):
        """Serialize read/merge/replace across desktop windows and CLI processes."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / (name + ".lock")).open("a+b") as handle:
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                lock = lambda: msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                unlock = lambda: msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                lock = lambda: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                unlock = lambda: fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            deadline = time.monotonic() + 10
            while True:
                try:
                    lock()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise OSError("复核记录正在由其他窗口更新，请稍后重试。") from None
                    time.sleep(.02)
            try:
                yield
            finally:
                handle.seek(0)
                unlock()

    @staticmethod
    def _decision(item):
        return item.status, str(item.note)[:1000]

    @staticmethod
    def _records(data):
        records = data.get("records", {})
        if not isinstance(records, dict):
            raise ValueError("本地复核记录格式错误。")
        return records

    @staticmethod
    def _history(data):
        history = data.get("history", {})
        if not isinstance(history, dict) or any(not isinstance(versions, dict) for versions in history.values()):
            raise ValueError("本地复核历史格式错误。")
        return history

    @staticmethod
    def _same_evidence(saved, evidence_hash):
        return isinstance(saved, dict) and bool(saved) and (not saved.get("evidence_hash") or saved["evidence_hash"] == evidence_hash)

    def apply(self, result):
        data = self.read(self.project_name(result))
        records, history = self._records(data), self._history(data)
        legacy_counts = Counter(getattr(item, "legacy_fingerprint", "") for item in result.matches)
        upgrades = {}
        for item in result.matches:
            key = item.fingerprint
            evidence_hash = getattr(item, "evidence_hash", "")
            legacy = getattr(item, "legacy_fingerprint", "")
            if key not in records and key not in history and legacy and legacy_counts[legacy] == 1:
                key = legacy
            saved = records.get(key, {})
            from_history = not self._same_evidence(saved, evidence_hash)
            if from_history:
                saved = history.get(key, {}).get(evidence_hash, {})
            if self._same_evidence(saved, evidence_hash) and saved.get("status") in STATUSES:
                item.status = saved["status"]
                item.note = str(saved.get("note", ""))[:1000]
                if not from_history and (key != item.fingerprint or evidence_hash and not saved.get("evidence_hash")):
                    upgrades[item.fingerprint] = (key, dict(saved))
        # Track only decisions loaded into this window. Saving another row must
        # not overwrite an unchanged row updated by a second window meanwhile.
        result._review_baseline = {item.fingerprint: self._decision(item) for item in result.matches}
        result._review_upgrades = upgrades

    def save_review(self, result):
        name = self.project_name(result)
        baseline = getattr(result, "_review_baseline", None)
        upgrades = getattr(result, "_review_upgrades", {})
        now = datetime.now(timezone.utc).isoformat()
        with self._review_lock(name):
            data = self.read(name)
            records = self._records(data)
            history = self._history(data)
            for item in result.matches:
                if not item.fingerprint or item.status not in STATUSES:
                    continue
                decision = self._decision(item)
                changed = baseline is None or baseline.get(item.fingerprint) != decision
                upgrade = upgrades.get(item.fingerprint)
                if not changed and not upgrade:
                    continue
                if not changed and records.get(upgrade[0]) != upgrade[1]:
                    # A newer decision wins over a metadata-only migration.
                    continue
                evidence_hash = getattr(item, "evidence_hash", "")
                latest = records.get(item.fingerprint, {})
                versions = history.get(item.fingerprint, {})
                same_version = self._same_evidence(latest, evidence_hash)
                if decision == (STATUSES[0], ""):
                    if same_version:
                        records.pop(item.fingerprint, None)
                    versions.pop(evidence_hash, None)
                else:
                    previous = latest if same_version else versions.get(evidence_hash, {})
                    if not previous and upgrade:
                        previous = records.get(upgrade[0], {})
                    previous = previous if isinstance(previous, dict) else {}
                    if isinstance(latest, dict) and latest.get("evidence_hash") and not same_version:
                        versions[latest["evidence_hash"]] = dict(latest)
                    record = dict(previous)
                    record.update(status=decision[0], note=decision[1],
                                  evidence_hash=evidence_hash,
                                  created_at=previous.get("created_at", now), updated_at=now)
                    if upgrade and upgrade[0] != item.fingerprint:
                        record["migrated_from"] = upgrade[0]
                    records[item.fingerprint] = record
                    versions.pop(evidence_hash, None)
                if versions:
                    history[item.fingerprint] = versions
                else:
                    history.pop(item.fingerprint, None)
                if upgrade and upgrade[0] != item.fingerprint:
                    records.pop(upgrade[0], None)
            self.write(name, {**data, "version": 2, "records": records, "history": history, "updated_at": now})
        result._review_baseline = {item.fingerprint: self._decision(item) for item in result.matches}
        result._review_upgrades = {}

    def preferences(self):
        data = self.read("preferences.json")
        return {key: str(data[key])[:500] for key in ("base_url", "model", "api_format", "language") if key in data}

    def save_preferences(self, **values):
        self.write("preferences.json", {key: str(values[key])[:500] for key in ("base_url", "model", "api_format", "language") if key in values})
