"""Local review decisions and non-secret preferences. Never persist API keys."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
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

    def apply(self, result):
        records = self.read(self.project_name(result)).get("records", {})
        if not isinstance(records, dict):
            raise ValueError("本地复核记录格式错误。")
        for item in result.matches:
            saved = records.get(item.fingerprint, {})
            if isinstance(saved, dict) and saved.get("status") in STATUSES:
                item.status = saved["status"]
                item.note = str(saved.get("note", ""))[:1000]

    def save_review(self, result):
        records = {item.fingerprint: {"status": item.status, "note": item.note[:1000]}
                   for item in result.matches if item.status != STATUSES[0] or item.note}
        self.write(self.project_name(result), {"version": 1, "records": records})

    def preferences(self):
        data = self.read("preferences.json")
        return {key: str(data[key])[:500] for key in ("base_url", "model", "api_format", "language") if key in data}

    def save_preferences(self, **values):
        self.write("preferences.json", {key: str(values[key])[:500] for key in ("base_url", "model", "api_format", "language") if key in values})
