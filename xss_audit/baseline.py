"""Compare review identities, never infer that a missing signal was fixed."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

MAX_BASELINE_BYTES = 64 * 1024 * 1024
NOTICE = "基线按路径、规则、线索指纹和源文件摘要比较；未再观察到不代表已修复。旧版缺少摘要可能全部显示为新增，请确认项目、引擎和扫描范围可比。"


def load_baseline(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BASELINE_BYTES + 1)
    if len(raw) > MAX_BASELINE_BYTES:
        raise ValueError("基线报告超过 64 MiB。")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("基线必须是本工具导出的有效 JSON 报告。") from error
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list) or not isinstance(data.get("root"), str):
        raise ValueError("基线必须是本工具导出的有效 JSON 报告。")
    if not isinstance(data.get("skipped", []), list) or type(data.get("files_scanned")) is not int:
        raise ValueError("基线必须是本工具导出的有效 JSON 报告。")
    if any(data.get(key) for key in ("cancelled", "truncated", "ast_incomplete", "incomplete", "coverage_errors")):
        raise ValueError("基线扫描不完整，请使用完整扫描报告。")
    filters = data.get("report_filters", {})
    if not isinstance(filters, dict) or filters.get("ignore_reviewed") or filters.get("only_new") or filters.get("min_priority", "信息") not in ("信息", "info"):
        raise ValueError("基线不能使用筛选后的报告，请重新导出全部线索。")
    rows = data["matches"]
    if len(rows) > 10000 or any(not isinstance(row, dict) or not all(isinstance(row.get(key), str) and row[key] for key in ("path", "rule_id", "fingerprint")) or not re.fullmatch(r"[0-9a-f]{32}", row["fingerprint"]) or type(row.get("line")) is not int or row["line"] < 1 for row in rows):
        raise ValueError("基线线索缺少有效的路径、规则、行号或指纹。")
    if filters.get("matches_before_filters", len(rows)) != len(rows):
        raise ValueError("基线不能使用筛选后的报告，请重新导出全部线索。")
    if any(not isinstance(row.get("evidence_hash", ""), str) or (row.get("evidence_hash") and not re.fullmatch(r"[0-9a-f]{64}", row["evidence_hash"])) for row in rows):
        raise ValueError("基线线索缺少有效的路径、规则、行号或指纹。")
    return data


def compare(result, data, name=""):
    # Validate/read the baseline before this function; never change review decisions.
    def identity(row):
        return row["path"], row["rule_id"], row["fingerprint"], row.get("evidence_hash", "")

    old = Counter(identity(row) for row in data["matches"])
    current = Counter((m.path, m.rule_id, m.fingerprint, m.evidence_hash) for m in result.matches)
    remaining = old.copy()
    states = []
    for match in result.matches:
        key = match.path, match.rule_id, match.fingerprint, match.evidence_hash
        states.append("unchanged" if remaining[key] else "new")
        if remaining[key]:
            remaining[key] -= 1
    missing = old - current
    not_observed = []
    for row in data["matches"]:
        key = identity(row)
        if missing[key]:
            not_observed.append({key: row[key] for key in ("path", "rule_id", "fingerprint", "line")})
            missing[key] -= 1
    comparison = {
        "file": Path(name).name, "created_at": data.get("created_at", ""),
        "new": states.count("new"), "unchanged": states.count("unchanged"),
        "not_observed": not_observed, "notice": NOTICE,
        "current_incomplete": bool(result.incomplete),
        "identity": "path-rule-fingerprint-evidence/v2",
        "baseline_legacy": any(not row.get("evidence_hash") for row in data["matches"]),
        "scope_changed": data.get("scan_config", {}) != result.scan_config,
        "baseline_skipped_count": len(data.get("skipped", [])),
        "current_skipped_count": len(result.skipped),
    }
    for match, state in zip(result.matches, states):
        match.baseline_state = state
    result.baseline = comparison
    return comparison
