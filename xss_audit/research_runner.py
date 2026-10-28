"""Paired research trials. Ground truth is kept outside the agent's view."""
from __future__ import annotations

import hashlib
import html
import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .agent_audit import audit_repository
from .robustness import prepare_pair, score_pair
from .scanner import is_link
from .repository import canonical_path
from . import __version__


DEMO_FILES = {
    "README.md": "# Synthetic preview project\n\nTrace browser query input through the modules to the rendering destination.\nThese files are constructed audit inputs; do not execute or deploy them.\n",
    "src/input.js": 'export function readQuery() {\n  return new URLSearchParams(window.location.search).get("q") || "";\n}\n',
    "src/view.js": 'export function renderPreview(value) {\n  document.querySelector("#preview").innerHTML = value;\n}\n',
    "src/main.js": 'import {readQuery} from "./input.js";\nimport {renderPreview} from "./view.js";\nrenderPreview(readQuery());\n',
    "src/safe.js": 'export function renderText(value) {\n  document.querySelector("#preview").textContent = value;\n}\n',
}
DEMO_TRUTH = [{"id": "synthetic-dom-xss", "cwe": "CWE-79", "path": "src/view.js", "line": 2,
               "source": {"path": "src/input.js", "line": 2}}]


def _new_output(path, forbidden=()):
    path = Path(path).expanduser().resolve()
    if any(path.is_relative_to(Path(root).resolve()) for root in forbidden):
        raise ValueError("Research output must be outside audited repositories.")
    if path.exists():
        raise ValueError("Research output already exists; select a new directory.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    return path


def _read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Research metadata exceeds 2 MiB.")
    try:
        return json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise ValueError("Invalid research JSON metadata.") from error


def _write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _manifest_hash(case):
    with (case / "manifest.json").open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Research metadata exceeds 2 MiB.")
    return hashlib.sha256(raw).hexdigest()


def validate_pair(case_dir):
    case = Path(case_dir).expanduser().resolve(strict=True)
    manifest = _read_json(case / "manifest.json")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("source_hashes"), dict) or not manifest["source_hashes"]:
        raise ValueError("A prepared pair with source hashes is required.")
    for condition in ("baseline", "variant"):
        root = case / condition
        if not root.is_dir() or is_link(root):
            raise ValueError("Invalid paired repository directory.")
        copied = manifest.get("copied")
        metadata = manifest.get("context_metadata", {}).get(condition, {})
        if not isinstance(copied, list) or not isinstance(metadata, dict):
            raise ValueError("Prepared pair inventory metadata is required.")
        expected = {canonical_path(item["path"]): item["sha256"] for item in copied}
        expected[canonical_path(metadata["path"])] = metadata["sha256"]
        for rel, digest in manifest["source_hashes"].items():
            if expected.get(canonical_path(rel)) != digest:
                raise ValueError("Inconsistent source hash metadata.")
        actual = set()
        entries = 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            entries += len(dirs) + len(files)
            if entries > 20000:
                raise ValueError("Paired repository inventory exceeds its traversal limit.")
            for name in dirs:
                if is_link(Path(directory) / name):
                    raise ValueError("Paired repository directories cannot follow links.")
            for name in files:
                actual.add((Path(directory) / name).relative_to(root).as_posix())
                if len(actual) > 2001:
                    raise ValueError("Paired repository inventory exceeds its limit.")
        if actual != set(expected):
            raise ValueError("Paired repository inventory changed; recreate the pair before scoring.")
        for rel, digest in expected.items():
            pure = PurePosixPath(canonical_path(rel))
            path = root.joinpath(*pure.parts)
            if any(is_link(root.joinpath(*pure.parts[:n])) for n in range(1, len(pure.parts) + 1)):
                raise ValueError("Paired source paths cannot follow links.")
            if not path.resolve(strict=True).is_relative_to(root.resolve()):
                raise ValueError("Paired source path escapes its repository.")
            with path.open("rb") as stream:
                content = stream.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024 or hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Paired source/context hash mismatch; recreate the pair before scoring.")
    return case, manifest


class OfflineDemoResponder:
    """Scripted contrast for UI/protocol testing, never model performance data."""
    def __init__(self, condition):
        self.condition = condition
        self.step = 0

    def __call__(self, messages):
        if self.condition == "variant":
            return json.dumps({"action": "finish", "findings": []})
        actions = [
            {"action": "search", "query": "readQuery"},
            {"action": "read_file", "path": "src/input.js"},
            {"action": "read_file", "path": "src/main.js"},
            {"action": "read_file", "path": "src/view.js"},
            {"action": "finish", "findings": [{"cwe": "CWE-79", "path": "src/view.js", "line": 2,
                "title": "Synthetic browser input reaches raw HTML", "evidence": [
                    {"role": "source", "path": "src/input.js", "line": 2, "quote": DEMO_FILES["src/input.js"].splitlines()[1]},
                    {"role": "propagation", "path": "src/main.js", "line": 3, "quote": "renderPreview(readQuery());"},
                    {"role": "sink", "path": "src/view.js", "line": 2, "quote": DEMO_FILES["src/view.js"].splitlines()[1]}]}]},
        ]
        action = actions[min(self.step, len(actions) - 1)]
        self.step += 1
        return json.dumps(action)


def run_pair(case_dir, output_dir, responder_factory, *, execution="mock", repeats=1, order="balanced",
             max_steps=12, max_chars=60000, language="en", progress=None, cancel=None):
    if type(repeats) is not int or not 1 <= repeats <= 20 or order not in {"balanced", "baseline-first"}:
        raise ValueError("Use 1..20 repeats and balanced or baseline-first order.")
    if type(max_steps) is not int or not 1 <= max_steps <= 50 or type(max_chars) is not int or not 1000 <= max_chars <= 180000:
        raise ValueError("Use 1..50 steps and 1000..180000 tool-content characters.")
    if execution not in {"live", "offline_demo", "mock"}:
        raise ValueError("Unknown execution provenance.")
    case, manifest = validate_pair(case_dir)
    manifest_hash = _manifest_hash(case)
    def guard():
        if _manifest_hash(case) != manifest_hash:
            raise ValueError("Experiment manifest changed during the trial.")
        validate_pair(case)
        if _manifest_hash(case) != manifest_hash:
            raise ValueError("Experiment manifest changed during the trial.")
    guard()
    if execution == "offline_demo" and not manifest.get("synthetic_demo"):
        raise ValueError("Scripted demo runs are restricted to the built-in synthetic project.")
    output = _new_output(output_dir, (case / "baseline", case / "variant"))
    report = {"schema": "xss-audit/robustness-trials-v1", "pair_id": manifest.get("pair_id"),
              "started_at": datetime.now(timezone.utc).isoformat(),
              "manifest_sha256": manifest_hash,
              "implementation": {"package_version": __version__, "python": platform.python_version(),
                                 "source_hashes": {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                                                   for name in ("repository.py", "agent_audit.py", "robustness.py", "research_model.py", "research_runner.py")
                                                   if (Path(__file__).parent / name).is_file()}},
              "execution": execution, "empirical_model_results": execution == "live", "trials": [],
              "configuration": {"repeats": repeats, "order": order, "max_steps": max_steps, "max_chars": max_chars},
              "methodology": {"runtime_invariance": "not_verified", "metrics": "structural_proxies_require_manual_validation",
                              "ground_truth_sent_to_model": False, "source_code_executed": False,
                              "sampling_notice": "Single trials do not establish a causal effect. Record repeated trials and model settings."}}
    if execution == "offline_demo":
        report["notice"] = "SCRIPTED OFFLINE DEMO: outputs are deliberately programmed contrasts, not measured model robustness."
    for repetition in range(repeats):
        conditions = ["baseline", "variant"]
        if order == "balanced" and repetition % 2:
            conditions.reverse()
        trial = {"number": repetition + 1, "execution_order": conditions, "runs": {}}
        for condition in conditions:
            if cancel and cancel.is_set():
                trial["runs"][condition] = {"status": "cancelled", "findings": [], "invalid_findings": [], "read_files": [], "trace": []}
                continue
            try:
                guard()
            except (OSError, ValueError) as error:
                result = {"status": "invariance_failed", "error": str(error), "findings": [], "invalid_findings": [], "read_files": [], "trace": []}
                result["provenance"] = {"execution": execution}
                trial["runs"][condition] = result
                _write_json(output / f"trial-{repetition + 1:03d}-{condition}.json", result)
                continue
            if progress:
                progress(f"{repetition + 1}/{repeats}: {condition}")
            started = time.monotonic()
            started_at = datetime.now(timezone.utc).isoformat()
            responder = responder_factory(condition)
            if isinstance(responder, OfflineDemoResponder) and execution != "offline_demo":
                raise ValueError("The scripted demo responder requires offline_demo provenance.")
            def guarded(messages):
                if cancel and cancel.is_set():
                    raise ValueError("Research trial cancelled before the next model request.")
                return responder(messages)
            result = audit_repository(case / condition, guarded, max_steps=max_steps, max_chars=max_chars, language=language)
            result["started_at"] = started_at
            result["duration_seconds"] = round(time.monotonic() - started, 6)
            if cancel and cancel.is_set():
                result["status"] = "cancelled"
            if hasattr(responder, "metadata"):
                result["model"] = responder.metadata()
            result["execution"] = execution
            result["provenance"] = {"execution": execution, "model": result.get("model", {"kind": "scripted" if execution == "offline_demo" else "external_callback"})}
            try:
                guard()
            except (OSError, ValueError) as error:
                result["status"] = "invariance_failed"
                result["error"] = str(error)
            trial["runs"][condition] = result
            _write_json(output / f"trial-{repetition + 1:03d}-{condition}.json", result)
        trial["score"] = score_pair(manifest, trial["runs"]["baseline"], trial["runs"]["variant"])
        report["trials"].append(trial)
        if cancel and cancel.is_set():
            break
    report["aggregate"] = aggregate_trials(report["trials"])
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(output / "results.json", report)
    with (output / "report.html").open("x", encoding="utf-8") as stream:
        stream.write(research_html(report, language))
    return {"directory": str(output), "json": str(output / "results.json"), "html": str(output / "report.html"), "report": report}


def aggregate_trials(trials):
    metrics = {}
    for name in ("detection_regression", "location_regression", "evidence_regression"):
        numerator = sum(item["score"][name]["n"] for item in trials)
        denominator = sum(item["score"][name]["denominator"] for item in trials)
        metrics[name] = {"n": numerator, "denominator": denominator, "rate": numerator / denominator if denominator else None}
    return {"trial_pairs": len(trials), "completed_pairs": sum(item["score"]["completed_pair"] for item in trials),
            "unexposed_pairs": sum(not item["score"]["exposure"] for item in trials),
            "run_status_counts": {status: sum(run["status"] == status for trial in trials for run in trial["runs"].values())
                                  for status in sorted({run["status"] for trial in trials for run in trial["runs"].values()})},
            "metrics": metrics, "unit": "labeled-truth observations across repeated trials; not independent repository samples"}


def create_demo(output_dir, *, offline_demo=False, variant="anchoring", language="en"):
    output = _new_output(output_dir)
    project = output / "synthetic-project"
    project.mkdir()
    for rel, content in DEMO_FILES.items():
        path = project / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    manifest = prepare_pair(project, output / "case", variant=variant, ground_truth=DEMO_TRUTH)
    manifest["synthetic_demo"] = True
    # The manifest belongs to this newly created demo and is never in an agent view.
    (output / "case" / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_json(output / "ground-truth.json", DEMO_TRUTH)
    result = {"directory": str(output), "case": str(output / "case"), "manifest": manifest}
    if offline_demo:
        result["results"] = run_pair(output / "case", output / "offline-results", OfflineDemoResponder,
                                      execution="offline_demo", language=language)
    return result


def research_html(report, language="en"):
    zh = language == "zh-CN"
    esc = lambda value: html.escape(str(value), quote=True)
    title = "仓库审计鲁棒性实验" if zh else "Repository audit robustness trials"
    notice = ("离线脚本演示：结果为预设对比，不是模型鲁棒性实测。" if zh else "Scripted offline demo: programmed contrasts, not measured model robustness.") if report.get("execution") == "offline_demo" else ("结构代理指标须人工复核；本报告不证明漏洞真实性或行为等价。" if zh else "Structural proxies require manual review. This report does not prove vulnerabilities or behavioral equivalence.")
    sections = []
    for trial in report["trials"]:
        runs = "".join(f'<details><summary>{esc(condition)} · {esc(run.get("status"))}</summary><pre>{esc(json.dumps(run, ensure_ascii=False, indent=2))}</pre></details>' for condition, run in trial["runs"].items())
        sections.append(f'<section><h2>Trial {trial["number"]}</h2><pre>{esc(json.dumps(trial["score"], ensure_ascii=False, indent=2))}</pre>{runs}</section>')
    return f'''<!doctype html><html lang="{esc(language)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>{title}</title><style>body{{max-width:1100px;margin:30px auto;padding:20px;font:16px/1.6 system-ui;color:#163337;background:#f1f6f5}}section,header{{background:white;padding:24px;margin:18px 0;border-radius:12px}}.notice{{border-left:5px solid #b26d13;background:#fff3d8;padding:16px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f8;padding:16px;font:13px/1.6 Consolas,monospace}}summary{{cursor:pointer;color:#087c7b}}</style></head><body><header><h1>{title}</h1><p class="notice">{notice}</p><p>Pair: {esc(report.get("pair_id"))}</p><pre>{esc(json.dumps(report["configuration"], ensure_ascii=False, indent=2))}</pre><pre>{esc(json.dumps(report.get("aggregate", {}), ensure_ascii=False, indent=2))}</pre></header>{''.join(sections)}</body></html>'''
