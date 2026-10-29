"""Exercise the actual frozen CLI without executing the source under review."""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    executable = ROOT / "release" / f"v{args.version}" / "xss-audit-cli.exe"
    output = ROOT / "build" / ("verify-v" + args.version + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir(parents=True)
    checks = []

    def run(name, parameters, code=0):
        result = subprocess.run([str(executable), *map(str, parameters)], cwd=ROOT, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        if result.returncode != code:
            raise AssertionError(f"{name}: expected exit {code}, got {result.returncode}: {result.stderr}")
        checks.append({"check": name, "exit_code": result.returncode})
        return result

    assert run("version", ["--version"]).stdout.strip() == args.version
    project = output / "project"
    project.mkdir()
    (project / "risk.js").write_text("const input = location.hash;\noutput.innerHTML = input;\n", encoding="utf-8")
    (project / "safe.js").write_text("output.textContent = location.hash;\n", encoding="utf-8")
    baseline = output / "baseline.json"
    run("complete JSON baseline", [project, "--no-saved-review", "--format", "json", "-o", baseline])
    old = json.loads(baseline.read_text(encoding="utf-8"))
    assert old["matches"] and not old["incomplete"]
    same = output / "unchanged.json"
    run("unchanged baseline gate", [project, "--no-saved-review", "--baseline", baseline, "--only-new", "--fail-on-match", "--format", "json", "-o", same])
    data = json.loads(same.read_text(encoding="utf-8"))
    assert not data["matches"] and data["baseline"]["unchanged"] > 0 and data["baseline"]["new"] == 0
    (project / "added.js").write_text("target.innerHTML = location.search;\n", encoding="utf-8")
    changed = output / "changed.json"
    run("new signal gate", [project, "--no-saved-review", "--baseline", baseline, "--only-new", "--fail-on-match", "--format", "json", "-o", changed], 1)
    data = json.loads(changed.read_text(encoding="utf-8"))
    assert data["matches"] and all(m["baseline_state"] == "new" for m in data["matches"])
    assert all(m["status"] != "已修复" for m in data["matches"])
    (project / ".xss-audit.toml").write_text('[scan]\ninclude=["safe.js"]\n', encoding="utf-8")
    scoped = output / "scoped.json"
    run("project configuration", [project, "--no-saved-review", "--format", "json", "-o", scoped])
    data = json.loads(scoped.read_text(encoding="utf-8"))
    assert data["files_scanned"] == 1 and not data["matches"] and data["skipped"]
    # Export a baseline for the independently opened GUI's same synthetic demo.
    run("GUI comparable demo baseline", [ROOT / "examples/demo-project", "--no-saved-review", "--format", "json", "-o", output / "demo-baseline.json"])
    for language in ["en", "zh-CN"]:
        for format_, extension in [("json", "json"), ("markdown", "md"), ("html", "html"), ("sarif", "sarif")]:
            path = output / (language + "." + extension)
            run(language + " " + format_, [ROOT / "examples/demo-project", "--no-saved-review", "--lang", language, "--format", format_, "-o", path])
            if format_ == "json":
                data = json.loads(path.read_text(encoding="utf-8"))
                assert data["files_scanned"] == 2 and len(data["matches"]) == 11 and not data["incomplete"]
            elif format_ == "sarif":
                data = json.loads(path.read_text(encoding="utf-8"))
                assert data["version"] == "2.1.0" and data["runs"][0]["invocations"][0]["executionSuccessful"]
            else:
                assert path.stat().st_size > 100
    partial = output / "partial"
    partial.mkdir()
    (partial / "bad.js").write_bytes(b"\xff\xfe\x00")
    run("strict incomplete exit", [partial, "--no-saved-review", "--format", "json", "-o", output / "partial.json"], 2)
    run("explicit partial opt-out", [partial, "--no-saved-review", "--allow-partial", "--format", "json", "-o", output / "partial-allowed.json"])
    run("existing report is not overwritten", [project, "--no-saved-review", "--format", "json", "-o", baseline], 2)
    receipt = {"version": args.version, "packaged_checks": checks, "count": len(checks), "notice": "Frozen CLI engineering checks with inert synthetic source; not a detection-quality benchmark."}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"checks_passed":len(checks), "output":str(output), "demo_baseline":str(output / "demo-baseline.json")}, indent=2))


if __name__ == "__main__":
    main()
