"""Research platform entry point; independent of ordinary source scanning."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .ai import DEFAULT_BASE_URL
from .research_model import ModelResponder
from .research_runner import _read_json, create_demo, run_pair
from .robustness import prepare_pair


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Paired repository-auditor robustness experiments / 仓库审计鲁棒性成对实验")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Create unchanged-code baseline/context variants")
    prepare.add_argument("project")
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--variant", choices=["anchoring", "authority", "instruction"], default="anchoring")
    prepare.add_argument("--ground-truth", help="Oracle JSON list, kept outside the agent view")
    demo = commands.add_parser("demo", help="Construct a synthetic multi-file case")
    demo.add_argument("--output", required=True)
    demo.add_argument("--variant", choices=["anchoring", "authority", "instruction"], default="anchoring")
    demo.add_argument("--offline-demo", action="store_true", help="Run scripted contrasts; NOT measured model robustness")
    demo.add_argument("--lang", choices=["en", "zh-CN"], default="en")
    run = commands.add_parser("run", help="Audit both prepared repositories with the same model and budgets")
    run.add_argument("case")
    run.add_argument("--output", required=True)
    run.add_argument("--ai", action="store_true", required=True, help="Explicitly send selected repository text to the configured API; charges may apply")
    run.add_argument("--model", default=os.environ.get("XSS_AUDIT_MODEL", ""))
    run.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL))
    run.add_argument("--api-format", choices=["responses", "chat"], default="responses")
    run.add_argument("--repeats", type=int, default=1)
    run.add_argument("--order", choices=["balanced", "baseline-first"], default="balanced")
    run.add_argument("--max-steps", type=int, default=12)
    run.add_argument("--max-chars", type=int, default=60000)
    run.add_argument("--lang", choices=["en", "zh-CN"], default="en")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            project = Path(args.project).expanduser().resolve(strict=True)
            if args.ground_truth and Path(args.ground_truth).expanduser().resolve().is_relative_to(project):
                raise ValueError("Ground-truth JSON must be outside the audited project.")
            Path(args.output).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
            truth = _read_json(args.ground_truth) if args.ground_truth else []
            manifest = prepare_pair(args.project, args.output, variant=args.variant, ground_truth=truth)
            print(json.dumps({"directory": str(Path(args.output).resolve()), "pair_id": manifest["pair_id"], "runtime_invariance": "not_verified"}, ensure_ascii=False))
        elif args.command == "demo":
            result = create_demo(args.output, offline_demo=args.offline_demo, variant=args.variant, language=args.lang)
            print(json.dumps({"directory": result["directory"], "case": result["case"], "execution": "offline_demo" if args.offline_demo else "prepared_only", "notice": "Offline contrasts are scripted and do not measure model robustness."}, ensure_ascii=False))
        else:
            key = os.environ.get("OPENAI_API_KEY", "")
            # Validate credentials/configuration before creating any result directory.
            ModelResponder(key, args.model, args.base_url, args.api_format)
            factory = lambda condition: ModelResponder(key, args.model, args.base_url, args.api_format)
            result = run_pair(args.case, args.output, factory, execution="live", repeats=args.repeats, order=args.order,
                              max_steps=args.max_steps, max_chars=args.max_chars, language=args.lang,
                              progress=lambda message: print(message, file=sys.stderr))
            print(json.dumps({"json": result["json"], "html": result["html"]}, ensure_ascii=False))
            if any(run["status"] != "completed" for trial in result["report"]["trials"] for run in trial["runs"].values()):
                return 2
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Research error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
