from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from . import __version__
from .ai import DEFAULT_BASE_URL, review
from .scanner import scan, write_report
from .importer import import_github
from .state import StateStore
from .baseline import load_baseline, compare
from .i18n import LANGUAGES, normalize, tr


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=LANGUAGES, default=os.environ.get("XSS_AUDIT_LANG", "en"))
    language = normalize(pre.parse_known_args(argv)[0].lang)
    t = lambda text: tr(text, language)

    class Parser(argparse.ArgumentParser):
        def add_argument(self, *names, **kwargs):
            if "help" in kwargs:
                kwargs["help"] = t(kwargs["help"])
            return super().add_argument(*names, **kwargs)

        def error(self, message):
            return super().error(t(message))

    parser = Parser(description=t("XSS 静态审计助手；匹配结果需人工确认。"))
    parser.add_argument("--lang", choices=LANGUAGES, default=language, help=t("界面和报告语言（默认英语）"))
    parser.add_argument("path", nargs="?", help="本地代码文件夹")
    parser.add_argument("--repo", help="下载并审计公开 GitHub 仓库，例如 owner/repository")
    parser.add_argument("--ref", default="", help="GitHub 分支、标签或 commit；默认使用仓库默认分支")
    parser.add_argument("--destination", help="GitHub 导入的存放目录；默认使用本机应用数据目录")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-o", "--output", help="报告路径（默认带时间戳，不覆盖已有文件）")
    parser.add_argument("--format", choices=["markdown", "json", "html", "sarif"], default="markdown")
    parser.add_argument("--min-priority", choices=["high", "medium", "info"], type=lambda value: {"高": "high", "中": "medium", "信息": "info"}.get(value, value), default="info", help="报告与 fail-on-match 的最低复核优先级")
    parser.add_argument("--ignore-reviewed", action="store_true", help="不导出已标记为误报 / 已修复的线索")
    parser.add_argument("--no-saved-review", action="store_true", help="不读取本机保存的复核状态")
    parser.add_argument("--baseline", help="对比之前导出的完整 JSON 报告")
    parser.add_argument("--only-new", action="store_true", help="仅导出基线之后新增的线索；需要 --baseline")
    parser.add_argument("--ai", action="store_true", help="明确同意发送已纳入范围的源代码到 AI 接口；可能产生 API 费用")
    parser.add_argument("--model", default=os.environ.get("XSS_AUDIT_MODEL", ""), help="AI 模型名称")
    parser.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-format", choices=["responses", "chat"], default="responses")
    parser.add_argument("--fail-on-match", action="store_true", help="有待确认线索时返回 1；默认完成时返回 0")
    args = parser.parse_args(argv)
    args.min_priority = {"high": "高", "medium": "中", "info": "信息"}.get(args.min_priority, args.min_priority)
    if bool(args.path) == bool(args.repo):
        parser.error("请提供本地代码文件夹或 --repo，二者选择一项。")
    if (args.ref or args.destination) and not args.repo:
        parser.error("--ref / --destination 仅与 --repo 一起使用。")
    if args.only_new and not args.baseline:
        parser.error("--only-new 需要 --baseline。")
    suffix = {"markdown": "md", "json": "json", "html": "html", "sarif": "sarif"}[args.format]
    output = args.output or f"xss-audit-report-{datetime.now():%Y%m%d-%H%M%S-%f}.{suffix}"
    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        metadata = {}
        path = args.path
        if args.repo:
            path, metadata = import_github(args.repo, args.ref, args.destination, progress=lambda text: print(t(text), file=sys.stderr))
        result = scan(path, collect_source=args.ai)
        result.language = language
        result.import_metadata = metadata
        if not args.no_saved_review:
            try:
                StateStore().apply(result)
            except (OSError, ValueError) as error:
                print(t(f"复核记录未加载：{error}"), file=sys.stderr)
                result.analysis_notes.append({"path": "本机复核记录", "reason": str(error)})
        ai_error = None
        if args.ai:
            print(t(f"AI 将发送 {len(result.sources)} 个完整文件；预算外 {len(result.ai_omitted)} 个。"), file=sys.stderr)
            try:
                review(result, os.environ.get("OPENAI_API_KEY", ""), args.model, args.base_url, args.api_format, language=language)
            except ValueError as error:
                ai_error = str(error)
                result.ai_metadata = {"error": ai_error}
        if baseline is not None:
            compare(result, baseline, args.baseline)
        order = {"高": 0, "中": 1, "信息": 2}
        result.report_filters = {"min_priority": args.min_priority, "ignore_reviewed": args.ignore_reviewed,
                                 "matches_before_filters": len(result.matches), "only_new": args.only_new}
        result.matches = [m for m in result.matches if order[m.priority] <= order[args.min_priority]
                          and not (args.ignore_reviewed and m.status in {"误报", "已修复"})
                          and not (args.only_new and m.baseline_state != "new")]
        target = write_report(result, output, args.format, language=language)
        print(t(f"扫描 {result.files_scanned} 个文件，{len(result.matches)} 条待确认线索。报告：{target}"))
        if ai_error:
            print(t(f"AI 失败，本地报告已保留：{ai_error}"), file=sys.stderr)
            return 2
        if result.truncated or result.cancelled or result.ast_incomplete:
            print(t("扫描不完整，请缩小范围。"), file=sys.stderr)
            return 2
        return 1 if args.fail_on_match and result.matches else 0
    except (OSError, ValueError) as error:
        print(t(f"错误：{error}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(t("扫描已中断。"), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
