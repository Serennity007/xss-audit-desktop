from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from . import __version__
from .ai import DEFAULT_BASE_URL, review
from .scanner import scan, write_report


def main(argv=None) -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="XSS 静态审计助手；匹配结果需人工确认。")
    parser.add_argument("path", nargs="?", help="本地代码文件夹")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-o", "--output", help="报告路径（默认带时间戳，不覆盖已有文件）")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--ai", action="store_true", help="明确同意发送已纳入范围的源代码到 AI 接口；可能产生 API 费用")
    parser.add_argument("--model", default=os.environ.get("XSS_AUDIT_MODEL", ""), help="AI 模型名称")
    parser.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-format", choices=["responses", "chat"], default="responses")
    parser.add_argument("--fail-on-match", action="store_true", help="有待确认线索时返回 1；默认完成时返回 0")
    args = parser.parse_args(argv)
    if not args.path:
        parser.error("请提供本地代码文件夹。")
    suffix = "json" if args.format == "json" else "md"
    output = args.output or f"xss-audit-report-{datetime.now():%Y%m%d-%H%M%S-%f}.{suffix}"
    try:
        result = scan(args.path, collect_source=args.ai)
        ai_error = None
        if args.ai:
            print(f"AI 将发送 {len(result.sources)} 个完整文件；预算外 {len(result.ai_omitted)} 个。", file=sys.stderr)
            try:
                review(result, os.environ.get("OPENAI_API_KEY", ""), args.model, args.base_url, args.api_format)
            except ValueError as error:
                ai_error = str(error)
                result.ai_metadata = {"error": ai_error}
        target = write_report(result, output, args.format)
        print(f"扫描 {result.files_scanned} 个文件，{len(result.matches)} 条待确认线索。报告：{target}")
        if ai_error:
            print(f"AI 失败，本地报告已保留：{ai_error}", file=sys.stderr)
            return 2
        if result.truncated or result.cancelled:
            print("扫描不完整，请缩小范围。", file=sys.stderr)
            return 2
        return 1 if args.fail_on_match and result.matches else 0
    except (OSError, ValueError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("扫描已中断。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
