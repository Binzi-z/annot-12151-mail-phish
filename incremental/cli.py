"""命令行入口。

用法：
  python -m incremental.cli scan --root src --sarif out.sarif [--full]
                                [--policy fail-closed|quarantine]
                                [--cache-dir DIR] [--explain]
退出码见 engine.py 顶部约定。
"""
from __future__ import annotations

import argparse
import sys

from .engine import (
    EXIT_CACHE_FORCED_FULL, EXIT_CLEAN, EXIT_FATAL, EXIT_FINDINGS, EXIT_UNRESOLVED,
    render_report, run_scan,
)
from .taint import POLICY_FAIL_CLOSED, POLICY_QUARANTINE


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="incremental", description="增量污点分析器")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="对扫描根执行全量或增量分析")
    s.add_argument("--root", required=True, help="扫描根目录")
    s.add_argument("--sarif", help="SARIF 输出路径；缺省输出到 stdout")
    s.add_argument("--cache-dir", help="缓存目录（默认 <root>/.incremental-cache）")
    s.add_argument("--full", action="store_true", help="放弃缓存强制全量")
    s.add_argument("--policy", choices=[POLICY_FAIL_CLOSED, POLICY_QUARANTINE],
                   default=POLICY_FAIL_CLOSED,
                   help="动态派发解析失败的降级策略（默认 fail-closed）")
    s.add_argument("--explain", action="store_true",
                   help="stderr 打印缓存命中/失效原因")
    s.add_argument("--uri-prefix",
                   help="SARIF artifact URI 前缀（扫描根是子目录时对齐仓库路径，如 src）")
    s.add_argument("--no-forced-full-code", action="store_true",
                   help="强制全量且无发现时退出码仍为 0（默认 4，仅作观测信号）")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd != "scan":  # pragma: no cover - argparse 已保证
        return 2

    result = run_scan(
        args.root, cache_dir=args.cache_dir, full=args.full, policy=args.policy,
        quiet_cache_miss=args.no_forced_full_code, uri_prefix=args.uri_prefix,
    )
    report = render_report(result)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)

    if args.explain:
        print(f"[cache] mode={result.stats['mode']} "
              f"rescanned={result.stats['filesRescanned']} "
              f"reused={result.stats['filesReusedFromCache']}", file=sys.stderr)
        for r in result.reasons:
            print(f"[cache] {r}", file=sys.stderr)

    code = result.exit_code
    if args.no_forced_full_code and code == EXIT_CACHE_FORCED_FULL:
        code = EXIT_CLEAN
    return code


if __name__ == "__main__":
    raise SystemExit(main())
