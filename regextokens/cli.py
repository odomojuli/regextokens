"""Command-line entry point: `regextokens scan|list|version`.

A thin, dependency-free (stdlib argparse) wrapper over the scanner, catalog,
and reporters. Exit status follows scanner convention:

    0  no findings
    1  findings at or above the requested confidence
    2  usage / runtime error

so `regextokens scan .` can gate a CI job or pre-commit hook.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .baseline import Baseline, write_baseline
from .catalog import load_catalog
from .report import as_json, human, sarif
from .scanner import scan_path
from .verify import Confidence

# CLI confidence names -> enum. Lets users pick a precision/recall point.
_CONF = {
    "low": Confidence.LOW,
    "probable": Confidence.PROBABLE,
    "verified": Confidence.VERIFIED_OFFLINE,
}
_FORMATTERS = {"human": human, "json": as_json, "sarif": sarif}


def _cmd_scan(args: argparse.Namespace) -> int:
    targets = [Path(p) for p in args.paths]
    for target in targets:
        if not target.exists():
            print(f"regextokens: no such file or directory: {target}", file=sys.stderr)
            return 2
    min_conf = _CONF[args.min_confidence]
    try:
        patterns = load_catalog(args.catalog)
    except (OSError, ValueError) as exc:
        print(f"regextokens: cannot load catalog: {exc}", file=sys.stderr)
        return 2
    findings = sorted(
        (f for target in targets for f in scan_path(target, patterns, min_confidence=min_conf)),
        key=lambda f: (f.path, f.line, f.column, f.pattern_id),
    )

    if args.write_baseline:
        n = write_baseline(args.write_baseline, findings)
        print(
            f"regextokens: wrote baseline with {n} finding{'s' if n != 1 else ''} "
            f"to {args.write_baseline}",
            file=sys.stderr,
        )
        return 0

    if args.baseline:
        try:
            baseline = Baseline.load(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"regextokens: cannot load baseline: {exc}", file=sys.stderr)
            return 2
        findings, suppressed = baseline.filter(findings)
        if suppressed:
            print(
                f"regextokens: suppressed {suppressed} baselined finding{'s' if suppressed != 1 else ''}",
                file=sys.stderr,
            )

    sys.stdout.write(_FORMATTERS[args.format](findings))
    sys.stdout.write("\n")
    return 1 if findings else 0


def _cmd_list(args: argparse.Namespace) -> int:
    patterns = load_catalog(args.catalog)
    if args.format == "json":
        import json

        sys.stdout.write(
            json.dumps(
                [
                    {"id": p.id, "provider": p.provider, "name": p.name, "strategy": p.strategy}
                    for p in patterns
                ],
                indent=2,
            )
            + "\n"
        )
    else:
        width = max((len(p.id) for p in patterns), default=0)
        for p in sorted(patterns, key=lambda p: (p.category, p.provider, p.id)):
            print(f"{p.id.ljust(width)}  [{p.strategy:10}] {p.provider} — {p.name}")
        print(f"\n{len(patterns)} patterns / {len({p.provider for p in patterns})} providers")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"regextokens {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="regextokens",
        description="Scan files for API tokens and secrets, with offline-proof confidence tiers.",
    )
    parser.add_argument("--version", action="version", version=f"regextokens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan files or directory trees for secrets")
    p_scan.add_argument("paths", nargs="+", help="files or directories to scan")
    p_scan.add_argument(
        "-f", "--format", choices=_FORMATTERS, default="human", help="output format (default: human)"
    )
    p_scan.add_argument(
        "-m",
        "--min-confidence",
        choices=_CONF,
        default="low",
        help="only report findings at or above this tier (default: low)",
    )
    p_scan.add_argument(
        "--catalog", default=None, help="path to a patterns.json (default: the bundled catalog)"
    )
    base_group = p_scan.add_mutually_exclusive_group()
    base_group.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="suppress findings recorded in this baseline file",
    )
    base_group.add_argument(
        "--write-baseline",
        default=None,
        metavar="FILE",
        help="record current findings as accepted and exit 0 (preserves the file's allow section)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_list = sub.add_parser("list", help="list catalog patterns")
    p_list.add_argument("-f", "--format", choices=("human", "json"), default="human")
    p_list.add_argument("--catalog", default=None)
    p_list.set_defaults(func=_cmd_list)

    p_version = sub.add_parser("version", help="print version")
    p_version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
