"""Command line interface and exit codes."""

import argparse
import sys
from datetime import datetime

from . import __version__
from .detectors import run_detectors
from .models import SEVERITY_ORDER, severity_rank
from .parsers import parse_files
from .report import RENDERERS, build_summary
from .rules import load_rules

# Exit codes, so the tool can be used inside scripts and CI pipelines.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_HIGH_FINDINGS = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the `analyze` command."""
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Analyse server logs and report suspicious behaviour.")
    parser.add_argument("--version", action="version",
                        version="logsentinel %s" % __version__)

    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="analyse one or more log files")
    analyze.add_argument("files", nargs="+", metavar="LOGFILE")
    analyze.add_argument("--rules", metavar="FILE",
                         help="YAML file with thresholds and allowlist")
    analyze.add_argument("--format", choices=sorted(RENDERERS), default="text",
                         help="output format (default: text)")
    analyze.add_argument("--output", metavar="FILE",
                         help="write the report to a file instead of stdout")
    analyze.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info",
                         help="hide findings below this severity")
    analyze.add_argument("--allow", action="append", default=[], metavar="IP",
                         help="extra allowlisted IP or network (repeatable)")
    analyze.add_argument("--year", type=int, default=datetime.now().year,
                         help="year used for syslog lines, which omit it")
    return parser


def main(argv=None) -> int:
    """Run the tool and return the process exit code."""
    args = build_parser().parse_args(argv)

    try:
        config = load_rules(args.rules)
        config["allowlist"].extend(args.allow)
        events, stats = parse_files(args.files, args.year)
    except (OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return EXIT_ERROR

    findings = run_detectors(events, config)
    # Findings below the requested severity are dropped before reporting.
    findings = [f for f in findings
                if severity_rank(f.severity) >= severity_rank(args.min_severity)]

    summary = build_summary(events, stats, findings)
    report = RENDERERS[args.format](findings, summary, list(args.files))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
        except OSError as error:
            print("error: %s" % error, file=sys.stderr)
            return EXIT_ERROR
    else:
        print(report)

    if not findings:
        return EXIT_CLEAN
    highest = max(severity_rank(finding.severity) for finding in findings)
    if highest >= severity_rank("high"):
        return EXIT_HIGH_FINDINGS
    return EXIT_FINDINGS
