"""Report rendering in text, JSON and CSV."""

import csv
import io
import json
from collections import Counter
from datetime import datetime
from typing import Dict, List

from .models import Event, Finding, SEVERITY_ORDER, sort_findings


def build_summary(events: List[Event], stats: Dict, findings: List[Finding]) -> Dict:
    """Collect the numbers shown at the end of every report."""
    sources = Counter(event.source for event in events)
    severities = Counter(finding.severity for finding in findings)

    return {
        "lines_read": stats["lines"],
        "events_parsed": stats["parsed"],
        "lines_ignored": stats["ignored"],
        "events_by_source": dict(sorted(sources.items())),
        "unique_source_ips": len({event.ip for event in events if event.ip}),
        "findings": len(findings),
        "findings_by_severity": {name: severities[name]
                                 for name in SEVERITY_ORDER if severities[name]},
        "first_event": events[0].timestamp.isoformat(sep=" ") if events else None,
        "last_event": events[-1].timestamp.isoformat(sep=" ") if events else None,
    }


def finding_to_dict(finding: Finding) -> Dict:
    """Flatten a finding so it can be written as JSON or CSV."""
    return {
        "rule": finding.rule,
        "title": finding.title,
        "severity": finding.severity,
        "source_ip": finding.ip,
        "first_seen": finding.first_seen.isoformat(sep=" "),
        "last_seen": finding.last_seen.isoformat(sep=" "),
        "events": finding.count,
        "details": dict(finding.details),
    }


def render_text(findings: List[Finding], summary: Dict, files: List[str]) -> str:
    """Render the human readable report."""
    lines = ["LogSentinel report - %s" % datetime.now().isoformat(sep=" ",
                                                                 timespec="seconds"),
             "Analysed files: %s" % ", ".join(files), ""]

    if not findings:
        lines.append("No suspicious activity detected.")
        lines.append("")
    for index, finding in enumerate(sort_findings(findings), start=1):
        lines.append("[%d] %s" % (index, finding.title))
        lines.append("")
        if finding.ip:
            lines.append("Source IP: %s" % finding.ip)
        for key, value in finding.details.items():
            lines.append("%s: %s" % (key, value))
        lines.append("First seen: %s" % finding.first_seen.isoformat(sep=" "))
        lines.append("Last seen: %s" % finding.last_seen.isoformat(sep=" "))
        lines.append("Severity: %s" % finding.severity.capitalize())
        lines.append("")

    lines.append("--- Summary ---")
    lines.append("Lines read: %d (parsed %d, ignored %d)" % (
        summary["lines_read"], summary["events_parsed"], summary["lines_ignored"]))
    if summary["events_by_source"]:
        lines.append("Events by source: %s" % ", ".join(
            "%s %d" % (name, total)
            for name, total in summary["events_by_source"].items()))
    lines.append("Unique source IPs: %d" % summary["unique_source_ips"])
    if summary["first_event"]:
        lines.append("Time range: %s to %s" % (summary["first_event"],
                                               summary["last_event"]))
    severities = ", ".join("%s %d" % (name, total)
                           for name, total in summary["findings_by_severity"].items())
    lines.append("Findings: %d%s" % (summary["findings"],
                                     " (%s)" % severities if severities else ""))
    return "\n".join(lines)


def render_json(findings: List[Finding], summary: Dict, files: List[str]) -> str:
    """Render the report as a single JSON document."""
    document = {
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "files": files,
        "summary": summary,
        "findings": [finding_to_dict(f) for f in sort_findings(findings)],
    }
    return json.dumps(document, indent=2)


def render_csv(findings: List[Finding], summary: Dict, files: List[str]) -> str:
    """Render one line per finding, for spreadsheets or other tools."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["rule", "title", "severity", "source_ip",
                     "first_seen", "last_seen", "events", "details"])

    for finding in sort_findings(findings):
        # The variable details are joined into one column as "key=value".
        details = "; ".join("%s=%s" % (key, value)
                            for key, value in finding.details.items())
        writer.writerow([finding.rule, finding.title, finding.severity,
                         finding.ip or "", finding.first_seen.isoformat(sep=" "),
                         finding.last_seen.isoformat(sep=" "), finding.count,
                         details])

    return buffer.getvalue().rstrip("\n")


RENDERERS = {"text": render_text, "json": render_json, "csv": render_csv}
