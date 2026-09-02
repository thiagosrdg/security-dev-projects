"""Detection rules applied to the parsed events.

Every detector receives the full list of events plus its own configuration
and returns a list of `Finding` objects.
"""

import math
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Dict, List

from .models import Event, Finding, escalate
from .rules import Allowlist


# --- helpers ---------------------------------------------------------------

def group_by_ip(events: List[Event]) -> Dict[str, List[Event]]:
    """Group events by source IP, skipping lines without an address."""
    groups: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.ip:
            groups[event.ip].append(event)
    return groups


def busiest_window(events: List[Event], window_minutes: int) -> List[Event]:
    """Return the largest group of events that still fits in one time window.

    The events are scanned with two indexes: `end` walks forward and `start`
    is pushed forward whenever the pair is further apart than the window.
    """
    if not events:
        return []

    events = sorted(events, key=lambda event: event.timestamp)
    window = timedelta(minutes=window_minutes)
    best: List[Event] = []
    start = 0

    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > len(best):
            best = events[start:end + 1]

    return best


def window_minutes(events: List[Event]) -> int:
    """Return how many minutes the events span, rounded up to at least one."""
    seconds = (events[-1].timestamp - events[0].timestamp).total_seconds()
    return max(1, math.ceil(seconds / 60))


def names(values, limit: int = 5) -> str:
    """Format a small sample of values for the report."""
    unique = sorted({value for value in values if value})
    shown = ", ".join(unique[:limit])
    if len(unique) > limit:
        shown += ", ... (+%d)" % (len(unique) - limit)
    return shown or "unknown"


def build_finding(rule: str, title: str, severity: str, ip, events: List[Event],
                  details: Dict[str, str]) -> Finding:
    """Create a finding from the events that triggered a rule."""
    events = sorted(events, key=lambda event: event.timestamp)
    return Finding(
        rule=rule,
        title=title,
        severity=severity,
        ip=ip,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        count=len(events),
        details=details,
    )


# --- detectors -------------------------------------------------------------

def detect_excessive_auth_failures(events, config, allowlist) -> List[Finding]:
    """Many failed authentications from the same IP: a brute-force attempt."""
    findings = []
    failures = [e for e in events
                if e.source in ("auth", "app") and e.outcome == "failure"]

    for ip, ip_events in group_by_ip(failures).items():
        if ip in allowlist:
            continue
        burst = busiest_window(ip_events, config["window_minutes"])
        if len(burst) < config["threshold"]:
            continue

        severity = config["severity"]
        # A burst five times above the threshold deserves a higher severity.
        if len(burst) >= config["threshold"] * 5:
            severity = escalate(severity)

        findings.append(build_finding(
            "excessive_auth_failures",
            "Potential brute-force activity detected",
            severity, ip, burst,
            {
                "Failed attempts": str(len(burst)),
                "Target accounts": names(e.user for e in burst),
                "Time window": "%d minutes" % window_minutes(burst),
            },
        ))
    return findings


def detect_account_targeting(events, config, allowlist) -> List[Finding]:
    """One IP trying several different accounts: account enumeration."""
    findings = []
    failures = [e for e in events
                if e.source in ("auth", "app") and e.outcome == "failure" and e.user]

    for ip, ip_events in group_by_ip(failures).items():
        if ip in allowlist:
            continue
        burst = busiest_window(ip_events, config["window_minutes"])
        accounts = {event.user for event in burst}
        if len(accounts) < config["threshold"]:
            continue

        findings.append(build_finding(
            "account_targeting",
            "Authentication attempts against multiple accounts",
            config["severity"], ip, burst,
            {
                "Accounts tried": str(len(accounts)),
                "Account names": names(accounts),
                "Time window": "%d minutes" % window_minutes(burst),
            },
        ))
    return findings


def detect_success_after_failures(events, config, allowlist) -> List[Finding]:
    """A successful login right after repeated failures from the same IP."""
    findings = []
    window = timedelta(minutes=config["window_minutes"])

    for ip, ip_events in group_by_ip(events).items():
        if ip in allowlist:
            continue
        auth_events = [e for e in ip_events
                       if e.source in ("auth", "app") and e.outcome]
        recent_failures: List[Event] = []

        for event in sorted(auth_events, key=lambda e: e.timestamp):
            if event.outcome == "failure":
                recent_failures.append(event)
                continue

            # Keep only the failures that happened inside the time window.
            recent_failures = [f for f in recent_failures
                               if event.timestamp - f.timestamp <= window]
            if len(recent_failures) >= config["threshold"]:
                findings.append(build_finding(
                    "success_after_failures",
                    "Successful login after repeated failures",
                    config["severity"], ip, recent_failures + [event],
                    {
                        "Account": event.user or "unknown",
                        "Failures before success": str(len(recent_failures)),
                        "Successful login": event.timestamp.isoformat(sep=" "),
                    },
                ))
            recent_failures = []
    return findings


def detect_suspicious_paths(events, config, allowlist) -> List[Finding]:
    """Requests to paths that are typical targets of automated scanners."""
    findings = []
    patterns = [pattern.lower() for pattern in config["patterns"]]
    requests = [e for e in events if e.path]

    for ip, ip_events in group_by_ip(requests).items():
        if ip in allowlist:
            continue
        hits = [e for e in ip_events
                if any(pattern in e.path.lower() for pattern in patterns)]
        burst = busiest_window(hits, config["window_minutes"])
        if len(burst) < config["threshold"]:
            continue

        findings.append(build_finding(
            "suspicious_paths",
            "Requests to suspicious paths",
            config["severity"], ip, burst,
            {
                "Requests": str(len(burst)),
                "Paths": names((e.path for e in burst), limit=6),
                "Time window": "%d minutes" % window_minutes(burst),
            },
        ))
    return findings


def detect_http_error_flood(events, config, allowlist) -> List[Finding]:
    """Too many 401/403/404 responses for one IP: probing or scanning."""
    findings = []
    statuses = set(config["statuses"])
    errors = [e for e in events if e.status in statuses]

    for ip, ip_events in group_by_ip(errors).items():
        if ip in allowlist:
            continue
        burst = busiest_window(ip_events, config["window_minutes"])
        if len(burst) < config["threshold"]:
            continue

        counts = defaultdict(int)
        for event in burst:
            counts[event.status] += 1
        breakdown = ", ".join("%d x%d" % (status, counts[status])
                              for status in sorted(counts))

        findings.append(build_finding(
            "http_error_flood",
            "Excessive HTTP error responses",
            config["severity"], ip, burst,
            {
                "Error responses": str(len(burst)),
                "Status codes": breakdown,
                "Time window": "%d minutes" % window_minutes(burst),
            },
        ))
    return findings


def detect_off_hours_activity(events, config, allowlist) -> List[Finding]:
    """Authentication activity outside the configured business hours."""
    findings = []
    start, end = config["business_start"], config["business_end"]
    relevant = [e for e in events
                if e.outcome and not (start <= e.timestamp.hour < end)]

    for ip, ip_events in group_by_ip(relevant).items():
        if ip in allowlist or len(ip_events) < config["threshold"]:
            continue

        findings.append(build_finding(
            "off_hours_activity",
            "Activity outside business hours",
            config["severity"], ip, ip_events,
            {
                "Events": str(len(ip_events)),
                "Business hours": "%02d:00-%02d:00" % (start, end),
                "Accounts": names(e.user for e in ip_events),
            },
        ))
    return findings


def detect_port_scan(events, config, allowlist) -> List[Finding]:
    """Firewall blocks against many different ports: a port scan."""
    findings = []
    blocked = [e for e in events
               if e.source == "firewall" and e.action == "block" and e.port]

    for ip, ip_events in group_by_ip(blocked).items():
        if ip in allowlist:
            continue
        burst = busiest_window(ip_events, config["window_minutes"])
        ports = {event.port for event in burst}
        if len(ports) < config["threshold"]:
            continue

        findings.append(build_finding(
            "port_scan",
            "Possible port scan blocked by the firewall",
            config["severity"], ip, burst,
            {
                "Blocked packets": str(len(burst)),
                "Distinct ports": str(len(ports)),
                "Ports": ", ".join(str(port) for port in sorted(ports)[:8])
                         + (", ..." if len(ports) > 8 else ""),
                "Time window": "%d minutes" % window_minutes(burst),
            },
        ))
    return findings


# Detectors that look at events. `anomalous_ip` runs later, over the results.
DETECTORS: Dict[str, Callable] = {
    "excessive_auth_failures": detect_excessive_auth_failures,
    "account_targeting": detect_account_targeting,
    "success_after_failures": detect_success_after_failures,
    "suspicious_paths": detect_suspicious_paths,
    "http_error_flood": detect_http_error_flood,
    "off_hours_activity": detect_off_hours_activity,
    "port_scan": detect_port_scan,
}


def detect_anomalous_ip(findings: List[Finding], config) -> List[Finding]:
    """Correlate the other findings: one IP triggering several rules at once."""
    by_ip: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.ip:
            by_ip[finding.ip].append(finding)

    results = []
    for ip, ip_findings in by_ip.items():
        rules = {finding.rule for finding in ip_findings}
        if len(rules) < config["threshold"]:
            continue

        results.append(Finding(
            rule="anomalous_ip",
            title="Anomalous behaviour from a single source IP",
            severity=config["severity"],
            ip=ip,
            first_seen=min(f.first_seen for f in ip_findings),
            last_seen=max(f.last_seen for f in ip_findings),
            count=sum(f.count for f in ip_findings),
            details={
                "Rules triggered": str(len(rules)),
                "Detections": ", ".join(sorted(rules)),
                "Related events": str(sum(f.count for f in ip_findings)),
            },
        ))
    return results


def run_detectors(events: List[Event], config: Dict) -> List[Finding]:
    """Run every enabled detector and return all the findings."""
    allowlist = Allowlist(config.get("allowlist", []))
    rules = config["rules"]
    findings: List[Finding] = []

    for name, detector in DETECTORS.items():
        rule = rules.get(name, {})
        if rule.get("enabled", True):
            findings.extend(detector(events, rule, allowlist))

    correlation = rules.get("anomalous_ip", {})
    if correlation.get("enabled", True):
        findings.extend(detect_anomalous_ip(findings, correlation))

    return findings
