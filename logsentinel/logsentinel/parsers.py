"""Parsers that turn raw log lines into `Event` objects.

Each line is offered to every parser until one of them recognises it, so a
single command can analyse mixed files without extra flags.
"""

import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from .models import Event

# --- syslog style lines (auth.log, secure, firewall) -----------------------
# Example: "Sep  2 10:15:01 srv01 sshd[2011]: Failed password for root ..."
SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w\-./]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)

# SSH messages we care about, in the order they are tested.
SSH_PATTERNS = [
    (re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
                r"from (?P<ip>\S+) port"), "failure"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) "
                r"from (?P<ip>\S+) port"), "success"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"), "failure"),
    (re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)"),
     "failure"),
]

# Firewall lines carry key=value fields such as "SRC=203.0.113.9 ... DPT=23".
FIREWALL_SRC_RE = re.compile(r"SRC=(?P<ip>\S+)")
FIREWALL_DPT_RE = re.compile(r"DPT=(?P<port>\d+)")
FIREWALL_BLOCK_RE = re.compile(r"\b(BLOCK|DROP|DENY|REJECT)\b", re.IGNORECASE)

# --- web server access logs (nginx / apache combined format) ---------------
# Example: '203.0.113.9 - - [02/Sep/2026:10:15:01 +0000] "GET /admin HTTP/1.1" 404 153'
HTTP_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r"\"(?P<method>[A-Z]+) (?P<path>\S+)[^\"]*\" (?P<status>\d{3})"
)

# --- fictional application log --------------------------------------------
# Example: "2026-09-02 10:15:01 WARNING login_failed user=admin ip=198.51.100.23"
APP_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+"
    r"(?P<event>\w+)(?P<fields>.*)$"
)
KEY_VALUE_RE = re.compile(r"(\w+)=([^\s]+)")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _syslog_timestamp(match: re.Match, year: int) -> datetime:
    """Build a datetime from a syslog line, which has no year of its own."""
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    return datetime(year, MONTHS[match.group("month")], int(match.group("day")),
                    hour, minute, second)


def parse_syslog(line: str, year: int) -> Optional[Event]:
    """Parse SSH/PAM authentication and firewall lines written by syslog."""
    match = SYSLOG_RE.match(line)
    if not match:
        return None

    timestamp = _syslog_timestamp(match, year)
    message = match.group("message")

    # Firewall lines are recognised by their SRC= field.
    src = FIREWALL_SRC_RE.search(message)
    if src:
        port = FIREWALL_DPT_RE.search(message)
        blocked = bool(FIREWALL_BLOCK_RE.search(message))
        return Event(
            timestamp=timestamp,
            source="firewall",
            raw=line,
            ip=src.group("ip"),
            port=int(port.group("port")) if port else None,
            action="block" if blocked else "allow",
        )

    for pattern, outcome in SSH_PATTERNS:
        found = pattern.search(message)
        if found:
            return Event(
                timestamp=timestamp,
                source="auth",
                raw=line,
                ip=found.group("ip"),
                user=found.group("user"),
                outcome=outcome,
            )
    return None


def parse_http(line: str, year: int) -> Optional[Event]:
    """Parse an nginx/apache access log line in the combined format."""
    match = HTTP_RE.match(line)
    if not match:
        return None

    # The timezone offset is dropped: all comparisons use a single log source.
    timestamp = datetime.strptime(match.group("time").split()[0], "%d/%b/%Y:%H:%M:%S")
    status = int(match.group("status"))
    return Event(
        timestamp=timestamp,
        source="http",
        raw=line,
        ip=match.group("ip"),
        path=match.group("path"),
        status=status,
        # 401 and 403 are authentication or authorisation failures.
        outcome="failure" if status in (401, 403) else None,
    )


def parse_app(line: str, year: int) -> Optional[Event]:
    """Parse the fictional application log ("<time> <LEVEL> <event> key=value")."""
    match = APP_RE.match(line)
    if not match:
        return None

    timestamp = datetime.strptime(match.group("time").replace("T", " "),
                                  "%Y-%m-%d %H:%M:%S")
    fields = dict(KEY_VALUE_RE.findall(match.group("fields")))
    name = match.group("event").lower()

    outcome = None
    if "fail" in name or "denied" in name or "invalid" in name:
        outcome = "failure"
    elif "success" in name or name.endswith("_ok"):
        outcome = "success"

    return Event(
        timestamp=timestamp,
        source="app",
        raw=line,
        ip=fields.get("ip"),
        user=fields.get("user"),
        outcome=outcome,
        path=fields.get("path"),
    )


PARSERS = [parse_syslog, parse_http, parse_app]


def parse_line(line: str, year: int) -> Optional[Event]:
    """Return the first event produced by a parser, or None if none matches."""
    line = line.strip()
    if not line:
        return None
    for parser in PARSERS:
        event = parser(line, year)
        if event:
            return event
    return None


def parse_files(paths: Iterable[str], year: int) -> Tuple[List[Event], dict]:
    """Read every file and return the parsed events plus simple statistics."""
    events: List[Event] = []
    stats = {"lines": 0, "parsed": 0, "ignored": 0}

    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                stats["lines"] += 1
                event = parse_line(line, year)
                if event:
                    events.append(event)
                    stats["parsed"] += 1
                else:
                    stats["ignored"] += 1

    events.sort(key=lambda event: event.timestamp)
    return events, stats
