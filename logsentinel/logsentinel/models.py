"""Data structures shared by the parsers, the detectors and the reports."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# Severity names ordered from the least to the most important one.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(name: str) -> int:
    """Return the position of a severity name, or 0 when it is unknown."""
    name = (name or "").lower()
    return SEVERITY_ORDER.index(name) if name in SEVERITY_ORDER else 0


def escalate(name: str, steps: int = 1) -> str:
    """Raise a severity by `steps` levels without going past `critical`."""
    index = min(severity_rank(name) + steps, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[index]


@dataclass
class Event:
    """One normalised log line.

    Every parser converts its own log format into this structure, so the
    detectors never need to know which file the line came from.
    """

    timestamp: datetime
    source: str  # "auth", "http", "firewall" or "app"
    raw: str
    ip: Optional[str] = None
    user: Optional[str] = None
    outcome: Optional[str] = None  # "success" or "failure"
    path: Optional[str] = None  # HTTP request path
    status: Optional[int] = None  # HTTP status code
    port: Optional[int] = None  # firewall destination port
    action: Optional[str] = None  # firewall "block" or "allow"


@dataclass
class Finding:
    """One suspicious behaviour reported by a detector."""

    rule: str
    title: str
    severity: str
    ip: Optional[str]
    first_seen: datetime
    last_seen: datetime
    count: int
    # Extra lines printed under the finding, in insertion order.
    details: Dict[str, str] = field(default_factory=dict)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings by severity first and by the number of events second."""
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.count, f.first_seen),
        reverse=True,
    )
