"""Default detection rules and YAML configuration loading."""

import ipaddress
from typing import Any, Dict, List

# Every threshold used by the detectors lives here, so a YAML file only needs
# to override the values that should be different.
DEFAULT_RULES: Dict[str, Any] = {
    "allowlist": [],
    "rules": {
        "excessive_auth_failures": {
            "enabled": True, "threshold": 10, "window_minutes": 5, "severity": "high",
        },
        "account_targeting": {
            "enabled": True, "threshold": 3, "window_minutes": 10, "severity": "medium",
        },
        "success_after_failures": {
            "enabled": True, "threshold": 5, "window_minutes": 10, "severity": "critical",
        },
        "suspicious_paths": {
            "enabled": True, "threshold": 3, "window_minutes": 5, "severity": "medium",
            "patterns": [
                "/admin", "/wp-login", "/wp-admin", "/phpmyadmin", "/.env",
                "/.git", "/cgi-bin", "/shell", "/etc/passwd", "/config",
            ],
        },
        "http_error_flood": {
            "enabled": True, "threshold": 15, "window_minutes": 5, "severity": "medium",
            "statuses": [401, 403, 404],
        },
        "off_hours_activity": {
            "enabled": True, "threshold": 3, "business_start": 8, "business_end": 20,
            "severity": "low",
        },
        "port_scan": {
            "enabled": True, "threshold": 10, "window_minutes": 5, "severity": "high",
        },
        "anomalous_ip": {
            "enabled": True, "threshold": 2, "severity": "high",
        },
    },
}


def load_rules(path: str = None) -> Dict[str, Any]:
    """Return the default rules, updated with the values found in a YAML file."""
    config = {"allowlist": list(DEFAULT_RULES["allowlist"]),
              "rules": {name: dict(values)
                        for name, values in DEFAULT_RULES["rules"].items()}}
    if not path:
        return config

    # PyYAML is only needed when a configuration file is supplied.
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        user_config = yaml.safe_load(handle) or {}

    if not isinstance(user_config, dict):
        raise ValueError("the rules file must contain a YAML mapping")

    config["allowlist"].extend(user_config.get("allowlist") or [])
    for name, values in (user_config.get("rules") or {}).items():
        if name not in config["rules"]:
            raise ValueError("unknown rule in the configuration: %s" % name)
        if not isinstance(values, dict):
            raise ValueError("rule '%s' must contain a YAML mapping" % name)
        config["rules"][name].update(values)

    return config


class Allowlist:
    """Addresses and networks that should never produce a finding."""

    def __init__(self, entries: List[str]):
        self.networks = []
        for entry in entries:
            # Plain addresses become /32 or /128 networks.
            self.networks.append(ipaddress.ip_network(str(entry), strict=False))

    def __contains__(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.networks)
