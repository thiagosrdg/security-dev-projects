# LogSentinel

LogSentinel is a small Python command-line tool that reads server logs and
reports suspicious behaviour, such as brute-force attempts, account
enumeration, web scanners and port scans.

It only reads log files. It never blocks, changes or attacks anything.

## Supported logs

The format of each line is detected automatically, so several files can be
analysed in the same command:

- Linux `auth.log` / `secure` (SSH and PAM messages)
- Nginx or Apache access logs in the combined format
- Firewall logs in the iptables/UFW syslog format
- A fictional application log (`<time> <LEVEL> <event> key=value`)

## Detections

| Rule | What it looks for | Default severity |
| --- | --- | --- |
| `excessive_auth_failures` | Many failed logins from one IP in a short window | high |
| `account_targeting` | One IP trying several different accounts | medium |
| `success_after_failures` | A successful login right after repeated failures | critical |
| `suspicious_paths` | Requests to paths such as `/admin`, `/.env`, `/wp-login` | medium |
| `http_error_flood` | Too many 401, 403 and 404 responses for one IP | medium |
| `off_hours_activity` | Authentication activity outside business hours | low |
| `port_scan` | Firewall blocks against many different ports | high |
| `anomalous_ip` | One IP triggering two or more of the rules above | high |

## Requirements

- Python 3.9 or newer
- PyYAML, only when the `--rules` option is used

```bash
pip install -r requirements.txt
```

## Usage

Run it directly from this directory:

```bash
python -m logsentinel analyze samples/auth.log
```

Or install it and use the `logsentinel` command:

```bash
pip install .
logsentinel analyze /var/log/auth.log
```

Sample output:

```text
[1] Potential brute-force activity detected

Source IP: 192.168.56.103
Failed attempts: 47
Target accounts: admin, root, test
Time window: 3 minutes
First seen: 2026-09-02 10:15:01
Last seen: 2026-09-02 10:17:55
Severity: High
```

Every report ends with a summary of the lines read, the events found per log
type and the number of findings per severity.

### Options

```text
logsentinel analyze LOGFILE [LOGFILE ...]
  --rules FILE          YAML file with thresholds and allowlist
  --format {text,json,csv}
  --output FILE         write the report to a file instead of stdout
  --min-severity LEVEL  hide findings below info/low/medium/high/critical
  --allow IP            extra allowlisted IP or network (repeatable)
  --year YEAR           year used for syslog lines, which omit it
```

Examples:

```bash
# Analyse several files at once and keep only the important findings
python -m logsentinel analyze samples/auth.log samples/nginx-access.log \
    --min-severity high

# Export the findings for another tool
python -m logsentinel analyze samples/firewall.log --format json --output report.json

# Ignore the internal network
python -m logsentinel analyze samples/auth.log --allow 192.168.56.0/24
```

## Configuration

Thresholds, severities and the allowlist live in a YAML file. Only the values
written in the file override the built-in defaults, so the file can be short.
See [`rules.yaml`](./rules.yaml) for the complete list.

```yaml
allowlist:
  - 127.0.0.1
  - 192.168.56.0/24

rules:
  excessive_auth_failures:
    threshold: 20
    window_minutes: 10
    severity: critical
  off_hours_activity:
    enabled: false
```

```bash
python -m logsentinel analyze samples/auth.log --rules rules.yaml
```

## Exit codes

The exit code makes the tool usable in scripts and CI pipelines:

| Code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Findings below the `high` severity |
| 2 | At least one `high` or `critical` finding |
| 3 | Invalid input, missing file or invalid configuration |

## Tests

The tests use only `unittest` and sanitised log lines:

```bash
python -m unittest discover
```

## Project structure

```text
logsentinel/
├── logsentinel/
│   ├── cli.py          # arguments, output and exit codes
│   ├── parsers.py      # log line -> Event
│   ├── detectors.py    # detection rules
│   ├── rules.py        # default thresholds, YAML loading and allowlist
│   ├── report.py       # text, JSON and CSV reports
│   └── models.py       # Event, Finding and severity helpers
├── samples/            # sanitised example logs
├── tests/
├── rules.yaml
├── requirements.txt
└── pyproject.toml
```

## How it works

Each line is offered to every parser until one recognises it, and the result is
a normalised `Event` (timestamp, source IP, user, outcome, path, status, port).
The detectors then work on that common structure, so a new log format only
needs a new parser.

Most rules count events inside a sliding time window: the events of one IP are
sorted by time and two indexes walk the list, keeping the largest group that
still fits in the window. That group becomes the finding, which is why the
report can show how many attempts happened and how long the burst lasted.

## Known limitations

- Reads whole files into memory; it is not meant for very large logs.
- Syslog lines have no year, so the current year is assumed unless `--year` is
  given, and time zones are ignored.
- Detection is based on thresholds only; there is no baseline or learning.
- The tool reports behaviour, not confirmed attacks. Findings still need to be
  reviewed by a person.

> For educational purposes and authorised environments only.
