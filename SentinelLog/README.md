# SentinelLog — SOC Log Analyzer & Suspicious Activity Detector

SentinelLog is a lightweight, standard-library-only Python project for practicing defensive security and SOC log triage. It parses Linux authentication logs and Apache/Nginx access logs, applies transparent detection rules, and produces text, JSON, and CSV findings.

> **Educational lab project:** alerts are rule-based indicators, not proof of compromise. Validate findings against the original logs and environment. Use only logs you are authorized to inspect. Sample logs are for testing and should not be treated as real incidents.

## Features

- Parse Linux `auth.log` / `secure` entries and Apache/Nginx combined access logs.
- Detect repeated SSH login failures within a configurable time window.
- Correlate multiple failed SSH attempts followed by a successful login from the same IP.
- Flag multiple attempted usernames, repeated HTTP 404s, and unusually high request volume.
- Detect requests for common sensitive paths such as `/.env`, `/.git`, `/wp-login.php`, `/phpmyadmin`, and backup/config files.
- Include supporting log lines, event counts, IP addresses, rule names, and available timestamps in alerts.
- Export reports as readable text plus optional JSON and CSV.
- Unit tests using Python's built-in `unittest`; no third-party packages required.

## Requirements

- Python 3.10 or newer recommended.
- Kali Linux, Debian/Ubuntu, or another Python-capable OS.
- No third-party dependencies. `requirements.txt` is intentionally empty.

## Quick start

```bash
# Run both included sample logs
python3 analyzer.py --auth logs/auth.log --access logs/access.log

# Auth-only scan, print to terminal without saving the default text report
python3 analyzer.py --auth logs/auth.log --no-save

# Configure a 10-minute SSH detection window and export multiple formats
python3 analyzer.py --auth logs/auth.log --access logs/nginx.log \
  --window-minutes 10 --threshold 5 \
  --out reports/triage.txt --json-out reports/triage.json --csv-out reports/triage.csv

# Run automated tests
python3 -m unittest discover -s tests -v
```

For actual host logs, point the CLI at a readable file, for example `/var/log/auth.log`. You may need elevated read permissions depending on your system. Prefer copying logs into a lab workspace rather than changing permissions on system log files.

## Detection rules (current defaults)

| Rule | Default behavior | Severity |
|---|---|---|
| SSH failed-login window | 5 or more failures from one IP within 5 minutes; `--threshold` and `--window-minutes` adjust this | MEDIUM; HIGH at 10+ |
| Failure then success | 3+ failures followed by a successful login from the same IP within 10 minutes, when timestamps are parseable | HIGH |
| Multiple usernames | 5+ distinct usernames attempted from one IP | MEDIUM |
| Repeated 404s | 20+ HTTP 404 responses from one IP in the input file | MEDIUM |
| Sensitive-path probing | 3+ requests or 3+ distinct matches for configured sensitive paths | MEDIUM; HIGH for 5+ distinct paths |
| High request volume | 200+ requests from one IP in the input file | LOW |

Thresholds are starting points for a small educational tool, not universal production SOC policy. High request volume and 404 counts are counted across the input file, not normalized by time.

## Timestamp limitations

Linux syslog auth lines commonly omit the year; SentinelLog attaches the current year when parsing those entries. If a log spans New Year or contains nonstandard timestamps, review timestamps before relying on time-window correlations. Access-log timezone offsets are retained in the parsed timestamp string; comparisons use the timestamp's clock portion. The tool does not currently normalize all timestamps to UTC.

## Project workflow

```text
Log files → Parse events → Apply detection rules → Attach evidence →
Terminal report + text/JSON/CSV exports → Analyst validates findings
```

## Structure

```text
analyzer.py             CLI entry point
parser.py               Auth/access log parsing
detector.py             Detection and correlation rules
report.py               Text, JSON, and CSV reporting
utils.py                File and timestamp helpers
logs/                   Sample input logs
reports/                Generated reports
tests/                  Automated unit tests
```

## Roadmap

1. Add timestamp normalization and robust year-rollover handling.
2. Add more unit tests for malformed lines, time-window boundaries, and false-positive cases.
3. Add configurable rules via a YAML/JSON configuration file.
4. Add safe severity/risk scoring and analyst triage notes.
5. Add a small dashboard only after the detection logic is reliable.

## Attribution

This version builds on the structure of the upstream **SOC-Log-Analyzer-Python** project by `SuchirBob`. The upstream license is retained in `LICENSE`. The detection rules, reporting, tests, and documentation in this version have been extended; review the repository history and license when redistributing.

## Disclaimer

SentinelLog is for education, defensive monitoring, and authorized log analysis only. It does not block IPs, perform live monitoring, or prove malicious intent by itself.
