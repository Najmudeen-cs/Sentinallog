"""Render SOC findings as terminal text, JSON, or CSV."""
import csv
import json
import os
from utils import timestamp, ensure_dir

BANNER = "=" * 48
DIVIDER = "-" * 48


def build_report_text(alerts, source_files=None):
    lines = [BANNER, "SENTINELLOG | SOC LOG ANALYZER", BANNER, "", f"Generated: {timestamp()}"]
    if source_files:
        lines.append("Sources: " + ", ".join(source_files))
    if not alerts:
        lines.extend(["", "No suspicious activity detected by the configured rules."])
    for alert in alerts:
        lines.extend(["", f"[{alert['severity']}] {alert['title']}", f"IP Address: {alert['ip']}", f"Details: {alert['detail']}"])
        if alert.get("first_seen") or alert.get("last_seen"):
            lines.append(f"Time range: {alert.get('first_seen') or 'unknown'} -> {alert.get('last_seen') or 'unknown'}")
        if alert.get("evidence"):
            lines.append("Evidence:")
            lines.extend("  - " + item for item in alert["evidence"] if item)
        lines.append(DIVIDER)
    counts = {level: sum(a["severity"] == level for a in alerts) for level in ("HIGH", "MEDIUM", "LOW")}
    lines.extend(["", "Summary", f"High alerts   : {counts['HIGH']}", f"Medium alerts : {counts['MEDIUM']}", f"Low alerts    : {counts['LOW']}", ""])
    return "\n".join(lines)


def print_report(alerts, source_files=None):
    print(build_report_text(alerts, source_files))


def save_report(alerts, output_path="reports/report.txt", source_files=None):
    ensure_dir(os.path.dirname(output_path) or ".")
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(build_report_text(alerts, source_files))
    return output_path


def save_json(alerts, output_path, source_files=None):
    ensure_dir(os.path.dirname(output_path) or ".")
    payload = {"generated_at": timestamp(), "sources": source_files or [], "alert_count": len(alerts), "alerts": alerts}
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return output_path


def save_csv(alerts, output_path):
    ensure_dir(os.path.dirname(output_path) or ".")
    fields = ["severity", "title", "ip", "detail", "rule", "count", "first_seen", "last_seen", "username", "paths", "evidence"]
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            row = dict(alert)
            for key in ("paths", "evidence"):
                if isinstance(row.get(key), list):
                    row[key] = " | ".join(row[key])
            writer.writerow(row)
    return output_path
