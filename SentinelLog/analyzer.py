"""SentinelLog command-line SOC log analyzer."""
import argparse
import sys
from parser import parse_auth_log, parse_access_log
from detector import run_all_detections
from report import print_report, save_report, save_json, save_csv


def build_arg_parser():
    parser = argparse.ArgumentParser(description="SentinelLog: analyze Linux auth and Apache/Nginx logs for suspicious activity.")
    parser.add_argument("--auth", help="Path to Linux auth.log / secure log")
    parser.add_argument("--access", help="Path to Apache/Nginx access log")
    parser.add_argument("--out", default="reports/report.txt", help="Text report output path (default: reports/report.txt)")
    parser.add_argument("--json-out", help="Optional JSON report output path")
    parser.add_argument("--csv-out", help="Optional CSV report output path")
    parser.add_argument("--window-minutes", type=int, default=5, help="Window for SSH failed-login detection (default: 5)")
    parser.add_argument("--threshold", type=int, default=5, help="Failed SSH attempts required for an alert (default: 5)")
    parser.add_argument("--no-save", action="store_true", help="Print only; do not save the default text report")
    return parser


def main():
    args = build_arg_parser().parse_args()
    if not args.auth and not args.access:
        print("Error: provide at least one of --auth or --access", file=sys.stderr)
        return 2
    if args.window_minutes < 1 or args.threshold < 1:
        print("Error: --window-minutes and --threshold must be positive integers", file=sys.stderr)
        return 2
    auth_events, access_events, sources = [], [], []
    try:
        if args.auth:
            auth_events = parse_auth_log(args.auth)
            sources.append(args.auth)
        if args.access:
            access_events = parse_access_log(args.access)
            sources.append(args.access)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    alerts = run_all_detections(auth_events, access_events, args.window_minutes, args.threshold)
    print_report(alerts, sources)
    if not args.no_save:
        print(f"Text report saved: {save_report(alerts, args.out, sources)}")
    if args.json_out:
        print(f"JSON report saved: {save_json(alerts, args.json_out, sources)}")
    if args.csv_out:
        print(f"CSV report saved: {save_csv(alerts, args.csv_out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
