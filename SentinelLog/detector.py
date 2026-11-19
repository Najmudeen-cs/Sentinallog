"""Rule-based detections for authentication and web-server logs."""
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import urlsplit

SSH_BRUTE_FORCE_THRESHOLD = 10
FAILED_LOGIN_THRESHOLD = 5
HTTP_404_THRESHOLD = 20
HIGH_REQUEST_THRESHOLD = 200
SUSPICIOUS_PATHS = ("/.env", "/.git", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/config.php", "/backup.zip", "/shell.php", "/xmlrpc.php", "/.DS_Store")


def _parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        pass
    try:
        return datetime.strptime(value.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _event_time(event):
    value = event.get("timestamp")
    if not value:
        return None
    parsed = _parse_time(value)
    if parsed:
        return parsed
    # Apache timestamp includes a timezone after the clock; parse its core.
    try:
        return datetime.strptime(value[:20], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def _alert(severity, title, ip, detail, **extra):
    result = {"severity": severity, "title": title, "ip": ip, "detail": detail}
    result.update(extra)
    return result


def detect_ssh_brute_force(auth_events, window_minutes=5, threshold=5):
    """Detect a threshold of failed SSH attempts within a sliding time window.

    If timestamps are unavailable, falls back to counting all failures per IP.
    """
    failed = defaultdict(list)
    for event in auth_events:
        if event.get("type") == "failed":
            failed[event["ip"]].append(event)
    alerts = []
    for ip, events in failed.items():
        timed = sorted((( _event_time(e), e) for e in events if _event_time(e)), key=lambda x: x[0])
        best = []
        if timed:
            left = 0
            for right, (stamp, event) in enumerate(timed):
                while left <= right and (stamp - timed[left][0]).total_seconds() > window_minutes * 60:
                    left += 1
                candidate = timed[left:right + 1]
                if len(candidate) > len(best):
                    best = candidate
            count = len(best)
            evidence = [item[1].get("raw", "") for item in best[-5:]]
            first_time = best[0][0].isoformat(sep=" ") if best else None
            last_time = best[-1][0].isoformat(sep=" ") if best else None
        else:
            count = len(events)
            evidence = [e.get("raw", "") for e in events[-5:]]
            first_time = last_time = None
        if count >= threshold:
            severity = "HIGH" if count >= SSH_BRUTE_FORCE_THRESHOLD else "MEDIUM"
            alerts.append(_alert(severity, "SSH Brute Force Detected" if severity == "HIGH" else "Repeated Failed Login Attempts", ip, f"{count} failed logins within {window_minutes} minute(s)" if timed else f"{count} failed logins (timestamps unavailable; whole file counted)", count=count, first_seen=first_time, last_seen=last_time, evidence=evidence, rule="ssh_failed_login_window"))
    return alerts


def detect_success_after_failures(auth_events, window_minutes=10, threshold=3):
    """Flag same-IP successful SSH logins following several failures."""
    by_ip = defaultdict(list)
    for event in auth_events:
        stamp = _event_time(event)
        if stamp:
            by_ip[event["ip"]].append((stamp, event))
    alerts = []
    for ip, entries in by_ip.items():
        entries.sort(key=lambda item: item[0])
        for index, (stamp, event) in enumerate(entries):
            if event.get("type") != "success":
                continue
            preceding = [(t, e) for t, e in entries[:index] if e.get("type") == "failed" and 0 <= (stamp - t).total_seconds() <= window_minutes * 60]
            if len(preceding) >= threshold:
                alerts.append(_alert("HIGH", "Successful Login After Repeated Failures", ip, f"{len(preceding)} failed login(s) followed by successful login for user '{event.get('user', 'unknown')}' within {window_minutes} minute(s)", count=len(preceding), username=event.get("user"), first_seen=preceding[0][0].isoformat(sep=" "), last_seen=stamp.isoformat(sep=" "), evidence=[e.get("raw", "") for _, e in preceding[-5:]] + [event.get("raw", "")], rule="ssh_fail_then_success"))
                break
    return alerts


def detect_invalid_users(auth_events):
    invalid_by_ip = defaultdict(set)
    for e in auth_events:
        if e.get("type") in ("invalid_user", "failed"):
            invalid_by_ip[e["ip"]].add(e["user"])
    return [_alert("MEDIUM", "Multiple Invalid Usernames Attempted", ip, f"Distinct usernames tried: {len(users)}", count=len(users), rule="multiple_invalid_usernames") for ip, users in invalid_by_ip.items() if len(users) >= 5]


def detect_web_scanning(access_events):
    not_found_by_ip = Counter(e["ip"] for e in access_events if e.get("status") == 404)
    return [_alert("MEDIUM", "Repeated 404 Requests", ip, f"404 errors: {count}", count=count, rule="repeated_404") for ip, count in not_found_by_ip.items() if count >= HTTP_404_THRESHOLD]


def detect_suspicious_paths(access_events, threshold=3):
    by_ip = defaultdict(list)
    for event in access_events:
        path = urlsplit(event.get("path", "")).path.lower()
        if any(path == candidate or path.startswith(candidate + "/") for candidate in SUSPICIOUS_PATHS):
            by_ip[event["ip"]].append(event)
    alerts = []
    for ip, events in by_ip.items():
        unique_paths = sorted({urlsplit(e.get("path", "")).path for e in events})
        if len(events) >= threshold or len(unique_paths) >= threshold:
            alerts.append(_alert("HIGH" if len(unique_paths) >= 5 else "MEDIUM", "Suspicious Web Path Probing", ip, f"{len(events)} request(s) to {len(unique_paths)} suspicious path(s): {', '.join(unique_paths[:8])}", count=len(events), paths=unique_paths, evidence=[e.get("raw", "") for e in events[-5:]], rule="suspicious_web_paths"))
    return alerts


def detect_high_frequency_ips(access_events):
    total_by_ip = Counter(e["ip"] for e in access_events)
    return [_alert("LOW", "High Request Frequency", ip, f"Total requests: {count}", count=count, rule="high_request_frequency") for ip, count in total_by_ip.items() if count >= HIGH_REQUEST_THRESHOLD]


def run_all_detections(auth_events=None, access_events=None, window_minutes=5, threshold=5):
    alerts = []
    if auth_events:
        alerts.extend(detect_ssh_brute_force(auth_events, window_minutes=window_minutes, threshold=threshold))
        alerts.extend(detect_success_after_failures(auth_events, window_minutes=max(window_minutes, 10), threshold=3))
        alerts.extend(detect_invalid_users(auth_events))
    if access_events:
        alerts.extend(detect_web_scanning(access_events))
        alerts.extend(detect_suspicious_paths(access_events))
        alerts.extend(detect_high_frequency_ips(access_events))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 3), a["title"], a["ip"]))
    return alerts
