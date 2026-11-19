"""Parse Linux auth and Apache/Nginx access logs into normalized events."""
import re
from datetime import datetime
from utils import read_lines

AUTH_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+")
AUTH_SUCCESS_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+")
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
AUTH_TS_RE = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})")
ACCESS_LOG_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)')


def _auth_timestamp(line):
    m = AUTH_TS_RE.search(line)
    if not m:
        return None
    now = datetime.now()
    try:
        # Syslog auth logs omit the year. Use the current year; detections use
        # event ordering and time differences, so year ambiguity is documented.
        return datetime.strptime(f"{now.year} {m.group('month')} {m.group('day')} {m.group('clock')}", "%Y %b %d %H:%M:%S").isoformat(sep=" ")
    except ValueError:
        return None


def parse_auth_log(filepath: str):
    events = []
    for line in read_lines(filepath):
        for event_type, pattern in (("failed", AUTH_FAILED_RE), ("success", AUTH_SUCCESS_RE), ("invalid_user", INVALID_USER_RE)):
            m = pattern.search(line)
            if m:
                events.append({"type": event_type, "user": m.group("user"), "ip": m.group("ip"), "timestamp": _auth_timestamp(line), "raw": line})
                break
    return events


def parse_access_log(filepath: str):
    events = []
    for line in read_lines(filepath):
        m = ACCESS_LOG_RE.search(line)
        if m:
            events.append({"ip": m.group("ip"), "timestamp": m.group("timestamp"), "method": m.group("method"), "path": m.group("path"), "status": int(m.group("status")), "size": m.group("size"), "raw": line})
    return events
