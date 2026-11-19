import os
import tempfile
import unittest
from parser import parse_auth_log, parse_access_log
from detector import run_all_detections, detect_ssh_brute_force, detect_success_after_failures, detect_suspicious_paths
from report import save_json, save_csv

class SentinelLogTests(unittest.TestCase):
    def test_parse_auth_and_timestamp(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("Oct 23 10:00:00 host sshd[1]: Failed password for admin from 203.0.113.9 port 2222 ssh2\n")
            path = f.name
        try:
            events = parse_auth_log(path)
            self.assertEqual(events[0]["type"], "failed")
            self.assertEqual(events[0]["ip"], "203.0.113.9")
            self.assertIsNotNone(events[0]["timestamp"])
        finally:
            os.unlink(path)

    def test_bruteforce_window(self):
        events = [{"type": "failed", "ip": "203.0.113.9", "user": "admin", "timestamp": f"2026-10-23 10:00:0{i}", "raw": f"failed {i}"} for i in range(5)]
        alerts = detect_ssh_brute_force(events, window_minutes=5, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["count"], 5)

    def test_failures_then_success(self):
        events = [{"type": "failed", "ip": "203.0.113.9", "user": "admin", "timestamp": f"2026-10-23 10:00:0{i}", "raw": f"failed {i}"} for i in range(3)]
        events.append({"type": "success", "ip": "203.0.113.9", "user": "admin", "timestamp": "2026-10-23 10:01:00", "raw": "accepted password"})
        alerts = detect_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_suspicious_paths(self):
        events = [{"ip": "198.51.100.7", "path": path, "status": 404, "raw": path} for path in ("/.env", "/.git/config", "/wp-login.php")]
        alerts = detect_suspicious_paths(events)
        self.assertEqual(len(alerts), 1)
        self.assertIn("Suspicious Web Path Probing", alerts[0]["title"])

    def test_parse_access(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write('198.51.100.7 - - [23/Oct/2026:10:15:00 +0000] "GET /.env HTTP/1.1" 404 100\n')
            path = f.name
        try:
            event = parse_access_log(path)[0]
            self.assertEqual(event["path"], "/.env")
            self.assertEqual(event["status"], 404)
        finally:
            os.unlink(path)

    def test_json_csv_export(self):
        alert = {"severity": "HIGH", "title": "Test", "ip": "203.0.113.9", "detail": "proof", "evidence": ["line 1"]}
        with tempfile.TemporaryDirectory() as folder:
            json_path = save_json([alert], os.path.join(folder, "report.json"), ["auth.log"])
            csv_path = save_csv([alert], os.path.join(folder, "report.csv"))
            self.assertTrue(os.path.getsize(json_path) > 0)
            self.assertTrue(os.path.getsize(csv_path) > 0)

if __name__ == "__main__":
    unittest.main()
