import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from leak_detector import analyzer
from leak_detector.server import Service, validate_event
from leak_detector.control import owned


def report(app=0, library=0):
    return ("HEAP ANALYSIS RESULT\n" + f"{app} APPLICATION LEAKS\n"
            + f"{library} LIBRARY LEAKS\n0 UNREACHABLE OBJECTS\n"
            + "".join("Signature: " + f"{i:040x}" + "\n" for i in range(app + library))
            + "Analysis duration: 123 ms\n")


class Contracts(unittest.TestCase):
    def test_parse_success_and_signatures(self):
        self.assertEqual("no_leaks_found", analyzer.parse_analysis(report())["status"])
        parsed = analyzer.parse_analysis(report(1, 1))
        self.assertEqual("leaks_found", parsed["status"])
        self.assertEqual(2, len(parsed["signatures"]))

    def test_exit_zero_or_partial_output_is_not_success(self):
        for text in ("", "HEAP ANALYSIS FAILED", report(1).replace("Signature:", "Unknown:"),
                     report().replace("Analysis duration: 123 ms", ""), report() + report()):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                analyzer.parse_analysis(text)

    def test_validation_rejects_wrong_package_types_and_old_event(self):
        event = {"packageName": "com.example.app", "pid": 1,
                 "timestamp": int(time.time() * 1000), "retainedCount": 1, "reason": "destroyed"}
        self.assertEqual(event, validate_event(event, "com.example.app"))
        for changes in ({"pid": True}, {"timestamp": 1}, {"packageName": "other"},
                        {"retainedCount": 0}, {"reason": []}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_event(dict(event, **changes), "com.example.app")

    def test_process_restart_is_rejected(self):
        with patch.object(analyzer, "command", return_value="2\n"), self.assertRaises(RuntimeError):
            analyzer.verify_process("device", {"packageName": "com.example.app", "pid": 1})

    def test_service_identity_requires_instance_pid_and_root(self):
        from leak_detector.control import ROOT
        state = {"instance": "ours", "pid": 1}
        live = {"service": "leak-detector", "instance": "ours", "pid": 1, "root": str(ROOT)}
        self.assertTrue(owned(state, live))
        self.assertFalse(owned(state, dict(live, instance="other")))
        self.assertFalse(owned(state, dict(live, pid=2)))

    def test_failed_dump_is_saved_and_never_called_no_leaks(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with patch.object(analyzer, "check_shark", return_value=("shark-cli", "2.14")), \
                 patch.object(analyzer, "verify_process"), \
                 patch.object(analyzer, "run_logged", side_effect=RuntimeError("capture failed")):
                result = analyzer.analyze({"packageName": "com.example.app", "pid": 1}, "device", directory)
            self.assertEqual("capture_failed", result["status"])
            self.assertEqual(result, json.loads((directory / "result.json").read_text()))

    def test_analysis_failure_separated_from_capture_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            def fake_run(args, directory, name, timeout):
                if name == "capture.log":
                    (directory / "heap.hprof").write_bytes(b"fake fixture")
                else:
                    (directory / name).write_text("HEAP ANALYSIS FAILED")
            with patch.object(analyzer, "check_shark", return_value=("shark-cli", "2.14")), \
                 patch.object(analyzer, "verify_process"), patch.object(analyzer, "run_logged", fake_run):
                result = analyzer.analyze({"packageName": "com.example.app", "pid": 1}, "device", directory)
            self.assertEqual("analysis_failed", result["status"])

    def test_notification_records_signature_only_after_success(self):
        import io
        from leak_detector.notifier import notify
        event = {"packageName": "com.example.app", "pid": 1}
        result = analyzer.parse_analysis(report(1))
        with tempfile.TemporaryDirectory() as temp, patch.dict(
                "os.environ", {"LEAK_DINGTALK_TOKEN": "fixture-only"}):
            state = Path(temp) / "notified.json"
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"errcode":1}')):
                with self.assertRaises(RuntimeError):
                    notify(event, result, Path(temp), state)
            self.assertFalse(state.exists())
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"errcode":0}')):
                self.assertEqual("sent", notify(event, result, Path(temp), state))
            with patch("urllib.request.urlopen") as request:
                self.assertEqual("deduplicated", notify(event, result, Path(temp), state))
                request.assert_not_called()

    def test_queue_merges_active_process_and_cooldown(self):
        import queue
        import threading
        service = Service.__new__(Service)
        service.jobs = queue.Queue(maxsize=1)
        service.lock = threading.Lock()
        service.active = set()
        service.followups = {}
        service.last_success = {}
        service.cooldown = 60
        event = {"pid": 1}
        self.assertEqual("accepted", service.submit(event)["status"])
        self.assertEqual("merged", service.submit(event)["status"])
        self.assertEqual(event, service.followups[1])
        service.jobs.get_nowait()
        service.active.clear()
        service.last_success[1] = time.monotonic()
        self.assertEqual("accepted", service.submit(event)["status"])


if __name__ == "__main__":
    unittest.main()
