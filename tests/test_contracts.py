import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from leak.radar import analyzer
from leak.radar.server import Service, validate_event
from leak.radar.control import owned


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
        from leak.radar.control import ROOT
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
        from leak.radar.notifier import notify
        event = {"packageName": "com.example.app", "pid": 1,
                 "appName": "MrcdOpt", "versionName": "1.0", "versionCode": 1}
        result = analyzer.parse_analysis(report(1))
        with tempfile.TemporaryDirectory() as temp, patch.dict(
                "os.environ", {"LEAK_LOCAL_PROPERTIES": str(Path(temp) / "local.properties")}):
            (Path(temp) / "local.properties").write_text(
                "simpleLeakCanary.dingTalkToken=fixture-only\nsimpleLeakCanary.atMobiles=13800000000\n")
            state = Path(temp) / "notified.json"
            (Path(temp) / "analysis.log").write_text(
                report(1).replace("Analysis duration:", "GC Root: Global variable\n└→ com.example.LeakedActivity\nAnalysis duration:"))
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"errcode":1}')):
                with self.assertRaises(RuntimeError):
                    notify(event, result, Path(temp), state)
            self.assertFalse(state.exists())
            with self.assertLogs(level="INFO") as logs, patch("urllib.request.urlopen", return_value=io.BytesIO(b'{"errcode":0}')) as request:
                self.assertEqual("sent", notify(event, result, Path(temp), state))
                content = json.loads(request.call_args.args[0].data)["text"]["content"]
                self.assertIn("【注意】MrcdOpt *v1.0* 检测到内存泄漏", content)
                self.assertEqual(content, (Path(temp) / "notification.txt").read_text())
                self.assertIn("GC Root: Global variable", content)
                self.assertIn("com.example.LeakedActivity", content)
                self.assertTrue(any("notification_report" in message and content in message for message in logs.output))
                self.assertTrue(any("notification_sent" in message for message in logs.output))
                self.assertTrue(all("fixture-only" not in message for message in logs.output))
                self.assertIn("@13800000000", content)
                self.assertEqual(["13800000000"], json.loads(request.call_args.args[0].data)["at"]["atMobiles"])
            with patch("urllib.request.urlopen") as request:
                self.assertEqual("deduplicated", notify(event, result, Path(temp), state))
                request.assert_not_called()

    def test_truncated_notification_does_not_deduplicate_omitted_signature(self):
        import io
        from leak.radar.notifier import notify
        first, second = "a" * 40, "b" * 40
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            state = directory / "notified.json"
            properties = directory / "local.properties"
            properties.write_text("simpleLeakCanary.dingTalkToken=fixture-only\n")
            (directory / "analysis.log").write_text(
                f"Signature: {first}\n" + "x" * 11000 +
                f"\nSignature: {second}\nGC Root: second-root\n")
            event = {"packageName": "com.example.app", "pid": 1}
            result = {"status": "leaks_found", "applicationLeaks": 2,
                      "libraryLeaks": 0, "signatures": [first, second]}
            with patch.dict("os.environ", {"LEAK_LOCAL_PROPERTIES": str(properties)}), patch(
                    "urllib.request.urlopen", side_effect=lambda *args, **kwargs: io.BytesIO(b'{"errcode":0}')):
                self.assertEqual("sent", notify(event, result, directory, state))
                self.assertEqual([event["packageName"] + ":" + first], json.loads(state.read_text()))


    def test_new_signature_notification_contains_all_current_traces(self):
        import io
        from leak.radar.notifier import notify
        first, second = "a" * 40, "b" * 40
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            state = directory / "notified.json"
            properties = directory / "local.properties"
            properties.write_text("simpleLeakCanary.dingTalkToken=fixture-only\n")
            event = {"packageName": "com.example.app", "pid": 1}
            state.write_text(json.dumps([event["packageName"] + ":" + first]))
            (directory / "analysis.log").write_text(
                f"Signature: {first}\nGC Root: first-root\n"
                f"Signature: {second}\nGC Root: second-root\n")
            result = {"status": "leaks_found", "applicationLeaks": 2,
                      "libraryLeaks": 0, "signatures": [first, second]}
            with patch.dict("os.environ", {"LEAK_LOCAL_PROPERTIES": str(properties)}), patch(
                    "urllib.request.urlopen", side_effect=lambda *args, **kwargs: io.BytesIO(b'{"errcode":0}')) as request:
                self.assertEqual("sent", notify(event, result, directory, state))
                text = (directory / "notification.txt").read_text()
                self.assertIn("Application leaks: *2*", text)
                self.assertIn(f"1. Signature: *{first}*", text)
                self.assertIn(f"2. Signature: *{second}*", text)
                self.assertEqual("deduplicated", notify(event, result, directory, state))
                self.assertEqual(1, request.call_count)

    def test_private_properties_are_read_live_and_legacy_credentials_are_ignored(self):
        from leak.radar.notifier import notification_token, at_mobiles
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "leak-radar" / ".runtime"
            runtime.mkdir(parents=True)
            properties = Path(temp) / "local.properties"
            (runtime / "notification.json").write_text(json.dumps({"dingTalkEnabled": False}))
            with patch.dict("os.environ", {"LEAK_LOCAL_PROPERTIES": str(properties),
                                           "LEAK_DINGTALK_TOKEN": "fixture-ignored"}):
                self.assertIsNone(notification_token(runtime))
                properties.write_text("simpleLeakCanary.dingTalkToken=fixture-property\n"
                                      "simpleLeakCanary.atMobiles=13800000000,13800000000\n")
                self.assertEqual("fixture-property", notification_token(runtime))
                self.assertEqual(["13800000000"], at_mobiles(runtime))
                properties.write_text("simpleLeakCanary.dingTalkToken=fixture-changed\n")
                self.assertEqual("fixture-changed", notification_token(runtime))
                self.assertEqual([], at_mobiles(runtime))
                self.assertEqual({"dingTalkEnabled": False}, json.loads(
                    (runtime / "notification.json").read_text()))

    def test_disabled_dingtalk_still_logs_reports_without_network_or_dedup_changes(self):
        from leak.radar.notifier import notify, set_dingtalk_enabled, dingtalk_enabled
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "notification.json").write_text(json.dumps({"dingTalkEnabled": True}))
            set_dingtalk_enabled(directory, False)
            self.assertFalse(dingtalk_enabled(directory))
            self.assertEqual({"dingTalkEnabled": False}, json.loads((directory / "notification.json").read_text()))
            result = analyzer.parse_analysis(report(1))
            event = {"packageName": "com.example.app", "pid": 1}
            state = directory / "notified.json"
            state.write_text(json.dumps([event["packageName"] + ":" + result["signatures"][0]]))
            original = state.read_text()
            (directory / "analysis.log").write_text(report(1) + "GC Root: fixture")
            with self.assertLogs(level="INFO") as logs, patch("urllib.request.urlopen") as request:
                self.assertEqual("log_only", notify(event, result, directory, state))
                self.assertEqual("log_only", notify(event, result, directory, state))
                request.assert_not_called()
            self.assertTrue((directory / "notification.txt").exists())
            self.assertEqual(original, state.read_text())
            self.assertEqual(2, sum("notification_report" in message for message in logs.output))
            set_dingtalk_enabled(directory, True)
            self.assertTrue(dingtalk_enabled(directory))

    def test_reference_traces_filters_signatures_and_limits_utf8_size(self):
        from leak.radar.notifier import reference_traces
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            first, second = "a" * 40, "b" * 40
            (directory / "analysis.log").write_text(
                f"Signature: {first}\nGC Root: old-root\n===========\n"
                f"Signature: {second}\nGC Root: new-root\n└→ 泄漏对象\n" + "引用" * 200)
            text = reference_traces(directory, {second})
            self.assertIn("new-root", text)
            self.assertNotIn("old-root", text)
            limited = reference_traces(directory, {second}, limit_bytes=100)
            self.assertIn("已截断", limited)
            self.assertLess(len(limited.encode()), 300)

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
