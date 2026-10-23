"""单设备主进程的 HTTP 事件入口和串行分析队列。"""
import hmac
import json
import logging
import os
import queue
import re
import signal
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from . import analyzer, notifier
from .private_config import read_properties

ROOT = Path(__file__).resolve().parents[3]


def validate_event(event, package):
    if not isinstance(event, dict) or event.get("packageName") != package:
        raise ValueError("packageName 与服务配置不匹配")
    for key in ("pid", "timestamp", "retainedCount"):
        if type(event.get(key)) is not int or event[key] <= 0:
            raise ValueError(key + " 必须为正整数")
    if event["timestamp"] > 10**15 or abs(time.time() * 1000 - event["timestamp"]) > 300_000:
        raise ValueError("事件过期或设备时钟偏差超过 5 分钟")
    if not isinstance(event.get("reason"), str) or len(event["reason"]) > 1024:
        raise ValueError("reason 必须是长度不超过 1024 的字符串")
    for key in ("appName", "versionName"):
        if key in event and (not isinstance(event[key], str) or len(event[key]) > 128
                             or "\n" in event[key] or "\r" in event[key]):
            raise ValueError(key + " 必须为不超过 128 字符的单行文本")
    if "versionCode" in event and (type(event["versionCode"]) is not int or event["versionCode"] < 0):
        raise ValueError("versionCode 必须为非负整数")
    if "sessionId" in event and (not isinstance(event["sessionId"], str)
                                  or not 1 <= len(event["sessionId"]) <= 128):
        raise ValueError("sessionId 必须为 1 至 128 字符的字符串")
    # 可选 candidates 仅归档，V1 不把它们当作 Shark 已确认的泄漏。
    return event


class Service:
    def __init__(self):
        self.instance = os.environ["LEAK_INSTANCE"]
        self.package = os.environ["LEAK_PACKAGE"]
        self.serial = analyzer.device(os.getenv("DEVICE_SERIAL"))
        self.token = read_properties(ROOT / ".runtime").get("leakRadar.httpToken", "")
        self.jobs = queue.Queue(maxsize=16)
        self.lock = threading.Lock()
        self.active = set()
        self.last_success = {}
        self.followups = {}
        self.cooldown = float(os.getenv("LEAK_COOLDOWN_SECONDS", "60"))
        self.reports = ROOT / "reports"
        self.reports.mkdir(exist_ok=True)
        threading.Thread(target=self.worker, daemon=True).start()

    def submit(self, event):
        identity = event["pid"]
        with self.lock:
            if identity in self.active:
                # 留一份后续触发，避免 Dump 进行中新出现的候选只收到一次回调就丢失。
                self.followups[identity] = event
                return {"status": "merged", "reason": "已保留一次后续采集"}
            if len(self.active) >= 16:
                raise queue.Full
            job = uuid.uuid4().hex
            self.jobs.put_nowait((job, event))
            self.active.add(identity)
            return {"status": "accepted", "jobId": job}

    def worker(self):
        while True:
            job, event = self.jobs.get()
            try:
                remaining = self.cooldown - (time.monotonic() - self.last_success.get(
                    event["pid"], -float("inf")))
                if remaining > 0:
                    logging.info("[LeakRadar] job_cooling job=%s seconds=%.1f", job, remaining)
                    time.sleep(remaining)
                logging.info("[LeakRadar] job_started job=%s package=%s pid=%s",
                             job, event["packageName"], event["pid"])
                directory = self.reports / job
                directory.mkdir()
                (directory / "event.json").write_text(json.dumps(event, ensure_ascii=False, indent=2))
                result = analyzer.analyze(event, self.serial, directory)
                try:
                    result["notification"] = notifier.notify(
                        event, result, directory, ROOT / ".runtime" / "notified.json")
                except Exception as error:
                    # 不把含认证地址的异常文本写入报告。
                    result["notification"] = "failed"
                    result["notificationErrorType"] = type(error).__name__
                (directory / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
                logging.info("任务 %s：%s notification=%s report=%s", job, result["status"],
                             result["notification"], directory)
                if result["status"] in ("leaks_found", "no_leaks_found"):
                    with self.lock:
                        self.last_success[event["pid"]] = time.monotonic()
            except Exception:
                logging.exception("任务 %s 异常", job)
            finally:
                with self.lock:
                    followup = self.followups.pop(event["pid"], None)
                    if followup is None:
                        self.active.discard(event["pid"])
                    else:
                        self.jobs.put_nowait((uuid.uuid4().hex, followup))
                self.jobs.task_done()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    package = os.environ.get("LEAK_PACKAGE", "")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
        raise SystemExit("请配置有效的 LEAK_PACKAGE 主进程包名")
    host = os.getenv("LEAK_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not read_properties(ROOT / ".runtime").get("leakRadar.httpToken"):
        raise SystemExit("非回环监听必须在 local.properties 配置 leakRadar.httpToken")
    service = Service()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body):
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != "/health":
                self.reply(404, {"error": "not found"})
                return
            self.reply(200, {"service": "leak-detector", "instance": service.instance,
                             "pid": os.getpid(), "root": str(ROOT), "protocolVersion": 1,
                             "packageName": service.package, "deviceSerial": service.serial,
                             "notificationEnabled": bool(notifier.dingtalk_enabled(ROOT / ".runtime") and notifier.notification_token(ROOT / ".runtime"))})

        def do_POST(self):
            if self.path != "/leak-event":
                self.reply(404, {"error": "not found"})
                return
            if service.token and not hmac.compare_digest(
                    self.headers.get("Authorization", ""), "Bearer " + service.token):
                self.reply(401, {"error": "unauthorized"})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise ValueError("请求体必须为 1 至 65536 字节")
                event = validate_event(json.loads(self.rfile.read(size)), service.package)
                result = service.submit(event)
                logging.info("[LeakRadar] event_received package=%s pid=%s retained=%s status=%s job=%s",
                             event["packageName"], event["pid"], event["retainedCount"],
                             result["status"], result.get("jobId", "merged"))
                self.reply(202, result)
            except (ValueError, UnicodeDecodeError) as error:
                logging.warning("[LeakRadar] event_rejected: %s", error)
                self.reply(400, {"error": str(error)})
            except queue.Full:
                self.reply(429, {"error": "queue full"})

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

    server = ThreadingHTTPServer((host, int(os.getenv("LEAK_PORT", "8765"))), Handler)
    def stop(signum, frame):
        analyzer.terminate_commands()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.info("服务启动，设备 %s，包名 %s", service.serial, service.package)
    logging.info("[LeakRadar] notification_config enabled=%s",
                 bool(notifier.dingtalk_enabled(ROOT / ".runtime") and notifier.notification_token(ROOT / ".runtime")))
    server.serve_forever()


if __name__ == "__main__":
    main()
