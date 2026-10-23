"""Shark 2.14 的采集、文本契约解析及原始证据保存。"""
import logging
import os
import signal
import threading
import json
import re
import shutil
import subprocess
from pathlib import Path

VERSION = "2.14"
_RUNNING = set()
_RUNNING_LOCK = threading.Lock()


def terminate_commands():
    with _RUNNING_LOCK:
        for process in list(_RUNNING):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)



def command(args, cwd=None, timeout=30):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=True).stdout


def check_shark():
    executable = shutil.which("shark-cli")
    if not executable:
        raise RuntimeError("未安装 shark-cli；请执行：brew install leakcanary-shark")
    version = command([executable, "--version"]).strip()
    if not re.search(r"(?<![\d.])2\.14(?![\d.])", version):
        raise RuntimeError("仅支持 Shark CLI 2.14，实际版本：" + version)
    return executable, version


def device(serial):
    devices = [line.split()[0] for line in command(["adb", "devices"]).splitlines()[1:]
               if len(line.split()) == 2 and line.split()[1] == "device"]
    if serial:
        if serial not in devices:
            raise RuntimeError("指定设备不可用")
        return serial
    if len(devices) != 1:
        raise RuntimeError("需要恰好一台可用设备，或配置 DEVICE_SERIAL")
    return devices[0]


def verify_process(serial, event):
    # V1 只允许配置包的主进程，PID 必须与事件完全一致。
    pids = command(["adb", "-s", serial, "shell", "pidof", event["packageName"]]).split()
    if pids != [str(event["pid"])]:
        raise RuntimeError("目标进程已退出、重启或 PID 不匹配")


def parse_analysis(text):
    if "HEAP ANALYSIS FAILED" in text:
        raise RuntimeError("Shark 报告分析失败")
    if "HEAP ANALYSIS RESULT" not in text:
        raise RuntimeError("缺少 Shark 分析成功标记")
    counts = []
    for label in ("APPLICATION LEAKS", "LIBRARY LEAKS", "UNREACHABLE OBJECTS"):
        matches = re.findall(r"^([0-9]+) " + label + r"\s*$", text, re.M)
        if len(matches) != 1:
            raise RuntimeError("无法识别 Shark 结果段：" + label)
        counts.append(int(matches[0]))
    if not re.search(r"^Analysis duration: [0-9]+ ms$", text, re.M):
        raise RuntimeError("Shark 输出不完整")
    signatures = re.findall(r"^Signature: ([0-9a-f]{40})\s*$", text, re.M)
    if len(signatures) != sum(counts[:2]):
        raise RuntimeError("泄漏数量与签名数量不一致")
    return {"status": "leaks_found" if sum(counts[:2]) else "no_leaks_found",
            "applicationLeaks": counts[0], "libraryLeaks": counts[1],
            "unreachableObjects": counts[2], "signatures": sorted(set(signatures))}


def run_logged(args, directory, name, timeout):
    # 文件直接接收子进程输出，避免 HPROF 分析的大量日志占用 Python 内存。
    with (directory / name).open("w") as output:
        process = subprocess.Popen(args, cwd=directory, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with _RUNNING_LOCK:
            _RUNNING.add(process)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(process)
    if process.returncode:
        raise RuntimeError(name + " 命令失败，详见原始日志")


def analyze(event, serial, directory):
    result = {"status": "capture_failed"}
    try:
        shark, version = check_shark()
        result["sharkVersion"] = version
        verify_process(serial, event)
        logging.info("[LeakRadar] capture_started device=%s pid=%s report=%s",
                     serial, event["pid"], directory)
        run_logged([shark, "--device", serial, "--process", event["packageName"],
                    "dump-process"], directory, "capture.log", 120)
        heaps = list(directory.glob("*.hprof"))
        if len(heaps) != 1 or heaps[0].stat().st_size == 0:
            raise RuntimeError("采集未产生唯一有效 HPROF")
        # CLI 按名称重新解析 PID；采集前后核验，变更则不采信结果。
        verify_process(serial, event)
        logging.info("[LeakRadar] capture_finished bytes=%s", heaps[0].stat().st_size)
        result["status"] = "analysis_failed"
        logging.info("[LeakRadar] analysis_started report=%s", directory)
        run_logged([shark, "--hprof", str(heaps[0]), "analyze"], directory,
                   "analysis.log", 600)
        result.update(parse_analysis((directory / "analysis.log").read_text()))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
        logging.warning("[LeakRadar] job_failed stage=%s error=%s report=%s",
                        result["status"], error, directory)
    (directory / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return result
