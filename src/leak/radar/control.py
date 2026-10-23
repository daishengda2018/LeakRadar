"""服务身份校验、生命周期锁和 ADB Reverse；不读取或修改 Gradle。"""
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from .server import ROOT
from . import analyzer, notifier
from .private_config import read_properties, properties_path

RUNTIME = ROOT / ".runtime"
STATE = RUNTIME / "service.json"


def health(port):
    try:
        # 本机生命周期请求不走系统 HTTP 代理。
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/health", timeout=1) as response:
            return json.load(response)
    except (OSError, ValueError, urllib.error.URLError):
        return None


def owned(state, live):
    return bool(live and live.get("service") == "leak-detector"
                and live.get("root") == str(ROOT)
                and live.get("instance") == state.get("instance")
                and live.get("pid") == state.get("pid"))


def reverse(serial, port):
    try:
        analyzer.command(["adb", "-s", serial, "reverse", f"tcp:{port}", f"tcp:{port}"])
        print(f"ADB Reverse 已配置：{serial} tcp:{port}；App 仍需实际请求 /health 验证连通")
    except (OSError, subprocess.SubprocessError) as error:
        print("ADB Reverse 失败，可手动使用局域网模式：" + str(error), file=sys.stderr)


def main():
    action = sys.argv[1]
    if action == "dingtalk":
        if len(sys.argv) != 3 or sys.argv[2] not in ("on", "off"):
            raise SystemExit("用法：dingtalk on / off")
        enabled = sys.argv[2] == "on"
        notifier.set_dingtalk_enabled(RUNTIME, enabled)
        print("钉钉发送已" + ("开启" if enabled else "关闭，仅输出报告日志") + "；下次报告生效")
        return
    if action == "configure-dingtalk":
        if len(sys.argv) > 2:
            if len(sys.argv) != 4 or sys.argv[2] != "--properties":
                raise SystemExit("用法：configure-dingtalk [--properties 本地配置路径]")
            os.environ["LEAK_LOCAL_PROPERTIES"] = sys.argv[3]
        config = read_properties(RUNTIME)
        missing = [key for key in ("simpleLeakCanary.dingTalkToken", "simpleLeakCanary.atMobiles")
                   if not config.get(key)]
        if missing:
            raise SystemExit("local.properties 缺少必填配置：" + ", ".join(missing))
        print("local.properties 钉钉必填配置校验通过；未复制凭据、未发送消息")
        return
    if action == "setup":
        for executable in ("adb", "java"):
            if not shutil.which(executable):
                raise SystemExit("未找到 " + executable + "，请配置 PATH")
            print(executable + "：" + shutil.which(executable))
        print(analyzer.check_shark()[1])
        print("工具检查通过；尚未验证真实 Heap 分析兼容性")
        return
    RUNTIME.mkdir(exist_ok=True)
    with (RUNTIME / "control.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        port = state.get("port", int(os.getenv("LEAK_PORT", "8765")))
        live = health(port)
        if action == "stop":
            if not state:
                print("无本工具启动记录")
                return
            if not owned(state, live):
                raise SystemExit("无法核实服务身份，未发送停止信号；请检查 .runtime 记录和进程")
            os.kill(state["pid"], signal.SIGTERM)
            for _ in range(50):
                if not owned(state, health(port)):
                    STATE.unlink(missing_ok=True)
                    print("服务已停止，报告保留；ADB Reverse 映射保留")
                    return
                time.sleep(.1)
            raise SystemExit("停止超时，请检查服务日志")
        if action != "start":
            raise SystemExit("用法：setup / start / stop")
        requested_port = int(os.getenv("LEAK_PORT", "8765"))
        if live:
            if not owned(state, live):
                raise SystemExit("端口由其他服务占用，拒绝复用")
            if live.get("packageName") != os.getenv("LEAK_PACKAGE") or port != requested_port:
                raise SystemExit("运行配置已变化，请先 stop 再 start")
            print(f"服务已运行，PID {state['pid']}")
            reverse(live["deviceSerial"], port)
            return
        port = requested_port
        analyzer.check_shark()
        serial = analyzer.device(os.getenv("DEVICE_SERIAL"))
        if not os.getenv("LEAK_PACKAGE"):
            raise SystemExit("请配置 LEAK_PACKAGE")
        instance = uuid.uuid4().hex
        env = dict(os.environ, LEAK_INSTANCE=instance, DEVICE_SERIAL=serial)
        with (RUNTIME / "server.log").open("a") as log:
            process = subprocess.Popen([sys.executable, "-m", "leak.radar.server"],
                                       cwd=ROOT, env=env, stdout=log, stderr=log,
                                       start_new_session=True)
        state = {"pid": process.pid, "instance": instance, "port": port}
        STATE.write_text(json.dumps(state))
        for _ in range(100):
            live = health(port)
            if owned(state, live):
                print(f"服务就绪：http://127.0.0.1:{port}，PID {process.pid}")
                reverse(serial, port)
                return
            if process.poll() is not None:
                STATE.unlink(missing_ok=True)
                raise SystemExit("启动失败，见 .runtime/server.log")
            time.sleep(.1)
        process.terminate()
        process.wait(timeout=5)
        STATE.unlink(missing_ok=True)
        raise SystemExit("启动超时，见 .runtime/server.log")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
