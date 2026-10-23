"""仅分析确认后通知；成功发送才记录签名，不发送原始 Heap。"""
import fcntl
import logging
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from .private_config import read_properties


def dingtalk_enabled(runtime):
    config = runtime / "notification.json"
    return not config.exists() or json.loads(config.read_text()).get("dingTalkEnabled", True)


def set_dingtalk_enabled(runtime, enabled):
    """切换发送，不影响报告生成，也不清除凭据或发送去重记录。"""
    runtime.mkdir(exist_ok=True)
    with (runtime / "control.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = runtime / "notification.json"
        saved = {"dingTalkEnabled": bool(enabled)}
        temporary = config.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(saved, output)
        temporary.replace(config)


def notification_token(runtime):
    return read_properties(runtime).get("simpleLeakCanary.dingTalkToken") or None


def at_mobiles(runtime):
    value = read_properties(runtime).get("simpleLeakCanary.atMobiles", "")
    return list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


def reference_traces(directory, signatures, limit_bytes=10000):
    """按新签名提取 Shark 引用链，保留本机完整结果作为超长内容的补充。"""
    analysis = (directory / "analysis.log").read_text()
    chunks = []
    # GC Root 到泄漏对象的路径是 Heap 引用链，不是线程调用栈。
    pattern = r"^Signature: ([0-9a-f]{40})[^\n]*\n(.*?)(?=^Signature: |^={10,}|\Z)"
    for match in re.finditer(pattern, analysis, re.M | re.S):
        if match[1] in signatures:
            chunks.append(f"{len(chunks) + 1}. Signature: *{match[1]}*\n" + match[2].strip())
    text = "\n\n".join(chunks) or "未提取到引用链，请查看本机 analysis.log"
    raw = text.encode("utf-8")
    if len(raw) > limit_bytes:
        text = raw[:limit_bytes].decode("utf-8", errors="ignore") + "\n（引用链已截断，完整内容见本机报告）"
    return text


def notify(event, result, directory, state_file):
    if result.get("status") != "leaks_found":
        return "not_required"
    enabled = dingtalk_enabled(state_file.parent)
    token = notification_token(state_file.parent) if enabled else None
    # 只记录日志时不应用发送去重，保证每次分析报告都可见。
    state = json.loads(state_file.read_text()) if enabled and token and state_file.exists() else []
    # 包名参与去重，不同 App 不互相屏蔽。
    keys = [event["packageName"] + ":" + signature for signature in result["signatures"]]
    fresh = [key for key in keys if key not in state]
    if not fresh:
        return "deduplicated"
    traces = reference_traces(directory, set(result["signatures"]))
    mobiles = at_mobiles(state_file.parent)
    app_name = event.get("appName") or event["packageName"]
    version = " *v" + event["versionName"] + "*" if event.get("versionName") else ""
    text = (f"【注意】{app_name}{version} 检测到内存泄漏\n"
            f"Application leaks: *{result['applicationLeaks']}*\n"
            f"Library leaks: *{result['libraryLeaks']}*\n"
            f"本机报告：{directory.parent}/*{directory.name}*\n\nGC Root 引用链：\n{traces}")
    if mobiles:
        text += "\n" + " ".join("@" + mobile for mobile in mobiles)
    (directory / "notification.txt").write_text(text)
    logging.info("[LeakRadar] notification_report report=%s\n%s", directory, text)
    if not enabled or not token:
        logging.info("[LeakRadar] notification_log_only report=%s", directory)
        return "log_only"
    request = urllib.request.Request(
        "https://oapi.dingtalk.com/robot/send?" + urllib.parse.urlencode({"access_token": token}),
        data=json.dumps({"msgtype": "text", "text": {"content": text},
                         "at": {"atMobiles": mobiles, "isAtAll": False}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    if body.get("errcode") != 0:
        raise RuntimeError("钉钉接口返回失败")
    pending = state_file.with_suffix(".tmp")
    # 超长正文可能省略后续引用链，只对正文实际包含的签名记录发送成功。
    displayed = set(re.findall(r"^\d+\. Signature: \*([0-9a-f]{40})\*", traces, re.M))
    sent_keys = [key for key in fresh if key.split(":", 1)[1] in displayed]
    pending.write_text(json.dumps(sorted(set(state + sent_keys))))
    pending.replace(state_file)
    logging.info("[LeakRadar] notification_sent report=%s", directory)
    return "sent"
