"""仅分析确认后通知；成功发送才记录签名，不发送原始 Heap。"""
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path


def notify(event, result, directory, state_file):
    token = os.getenv("LEAK_DINGTALK_TOKEN")
    if not token:
        return "disabled"
    if result.get("status") != "leaks_found":
        return "not_required"
    state = json.loads(state_file.read_text()) if state_file.exists() else []
    # 包名参与去重，不同 App 不互相屏蔽。
    keys = [event["packageName"] + ":" + signature for signature in result["signatures"]]
    fresh = [key for key in keys if key not in state]
    if not fresh:
        return "deduplicated"
    text = (f"内存泄漏分析结果：{event['packageName']} PID {event['pid']}\n"
            f"Application leaks: {result['applicationLeaks']}\n"
            f"Library leaks: {result['libraryLeaks']}\n"
            f"新增签名：{', '.join(fresh[:10])}\n"
            f"本机报告：{directory}\n引用链见 analysis.log")
    request = urllib.request.Request(
        "https://oapi.dingtalk.com/robot/send?" + urllib.parse.urlencode({"access_token": token}),
        data=json.dumps({"msgtype": "text", "text": {"content": text}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    if body.get("errcode") != 0:
        raise RuntimeError("钉钉接口返回失败")
    pending = state_file.with_suffix(".tmp")
    pending.write_text(json.dumps(sorted(set(state + keys))))
    pending.replace(state_file)
    return "sent"
