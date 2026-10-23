"""隐私配置只读 local.properties；不写入运行状态或日志。"""
import os
from pathlib import Path


def properties_path(runtime):
    explicit = os.getenv("LEAK_LOCAL_PROPERTIES")
    return Path(explicit).expanduser() if explicit else runtime.parent.parent / "local.properties"


def read_properties(runtime):
    path = properties_path(runtime)
    if not path.is_file():
        return {}
    allowed = {"simpleLeakCanary.dingTalkToken", "simpleLeakCanary.atMobiles", "leakRadar.httpToken"}
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        if separator and key.strip() in allowed:
            result[key.strip()] = value.strip()
    return result
