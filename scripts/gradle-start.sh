#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Finder 启动的 IDE 可能没有 Homebrew PATH，优先使用现有环境。
if ! command -v uv >/dev/null 2>&1; then
    for prefix in /opt/homebrew/bin /usr/local/bin; do
        if [[ -x "$prefix/uv" ]]; then
            export PATH="$prefix:$PATH"
            break
        fi
    done
fi
if ! command -v uv >/dev/null 2>&1; then
    echo '未安装或找不到 uv；请执行：brew install uv' >&2
    exit 1
fi
if ! command -v adb >/dev/null 2>&1; then
    sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
    if [[ -x "$sdk_root/platform-tools/adb" ]]; then
        export PATH="$sdk_root/platform-tools:$PATH"
    fi
fi
exec ./scripts/start.sh
