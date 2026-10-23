#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "请安装 uv" >&2; exit 1; }
uv sync --locked
exec uv run --locked python -m leak.radar.control setup
