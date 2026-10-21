#!/usr/bin/env bash
# Dùng cho cron (Linux/macOS/VPS). Chạy mỗi giờ.
cd "$(dirname "$0")/.." || exit 1
source .venv/bin/activate
python -m src.collector >> logs/cron.log 2>&1
