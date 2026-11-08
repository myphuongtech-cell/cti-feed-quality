"""Chuẩn bị danh sách Tranco top-N làm danh sách chống báo động giả.

Tải file danh sách mới nhất từ trang chủ https://tranco-list.eu (nút tải về, file dạng top-1m.csv.zip hoặc .csv),
rồi chạy:
    python -m src.tranco đường/dẫn/top-1m.csv.zip --top 10000

Kết quả: data/external/tranco_top10k.csv (rank,domain) và tranco_top10k.meta.json (ngày tải, SHA-256 file gốc),
để báo cáo ghi rõ "snapshot Tranco ngày ...".
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "external"


def read_rows(path: Path, top: int) -> list[list[str]]:
    raw = path.read_bytes()
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
            text = z.read(name).decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    rows = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[0].strip().isdigit():
            rows.append([row[0].strip(), row[1].strip().lower()])
        if len(rows) >= top:
            break
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("--top", type=int, default=10000)
    args = ap.parse_args()
    src = Path(args.source)
    rows = read_rows(src, args.top)
    if not rows:
        print("Không đọc được dòng nào (cần định dạng: rank,domain).")
        return
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "tranco_top10k.csv", "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(rows)
    meta = {"source_file": src.name, "sha256": hashlib.sha256(src.read_bytes()).hexdigest(), "top": len(rows),
            "prepared_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    (OUT / "tranco_top10k.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Đã ghi {len(rows)} domain -> {OUT / 'tranco_top10k.csv'}")


if __name__ == "__main__":
    main()
