"""Báo cáo thu thập theo ngày, đọc từ data/manifest/manifest.jsonl.

    python -m src.report                  # tất cả các ngày
    python -m src.report --date 2026-10-21
    python -m src.report --gap 90         # coi là "khoảng trống" nếu hai lần tải cách nhau quá 90 phút

Thời gian hiển thị theo UTC (giờ Việt Nam = UTC + 7).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "manifest" / "manifest.jsonl"
RAW = ROOT / "data" / "raw"


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_rows() -> list[dict]:
    if not MANIFEST.exists():
        return []
    rows = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return str(n)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", help="chỉ xem một ngày UTC, dạng YYYY-MM-DD")
    ap.add_argument("--gap", type=int, default=90, help="ngưỡng khoảng trống (phút), mặc định 90")
    args = ap.parse_args()

    rows = load_rows()
    if not rows:
        print("Chưa có dữ liệu trong manifest. Collector đã chạy chưa?")
        return
    now = datetime.now(timezone.utc)
    for r in rows:
        r["_t"] = parse_ts(r["ts_utc"])
    if args.date:
        rows = [r for r in rows if r["ts_utc"].startswith(args.date)]
        if not rows:
            print(f"Không có lần tải nào trong ngày {args.date} (UTC).")
            return

    # 1) Theo ngày x feed
    table: dict[tuple[str, str], dict] = defaultdict(lambda: {"n": 0, "ok": 0, "err": 0, "new": 0, "bytes": 0})
    for r in rows:
        key = (r["ts_utc"][:10], r["feed"])
        t = table[key]
        t["n"] += 1
        if r["status"] in (200, 304):
            t["ok"] += 1
        else:
            t["err"] += 1
        if r.get("stored"):
            t["new"] += 1
            t["bytes"] += r.get("bytes", 0)

    print("\n=== Theo ngày (UTC) và feed ===")
    print(f"{'ngày':10} {'feed':15} {'lượt':>5} {'thành công':>10} {'lỗi':>4} {'bản mới':>8} {'dung lượng mới':>15}")
    for (day, feed), t in sorted(table.items()):
        print(f"{day:10} {feed:15} {t['n']:>5} {t['ok']:>10} {t['err']:>4} {t['new']:>8} {fmt_bytes(t['bytes']):>15}")

    # 2) Lần tải cuối
    print("\n=== Lần tải gần nhất của từng feed ===")
    last: dict[str, dict] = {}
    for r in rows:
        last[r["feed"]] = r
    for feed, r in sorted(last.items()):
        ago = int((now - r["_t"]).total_seconds() // 60)
        flag = "  <-- QUÁ LÂU, collector có thể đã dừng" if ago > 120 else ""
        print(f"{feed:15} {r['ts_utc']}  ({ago} phút trước)  status={r['status']}{flag}")

    # 3) Khoảng trống
    print(f"\n=== Khoảng trống giữa hai lần tải liên tiếp (> {args.gap} phút) ===")
    by_feed: dict[str, list[datetime]] = defaultdict(list)
    for r in rows:
        by_feed[r["feed"]].append(r["_t"])
    found = False
    for feed, ts in sorted(by_feed.items()):
        ts.sort()
        for a, b in zip(ts, ts[1:]):
            minutes = (b - a).total_seconds() / 60
            if minutes > args.gap:
                found = True
                print(f"{feed:15} {a:%Y-%m-%d %H:%M} -> {b:%Y-%m-%d %H:%M} UTC  ({minutes / 60:.1f} giờ)")
    if not found:
        print("Không có.")

    # 4) Lỗi gần đây
    errs = [r for r in rows if r["status"] not in (200, 304)]
    if errs:
        print("\n=== 5 lỗi gần nhất ===")
        for r in errs[-5:]:
            print(f"{r['ts_utc']} {r['feed']:15} status={r['status']} lỗi={r.get('error')}")

    # 5) Dung lượng
    total = sum(p.stat().st_size for p in RAW.rglob("*.gz")) if RAW.exists() else 0
    files = sum(1 for _ in RAW.rglob("*.gz")) if RAW.exists() else 0
    print(f"\nDữ liệu thô: {files} file, {fmt_bytes(total)} trong data/raw")


if __name__ == "__main__":
    main()
