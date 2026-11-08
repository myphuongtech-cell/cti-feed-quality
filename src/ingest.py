"""Dựng bảng IoC ở mức từng IoC từ manifest và các bản chụp thô.

Đây là nền cho các chỉ số: độ chính xác (mẫu), độ kịp thời (feed nào thấy trước), độ độc nhất, ổn định,
thời gian nằm trong feed (E4a), và so sánh giữa các feed.

Khái niệm (khớp docs/PREREGISTRATION.md mục 3):
- "lần kiểm tra" (check): một dòng manifest thành công (200 hoặc 304) của một feed. Status 304 hoặc 200 không đổi
  nghĩa là nội dung giống bản chụp đã lưu gần nhất, nên mọi IoC trong bản đó vẫn đang có mặt ở lần kiểm tra này.
- IoC "bị gỡ" (delisted): vắng mặt ở >= MISSING_CHECKS lần kiểm tra liên tiếp sau lần cuối có mặt.
  Nếu không thì "cắt cụt" (right_censored), tức còn trong feed đến hết dữ liệu.
- "gap_affected": có khoảng trống thu thập (> GAP_MINUTES giữa hai lần kiểm tra) nằm trong đời IoC, nên thời điểm
  thật sự bị gỡ không đáng tin; khi phân tích E4a nên loại hoặc xử lý riêng.

Dùng:
    python -m src.ingest                  # tất cả feed
    python -m src.ingest --feeds urlhaus cins
Đầu ra (data/processed/):
    ioc_table.csv.gz   một dòng cho mỗi (feed, loại IoC, giá trị)
    feed_daily.csv     thống kê theo feed và ngày UTC
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.feeds import PARSERS, parse_snapshot

ROOT = Path(__file__).resolve().parents[1]
MISSING_CHECKS = 3
GAP_MINUTES = 180


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_manifest(root: Path) -> list[dict]:
    path = root / "data" / "manifest" / "manifest.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def load_operators(root: Path) -> dict[str, str]:
    cfg = root / "config" / "feeds.yaml"
    if not cfg.exists():
        return {}
    import yaml
    data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    return {f["id"]: f.get("operator") for f in data.get("feeds", [])}


def build_checks(rows: list[dict]) -> tuple[list[datetime], list[dict]]:
    """Từ các dòng manifest của một feed: danh sách thời điểm kiểm tra và các bản chụp (kèm khoảng chỉ số kiểm tra)."""
    checks: list[datetime] = []
    snaps: list[dict] = []
    for r in sorted(rows, key=lambda x: x["ts_utc"]):
        if r.get("status") not in (200, 304):
            continue
        ts = parse_ts(r["ts_utc"])
        if r.get("status") == 200 and r.get("stored"):
            snaps.append({"path": r["path"], "a": len(checks), "b": len(checks)})
            checks.append(ts)
        elif snaps:
            checks.append(ts)
            snaps[-1]["b"] = len(checks) - 1
    return checks, snaps


def _s(v):
    return v if isinstance(v, str) and v else None


def build_feed_table(feed_id: str, rows: list[dict], root: Path, operator: str | None,
                     missing_checks: int, gap_minutes: int) -> pd.DataFrame:
    checks, snaps = build_checks(rows)
    if not snaps:
        return pd.DataFrame()
    n_checks = len(checks)
    gap_idx = [k for k in range(1, n_checks) if (checks[k] - checks[k - 1]).total_seconds() / 60 > gap_minutes]

    recs: dict[tuple, dict] = {}
    for si, snap in enumerate(snaps):
        df = parse_snapshot(feed_id, root / Path(snap["path"].replace("\\", "/")))
        df = df.drop_duplicates(subset=["ioc_type", "ioc_value", "hash_type"])
        for row in df.itertuples(index=False):
            ht = row.hash_type if isinstance(row.hash_type, str) else ""
            key = (row.ioc_type, row.ioc_value, ht)
            rec = recs.get(key)
            status = _s(row.status)
            if rec is None:
                rec = {"first": si, "last": si, "n": 1, "src": row.source_first_seen,
                       "malware": _s(row.malware), "threat": _s(row.threat),
                       "status_first": status, "status_last": status,
                       "offline": si if status == "offline" else None}
                recs[key] = rec
            else:
                rec["last"] = si
                rec["n"] += 1
                if status:
                    rec["status_last"] = status
                    if rec["offline"] is None and status == "offline":
                        rec["offline"] = si
                if pd.notna(row.source_first_seen) and (pd.isna(rec["src"]) or row.source_first_seen < rec["src"]):
                    rec["src"] = row.source_first_seen
                rec["malware"] = rec["malware"] or _s(row.malware)
                rec["threat"] = rec["threat"] or _s(row.threat)

    out = []
    for (ioc_type, value, ht), rec in recs.items():
        first_check = snaps[rec["first"]]["a"]
        last_check = snaps[rec["last"]]["b"]
        after = n_checks - 1 - last_check
        delisted = after >= missing_checks
        end_k = min(last_check + (missing_checks if delisted else 0), n_checks - 1)
        gap_affected = any(first_check < g <= end_k for g in gap_idx)
        offline_ts = checks[snaps[rec["offline"]]["a"]] if rec["offline"] is not None else None
        out.append({
            "feed": feed_id, "operator": operator, "ioc_type": ioc_type, "ioc_value": value,
            "hash_type": ht or None,
            "first_check_ts": checks[first_check], "last_check_ts": checks[last_check],
            "n_snapshots_present": rec["n"],
            "delisted": delisted, "right_censored": not delisted, "gap_affected": gap_affected,
            "listing_hours": (checks[last_check] - checks[first_check]).total_seconds() / 3600,
            "source_first_seen": rec["src"], "malware": rec["malware"], "threat": rec["threat"],
            "status_first": rec["status_first"], "status_last": rec["status_last"], "first_offline_ts": offline_ts,
            "present_in_first_snapshot": rec["first"] == 0,
        })
    return pd.DataFrame(out)


def build_daily(rows: list[dict], table: pd.DataFrame) -> pd.DataFrame:
    recs = []
    for r in rows:
        recs.append({"feed": r["feed"], "day": r["ts_utc"][:10], "ok": r.get("status") in (200, 304),
                     "stored": bool(r.get("stored"))})
    base = pd.DataFrame(recs)
    daily = base.groupby(["feed", "day"]).agg(lan_tai=("ok", "size"), thanh_cong=("ok", "sum"),
                                              ban_moi=("stored", "sum")).reset_index()
    if not table.empty:
        t = table.copy()
        t["day"] = t["first_check_ts"].dt.strftime("%Y-%m-%d")
        new = t[~t["present_in_first_snapshot"]].groupby(["feed", "day"]).size().rename("ioc_moi_thay").reset_index()
        daily = daily.merge(new, on=["feed", "day"], how="left").fillna({"ioc_moi_thay": 0})
        daily["ioc_moi_thay"] = daily["ioc_moi_thay"].astype(int)
    return daily


def build_all(root: Path = ROOT, feeds: list[str] | None = None, missing_checks: int = MISSING_CHECKS,
              gap_minutes: int = GAP_MINUTES, verbose: bool = False) -> tuple[pd.DataFrame, pd.DataFrame]:
    rows = load_manifest(root)
    operators = load_operators(root)
    by_feed: dict[str, list[dict]] = {}
    for r in rows:
        by_feed.setdefault(r["feed"], []).append(r)
    tables = []
    for feed_id in sorted(by_feed):
        if feeds and feed_id not in feeds:
            continue
        if feed_id not in PARSERS:  # ví dụ feodo đã loại
            if verbose:
                print(f"{feed_id}: không có parser, bỏ qua")
            continue
        t0 = time.time()
        table = build_feed_table(feed_id, by_feed[feed_id], root, operators.get(feed_id), missing_checks, gap_minutes)
        if verbose:
            if table.empty:
                print(f"{feed_id}: chưa có dữ liệu")
            else:
                print(f"{feed_id}: {len(table):,} IoC | bị gỡ {table['delisted'].mean():.0%} | "
                      f"bị ảnh hưởng bởi khoảng trống {table['gap_affected'].mean():.0%} | {time.time() - t0:.0f}s")
        tables.append(table)
    ioc = pd.concat([t for t in tables if not t.empty], ignore_index=True) if tables else pd.DataFrame()
    daily = build_daily([r for r in rows if r["feed"] in PARSERS and (not feeds or r["feed"] in feeds)], ioc)
    return ioc, daily


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feeds", nargs="*", help="chỉ xử lý các feed id này")
    ap.add_argument("--out", default=str(ROOT / "data" / "processed"))
    args = ap.parse_args()
    ioc, daily = build_all(ROOT, args.feeds, verbose=True)
    if ioc.empty:
        print("Chưa có dữ liệu để dựng bảng.")
        return
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ioc.to_csv(out / "ioc_table.csv.gz", index=False, compression="gzip")
    daily.to_csv(out / "feed_daily.csv", index=False)
    print(f"\nĐã ghi {len(ioc):,} dòng -> {out / 'ioc_table.csv.gz'}")
    print(f"Đã ghi thống kê theo ngày -> {out / 'feed_daily.csv'}")
    print("\n" + daily.to_string(index=False))


if __name__ == "__main__":
    main()
