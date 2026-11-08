"""Ground truth theo docs/PREREGISTRATION.md mục 3.

Các bước:
1. Dựng "khung lấy mẫu" từ data/processed/ioc_table.csv.gz (xem src.ingest):
   - bỏ IP không công khai, bỏ hàng md5 của MalwareBazaar (trùng mẫu với sha256),
   - gắn nhãn GT-2: IoC xuất hiện ở >= 2 TỔ CHỨC vận hành khác nhau (đếm theo operator, không theo feed),
   - gắn cờ báo động giả: domain hoặc host của URL nằm trong Tranco top-N (khớp chính xác).
2. Rút mẫu phân tầng ngẫu nhiên theo feed x loại IoC: tối đa PER_STRATUM IoC mỗi tầng, seed 42,
   chỉ lấy IoC đã xuất hiện ít nhất MIN_AGE_HOURS giờ (để các engine kịp nhận diện).
3. Ghi data/processed/gt_sample.csv. Mẫu chỉ được rút MỘT LẦN (cần --force để rút lại).
   Ghi kèm kích thước mỗi tầng để sau này có thể tính trọng số và khoảng tin cậy.

Dùng:
    python -m src.groundtruth --asof 2026-10-26T00:00:00Z --tranco data/external/tranco_top10k.csv
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from src.extract import normalize_url

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"
SEED = 42
PER_STRATUM = 100
MIN_AGE_HOURS = 48


def load_tranco(path: str | Path | None, top: int = 10000) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    out: set[str] = set()
    with open(path, encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.reader(f)):
            if i >= top:
                break
            if len(row) >= 2:
                out.add(row[1].strip().lower())
    return out


def _host(ioc_type: str, value: str) -> str | None:
    if ioc_type == "domain":
        return value.lower()
    if ioc_type == "url":
        try:
            host = urlsplit(value).hostname
        except ValueError:
            return None
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return None  # host là IP, không phải domain
        except ValueError:
            return host.lower()
    return None


def _is_global_ip(v: str) -> bool:
    try:
        return ipaddress.ip_address(v).is_global
    except ValueError:
        return False


def build_frame(ioc: pd.DataFrame, tranco: set[str] | None = None) -> pd.DataFrame:
    """Khung lấy mẫu: lọc, gắn GT-2 và cờ báo động giả."""
    df = ioc.copy()
    for col in ("first_check_ts", "last_check_ts"):
        df[col] = pd.to_datetime(df[col], utc=True)
    df["hash_type"] = df["hash_type"].fillna("")

    # loại md5 của MalwareBazaar (cùng mẫu với sha256), loại IP không công khai
    df = df[~((df["feed"] == "malwarebazaar") & (df["hash_type"] == "md5"))]
    df = df[~((df["ioc_type"] == "ip") & ~df["ioc_value"].map(_is_global_ip))]

    # khóa so sánh giữa các feed
    df["key_value"] = [normalize_url(v) if t == "url" else v for t, v in zip(df["ioc_type"], df["ioc_value"])]
    group = ["ioc_type", "key_value", "hash_type"]
    df["operators_count"] = df.groupby(group)["operator"].transform("nunique")
    df["gt2"] = df["operators_count"] >= 2

    tranco = tranco or set()
    hosts = [_host(t, v) for t, v in zip(df["ioc_type"], df["ioc_value"])]
    df["fp_tranco"] = [h in tranco if h else False for h in hosts]
    return df.reset_index(drop=True)


def draw_sample(frame: pd.DataFrame, asof: datetime, per_stratum: int = PER_STRATUM,
                min_age_hours: int = MIN_AGE_HOURS, seed: int = SEED) -> pd.DataFrame:
    cutoff = pd.Timestamp(asof - timedelta(hours=min_age_hours))
    eligible = frame[frame["first_check_ts"] <= cutoff].copy()
    eligible["stratum"] = eligible["feed"] + "|" + eligible["ioc_type"]
    eligible = eligible.sort_values(["stratum", "key_value", "hash_type"]).reset_index(drop=True)
    parts = []
    for stratum, g in eligible.groupby("stratum", sort=True):
        n = min(per_stratum, len(g))
        s = g.sample(n=n, random_state=seed).copy()
        s["stratum_size"] = len(g)
        s["n_sampled"] = n
        parts.append(s)
    if not parts:
        return pd.DataFrame()
    out = pd.concat(parts, ignore_index=True)
    out["drawn_asof"] = asof.strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


def parse_asof(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--asof", required=True, help="thời điểm rút mẫu, ví dụ 2026-10-26T00:00:00Z")
    ap.add_argument("--tranco", default=str(ROOT / "data" / "external" / "tranco_top10k.csv"))
    ap.add_argument("--per-stratum", type=int, default=PER_STRATUM)
    ap.add_argument("--force", action="store_true", help="cho phép rút lại và ghi đè mẫu cũ")
    args = ap.parse_args()

    out_path = PROCESSED / "gt_sample.csv"
    if out_path.exists() and not args.force:
        print(f"{out_path} đã tồn tại. Mẫu chỉ rút một lần theo đề cương; dùng --force nếu thật sự cần (và ghi vào DEVIATIONS).")
        return
    table = PROCESSED / "ioc_table.csv.gz"
    if not table.exists():
        print("Chưa có ioc_table.csv.gz. Chạy trước: python -m src.ingest")
        return
    tranco = load_tranco(args.tranco)
    if not tranco:
        print("CẢNH BÁO: không đọc được danh sách Tranco; cờ báo động giả sẽ trống.")
    frame = build_frame(pd.read_csv(table), tranco)
    sample = draw_sample(frame, parse_asof(args.asof), args.per_stratum)
    if sample.empty:
        print("Không có IoC nào đủ tuổi để lấy mẫu.")
        return
    PROCESSED.mkdir(parents=True, exist_ok=True)
    sample.to_csv(out_path, index=False)
    summary = sample.groupby("stratum").agg(kich_thuoc_tang=("stratum_size", "first"), da_lay=("n_sampled", "first"),
                                            gt2=("gt2", "sum"), fp_tranco=("fp_tranco", "sum"))
    print(summary.to_string())
    print(f"\nTổng {len(sample)} IoC -> {out_path}")


if __name__ == "__main__":
    main()
