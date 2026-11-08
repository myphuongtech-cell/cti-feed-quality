"""Mô hình chấm điểm độ tin cậy của feed theo docs/PREREGISTRATION.md mục 4.

S(f,t) = 0,2*A + 0,2*T + 0,2*U + 0,2*C + 0,2*St, tính riêng cho từng (feed f, loại IoC t).

A  Độ chính xác: tỷ lệ IoC trong mẫu được xác nhận độc hại (GT-1 hoặc GT-2). Mẫu số gồm IoC đã tra được VirusTotal
   hoặc đạt GT-2. 404 (not_found) tính là CHƯA xác nhận (thận trọng); A_resolved loại chúng ra để so sánh.
T  Độ kịp thời: chỉ trên IoC xuất hiện ở >= 2 feed và không có sẵn từ bản chụp đầu của feed nào (để "lần đầu thấy"
   là thật). T = tỷ lệ các IoC đó mà feed f là feed thấy trước (đồng hạng thì chia đều). Ít hơn MIN_T_IOCS IoC: NaN.
U  Độ độc nhất: tỷ lệ IoC trong mẫu vừa độc hại vừa chỉ có ở feed này.
C  Ngữ cảnh: tỷ lệ IoC có ít nhất một thông tin đi kèm (họ mã độc, loại mối đe dọa, hoặc thời gian nguồn).
St Ổn định (theo feed): trung bình của (1 - hệ số biến thiên của số IoC mới theo ngày, cắt về [0,1]) và tỷ lệ lần
   tải thành công. Bỏ các ngày bị khoảng trống thu thập khỏi phần hệ số biến thiên.

Chiều nào là NaN thì điểm S được tính trên các chiều còn lại với trọng số chia lại cho tổng bằng 1 (cột n_dims ghi
số chiều dùng được). Quyết định này được viết trước khi thấy dữ liệu.

Dùng:
    python -m src.scoring
Đầu ra: data/processed/feed_scores.csv, feed_scores_sensitivity.csv
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import kendalltau

from src.groundtruth import build_frame, load_tranco

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
DIMS = ["A", "T", "U", "C", "St"]
BASE_WEIGHTS = {d: 0.2 for d in DIMS}
MIN_IOC = 30
MIN_T_IOCS = 30
MIN_CHECKS_PER_DAY = 20  # chỉ ngày thu thập gần đủ 24 lần mới dùng cho hệ số biến thiên (tránh phạt feed vì máy của mình tắt)
EXCLUDE_DAYS = ("2026-10-21", "2026-10-22")  # ngày có khoảng trống thu thập, không dùng cho hệ số biến thiên
KEY = ["ioc_type", "key_value", "hash_type"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def admiralty(score: float, n_ioc: int) -> str:
    if n_ioc < MIN_IOC or pd.isna(score):
        return "F"
    if score >= 0.80:
        return "A"
    if score >= 0.65:
        return "B"
    if score >= 0.50:
        return "C"
    if score >= 0.35:
        return "D"
    return "E"


def load_vt(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["ioc_type", "ioc_value", "label"])
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return pd.DataFrame(rows)[["ioc_type", "ioc_value", "label"]].drop_duplicates(["ioc_type", "ioc_value"])


def build_labels(sample: pd.DataFrame, vt: pd.DataFrame) -> pd.DataFrame:
    m = sample.merge(vt, how="left", on=["ioc_type", "ioc_value"])
    m["queried"] = m["label"].notna()
    m["gt1"] = m["label"] == "malicious"
    m["has_vt"] = m["label"].isin(["malicious", "below_threshold"])
    m["in_denominator"] = m["queried"] | m["gt2"]
    m["resolved"] = m["has_vt"] | m["gt2"]
    m["malicious"] = m["gt1"] | m["gt2"]
    return m


def dim_a(labels: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (feed, t), g in labels.groupby(["feed", "ioc_type"]):
        d = g[g["in_denominator"]]
        n, k = len(d), int(d["malicious"].sum())
        r = g[g["resolved"]]
        lo, hi = wilson(k, n)
        rows.append({"feed": feed, "ioc_type": t, "A": k / n if n else np.nan, "A_ci_low": lo, "A_ci_high": hi,
                     "A_n": n, "A_resolved": r["malicious"].mean() if len(r) else np.nan,
                     "n_not_found": int((d["label"] == "not_found").sum())})
    return pd.DataFrame(rows)


def dim_t(frame: pd.DataFrame) -> pd.DataFrame:
    f = frame.copy()
    f["feed_count"] = f.groupby(KEY)["feed"].transform("nunique")
    f["any_initial"] = f.groupby(KEY)["present_in_first_snapshot"].transform("any")
    sub = f[(f["feed_count"] >= 2) & (~f["any_initial"])].copy()
    if sub.empty:
        return pd.DataFrame(columns=["feed", "ioc_type", "T", "T_n"])
    sub["min_ts"] = sub.groupby(KEY)["first_check_ts"].transform("min")
    sub["is_first"] = sub["first_check_ts"] == sub["min_ts"]
    sub["n_first"] = sub.groupby(KEY)["is_first"].transform("sum")
    sub["credit"] = np.where(sub["is_first"], 1.0 / sub["n_first"], 0.0)
    out = sub.groupby(["feed", "ioc_type"]).agg(T=("credit", "mean"), T_n=("credit", "size")).reset_index()
    out.loc[out["T_n"] < MIN_T_IOCS, "T"] = np.nan
    return out


def dim_u(labels: pd.DataFrame, frame: pd.DataFrame) -> pd.DataFrame:
    fc = frame.groupby(KEY)["feed"].nunique().rename("feed_count").reset_index()
    m = labels.merge(fc, how="left", on=KEY)
    m = m[m["in_denominator"]]
    m["unique_malicious"] = m["malicious"] & (m["feed_count"] == 1)
    return m.groupby(["feed", "ioc_type"])["unique_malicious"].mean().rename("U").reset_index()


def dim_c(frame: pd.DataFrame) -> pd.DataFrame:
    f = frame.copy()
    f["has_ctx"] = f[["malware", "threat", "source_first_seen"]].notna().any(axis=1)
    return f.groupby(["feed", "ioc_type"])["has_ctx"].mean().rename("C").reset_index()


def dim_st(daily: pd.DataFrame, exclude_days=EXCLUDE_DAYS) -> pd.DataFrame:
    rows = []
    for feed, g in daily.groupby("feed"):
        success = g["thanh_cong"].sum() / g["lan_tai"].sum() if g["lan_tai"].sum() else np.nan
        d = g[~g["day"].isin(exclude_days)]
        d = d[d["lan_tai"] >= MIN_CHECKS_PER_DAY]
        d = d.iloc[:-1] if len(d) > 1 else d  # bỏ ngày cuối (chưa trọn)
        stab = np.nan
        if len(d) >= 3 and d["ioc_moi_thay"].mean() > 0:
            cv = d["ioc_moi_thay"].std(ddof=0) / d["ioc_moi_thay"].mean()
            stab = 1 - min(1.0, cv)
        parts = [x for x in (stab, success) if pd.notna(x)]
        rows.append({"feed": feed, "St": float(np.mean(parts)) if parts else np.nan, "St_cv_part": stab,
                     "St_success_part": success})
    return pd.DataFrame(rows)


def combine(dims: pd.DataFrame, weights: dict[str, float]) -> pd.Series:
    """Điểm S theo trọng số, chia lại trọng số trên các chiều không NaN."""
    w = pd.Series(weights)[DIMS]
    vals = dims[DIMS]
    avail = vals.notna()
    wsum = (avail * w).sum(axis=1)
    s = (vals.fillna(0) * w).sum(axis=1) / wsum.replace(0, np.nan)
    return s


def score_table(frame: pd.DataFrame, labels: pd.DataFrame, daily: pd.DataFrame,
                weights: dict[str, float] | None = None) -> pd.DataFrame:
    weights = weights or BASE_WEIGHTS
    base = frame.groupby(["feed", "ioc_type"]).agg(operator=("operator", "first"), n_ioc=("ioc_value", "size")).reset_index()
    t = base.merge(dim_a(labels), how="left", on=["feed", "ioc_type"]) if not labels.empty else base.assign(A=np.nan)
    t = t.merge(dim_t(frame), how="left", on=["feed", "ioc_type"])
    t = t.merge(dim_u(labels, frame), how="left", on=["feed", "ioc_type"]) if not labels.empty else t.assign(U=np.nan)
    t = t.merge(dim_c(frame), how="left", on=["feed", "ioc_type"])
    t = t.merge(dim_st(daily), how="left", on="feed")
    for d in DIMS:
        if d not in t:
            t[d] = np.nan
    t["n_dims"] = t[DIMS].notna().sum(axis=1)
    t["S"] = combine(t, weights)
    t["admiralty"] = [admiralty(s, n) for s, n in zip(t["S"], t["n_ioc"])]
    t["rank_in_type"] = t.groupby("ioc_type")["S"].rank(ascending=False, method="min")
    return t.sort_values(["ioc_type", "S"], ascending=[True, False]).reset_index(drop=True)


def sensitivity(table: pd.DataFrame, factor: float = 0.2) -> pd.DataFrame:
    """Đổi từng trọng số +-20% (chia lại tổng = 1), đo Kendall tau của thứ hạng feed so với bản gốc, theo từng loại IoC."""
    rows = []
    base_s = table["S"]
    for d in DIMS:
        for mult in (1 - factor, 1 + factor):
            w = dict(BASE_WEIGHTS)
            w[d] *= mult
            total = sum(w.values())
            w = {k: v / total for k, v in w.items()}
            s = combine(table, w)
            for t, idx in table.groupby("ioc_type").groups.items():
                a, b = base_s.loc[idx], s.loc[idx]
                ok = a.notna() & b.notna()
                tau = kendalltau(a[ok], b[ok]).statistic if ok.sum() >= 3 else np.nan
                rows.append({"dim_changed": d, "multiplier": round(mult, 2), "ioc_type": t, "n_feeds": int(ok.sum()),
                             "kendall_tau": tau})
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tranco", default=str(ROOT / "data" / "external" / "tranco_top10k.csv"))
    args = ap.parse_args()
    ioc_path = PROC / "ioc_table.csv.gz"
    daily_path = PROC / "feed_daily.csv"
    if not ioc_path.exists() or not daily_path.exists():
        print("Chưa có ioc_table/feed_daily. Chạy trước: python -m src.ingest")
        return
    frame = build_frame(pd.read_csv(ioc_path), load_tranco(args.tranco))
    daily = pd.read_csv(daily_path)
    sample_path = PROC / "gt_sample.csv"
    if sample_path.exists():
        labels = build_labels(pd.read_csv(sample_path), load_vt(PROC / "gt_vt.jsonl"))
    else:
        print("Chưa có gt_sample.csv: điểm A và U sẽ là NaN (S tính trên các chiều còn lại).")
        labels = pd.DataFrame()
    table = score_table(frame, labels, daily)
    table.to_csv(PROC / "feed_scores.csv", index=False)
    sens = sensitivity(table)
    sens.to_csv(PROC / "feed_scores_sensitivity.csv", index=False)
    show = ["feed", "ioc_type", "n_ioc", "A", "T", "U", "C", "St", "n_dims", "S", "admiralty"]
    print(table[show].round(3).to_string(index=False))
    if sens["kendall_tau"].notna().any():
        print(f"\nĐộ nhạy trọng số: Kendall tau nhỏ nhất = {sens['kendall_tau'].min():.2f} "
              f"(gần 1 nghĩa là thứ hạng ổn định khi đổi trọng số)")


if __name__ == "__main__":
    main()
