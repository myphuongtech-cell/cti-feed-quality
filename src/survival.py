"""Phân tích sống sót cho thí nghiệm E4 (docs/PREREGISTRATION.md mục 3 và 5).

E4a  Thời gian nằm trong feed (listing duration): sự kiện = bị gỡ (vắng mặt >= 3 lần kiểm tra liên tiếp).
     Đây là hành vi của feed, KHÔNG phải bằng chứng IoC hết hoạt động.
E4b  Thời gian còn hoạt động (khám phá), chỉ với URLhaus: sự kiện = trường trạng thái chuyển sang offline.

Quy tắc đã cố định:
- Loại IoC có mặt ngay từ bản chụp đầu của feed (không biết thời điểm bắt đầu thật: cắt cụt trái).
- Loại IoC bị ảnh hưởng bởi khoảng trống thu thập (gap_affected).
- Không suy diễn ngoài cửa sổ quan sát: còn mặt đến hết dữ liệu thì là cắt cụt phải.
- Nhóm quá nhỏ (< MIN_GROUP) không được so sánh.

Dùng:
    python -m src.survival
Đầu ra: results/e4a_summary.csv, results/e4a_logrank.csv, results/e4b_urlhaus.csv, results/e4a_km_by_type.png
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter
from lifelines.statistics import multivariate_logrank_test

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
RESULTS = ROOT / "results"
MIN_GROUP = 30


def cohort(ioc: pd.DataFrame) -> pd.DataFrame:
    """Nhóm đủ điều kiện: bỏ IoC có sẵn từ đầu và IoC bị ảnh hưởng bởi khoảng trống."""
    df = ioc.copy()
    df = df[~df["present_in_first_snapshot"].astype(bool)]
    df = df[~df["gap_affected"].astype(bool)]
    return df


def e4a_durations(df: pd.DataFrame) -> pd.DataFrame:
    out = df[["feed", "operator", "ioc_type", "listing_hours", "delisted"]].copy()
    out["duration_h"] = out["listing_hours"].astype(float)
    out["event"] = out["delisted"].astype(bool).astype(int)
    return out


def km_summary(d: pd.DataFrame, group_cols: list[str]) -> pd.DataFrame:
    rows = []
    for key, g in d.groupby(group_cols):
        key = key if isinstance(key, tuple) else (key,)
        rec = dict(zip(group_cols, key))
        rec.update({"n": len(g), "events": int(g["event"].sum()), "censored": int((1 - g["event"]).sum())})
        if len(g) >= MIN_GROUP:
            kmf = KaplanMeierFitter().fit(g["duration_h"], g["event"])
            med = kmf.median_survival_time_
            rec["median_hours"] = float(med) if np.isfinite(med) else np.nan  # inf = chưa quan sát đủ để ước lượng
            rec["median_note"] = "" if np.isfinite(med) else "trung vị chưa ước lượng được (quá nửa còn trong feed)"
            for h in (6, 24, 72):
                rec[f"S({h}h)"] = float(kmf.predict(h)) if h <= g["duration_h"].max() else np.nan
        else:
            rec["median_note"] = f"nhóm quá nhỏ (< {MIN_GROUP})"
        rows.append(rec)
    return pd.DataFrame(rows)


def logrank(d: pd.DataFrame, by: str, within: str | None = None) -> pd.DataFrame:
    rows = []
    parts = [(None, d)] if within is None else list(d.groupby(within))
    for key, g in parts:
        sizes = g.groupby(by).size()
        keep = sizes[sizes >= MIN_GROUP].index
        g = g[g[by].isin(keep)]
        if g[by].nunique() < 2:
            continue
        res = multivariate_logrank_test(g["duration_h"], g[by], g["event"])
        rows.append({"within": key, "compare": by, "groups": ", ".join(map(str, sorted(keep))),
                     "n": len(g), "test_statistic": float(res.test_statistic), "p_value": float(res.p_value)})
    return pd.DataFrame(rows)


def e4b_urlhaus(ioc: pd.DataFrame) -> pd.DataFrame:
    """Thời gian còn hoạt động: từ lần đầu thấy đến lần đầu chuyển offline (cắt cụt tại lần kiểm tra cuối)."""
    u = ioc[(ioc["feed"] == "urlhaus")].copy()
    u = u[~u["present_in_first_snapshot"].astype(bool)]
    u = u[u["status_first"] != "offline"]  # đã offline ngay từ đầu: không có thông tin về thời điểm chuyển
    u["first_check_ts"] = pd.to_datetime(u["first_check_ts"], utc=True)
    u["last_check_ts"] = pd.to_datetime(u["last_check_ts"], utc=True)
    u["first_offline_ts"] = pd.to_datetime(u["first_offline_ts"], utc=True)
    event = u["first_offline_ts"].notna()
    end = u["first_offline_ts"].where(event, u["last_check_ts"])
    u["duration_h"] = (end - u["first_check_ts"]).dt.total_seconds() / 3600
    u["event"] = event.astype(int)
    return u[["feed", "ioc_type", "duration_h", "event"]]


def plot_km(d: pd.DataFrame, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for t, g in d.groupby("ioc_type"):
        if len(g) >= MIN_GROUP:
            KaplanMeierFitter().fit(g["duration_h"], g["event"], label=f"{t} (n={len(g)})").plot_survival_function(ax=ax, ci_show=True)
    ax.set_xlabel("Giờ kể từ lần đầu quan sát")
    ax.set_ylabel("Xác suất còn nằm trong feed")
    ax.set_title("E4a: thời gian nằm trong feed theo loại IoC (Kaplan-Meier)")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main() -> None:
    path = PROC / "ioc_table.csv.gz"
    if not path.exists():
        print("Chưa có ioc_table.csv.gz. Chạy trước: python -m src.ingest")
        return
    ioc = pd.read_csv(path)
    ioc["present_in_first_snapshot"] = ioc["present_in_first_snapshot"].astype(bool)
    df = cohort(ioc)
    print(f"IoC tổng: {len(ioc):,} | đủ điều kiện sau khi loại có sẵn từ đầu và bị ảnh hưởng bởi khoảng trống: {len(df):,}")
    if df.empty:
        print("Chưa đủ dữ liệu cho E4a.")
        return
    d = e4a_durations(df)
    RESULTS.mkdir(parents=True, exist_ok=True)
    summary = pd.concat([km_summary(d, ["ioc_type"]).assign(level="theo loại IoC"),
                         km_summary(d, ["feed", "ioc_type"]).assign(level="theo feed và loại")], ignore_index=True)
    summary.to_csv(RESULTS / "e4a_summary.csv", index=False)
    lr = pd.concat([logrank(d, "ioc_type"), logrank(d, "feed", within="ioc_type")], ignore_index=True)
    lr.to_csv(RESULTS / "e4a_logrank.csv", index=False)
    plot_km(d, RESULTS / "e4a_km_by_type.png")
    print(summary.round(2).to_string(index=False))
    print("\nLog-rank:\n" + (lr.round(4).to_string(index=False) if not lr.empty else "(chưa đủ nhóm lớn để so sánh)"))

    b = e4b_urlhaus(ioc)
    if len(b) >= MIN_GROUP:
        res = km_summary(b, ["feed"])
        res.to_csv(RESULTS / "e4b_urlhaus.csv", index=False)
        print("\nE4b (URLhaus, khám phá):\n" + res.round(2).to_string(index=False))


if __name__ == "__main__":
    main()
