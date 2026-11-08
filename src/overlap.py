"""Độ trùng lặp giữa các feed và đường cong độ bao phủ biên (E3, luận điểm L2: nhiều feed không bằng chất lượng).

Với mỗi loại IoC có từ 2 feed trở lên:
- ma trận Jaccard giữa các feed (và giữa các TỔ CHỨC vận hành, vì feed cùng tổ chức không độc lập),
- đóng góp độc nhất: tỷ lệ IoC chỉ feed đó có,
- tỷ lệ IoC có ở >= 2 feed và ở >= 2 tổ chức,
- đường cong bao phủ: thêm dần feed, độ bao phủ (so với hợp của tất cả feed) tăng bao nhiêu. Lấy trung bình trên
  nhiều hoán vị ngẫu nhiên (seed 42) để không phụ thuộc thứ tự, kèm thứ tự tham lam (feed nào đóng góp thêm nhiều nhất trước).

Lưu ý khi diễn giải: đây là hợp của mọi IoC từng xuất hiện trong cửa sổ quan sát; "độ bao phủ" chỉ nói về việc các
feed có cùng liệt kê một IoC, KHÔNG nói IoC đó có thật sự độc hại hay không (xem điểm A trong src.scoring).

Dùng:
    python -m src.overlap
Đầu ra (results/): overlap_summary.csv, overlap_jaccard_<loại>.csv, overlap_jaccard_operator_<loại>.csv,
                   unique_contribution.csv, coverage_curve_<loại>.csv, coverage_curve.png
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from src.groundtruth import build_frame

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
RESULTS = ROOT / "results"
SEED = 42
N_PERM = 200
TYPES = ["ip", "domain", "url", "hash"]


def key_sets(frame: pd.DataFrame, ioc_type: str, by: str = "feed") -> dict[str, set]:
    sub = frame[frame["ioc_type"] == ioc_type]
    return {g: set(zip(d["key_value"], d["hash_type"])) for g, d in sub.groupby(by)}


def jaccard_matrix(sets: dict[str, set]) -> pd.DataFrame:
    names = sorted(sets)
    m = pd.DataFrame(index=names, columns=names, dtype=float)
    for a in names:
        for b in names:
            u = sets[a] | sets[b]
            m.loc[a, b] = len(sets[a] & sets[b]) / len(u) if u else np.nan
    return m


def unique_contribution(sets: dict[str, set]) -> pd.DataFrame:
    rows = []
    for name, s in sets.items():
        others = set().union(*[v for k, v in sets.items() if k != name]) if len(sets) > 1 else set()
        only = len(s - others)
        rows.append({"feed": name, "size": len(s), "unique_only": only, "unique_share": only / len(s) if s else np.nan})
    return pd.DataFrame(rows)


def coverage_curve(sets: dict[str, set], n_perm: int = N_PERM, seed: int = SEED) -> tuple[pd.DataFrame, list[str]]:
    names = sorted(sets)
    total = len(set().union(*sets.values()))
    rng = np.random.default_rng(seed)
    curves = []
    for _ in range(n_perm):
        order = list(rng.permutation(names))
        seen: set = set()
        cov = []
        for n in order:
            seen |= sets[n]
            cov.append(len(seen) / total)
        curves.append(cov)
    arr = np.array(curves)
    # thứ tự tham lam
    chosen, seen = [], set()
    remaining = set(names)
    greedy_cov = []
    while remaining:
        best = max(sorted(remaining), key=lambda n: len(sets[n] - seen))
        chosen.append(best)
        seen |= sets[best]
        remaining.remove(best)
        greedy_cov.append(len(seen) / total)
    out = pd.DataFrame({"k_feeds": range(1, len(names) + 1), "coverage_mean": arr.mean(axis=0),
                        "coverage_min": arr.min(axis=0), "coverage_max": arr.max(axis=0),
                        "coverage_greedy": greedy_cov, "greedy_added": chosen})
    return out, chosen


def overlap_summary(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for t in TYPES:
        sub = frame[frame["ioc_type"] == t]
        if sub.empty:
            continue
        g = sub.groupby(["key_value", "hash_type"])
        feeds = g["feed"].nunique()
        ops = g["operator"].nunique()
        rows.append({"ioc_type": t, "n_feeds": sub["feed"].nunique(), "n_operators": sub["operator"].nunique(),
                     "union_size": len(feeds), "share_in_2plus_feeds": float((feeds >= 2).mean()),
                     "share_in_2plus_operators": float((ops >= 2).mean())})
    return pd.DataFrame(rows)


def plot_curves(curves: dict[str, pd.DataFrame], path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for t, c in curves.items():
        ax.plot(c["k_feeds"], c["coverage_mean"], marker="o", label=f"{t} (trung bình các thứ tự)")
        ax.fill_between(c["k_feeds"], c["coverage_min"], c["coverage_max"], alpha=0.12)
    ax.set_xlabel("Số feed được thêm vào")
    ax.set_ylabel("Độ bao phủ so với hợp của tất cả feed")
    ax.set_title("Đường cong độ bao phủ biên theo loại IoC")
    ax.set_ylim(0, 1.02)
    ax.legend()
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def run(frame: pd.DataFrame, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = overlap_summary(frame)
    summary.to_csv(out_dir / "overlap_summary.csv", index=False)
    uniq_all, curves = [], {}
    for t in TYPES:
        sets = key_sets(frame, t)
        if len(sets) < 2:
            continue
        jaccard_matrix(sets).to_csv(out_dir / f"overlap_jaccard_{t}.csv")
        ops = key_sets(frame, t, by="operator")
        if len(ops) >= 2:
            jaccard_matrix(ops).to_csv(out_dir / f"overlap_jaccard_operator_{t}.csv")
        uniq_all.append(unique_contribution(sets).assign(ioc_type=t))
        curve, _ = coverage_curve(sets)
        curve.to_csv(out_dir / f"coverage_curve_{t}.csv", index=False)
        curves[t] = curve
    if uniq_all:
        pd.concat(uniq_all).to_csv(out_dir / "unique_contribution.csv", index=False)
    if curves:
        plot_curves(curves, out_dir / "coverage_curve.png")
    return {"summary": summary, "curves": curves}


def main() -> None:
    path = PROC / "ioc_table.csv.gz"
    if not path.exists():
        print("Chưa có ioc_table.csv.gz. Chạy trước: python -m src.ingest")
        return
    frame = build_frame(pd.read_csv(path))
    res = run(frame, RESULTS)
    print(res["summary"].round(3).to_string(index=False))
    for t, c in res["curves"].items():
        print(f"\n{t}: thứ tự tham lam {list(c['greedy_added'])}")
        print(c[["k_feeds", "coverage_mean", "coverage_greedy"]].round(3).to_string(index=False))
    print(f"\nKết quả trong {RESULTS}")


if __name__ == "__main__":
    main()
