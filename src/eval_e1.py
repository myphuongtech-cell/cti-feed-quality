"""Thí nghiệm E1: trích xuất IoC từ văn bản, so sánh hai hệ thống với nhãn tay (docs/PREREGISTRATION.md H1).

Cấu trúc dữ liệu:
    data/e1/texts/<doc_id>.txt        văn bản báo cáo (từ src.fetch_reports, KHÔNG commit vì bản quyền)
    data/e1/gold/<doc_id>.json        nhãn tay: {"ip": [...], "domain": [...], "url": [...], "hash": [...]}
                                      giá trị đã khử defang và chuẩn hóa (domain/hash chữ thường, IP dạng chuẩn)
    data/e1/gold_b/<doc_id>.json      (tùy chọn) nhãn của người thứ hai để tính kappa

Hai hệ thống:
    baseline  regex thuần: không khử defang, không kiểm tra hợp lệ, không lọc ngữ cảnh
    pipeline  khử defang + kiểm tra + lọc ngữ cảnh (ContextFilter, kèm Tranco nếu có)

Chỉ số: precision, recall, F1 theo loại (gộp trên tất cả tài liệu) và macro-F1 (trung bình các loại có nhãn).
Khoảng tin cậy: bootstrap 1000 lần theo tài liệu, seed 42; chênh lệch macro-F1 (pipeline - baseline) tính theo cặp.
Tiêu chí H1 (đã khóa): chênh lệch >= 0,05 và khoảng tin cậy 95% không chứa 0; bác bỏ nếu < 0,02 hoặc khoảng chứa 0.

Dùng:
    python -m src.eval_e1 --blank          # tạo file nhãn rỗng cho mỗi văn bản (gán nhãn KHÔNG nhìn đầu ra hệ thống)
    python -m src.eval_e1                  # đánh giá
    python -m src.eval_e1 --kappa          # độ đồng thuận giữa hai người gán nhãn
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.extract import ContextFilter, extract_by_type
from src.groundtruth import load_tranco

ROOT = Path(__file__).resolve().parents[1]
E1 = ROOT / "data" / "e1"
RESULTS = ROOT / "results"
TYPES = ["ip", "domain", "url", "hash"]
SEED = 42
N_BOOT = 1000


def load_gold(folder: Path) -> dict[str, dict[str, set[str]]]:
    gold = {}
    for p in sorted(folder.glob("*.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        gold[p.stem] = {t: {str(x) for x in data.get(t, [])} for t in TYPES}
    return gold


def systems(tranco_path: Path | None) -> dict:
    cf = ContextFilter(tranco_path=tranco_path if tranco_path and tranco_path.exists() else None)
    return {
        "baseline": lambda text: extract_by_type(text, refang_input=False, validate=False, context_filter=None),
        "pipeline": lambda text: extract_by_type(text, context_filter=cf),
    }


def counts(pred: dict[str, set], gold: dict[str, set]) -> dict[str, tuple[int, int, int]]:
    """tp, fp, fn theo loại cho một tài liệu."""
    out = {}
    for t in TYPES:
        p, g = pred.get(t, set()), gold.get(t, set())
        out[t] = (len(p & g), len(p - g), len(g - p))
    return out


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else np.nan
    r = tp / (tp + fn) if tp + fn else np.nan
    f = 2 * p * r / (p + r) if (p and r and not np.isnan(p) and not np.isnan(r)) else (0.0 if tp + fp + fn else np.nan)
    return p, r, f


def aggregate(per_doc: list[dict[str, tuple[int, int, int]]]) -> dict[str, tuple[float, float, float]]:
    res = {}
    for t in TYPES:
        tp = sum(d[t][0] for d in per_doc)
        fp = sum(d[t][1] for d in per_doc)
        fn = sum(d[t][2] for d in per_doc)
        res[t] = prf(tp, fp, fn) if tp + fn > 0 else (np.nan, np.nan, np.nan)  # loại không có nhãn nào: bỏ qua
    return res


def macro_f1(agg: dict[str, tuple[float, float, float]]) -> float:
    fs = [v[2] for v in agg.values() if not np.isnan(v[2])]
    return float(np.mean(fs)) if fs else np.nan


def bootstrap(per_doc_by_system: dict[str, list], n_boot: int = N_BOOT, seed: int = SEED) -> dict:
    rng = np.random.default_rng(seed)
    n = len(next(iter(per_doc_by_system.values())))
    samples = {name: [] for name in per_doc_by_system}
    diffs = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        m = {}
        for name, docs in per_doc_by_system.items():
            m[name] = macro_f1(aggregate([docs[i] for i in idx]))
            samples[name].append(m[name])
        if "pipeline" in m and "baseline" in m:
            diffs.append(m["pipeline"] - m["baseline"])
    out = {name: tuple(np.nanpercentile(v, [2.5, 97.5])) for name, v in samples.items()}
    if diffs:
        out["diff"] = tuple(np.nanpercentile(diffs, [2.5, 97.5]))
    return out


def h1_decision(diff: float, ci: tuple[float, float]) -> str:
    if diff < 0.02 or (ci[0] <= 0 <= ci[1]):
        return "BÁC BỎ H1 (chênh lệch < 0,02 hoặc khoảng tin cậy chứa 0)"
    if diff >= 0.05:
        return "ỦNG HỘ H1 (chênh lệch >= 0,05 và khoảng tin cậy không chứa 0)"
    return "KHÔNG KẾT LUẬN (chênh lệch trong khoảng 0,02-0,05)"


def cohens_kappa(a: list[int], b: list[int]) -> float:
    a, b = np.array(a), np.array(b)
    po = (a == b).mean()
    pe = sum(((a == k).mean() * (b == k).mean()) for k in (0, 1))
    return float((po - pe) / (1 - pe)) if pe < 1 else 1.0


def kappa_between(gold_a: dict, gold_b: dict) -> float:
    docs = sorted(set(gold_a) & set(gold_b))
    xa, xb = [], []
    for d in docs:
        for t in TYPES:
            items = gold_a[d][t] | gold_b[d][t]
            for it in sorted(items):
                xa.append(int(it in gold_a[d][t]))
                xb.append(int(it in gold_b[d][t]))
    return cohens_kappa(xa, xb) if xa else float("nan")


def run_eval(texts_dir: Path, gold_dir: Path, tranco: Path | None) -> tuple[pd.DataFrame, pd.DataFrame, dict, pd.DataFrame]:
    gold = load_gold(gold_dir)
    docs = [d for d in gold if (texts_dir / f"{d}.txt").exists()]
    if not docs:
        raise SystemExit("Không có tài liệu nào vừa có văn bản vừa có nhãn.")
    sys_fns = systems(tranco)
    per_doc = {name: [] for name in sys_fns}
    errors = []
    for d in docs:
        text = (texts_dir / f"{d}.txt").read_text(encoding="utf-8", errors="replace")
        for name, fn in sys_fns.items():
            pred = fn(text)
            per_doc[name].append(counts(pred, gold[d]))
            for t in TYPES:
                for v in sorted(pred[t] - gold[d][t]):
                    errors.append({"system": name, "doc": d, "type": t, "error": "FP", "value": v})
                for v in sorted(gold[d][t] - pred[t]):
                    errors.append({"system": name, "doc": d, "type": t, "error": "FN", "value": v})
    rows = []
    for name, docs_counts in per_doc.items():
        agg = aggregate(docs_counts)
        for t, (p, r, f) in agg.items():
            rows.append({"system": name, "type": t, "precision": p, "recall": r, "f1": f})
        rows.append({"system": name, "type": "MACRO", "precision": np.nan, "recall": np.nan, "f1": macro_f1(agg)})
    metrics = pd.DataFrame(rows)
    ci = bootstrap(per_doc)
    return metrics, pd.DataFrame(errors), ci, pd.DataFrame({"n_docs": [len(docs)]})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--blank", action="store_true", help="tạo file nhãn rỗng cho mỗi văn bản chưa có nhãn")
    ap.add_argument("--kappa", action="store_true")
    ap.add_argument("--tranco", default=str(ROOT / "data" / "external" / "tranco_top10k.csv"))
    args = ap.parse_args()
    texts, gold_dir = E1 / "texts", E1 / "gold"

    if args.blank:
        gold_dir.mkdir(parents=True, exist_ok=True)
        created = 0
        for p in sorted(texts.glob("*.txt")):
            g = gold_dir / f"{p.stem}.json"
            if not g.exists():
                g.write_text(json.dumps({t: [] for t in TYPES}, indent=2), encoding="utf-8")
                created += 1
        print(f"Đã tạo {created} file nhãn rỗng trong {gold_dir}. Gán nhãn trước khi xem đầu ra của hệ thống để tránh thiên lệch.")
        return

    if args.kappa:
        k = kappa_between(load_gold(gold_dir), load_gold(E1 / "gold_b"))
        print(f"Cohen's kappa giữa hai người gán nhãn: {k:.3f} (mục tiêu >= 0,7)")
        return

    metrics, errors, ci, info = run_eval(texts, gold_dir, Path(args.tranco))
    RESULTS.mkdir(parents=True, exist_ok=True)
    metrics.to_csv(RESULTS / "e1_metrics.csv", index=False)
    errors.to_csv(RESULTS / "e1_errors.csv", index=False)
    print(f"Số tài liệu: {int(info['n_docs'][0])}\n")
    print(metrics.round(3).to_string(index=False))
    mb = metrics[(metrics.system == "baseline") & (metrics.type == "MACRO")]["f1"].iloc[0]
    mp = metrics[(metrics.system == "pipeline") & (metrics.type == "MACRO")]["f1"].iloc[0]
    diff = mp - mb
    print(f"\nMacro-F1: baseline {mb:.3f} [{ci['baseline'][0]:.3f}, {ci['baseline'][1]:.3f}] | "
          f"pipeline {mp:.3f} [{ci['pipeline'][0]:.3f}, {ci['pipeline'][1]:.3f}]")
    print(f"Chênh lệch (pipeline - baseline): {diff:+.3f}  CI95% [{ci['diff'][0]:+.3f}, {ci['diff'][1]:+.3f}]")
    print("Kết luận theo tiêu chí đã khóa:", h1_decision(diff, ci["diff"]))
    print(f"Danh sách lỗi (FP/FN) để phân tích: {RESULTS / 'e1_errors.csv'}")


if __name__ == "__main__":
    main()
