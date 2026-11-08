"""In ảnh chụp tiến độ dự án (để dán cho người hỗ trợ). Không in giá trị khóa hay bí mật nào.

    python -m src.progress
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = ["collector", "report", "extract", "feeds", "ingest", "to_stix", "validate_stix", "groundtruth", "tranco",
           "vt_lookup", "scoring", "survival", "eval_e1", "fetch_reports", "taxii_server", "taxii_client", "overlap"]
GAP_MIN = 180


def git(*args) -> str | None:
    try:
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def size_str(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


def line_count(p: Path) -> int:
    return sum(1 for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()) if p.exists() else 0


def mtime(p: Path) -> str:
    return datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%MZ")


def section(title: str) -> None:
    print(f"\n== {title} ==")


def main() -> None:
    now = datetime.now(timezone.utc)
    print("ẢNH CHỤP TIẾN ĐỘ DỰ ÁN")
    section("Thời gian trên máy của bạn")
    print(f"UTC: {now:%Y-%m-%d %H:%M}   Giờ Việt Nam: {(now + timedelta(hours=7)):%Y-%m-%d %H:%M}")

    section("Thu thập (từ manifest)")
    mpath = ROOT / "data" / "manifest" / "manifest.jsonl"
    rows = []
    if mpath.exists():
        for l in mpath.read_text(encoding="utf-8").splitlines():
            if l.strip():
                try:
                    rows.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    if not rows:
        print("Chưa có manifest.")
    else:
        by = defaultdict(list)
        for r in rows:
            by[r["feed"]].append(r)
        print(f"{'feed':15} {'lượt':>5} {'ok':>5} {'lỗi':>4} {'lần đầu (UTC)':>18} {'lần cuối (UTC)':>18} {'cách đây':>9} {'trống>3h':>9}")
        for feed, rs in sorted(by.items()):
            rs.sort(key=lambda x: x["ts_utc"])
            ts = [datetime.strptime(x["ts_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) for x in rs]
            ok = sum(1 for x in rs if x["status"] in (200, 304))
            gaps = [(b - a).total_seconds() / 3600 for a, b in zip(ts, ts[1:]) if (b - a).total_seconds() / 60 > GAP_MIN]
            ago = (now - ts[-1]).total_seconds() / 3600
            print(f"{feed:15} {len(rs):>5} {ok:>5} {len(rs) - ok:>4} {ts[0]:%m-%d %H:%M}Z{'':>5} {ts[-1]:%m-%d %H:%M}Z{'':>5} "
                  f"{ago:>7.1f}h {len(gaps):>9}")
            if gaps:
                print(f"{'':15} khoảng trống (giờ): {', '.join(f'{g:.0f}' for g in sorted(gaps, reverse=True)[:5])}")
    raw = ROOT / "data" / "raw"
    if raw.exists():
        files = list(raw.rglob("*.gz"))
        print(f"Dữ liệu thô: {len(files)} file, {size_str(sum(f.stat().st_size for f in files))}")

    section("Mã nguồn có trong src/")
    have = [m for m in MODULES if (ROOT / "src" / f"{m}.py").exists()]
    missing = [m for m in MODULES if m not in have]
    print("Có :", ", ".join(have) or "(không)")
    print("Thiếu:", ", ".join(missing) or "(không)")
    tests = len(list((ROOT / "tests").glob("test_*.py"))) if (ROOT / "tests").exists() else 0
    print(f"File test: {tests}")

    section("Kết quả đã tạo")
    proc = ROOT / "data" / "processed"
    for name in ["ioc_table.csv.gz", "feed_daily.csv", "gt_sample.csv", "gt_vt.jsonl", "feed_scores.csv",
                 "feed_scores_sensitivity.csv"]:
        p = proc / name
        extra = ""
        if p.exists() and name in ("gt_sample.csv", "gt_vt.jsonl"):
            n = max(0, line_count(p) - (1 if name.endswith(".csv") else 0))
            extra = f", {n} dòng"
            if name == "gt_vt.jsonl":
                c = Counter()
                for l in p.read_text(encoding="utf-8").splitlines():
                    try:
                        c[json.loads(l).get("label")] += 1
                    except json.JSONDecodeError:
                        pass
                extra += f", nhãn: {dict(c)}"
        print(f"{name:30} {'CÓ  (' + mtime(p) + ', ' + size_str(p.stat().st_size) + extra + ')' if p.exists() else 'chưa có'}")
    stix = list((proc / "stix").glob("*.json")) if (proc / "stix").exists() else []
    print(f"{'stix/*.json':30} {len(stix)} file")
    tr = ROOT / "data" / "external" / "tranco_top10k.csv"
    print(f"{'Tranco top 10k':30} {'CÓ' if tr.exists() else 'chưa có'}")
    res = ROOT / "results"
    print(f"{'results/':30} {', '.join(sorted(p.name for p in res.iterdir())) if res.exists() and any(res.iterdir()) else 'trống'}")

    section("E1 (báo cáo và nhãn tay)")
    rp = ROOT / "data" / "reports.csv"
    e1 = ROOT / "data" / "e1"
    texts = len(list((e1 / "texts").glob("*.txt"))) if (e1 / "texts").exists() else 0
    gold = list((e1 / "gold").glob("*.json")) if (e1 / "gold").exists() else []
    labeled = 0
    for g in gold:
        try:
            if any(json.loads(g.read_text(encoding="utf-8")).get(t) for t in ("ip", "domain", "url", "hash")):
                labeled += 1
        except Exception:  # noqa: BLE001
            pass
    print(f"reports.csv: {max(0, line_count(rp) - 1)} báo cáo | văn bản đã tải: {texts} | file nhãn: {len(gold)} (đã gán ít nhất 1 IoC: {labeled}) | "
          f"nhãn người 2: {len(list((e1 / 'gold_b').glob('*.json'))) if (e1 / 'gold_b').exists() else 0}")

    section("Git")
    print("nhánh:", git("rev-parse", "--abbrev-ref", "HEAD") or "(không đọc được git)")
    print("commit mới nhất:", git("log", "-1", "--format=%h | %cI | %s") or "-")
    tags = git("tag", "-n") or ""
    print("tag:", tags.replace("\n", " ; ") or "(không có)")
    st = git("status", "--porcelain")
    print(f"file thay đổi chưa commit: {len(st.splitlines()) if st else 0}")
    ahead = git("rev-list", "--count", "@{u}..HEAD")
    print(f"commit chưa push: {ahead if ahead is not None else '(không rõ)'}")

    section("Cấu hình (chỉ tên, không in giá trị)")
    env = ROOT / ".env"
    if env.exists():
        for l in env.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in l and not l.strip().startswith("#"):
                k, v = l.split("=", 1)
                print(f"{k.strip():22} {'đã điền' if v.strip() else 'TRỐNG'}")
    else:
        print(".env chưa có")
    dev = ROOT / "docs" / "DEVIATIONS.md"
    n_dev = sum(1 for l in dev.read_text(encoding="utf-8").splitlines() if l.startswith("| 20")) if dev.exists() else 0
    print(f"DEVIATIONS.md: {n_dev} dòng ghi nhận thay đổi")
    print("\n(Hết. Hãy dán toàn bộ phần trên cho người hỗ trợ.)")


if __name__ == "__main__":
    main()
