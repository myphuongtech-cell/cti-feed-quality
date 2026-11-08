import gzip
import json
from datetime import datetime, timedelta, timezone

from src.ingest import build_all, build_checks

T0 = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_root(tmp_path, plan):
    """plan: danh sách (giờ_so_với_T0, status, nội_dung_hoặc_None). nội dung = bản chụp mới (stored)."""
    root = tmp_path
    (root / "data" / "manifest").mkdir(parents=True)
    rows = []
    for i, (hours, status, content) in enumerate(plan):
        ts = T0 + timedelta(hours=hours)
        rec = {"ts_utc": iso(ts), "feed": "blocklist_de", "status": status, "stored": False, "path": None}
        if content is not None:
            rel = f"data/raw/blocklist_de/{ts:%Y%m%d}/blocklist_de_{ts:%Y%m%dT%H%M%SZ}.txt.gz"
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(p, "wt", encoding="utf-8") as f:
                f.write("\n".join(content) + "\n")
            rec.update(stored=True, path=rel.replace("/", "\\"))  # giống đường dẫn Windows trong manifest thật
        rows.append(rec)
    (root / "data" / "manifest" / "manifest.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return root


def row(df, value):
    return df[df["ioc_value"] == value].iloc[0]


def test_delisting_and_censoring(tmp_path):
    plan = [
        (0, 200, ["1.1.1.1", "2.2.2.2"]),   # check 0: snapshot 0
        (1, 304, None),                      # check 1: không đổi
        (2, 200, ["1.1.1.1", "3.3.3.3"]),   # check 2: snapshot 1 (2.2.2.2 biến mất)
        (3, 304, None), (4, 304, None), (5, 304, None),
    ]
    ioc, daily = build_all(make_root(tmp_path, plan))
    a, b, c = row(ioc, "1.1.1.1"), row(ioc, "2.2.2.2"), row(ioc, "3.3.3.3")
    assert bool(b["delisted"]) is True      # vắng ở các lần kiểm tra 2,3,4,5 (>= 3)
    assert b["listing_hours"] == 1.0        # từ check 0 đến check 1
    assert bool(a["right_censored"]) is True and bool(c["right_censored"]) is True
    assert c["first_check_ts"] == T0 + timedelta(hours=2)
    assert bool(a["present_in_first_snapshot"]) is True and bool(c["present_in_first_snapshot"]) is False
    d = daily.set_index("day").loc["2026-10-22"]
    assert int(d["ioc_moi_thay"]) == 1      # chỉ 3.3.3.3 là mới (hai IP kia có từ snapshot đầu)


def test_not_delisted_if_absent_fewer_than_three_checks(tmp_path):
    plan = [(0, 200, ["1.1.1.1", "2.2.2.2"]), (1, 200, ["1.1.1.1"]), (2, 304, None)]
    ioc, _ = build_all(make_root(tmp_path, plan))
    assert bool(row(ioc, "2.2.2.2")["delisted"]) is False  # mới vắng 2 lần kiểm tra


def test_failed_checks_are_ignored(tmp_path):
    plan = [(0, 200, ["1.1.1.1"]), (1, 503, None), (2, 304, None)]
    ioc, _ = build_all(make_root(tmp_path, plan))
    r = row(ioc, "1.1.1.1")
    assert r["last_check_ts"] == T0 + timedelta(hours=2)


def test_gap_flag(tmp_path):
    plan = [
        (0, 200, ["1.1.1.1", "2.2.2.2"]),
        (1, 304, None),
        (30, 200, ["1.1.1.1"]),             # khoảng trống 29 giờ
        (31, 304, None), (32, 304, None), (33, 304, None),
    ]
    ioc, _ = build_all(make_root(tmp_path, plan))
    assert bool(row(ioc, "2.2.2.2")["gap_affected"]) is True   # biến mất sau khoảng trống
    assert bool(row(ioc, "1.1.1.1")["gap_affected"]) is True   # đời của nó cắt ngang khoảng trống


def test_build_checks_skips_unchanged_before_first_snapshot():
    rows = [
        {"ts_utc": "2026-10-22T08:00:00Z", "status": 304, "stored": False},
        {"ts_utc": "2026-10-22T09:00:00Z", "status": 200, "stored": True, "path": "x"},
    ]
    checks, snaps = build_checks(rows)
    assert len(checks) == 1 and snaps[0]["a"] == 0
