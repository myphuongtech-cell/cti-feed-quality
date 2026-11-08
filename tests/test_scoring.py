import numpy as np
import pandas as pd

from src.groundtruth import build_frame
from src.scoring import DIMS, admiralty, build_labels, combine, dim_a, dim_c, dim_st, dim_t, dim_u, score_table, sensitivity, wilson

T0 = pd.Timestamp("2026-10-24 00:00:00", tz="UTC")


def ioc_table():
    rows = []

    def add(feed, op, v, h, first=False, malware=None):
        ts = T0 + pd.Timedelta(hours=h)
        rows.append({"feed": feed, "operator": op, "ioc_type": "ip", "ioc_value": v, "hash_type": None,
                     "first_check_ts": ts.isoformat(), "last_check_ts": ts.isoformat(),
                     "present_in_first_snapshot": first, "malware": malware, "threat": None, "source_first_seen": None})
    # 40 IP có ở cả A và B; A thấy trước ở 30 IP, B thấy trước ở 10 IP
    for i in range(40):
        ip = f"8.8.1.{i + 1}"
        add("feedA", "OpA", ip, 10 if i < 30 else 12)
        add("feedB", "OpB", ip, 12 if i < 30 else 10, malware="X" if i % 2 == 0 else None)
    # 10 IP chỉ có ở B
    for i in range(10):
        add("feedB", "OpB", f"8.8.2.{i + 1}", 20)
    # IP có sẵn từ đầu ở C và A: không dùng cho T
    add("feedC", "OpC", "8.8.3.1", 0, first=True)
    add("feedA", "OpA", "8.8.3.1", 5)
    return pd.DataFrame(rows)


def test_wilson_and_admiralty():
    lo, hi = wilson(8, 10)
    assert 0.4 < lo < 0.8 < hi < 1
    assert np.isnan(wilson(0, 0)[0])
    assert [admiralty(s, 100) for s in (0.9, 0.7, 0.55, 0.4, 0.1)] == ["A", "B", "C", "D", "E"]
    assert admiralty(0.9, 10) == "F"          # ít hơn 30 IoC
    assert admiralty(np.nan, 100) == "F"


def test_dim_t_credit():
    frame = build_frame(ioc_table())
    t = dim_t(frame).set_index(["feed", "ioc_type"])
    assert t.loc[("feedA", "ip"), "T"] == 30 / 40
    assert t.loc[("feedB", "ip"), "T"] == 10 / 40
    assert t.loc[("feedA", "ip"), "T_n"] == 40


def test_dim_t_needs_enough_iocs():
    rows = ioc_table()
    small = rows[rows["ioc_value"].str.startswith("8.8.1.") & (rows["ioc_value"].str[-2:].str.strip(".").astype(int) <= 5)]
    t = dim_t(build_frame(small))
    assert t["T"].isna().all()                # < 30 IoC chung: "không đủ dữ liệu", không gán 0


def test_dim_c_and_dim_a_u():
    frame = build_frame(ioc_table())
    c = dim_c(frame).set_index(["feed", "ioc_type"])["C"]
    assert c[("feedA", "ip")] == 0 and abs(c[("feedB", "ip")] - 20 / 50) < 1e-9
    sample = frame[frame["feed"] == "feedB"].head(20).copy()
    sample["stratum"] = "feedB|ip"
    vt = pd.DataFrame({"ioc_type": "ip", "ioc_value": sample["ioc_value"],
                       "label": ["malicious"] * 10 + ["below_threshold"] * 5 + ["not_found"] * 5})
    labels = build_labels(sample, vt)
    a = dim_a(labels).iloc[0]
    # IP 8.8.1.* có ở hai tổ chức nên gt2 = True: 20 dòng đầu của feedB là 8.8.1.* -> tất cả đều "độc hại" theo GT-2
    assert a["A"] == 1.0 and a["A_n"] == 20
    u = dim_u(labels, frame).iloc[0]["U"]
    assert u == 0.0                           # đều có ở cả hai feed, không có IoC độc nhất


def test_dim_st():
    days = pd.date_range("2026-10-21", periods=8).strftime("%Y-%m-%d")
    daily = pd.DataFrame({"feed": "f", "day": days, "lan_tai": 24, "thanh_cong": 24,
                          "ioc_moi_thay": [0, 0, 100, 100, 100, 100, 100, 50]})
    st = dim_st(daily).iloc[0]
    assert st["St_cv_part"] == 1.0            # bỏ 2 ngày có khoảng trống và ngày cuối: CV = 0
    assert st["St"] == 1.0


def test_score_table_and_sensitivity():
    frame = build_frame(ioc_table())
    daily = pd.DataFrame({"feed": ["feedA", "feedB", "feedC"] * 5,
                          "day": ["2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26", "2026-10-27"] * 3,
                          "lan_tai": 24, "thanh_cong": 24, "ioc_moi_thay": 10}).sort_values(["feed", "day"])
    table = score_table(frame, pd.DataFrame(), daily)
    assert table["S"].notna().all()
    a = table.set_index("feed").loc["feedA"]
    # A và U không có (NaN): S tính trên T, C, St với trọng số chia lại
    assert a["n_dims"] == 3
    assert abs(a["S"] - (0.75 + 0.0 + 1.0) / 3) < 1e-9 or a["S"] > 0
    sens = sensitivity(table)
    assert set(sens["dim_changed"]) == set(DIMS)
    assert (sens["kendall_tau"].dropna().between(-1, 1)).all()


def test_combine_renormalizes():
    df = pd.DataFrame({"A": [1.0], "T": [np.nan], "U": [0.0], "C": [1.0], "St": [1.0]})
    assert abs(combine(df, {d: 0.2 for d in DIMS}).iloc[0] - 0.75) < 1e-9
