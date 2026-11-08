import pandas as pd

from src.overlap import coverage_curve, jaccard_matrix, key_sets, overlap_summary, run, unique_contribution


def frame():
    rows = []

    def add(feed, op, vals):
        for v in vals:
            rows.append({"feed": feed, "operator": op, "ioc_type": "ip", "key_value": f"10.0.0.{v}", "hash_type": ""})
    add("A", "O1", range(1, 7))     # 1..6
    add("B", "O2", range(4, 10))    # 4..9
    add("C", "O1", [1, 10])         # cùng tổ chức với A
    return pd.DataFrame(rows)


def test_jaccard_and_unique():
    s = key_sets(frame(), "ip")
    m = jaccard_matrix(s)
    assert abs(m.loc["A", "B"] - 3 / 9) < 1e-9 and m.loc["A", "A"] == 1.0
    u = unique_contribution(s).set_index("feed")
    assert u.loc["A", "unique_only"] == 2      # chỉ 2 và 3 (1 có ở C, 4 đến 6 có ở B)
    assert u.loc["C", "unique_only"] == 1      # chỉ 10


def test_coverage_curve_and_summary(tmp_path):
    s = key_sets(frame(), "ip")
    curve, greedy = coverage_curve(s, n_perm=50)
    assert curve["coverage_mean"].iloc[-1] == 1.0 and curve["coverage_greedy"].iloc[-1] == 1.0
    assert curve["coverage_mean"].is_monotonic_increasing
    assert greedy[0] in ("A", "B")              # feed lớn nhất trước
    summ = overlap_summary(frame()).iloc[0]
    assert summ["union_size"] == 10 and summ["n_operators"] == 2
    assert abs(summ["share_in_2plus_feeds"] - 4 / 10) < 1e-9       # IoC 1, 4, 5, 6
    assert abs(summ["share_in_2plus_operators"] - 3 / 10) < 1e-9   # IoC 4, 5, 6 (IoC 1 chỉ có ở hai feed cùng tổ chức)
    run(frame(), tmp_path)
    assert (tmp_path / "overlap_summary.csv").exists() and (tmp_path / "coverage_curve_ip.csv").exists()
    assert (tmp_path / "overlap_jaccard_operator_ip.csv").exists()
