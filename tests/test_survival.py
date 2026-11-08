import numpy as np
import pandas as pd

from src.survival import cohort, e4a_durations, e4b_urlhaus, km_summary, logrank


def make(n_each=60):
    rng = np.random.default_rng(1)
    rows = []
    for t, scale in (("ip", 200.0), ("url", 20.0)):
        for i in range(n_each):
            dur = float(rng.exponential(scale))
            rows.append({"feed": "f1", "operator": "o", "ioc_type": t, "listing_hours": min(dur, 300.0),
                         "delisted": dur < 300.0, "present_in_first_snapshot": False, "gap_affected": False})
    return pd.DataFrame(rows)


def test_cohort_excludes_initial_and_gap():
    df = make(40)
    df.loc[0, "present_in_first_snapshot"] = True
    df.loc[1, "gap_affected"] = True
    assert len(cohort(df)) == len(df) - 2


def test_km_and_logrank_detect_difference():
    d = e4a_durations(cohort(make()))
    s = km_summary(d, ["ioc_type"]).set_index("ioc_type")
    assert s.loc["url", "median_hours"] < s.loc["ip", "median_hours"] or np.isnan(s.loc["ip", "median_hours"])
    lr = logrank(d, "ioc_type")
    assert lr.iloc[0]["p_value"] < 0.001


def test_small_groups_not_compared():
    d = e4a_durations(cohort(make(10)))
    s = km_summary(d, ["ioc_type"])
    assert s["median_note"].str.contains("quá nhỏ").all()
    assert logrank(d, "ioc_type").empty


def test_e4b_event_definition():
    t0 = pd.Timestamp("2026-10-25 00:00:00", tz="UTC")
    rows = []
    for i in range(40):
        went_offline = i % 2 == 0
        rows.append({"feed": "urlhaus", "ioc_type": "url", "present_in_first_snapshot": False, "status_first": "online",
                     "first_check_ts": t0.isoformat(), "last_check_ts": (t0 + pd.Timedelta(hours=100)).isoformat(),
                     "first_offline_ts": (t0 + pd.Timedelta(hours=10)).isoformat() if went_offline else None})
    rows.append({"feed": "urlhaus", "ioc_type": "url", "present_in_first_snapshot": False, "status_first": "offline",
                 "first_check_ts": t0.isoformat(), "last_check_ts": t0.isoformat(), "first_offline_ts": t0.isoformat()})
    out = e4b_urlhaus(pd.DataFrame(rows))
    assert len(out) == 40                         # IoC đã offline ngay từ đầu bị loại
    assert out["event"].sum() == 20 and out[out.event == 1]["duration_h"].eq(10).all()
    assert out[out.event == 0]["duration_h"].eq(100).all()
