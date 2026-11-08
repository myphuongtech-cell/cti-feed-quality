import csv
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pandas as pd

from src import vt_lookup
from src.groundtruth import build_frame, draw_sample, load_tranco
from src.tranco import read_rows

T = datetime(2026, 10, 26, tzinfo=timezone.utc)


def ioc_rows():
    def r(feed, op, t, v, age_h, ht=None):
        ts = (T - timedelta(hours=age_h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"feed": feed, "operator": op, "ioc_type": t, "ioc_value": v, "hash_type": ht,
                "first_check_ts": ts, "last_check_ts": ts}
    rows = []
    for i in range(150):
        rows.append(r("blocklist_de", "Blocklist.de", "ip", f"8.8.{i // 250}.{i % 250 + 1}", 100))
    rows += [
        r("cins", "CINS Score", "ip", "8.8.0.1", 100),           # cùng IP với blocklist_de -> hai tổ chức khác nhau
        r("blocklist_de", "Blocklist.de", "ip", "192.168.0.5", 100),   # IP riêng: bị loại
        r("blocklist_de", "Blocklist.de", "ip", "8.8.9.9", 10),         # quá mới: chưa đủ tuổi
        r("malwarebazaar", "abuse.ch", "hash", "a" * 32, 100, "md5"),   # md5 của MalwareBazaar: bị loại
        r("malwarebazaar", "abuse.ch", "hash", "b" * 64, 100, "sha256"),
        r("threatfox", "abuse.ch", "hash", "b" * 64, 100, "sha256"),    # cùng tổ chức (abuse.ch) -> không tính hai nguồn
        r("urlhaus", "abuse.ch", "url", "http://google.com/x", 100),
        r("threatfox", "abuse.ch", "domain", "evil-new.xyz", 100),
    ]
    return pd.DataFrame(rows)


def test_frame_filters_and_gt2():
    f = build_frame(ioc_rows(), tranco={"google.com"})
    assert not ((f["ioc_value"] == "192.168.0.5")).any()
    assert not ((f["feed"] == "malwarebazaar") & (f["hash_type"] == "md5")).any()
    ip = f[(f["ioc_value"] == "8.8.0.1")]
    assert set(ip["feed"]) == {"blocklist_de", "cins"} and ip["gt2"].all()
    sha = f[f["ioc_value"] == "b" * 64]
    assert not sha["gt2"].any()                      # cả hai feed đều thuộc abuse.ch
    assert f[f["ioc_value"] == "http://google.com/x"]["fp_tranco"].iloc[0]
    assert not f[f["ioc_value"] == "evil-new.xyz"]["fp_tranco"].iloc[0]


def test_sample_is_stratified_deterministic_and_age_filtered():
    f = build_frame(ioc_rows())
    a = draw_sample(f, T, per_stratum=100)
    b = draw_sample(f, T, per_stratum=100)
    assert a["ioc_value"].tolist() == b["ioc_value"].tolist()
    bl = a[a["stratum"] == "blocklist_de|ip"]
    assert len(bl) == 100 and (bl["stratum_size"] == 150).all()   # 192.168.* và IP quá mới đã bị loại
    assert "8.8.9.9" not in set(a["ioc_value"])
    assert (a["first_check_ts"] <= pd.Timestamp(T - timedelta(hours=48))).all()


def test_url_id_and_endpoints():
    assert vt_lookup.url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"
    assert vt_lookup.endpoint("ip", "1.2.3.4").endswith("/ip_addresses/1.2.3.4")
    assert vt_lookup.endpoint("hash", "ab").endswith("/files/ab")


def test_labels_use_preregistered_thresholds():
    assert vt_lookup.vt_label("hash", 5, 200) == "malicious"
    assert vt_lookup.vt_label("hash", 4, 200) == "below_threshold"
    assert vt_lookup.vt_label("ip", 3, 200) == "malicious"
    assert vt_lookup.vt_label("domain", 2, 200) == "below_threshold"
    assert vt_lookup.vt_label("url", None, 404) == "not_found"
    assert vt_lookup.vt_label("url", None, 500) == "error"


def test_parse_response():
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 10},
                                    "last_analysis_date": 1700000000}}}
    r = vt_lookup.parse_response("url", 200, body)
    assert r["malicious"] == 7 and r["label"] == "malicious"
    assert vt_lookup.parse_response("url", 404, None)["label"] == "not_found"


class FakeResp:
    def __init__(self, status, body=None):
        self.status_code, self._b = status, body

    def json(self):
        return self._b


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        assert headers["x-apikey"] == "KEY"
        if "9.9.9.9" in url:
            return FakeResp(404)
        return FakeResp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 6}}}})

    def close(self):
        pass


def test_run_is_resumable_and_never_requeries(tmp_path, monkeypatch):
    sample = tmp_path / "gt_sample.csv"
    cache = tmp_path / "gt_vt.jsonl"
    pd.DataFrame({"ioc_type": ["ip", "ip", "ip"], "ioc_value": ["1.1.1.1", "9.9.9.9", "2.2.2.2"],
                  "feed": ["a", "a", "b"]}).to_csv(sample, index=False)
    monkeypatch.setattr(vt_lookup, "CACHE", cache)
    s = FakeSession()
    assert vt_lookup.run(2, 0, session=s, key="KEY", sample_path=sample, cache_path=cache) == 0
    assert len(s.calls) == 2
    s2 = FakeSession()
    assert vt_lookup.run(10, 0, session=s2, key="KEY", sample_path=sample, cache_path=cache) == 0
    assert len(s2.calls) == 1                      # chỉ tra IoC còn lại
    rows = [json.loads(l) for l in cache.read_text(encoding="utf-8").splitlines()]
    labels = {r["ioc_value"]: r["label"] for r in rows}
    assert labels == {"1.1.1.1": "malicious", "9.9.9.9": "not_found", "2.2.2.2": "malicious"}


def test_tranco_prepare_from_zip(tmp_path):
    z = tmp_path / "top-1m.csv.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("top-1m.csv", "1,Google.com\n2,facebook.com\n3,pages.dev\n")
    assert read_rows(z, 2) == [["1", "google.com"], ["2", "facebook.com"]]
    p = tmp_path / "t.csv"
    p.write_text("1,google.com\n2,x.com\n", encoding="utf-8")
    assert load_tranco(p, top=1) == {"google.com"}
