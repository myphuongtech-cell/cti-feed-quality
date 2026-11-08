import json

import numpy as np

from src.eval_e1 import (aggregate, bootstrap, cohens_kappa, counts, h1_decision, kappa_between, load_gold, macro_f1,
                          prf, run_eval)
from src.fetch_reports import html_to_text


def test_prf_edge_cases():
    assert prf(2, 0, 0) == (1.0, 1.0, 1.0)
    p, r, f = prf(0, 3, 2)
    assert (p, r, f) == (0.0, 0.0, 0.0)
    assert np.isnan(prf(0, 0, 0)[2])


def test_counts_and_aggregate_skip_types_without_gold():
    pred = {"ip": {"1.1.1.1", "2.2.2.2"}, "domain": set(), "url": set(), "hash": set()}
    gold = {"ip": {"1.1.1.1", "3.3.3.3"}, "domain": set(), "url": set(), "hash": set()}
    c = counts(pred, gold)
    assert c["ip"] == (1, 1, 1)
    agg = aggregate([c])
    assert agg["ip"][2] == 0.5 and np.isnan(agg["domain"][2])
    assert macro_f1(agg) == 0.5               # chỉ trung bình các loại có nhãn


def test_h1_decision_rules():
    assert h1_decision(0.08, (0.03, 0.12)).startswith("ỦNG HỘ")
    assert h1_decision(0.08, (-0.01, 0.15)).startswith("BÁC BỎ")
    assert h1_decision(0.01, (0.0, 0.02)).startswith("BÁC BỎ")
    assert h1_decision(0.03, (0.01, 0.05)).startswith("KHÔNG KẾT LUẬN")


def test_kappa():
    assert cohens_kappa([1, 0, 1, 0], [1, 0, 1, 0]) == 1.0
    assert abs(cohens_kappa([1, 1, 0, 0], [1, 0, 1, 0])) < 1e-9
    a = {"d1": {"ip": {"1.1.1.1"}, "domain": set(), "url": set(), "hash": set()}}
    b = {"d1": {"ip": {"1.1.1.1", "2.2.2.2"}, "domain": set(), "url": set(), "hash": set()}}
    assert 0 <= kappa_between(a, b) <= 1


def test_end_to_end_pipeline_beats_baseline(tmp_path):
    texts, gold = tmp_path / "texts", tmp_path / "gold"
    texts.mkdir()
    gold.mkdir()
    docs = {}
    for i in range(12):
        docs[f"d{i}"] = (
            f"Sample {i} beacons to hxxp://evil{i}[.]com/gate and 8[.]8[.]{i + 1}[.]4. Internal host 10.0.0.{i + 1}, "
            f"version 1.2.3.4, see attack.mitre.org, dropped setup.exe.",
            {"ip": [f"8.8.{i + 1}.4"], "domain": [], "url": [f"http://evil{i}.com/gate"], "hash": []},
        )
    for d, (text, g) in docs.items():
        (texts / f"{d}.txt").write_text(text, encoding="utf-8")
        (gold / f"{d}.json").write_text(json.dumps(g), encoding="utf-8")
    metrics, errors, ci, info = run_eval(texts, gold, None)
    f1 = metrics.set_index(["system", "type"])["f1"]
    assert f1[("pipeline", "MACRO")] > f1[("baseline", "MACRO")]
    assert f1[("pipeline", "ip")] == 1.0 and f1[("pipeline", "url")] == 1.0
    assert (errors["system"] == "baseline").any() and not (errors["system"] == "pipeline").any()
    assert ci["diff"][0] > 0                   # khoảng tin cậy của chênh lệch không chứa 0
    assert int(info["n_docs"][0]) == 12


def test_bootstrap_is_deterministic():
    docs = [{"ip": (1, 0, 0), "domain": (0, 0, 0), "url": (0, 0, 0), "hash": (0, 0, 0)}] * 5
    a = bootstrap({"baseline": docs, "pipeline": docs}, n_boot=50)
    b = bootstrap({"baseline": docs, "pipeline": docs}, n_boot=50)
    assert a == b


def test_html_to_text_strips_scripts():
    html = "<html><head><title>x</title></head><body><script>var a='1.2.3.4';</script><p>C2: evil[.]com</p><nav>menu</nav></body></html>"
    t = html_to_text(html)
    assert "evil[.]com" in t and "1.2.3.4" not in t and "menu" not in t
