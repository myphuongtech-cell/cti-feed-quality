import json
from datetime import datetime, timezone

import pandas as pd
import stix2

from src.feeds import STD_COLS
from src.to_stix import build_bundle, confidence_from_score, make_pattern, pattern_to_ioc
from src.validate_stix import validate_file

TS = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)


def frame(rows):
    base = {c: None for c in STD_COLS}
    return pd.DataFrame([{**base, **r} for r in rows], columns=STD_COLS)


def sample():
    return frame([
        {"ioc_type": "ip", "ioc_value": "1.2.3.4", "port": "443", "malware": "Some Bot", "threat": "botnet_cc",
         "source_first_seen": pd.Timestamp("2026-10-22 07:00:00", tz="UTC")},
        {"ioc_type": "domain", "ioc_value": "bad-domain.com"},
        {"ioc_type": "url", "ioc_value": "http://evil.com/a.php?x=1&y='2'", "status": "online", "tags": "elf,Mozi"},
        {"ioc_type": "url", "ioc_value": "http://evil.com/back\\slash"},
        {"ioc_type": "hash", "ioc_value": "44d88612fea8a8f36de82e1278abb02f", "hash_type": "md5", "malware": "Some Bot"},
        {"ioc_type": "hash", "ioc_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash_type": "sha256"},
    ])


def test_patterns_roundtrip_with_escaping():
    cases = [("ip", "1.2.3.4", None), ("domain", "a.b.com", None),
             ("url", "http://x.com/it's\\ok", None), ("hash", "ab" * 16, "md5"), ("hash", "cd" * 32, "sha256")]
    for t, v, h in cases:
        assert pattern_to_ioc(make_pattern(t, v, h)) == (t, v, h)


def test_bundle_structure():
    b = build_bundle(sample(), "threatfox", TS, operator="abuse.ch")
    kinds = [o["type"] for o in json.loads(b.serialize())["objects"]]
    assert kinds.count("indicator") == 6
    assert kinds.count("malware") == 1  # "Some Bot" dùng chung
    assert kinds.count("relationship") == 2
    assert "marking-definition" in kinds and "identity" in kinds


def test_deterministic_ids_and_dedup():
    df = pd.concat([sample(), sample()], ignore_index=True)
    a = json.loads(build_bundle(df, "threatfox", TS).serialize())
    b = json.loads(build_bundle(sample(), "threatfox", TS).serialize())
    ids_a = sorted(o["id"] for o in a["objects"])
    ids_b = sorted(o["id"] for o in b["objects"])
    assert ids_a == ids_b


def test_valid_until_after_valid_from_and_confidence():
    b = json.loads(build_bundle(sample(), "urlhaus", TS, confidence=80).serialize())
    for o in b["objects"]:
        if o["type"] == "indicator":
            assert o["valid_until"] > o["valid_from"]
            assert o["confidence"] == 80
    assert confidence_from_score(0.734) == 73 and confidence_from_score(2) == 100


def test_old_ioc_still_has_valid_until_after_valid_from():
    df = frame([{"ioc_type": "url", "ioc_value": "http://old.example-bad.com/x",
                 "source_first_seen": pd.Timestamp("2026-01-01", tz="UTC")}])
    o = [x for x in json.loads(build_bundle(df, "urlhaus", TS).serialize())["objects"] if x["type"] == "indicator"][0]
    assert o["valid_until"] > o["valid_from"]


def test_validator_and_roundtrip(tmp_path):
    b = build_bundle(sample(), "threatfox", TS)
    p = tmp_path / "b.json"
    p.write_text(b.serialize(pretty=True), encoding="utf-8")
    r = validate_file(p)
    assert r["valid"], r["errors"]
    assert r["errors"] == []
    assert r["roundtrip_ok"] == r["indicators"] == 6
    assert r["parsed_objects"] == r["objects"]
    assert stix2.parse(p.read_text(encoding="utf-8"), version="2.1")
