import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import pandas as pd
import pytest
import requests

from src.feeds import STD_COLS
from src.taxii_client import compare, connect, pull_all, push_objects, roundtrip
from src.taxii_server import COLLECTION_ID, build_data, write_config
from src.to_stix import build_bundle

TS = datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def sample_objects(n=30):
    base = {c: None for c in STD_COLS}
    rows = [{**base, "ioc_type": "ip", "ioc_value": f"8.8.{i // 200}.{i % 200 + 1}", "malware": "Bot" if i % 3 == 0 else None}
            for i in range(n)]
    rows.append({**base, "ioc_type": "url", "ioc_value": "http://evil.com/a?b='c'", "status": "online"})
    df = pd.DataFrame(rows, columns=STD_COLS)
    return json.loads(build_bundle(df, "testfeed", TS).serialize())["objects"]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    port = free_port()
    work = tmp_path_factory.mktemp("taxii")
    cfg = write_config(work, "127.0.0.1", port)
    code = f"from medallion import load_app; load_app(r'{cfg}').run(host='127.0.0.1', port={port}, debug=False)"
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            r = requests.get(base + "/taxii2/", auth=("admin", "admin"), headers={"Accept": "application/taxii+json;version=2.1"}, timeout=1)
            if r.status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.25)
    else:
        proc.kill()
        pytest.fail("server không khởi động được")
    yield base
    proc.kill()


def test_build_data_has_collection():
    d = build_data("http://127.0.0.1:5000")
    assert d["cti"]["collections"][0]["id"] == COLLECTION_ID
    assert d["/discovery"]["default"] == "http://127.0.0.1:5000/cti/"


def test_compare_detects_missing_and_changed():
    a = [{"type": "indicator", "id": "indicator--1", "pattern": "p1"}, {"type": "indicator", "id": "indicator--2", "pattern": "p2"}]
    b = [{"type": "indicator", "id": "indicator--1", "pattern": "CHANGED"}]
    r = compare(a, b)
    assert r["missing"] == 1 and r["changed"] == 1 and r["sent"] == 2 and r["received"] == 1


def test_roundtrip_through_real_taxii_server(server):
    objects = sample_objects()
    col = connect(server, "admin", "admin")
    res = roundtrip(col, objects)
    assert res["push_failures"] == 0
    assert res["missing"] == 0 and res["changed"] == 0 and res["extra"] == 0
    assert res["sent"] == res["received"] == len({o["id"] for o in objects})
    assert res["filter_type_indicator_ok"] and res["filter_id_ok"]
    assert res["pulled_bundle_valid"], res
