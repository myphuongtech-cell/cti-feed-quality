"""Client TAXII 2.1: đẩy bundle STIX lên server, kéo về và kiểm tra khứ hồi (thí nghiệm E2).

Dùng (server phải đang chạy: python -m src.taxii_server):
    python -m src.taxii_client                         # đẩy mọi file trong data/processed/stix rồi kéo về kiểm tra
    python -m src.taxii_client --files path1.json ...
    python -m src.taxii_client --url http://127.0.0.1:5001

Đo: số đối tượng đẩy/kéo về, đối tượng mất, đối tượng khác nội dung, thời gian, lọc theo loại (type=indicator) và
theo ID, và kiểm tra bundle kéo về bằng stix2-validator (0 lỗi là đạt).
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from taxii2client.v21 import Collection, as_pages

from src.taxii_server import API_ROOT, COLLECTION_ID

ROOT = Path(__file__).resolve().parents[1]
STIX_DIR = ROOT / "data" / "processed" / "stix"
BATCH = 500


def connect(base_url: str, user: str, password: str) -> Collection:
    url = f"{base_url.rstrip('/')}/{API_ROOT}/collections/{COLLECTION_ID}/"
    return Collection(url, user=user, password=password)


def push_objects(collection: Collection, objects: list[dict], batch: int = BATCH) -> dict:
    ok = failed = 0
    for i in range(0, len(objects), batch):
        status = collection.add_objects({"objects": objects[i:i + batch]})
        status.wait_until_final(poll_interval=0.2, timeout=120)
        ok += status.success_count
        failed += status.failure_count
    return {"success": ok, "failure": failed}


def pull_all(collection: Collection, per_page: int = BATCH) -> list[dict]:
    objs: list[dict] = []
    for page in as_pages(collection.get_objects, per_request=per_page):
        objs.extend(page.get("objects", []))
    return objs


def load_bundle_objects(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8")).get("objects", [])


def compare(sent: list[dict], got: list[dict]) -> dict:
    sent_by_id = {o["id"]: o for o in sent}
    got_by_id = {o["id"]: o for o in got}
    missing = [i for i in sent_by_id if i not in got_by_id]
    extra = [i for i in got_by_id if i not in sent_by_id]
    changed = [i for i in sent_by_id if i in got_by_id and not _same(sent_by_id[i], got_by_id[i])]
    return {"sent": len(sent_by_id), "received": len(got_by_id), "missing": len(missing), "extra": len(extra),
            "changed": len(changed), "missing_ids": missing[:5], "changed_ids": changed[:5]}


def _same(a: dict, b: dict) -> bool:
    """Server có thể thêm/đổi cách ghi giờ; so sánh các trường lõi."""
    keys = ("type", "id", "spec_version", "pattern", "name", "valid_from", "valid_until", "confidence",
            "relationship_type", "source_ref", "target_ref", "is_family")
    return all(_norm(a.get(k)) == _norm(b.get(k)) for k in keys)


def _norm(v):
    return v.rstrip("Z").rstrip("0").rstrip(".") if isinstance(v, str) and v[:2] == "20" and "T" in v else v


def roundtrip(collection: Collection, objects: list[dict]) -> dict:
    t0 = time.time()
    push = push_objects(collection, objects)
    t_push = time.time() - t0
    t1 = time.time()
    got = pull_all(collection)
    t_pull = time.time() - t1
    res = compare(objects, got)
    res.update({"push_failures": push["failure"], "seconds_push": round(t_push, 2), "seconds_pull": round(t_pull, 2)})
    # lọc theo loại
    n_ind_sent = sum(1 for o in objects if o["type"] == "indicator")
    ind = []
    for page in as_pages(collection.get_objects, per_request=BATCH, type="indicator"):
        ind.extend(page.get("objects", []))
    res["filter_type_indicator_ok"] = len(ind) == n_ind_sent and all(o["type"] == "indicator" for o in ind)
    # lọc theo ID
    probe = next((o for o in objects if o["type"] == "indicator"), None)
    if probe:
        one = collection.get_objects(id=probe["id"]).get("objects", [])
        res["filter_id_ok"] = len(one) == 1 and one[0]["id"] == probe["id"]
    # bundle kéo về hợp lệ?
    from stix2validator import ValidationOptions, validate_string
    import uuid
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": got}
    vr = validate_string(json.dumps(bundle), ValidationOptions(version="2.1"))
    res["pulled_bundle_valid"] = bool(vr.is_valid)
    res["pulled_bundle_errors"] = len(vr.errors or [])
    return res


def main() -> int:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--files", nargs="*")
    args = ap.parse_args()
    files = [Path(f) for f in args.files] if args.files else sorted(STIX_DIR.glob("*.json"))
    if not files:
        print("Chưa có file STIX. Chạy trước: python -m src.to_stix --all --limit 2000")
        return 1
    col = connect(args.url, os.getenv("TAXII_USER", "admin"), os.getenv("TAXII_PASSWORD", "admin"))
    objects: dict[str, dict] = {}
    for f in files:
        for o in load_bundle_objects(f):
            objects[o["id"]] = o  # dùng chung identity và marking giữa các bundle
    print(f"Đẩy {len(objects)} đối tượng từ {len(files)} file...")
    res = roundtrip(col, list(objects.values()))
    for k, v in res.items():
        print(f"  {k}: {v}")
    ok = res["missing"] == 0 and res["changed"] == 0 and res["push_failures"] == 0 and res.get("pulled_bundle_valid", False)
    print("\nKẾT QUẢ E2 (TAXII):", "ĐẠT" if ok else "CÓ SAI LỆCH, xem chi tiết ở trên")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
