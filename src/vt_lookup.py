"""Tra VirusTotal cho mẫu ground truth (GT-1).

An toàn và đúng đề cương:
- Chỉ dùng các lệnh GET để ĐỌC báo cáo đã có. Không gửi (POST) URL hay file để quét, không truy cập trực tiếp URL độc hại.
- Giới hạn tốc độ mặc định ~4 yêu cầu/phút, tối đa --max yêu cầu mỗi lần chạy (bản miễn phí có hạn mức ngày; kiểm tra hạn mức hiện hành).
- Chạy tiếp được: kết quả lưu vào data/processed/gt_vt.jsonl, IoC đã tra xong sẽ không bị tra lại.
- 404 nghĩa là VirusTotal chưa có báo cáo: ghi riêng là not_found, KHÔNG coi là lành tính.

Ngưỡng nhãn (khóa trong đề cương): độc hại nếu >= 5 engine (hash, URL) hoặc >= 3 engine (IP, domain) đánh dấu malicious.

Dùng:
    # đặt VT_API_KEY=... trong file .env
    python -m src.vt_lookup --max 400
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "processed" / "gt_sample.csv"
CACHE = ROOT / "data" / "processed" / "gt_vt.jsonl"
BASE = "https://www.virustotal.com/api/v3"
THRESHOLDS = {"hash": 5, "url": 5, "ip": 3, "domain": 3}


def url_id(url: str) -> str:
    """VirusTotal dùng base64 url-safe không đệm của URL làm định danh."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def endpoint(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return f"{BASE}/ip_addresses/{value}"
    if ioc_type == "domain":
        return f"{BASE}/domains/{value}"
    if ioc_type == "hash":
        return f"{BASE}/files/{value}"
    if ioc_type == "url":
        return f"{BASE}/urls/{url_id(value)}"
    raise ValueError(ioc_type)


def vt_label(ioc_type: str, malicious: int | None, http_status: int) -> str:
    """malicious | below_threshold | not_found | error"""
    if http_status == 404:
        return "not_found"
    if http_status != 200 or malicious is None:
        return "error"
    return "malicious" if malicious >= THRESHOLDS[ioc_type] else "below_threshold"


def parse_response(ioc_type: str, status: int, body: dict | None) -> dict:
    stats = {}
    last_date = None
    if status == 200 and body:
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        last_date = attrs.get("last_analysis_date")
    malicious = stats.get("malicious") if status == 200 else None
    return {
        "http_status": status,
        "malicious": malicious,
        "suspicious": stats.get("suspicious") if status == 200 else None,
        "harmless": stats.get("harmless") if status == 200 else None,
        "undetected": stats.get("undetected") if status == 200 else None,
        "last_analysis_date": last_date,
        "label": vt_label(ioc_type, malicious, status),
    }


def load_cache(path: Path = CACHE) -> dict[tuple[str, str], dict]:
    cache: dict[tuple[str, str], dict] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                cache[(r["ioc_type"], r["ioc_value"])] = r
    return cache


def lookup_one(session: requests.Session, key: str, ioc_type: str, value: str) -> dict:
    resp = session.get(endpoint(ioc_type, value), headers={"x-apikey": key, "accept": "application/json"}, timeout=30)
    if resp.status_code in (401, 403):
        raise PermissionError(f"VirusTotal từ chối khóa (HTTP {resp.status_code})")
    if resp.status_code == 429:
        raise RuntimeError("429")
    body = resp.json() if resp.status_code == 200 else None
    return parse_response(ioc_type, resp.status_code, body)


def run(max_requests: int, delay: float, session: requests.Session | None = None, key: str | None = None,
        sample_path: Path = SAMPLE, cache_path: Path = CACHE) -> int:
    key = key or os.getenv("VT_API_KEY", "").strip()
    if not key:
        print("Thiếu VT_API_KEY trong file .env")
        return 1
    if not sample_path.exists():
        print("Chưa có gt_sample.csv. Chạy trước: python -m src.groundtruth --asof ...")
        return 1
    sample = pd.read_csv(sample_path)
    cache = load_cache(cache_path)
    todo = [(r.ioc_type, r.ioc_value, r.feed) for r in sample.itertuples()
            if (r.ioc_type, r.ioc_value) not in cache]
    # một IoC có thể nằm trong nhiều tầng: chỉ tra một lần
    seen, queue = set(), []
    for t, v, f in todo:
        if (t, v) not in seen:
            seen.add((t, v))
            queue.append((t, v))
    print(f"Mẫu: {len(sample)} dòng | đã có kết quả: {len(cache)} | còn phải tra: {len(queue)} | lần này tối đa: {max_requests}")
    own = session is None
    session = session or requests.Session()
    done = 0
    try:
        for ioc_type, value in queue[:max_requests]:
            try:
                result = lookup_one(session, key, ioc_type, value)
            except RuntimeError:
                print("Bị giới hạn tốc độ (429). Dừng; chạy lại sau ít phút hoặc ngày mai.")
                break
            record = {"ioc_type": ioc_type, "ioc_value": value,
                      "queried_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **result}
            with open(cache_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            done += 1
            if done % 25 == 0:
                print(f"  đã tra {done}/{min(max_requests, len(queue))}")
            time.sleep(delay)
    except PermissionError as exc:
        print(exc)
        return 1
    finally:
        if own:
            session.close()
    print(f"Xong lượt này: {done} IoC. Tổng đã có kết quả: {len(cache) + done}.")
    return 0


def main() -> int:
    load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max", type=int, default=400, help="số yêu cầu tối đa mỗi lần chạy")
    ap.add_argument("--delay", type=float, default=15.5, help="giây chờ giữa hai yêu cầu (4/phút ~ 15 giây)")
    args = ap.parse_args()
    return run(args.max, args.delay)


if __name__ == "__main__":
    raise SystemExit(main())
