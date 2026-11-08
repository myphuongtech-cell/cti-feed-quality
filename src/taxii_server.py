"""TAXII 2.1 server cục bộ bằng medallion (bộ nhớ trong), dùng cho thí nghiệm E2.

Chạy:
    python -m src.taxii_server                 # lắng nghe ở http://127.0.0.1:5000
    python -m src.taxii_server --port 5001

Tài khoản mặc định (CHỈ dùng trên máy bạn, server chỉ nghe 127.0.0.1): admin / admin
Đổi bằng biến môi trường TAXII_USER và TAXII_PASSWORD (trong .env).
API root: cti    Collection: IoC đã chuẩn hóa (ID cố định, xem COLLECTION_ID)

Dữ liệu nằm trong bộ nhớ nên mất khi tắt server; nạp lại bằng src.taxii_client.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKDIR = ROOT / "data" / "taxii"
API_ROOT = "cti"
COLLECTION_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/myphuongtech-cell/cti-feed-quality/collection"))
MEDIA_TYPE = "application/stix+json;version=2.1"


def build_data(base_url: str) -> dict:
    base = base_url.rstrip("/")
    return {
        "/discovery": {
            "title": "CTI Feed Quality TAXII server (local)",
            "description": "Server TAXII 2.1 cục bộ cho tiểu luận môn Thu thập và phân tích thông tin an ninh mạng",
            "contact": "student",
            "default": f"{base}/{API_ROOT}/",
            "api_roots": [f"{base}/{API_ROOT}/"],
        },
        API_ROOT: {
            "information": {
                "title": "CTI Feed Quality",
                "description": "IoC từ feed mở, đã chuẩn hóa sang STIX 2.1",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 9765625,
            },
            "status": [],
            "collections": [{
                "id": COLLECTION_ID,
                "title": "IoC chuẩn hóa",
                "description": "Indicator, Malware, Relationship từ các feed đã thu thập",
                "can_read": True,
                "can_write": True,
                "media_types": [MEDIA_TYPE],
                "objects": [],
                "manifest": [],
            }],
        },
    }


def write_config(workdir: Path, host: str, port: int) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    data_path = workdir / "taxii_data.json"
    data_path.write_text(json.dumps(build_data(f"http://{host}:{port}"), indent=2), encoding="utf-8")
    cfg = {
        "backend": {"module": "medallion.backends.memory_backend", "module_class": "MemoryBackend",
                    "filename": str(data_path)},
        "users": {os.getenv("TAXII_USER", "admin"): os.getenv("TAXII_PASSWORD", "admin")},
        "taxii": {"max_page_size": 1000},
    }
    cfg_path = workdir / "medallion_config.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg_path


def serve(host: str = "127.0.0.1", port: int = 5000, workdir: Path = WORKDIR) -> None:
    from medallion import load_app
    app = load_app(write_config(workdir, host, port))
    print(f"TAXII server: http://{host}:{port}/taxii2/  (API root: {API_ROOT}, collection: {COLLECTION_ID})")
    print("Giữ cửa sổ này mở. Ctrl+C để dừng.")
    app.run(host=host, port=port, debug=False, threaded=True)


def main() -> None:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
