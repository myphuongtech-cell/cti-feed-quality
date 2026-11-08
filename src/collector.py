"""Thu thập feed mở theo định kỳ.

Nguyên tắc (xem docs/DECISIONS.md):
- Lưu bản thô bất biến (gzip, mtime=0) và ghi manifest.jsonl với SHA-256 cho MỌI lần tải.
- Chỉ lưu file mới khi nội dung đổi so với lần trước (tiết kiệm dung lượng); lần không đổi vẫn có dòng trong manifest.
- Thời gian luôn là UTC.
- Tôn trọng min_interval_minutes, dùng conditional GET (ETag / Last-Modified), có retry với backoff.

Cách chạy:
    python -m src.collector              # một lượt (dùng với cron / Task Scheduler, chạy mỗi giờ)
    python -m src.collector --loop 60    # tự lặp mỗi 60 phút (không cần cron)
    python -m src.collector --status     # xem tóm tắt từ manifest
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RAW = DATA / "raw"
META = DATA / "manifest"
MANIFEST = META / "manifest.jsonl"
STATE = META / "state.json"
LOCK = META / ".collector.lock"
LOGFILE = ROOT / "logs" / "collector.log"
LOCK_STALE_SECONDS = 30 * 60
INTERVAL_TOLERANCE_SECONDS = 300  # cho phép cron lệch vài phút

log = logging.getLogger("collector")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("state.json hỏng, tạo mới")
    return {}


def save_state(state: dict) -> None:
    META.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STATE)


def acquire_lock() -> bool:
    META.mkdir(parents=True, exist_ok=True)
    if LOCK.exists():
        age = time.time() - LOCK.stat().st_mtime
        if age < LOCK_STALE_SECONDS:
            return False
        log.warning("Xóa lock cũ (%.0f giây)", age)
        LOCK.unlink(missing_ok=True)
    try:
        with open(LOCK, "x", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        return True
    except FileExistsError:
        return False


def release_lock() -> None:
    LOCK.unlink(missing_ok=True)


def append_manifest(record: dict) -> None:
    META.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_headers(feed: dict, st: dict, force: bool) -> dict:
    contact = os.getenv("CONTACT_EMAIL", "your-email@example.com")
    headers = {"User-Agent": f"student-cti-research/1.0 (academic project; contact: {contact})"}
    if not force:
        if st.get("etag"):
            headers["If-None-Match"] = st["etag"]
        if st.get("last_modified"):
            headers["If-Modified-Since"] = st["last_modified"]
    return headers


def resolve_url(feed: dict) -> tuple[str | None, list[str], list[str]]:
    """Thay {TEN_BIEN} trong URL bằng biến môi trường (ví dụ {ABUSECH_AUTH_KEY}).

    Trả về (url đã thay hoặc None nếu thiếu biến, danh sách giá trị bí mật để che, danh sách biến còn thiếu).
    Bản ghi manifest và log luôn dùng URL MẪU (không chứa khóa).
    """
    url = feed["url"]
    secrets: list[str] = []
    missing: list[str] = []
    for name in re.findall(r"\{([A-Z0-9_]+)\}", url):
        value = os.getenv(name, "").strip()
        if value:
            url = url.replace("{" + name + "}", value)
            secrets.append(value)
        else:
            missing.append(name)
    return (None if missing else url), secrets, missing


def redact(text: str | None, secrets: list[str]) -> str | None:
    if text is None:
        return None
    for secret in secrets:
        text = text.replace(secret, "<KEY>")
    return text


def fetch(feed: dict, defaults: dict, st: dict, session: requests.Session, force: bool, url: str, secrets: list[str]) -> dict:
    retries = int(feed.get("retries", defaults.get("retries", 3)))
    timeout = (
        feed.get("timeout_connect_s", defaults.get("timeout_connect_s", 10)),
        feed.get("timeout_read_s", defaults.get("timeout_read_s", 90)),
    )
    headers = build_headers(feed, st, force)
    last_error = None
    started = time.monotonic()
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 429 or resp.status_code >= 500:
                last_error = f"HTTP {resp.status_code}"
                log.warning("%s: %s (lần %d/%d)", feed["id"], last_error, attempt, retries)
                time.sleep(2 ** attempt)
                continue
            return {
                "status": resp.status_code,
                "content": resp.content if resp.status_code == 200 else b"",
                "etag": resp.headers.get("ETag"),
                "last_modified": resp.headers.get("Last-Modified"),
                "attempts": attempt,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }
        except requests.RequestException as exc:
            last_error = redact(f"{type(exc).__name__}: {exc}", secrets)
            log.warning("%s: %s (lần %d/%d)", feed["id"], last_error, attempt, retries)
            time.sleep(2 ** attempt)
    return {
        "status": None,
        "content": b"",
        "etag": None,
        "last_modified": None,
        "attempts": retries,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "error": last_error,
    }


def store_raw(feed: dict, content: bytes, ts: datetime) -> Path:
    day = ts.strftime("%Y%m%d")
    stamp = ts.strftime("%Y%m%dT%H%M%SZ")
    folder = RAW / feed["id"] / day
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{feed['id']}_{stamp}.{feed.get('ext', 'txt')}.gz"
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as raw_f:
        with gzip.GzipFile(fileobj=raw_f, mode="wb", mtime=0) as gz:
            gz.write(content)
    os.replace(tmp, path)
    return path


def is_due(feed: dict, defaults: dict, st: dict, now: datetime, force: bool) -> bool:
    if force or not st.get("last_attempt_utc"):
        return True
    interval = int(feed.get("min_interval_minutes", defaults.get("min_interval_minutes", 60))) * 60
    last = datetime.strptime(st["last_attempt_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (now - last).total_seconds() >= interval - INTERVAL_TOLERANCE_SECONDS


def process_feed(feed: dict, defaults: dict, state: dict, session: requests.Session, force: bool) -> None:
    fid = feed["id"]
    st = state.setdefault(fid, {})
    now = utcnow()
    if not is_due(feed, defaults, st, now, force):
        log.info("%s: chưa đến hạn, bỏ qua", fid)
        return

    url, secrets, missing = resolve_url(feed)
    if url is None:
        ts = utcnow()
        msg = "thiếu biến môi trường: " + ", ".join(missing) + " (điền trong file .env)"
        log.error("%s: %s", fid, msg)
        st["last_attempt_utc"] = iso(ts)
        st["last_status"] = None
        append_manifest({
            "ts_utc": iso(ts), "feed": fid, "operator": feed.get("operator"), "url": feed["url"], "status": None,
            "bytes": 0, "sha256": None, "stored": False, "unchanged": False, "path": None, "etag": None,
            "last_modified": None, "attempts": 0, "elapsed_ms": 0, "error": msg,
        })
        save_state(state)
        return

    res = fetch(feed, defaults, st, session, force, url, secrets)
    ts = utcnow()
    record = {
        "ts_utc": iso(ts),
        "feed": fid,
        "operator": feed.get("operator"),
        "url": feed["url"],
        "status": res["status"],
        "bytes": len(res["content"]),
        "sha256": None,
        "stored": False,
        "unchanged": False,
        "path": None,
        "etag": res["etag"],
        "last_modified": res["last_modified"],
        "attempts": res["attempts"],
        "elapsed_ms": res["elapsed_ms"],
        "error": res["error"],
    }

    if res["status"] == 200:
        digest = sha256_hex(res["content"])
        record["sha256"] = digest
        if digest == st.get("last_sha256"):
            record["unchanged"] = True
            log.info("%s: 200 nhưng nội dung không đổi", fid)
        else:
            path = store_raw(feed, res["content"], ts)
            record["stored"] = True
            record["path"] = str(path.relative_to(ROOT))
            st["last_sha256"] = digest
            log.info("%s: đã lưu %s (%d byte)", fid, record["path"], record["bytes"])
        st["etag"] = res["etag"]
        st["last_modified"] = res["last_modified"]
    elif res["status"] == 304:
        record["unchanged"] = True
        log.info("%s: 304 không đổi", fid)
    else:
        log.error("%s: thất bại, status=%s, lỗi=%s", fid, res["status"], res["error"])
        if res["status"] in (401, 403):
            log.error("%s: bị từ chối, kiểm tra khóa trong .env", fid)
        if res["status"] in (404, 410):
            log.error("%s: địa chỉ không còn tồn tại, kiểm tra lại URL trong config/feeds.yaml", fid)

    st["last_attempt_utc"] = iso(ts)
    st["last_status"] = res["status"]
    append_manifest(record)
    save_state(state)


def run_once(config: dict, only: list[str] | None, force: bool) -> int:
    if not acquire_lock():
        log.error("Đang có tiến trình khác chạy (lock). Thoát.")
        return 2
    try:
        defaults = config.get("defaults", {})
        feeds = config["feeds"]
        if only:
            feeds = [f for f in feeds if f["id"] in only]
        state = load_state()
        with requests.Session() as session:
            for feed in feeds:
                try:
                    process_feed(feed, defaults, state, session, force)
                except Exception:  # một feed lỗi không được làm hỏng các feed khác
                    log.exception("%s: lỗi không mong đợi", feed["id"])
                time.sleep(1)
        return 0
    finally:
        release_lock()


def show_status() -> None:
    if not MANIFEST.exists():
        print("Chưa có manifest.")
        return
    rows = [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_feed: dict[str, list[dict]] = {}
    for r in rows:
        by_feed.setdefault(r["feed"], []).append(r)
    print(f"{'feed':16} {'lượt':>5} {'200/304':>8} {'lỗi':>5} {'đã lưu':>7} {'lần cuối (UTC)':>22} {'status':>7}")
    for fid, rs in sorted(by_feed.items()):
        ok = sum(1 for r in rs if r["status"] in (200, 304))
        err = len(rs) - ok
        stored = sum(1 for r in rs if r["stored"])
        last = rs[-1]
        print(f"{fid:16} {len(rs):>5} {ok:>8} {err:>5} {stored:>7} {last['ts_utc']:>22} {str(last['status']):>7}")


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(ROOT / "config" / "feeds.yaml"))
    parser.add_argument("--only", nargs="*", help="chỉ chạy các feed id này")
    parser.add_argument("--force", action="store_true", help="bỏ qua kiểm tra khoảng cách tối thiểu và conditional GET")
    parser.add_argument("--loop", type=int, metavar="PHUT", help="lặp lại mỗi PHUT phút (Ctrl+C để dừng)")
    parser.add_argument("--status", action="store_true", help="in tóm tắt từ manifest rồi thoát")
    args = parser.parse_args()

    if args.status:
        show_status()
        return 0

    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOGFILE, encoding="utf-8"), logging.StreamHandler(sys.stderr)],
    )
    logging.Formatter.converter = time.gmtime  # log theo UTC

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))

    if args.loop:
        try:
            while True:
                run_once(config, args.only, args.force)
                time.sleep(max(60, args.loop * 60))
        except KeyboardInterrupt:
            log.info("Dừng theo yêu cầu.")
            return 0
    return run_once(config, args.only, args.force)


if __name__ == "__main__":
    sys.exit(main())
