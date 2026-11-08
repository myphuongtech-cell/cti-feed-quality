"""Tải các báo cáo bảo mật công khai về dạng văn bản thuần để làm thí nghiệm E1.

Đầu vào: data/reports.csv với các cột: doc_id,url,title,source
    doc_id  mã ngắn không dấu cách, ví dụ r001
Đầu ra:  data/e1/texts/<doc_id>.txt  và  data/e1/fetch_log.csv (thời điểm tải, trạng thái, SHA-256 của văn bản)

Lưu ý bản quyền và đạo đức:
- Văn bản chỉ để phân tích nghiên cứu. KHÔNG commit data/e1/texts/ lên GitHub (đã nằm trong gợi ý .gitignore); chỉ commit
  data/reports.csv (liên kết) và data/e1/gold/ (nhãn tay của bạn).
- Tôn trọng robots.txt/điều khoản của trang; script chờ 3 giây giữa hai yêu cầu và dùng User-Agent nêu rõ mục đích.
- Không ghi tên cá nhân; nếu báo cáo chứa dữ liệu cá nhân thì loại bỏ trước khi lưu.

Dùng:
    python -m src.fetch_reports
"""
from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "data" / "reports.csv"
TEXTS = ROOT / "data" / "e1" / "texts"
LOG = ROOT / "data" / "e1" / "fetch_log.csv"
DELAY = 3.0


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer"}

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        if tag in {"p", "br", "li", "tr", "h1", "h2", "h3", "h4", "pre", "div"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    text = "".join(p.parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def pdf_to_text(data: bytes) -> str:
    import pdfplumber
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        return "\n\n".join((page.extract_text() or "") for page in pdf.pages).strip()


def fetch_text(session: requests.Session, url: str) -> tuple[int | None, str]:
    resp = session.get(url, timeout=45)
    if resp.status_code != 200:
        return resp.status_code, ""
    ctype = resp.headers.get("Content-Type", "").lower()
    if "pdf" in ctype or url.lower().split("?")[0].endswith(".pdf"):
        return 200, pdf_to_text(resp.content)
    return 200, html_to_text(resp.text)


def main() -> None:
    load_dotenv(ROOT / ".env")
    if not REPORTS.exists():
        print("Chưa có data/reports.csv (cột: doc_id,url,title,source).")
        return
    contact = os.getenv("CONTACT_EMAIL", "your-email@example.com")
    TEXTS.mkdir(parents=True, exist_ok=True)
    new_log = not LOG.exists()
    with open(REPORTS, encoding="utf-8", newline="") as f, open(LOG, "a", encoding="utf-8", newline="") as lf, \
            requests.Session() as s:
        s.headers["User-Agent"] = f"student-cti-research/1.0 (academic project; contact: {contact})"
        log = csv.writer(lf)
        if new_log:
            log.writerow(["doc_id", "url", "fetched_at_utc", "http_status", "chars", "sha256", "note"])
        for row in csv.DictReader(f):
            doc_id, url = row["doc_id"].strip(), row["url"].strip()
            out = TEXTS / f"{doc_id}.txt"
            if out.exists():
                continue
            note = ""
            try:
                status, text = fetch_text(s, url)
            except Exception as exc:  # noqa: BLE001
                status, text, note = None, "", f"{type(exc).__name__}"
            when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if status == 200 and len(text) > 300:
                out.write_text(text, encoding="utf-8")
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                print(f"{doc_id}: OK ({len(text):,} ký tự)")
            else:
                digest = ""
                note = note or "không lấy được văn bản (trống, chặn, hoặc cần đăng nhập)"
                print(f"{doc_id}: BỎ QUA (status={status}) {url}")
            log.writerow([doc_id, url, when, status, len(text), digest, note])
            time.sleep(DELAY)


if __name__ == "__main__":
    main()
