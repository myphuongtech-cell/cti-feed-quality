"""Trích xuất IoC từ văn bản phi cấu trúc (thí nghiệm E1).

Pipeline: refang (khử defang) -> regex ứng viên -> kiểm tra hợp lệ -> lọc ngữ cảnh -> chuẩn hóa -> khử trùng lặp.

Có hai mức để so sánh trong E1:
- baseline "regex thuần": extract_iocs(text, refang_input=False, validate=False, context_filter=None)
- pipeline đầy đủ:        extract_iocs(text, context_filter=ContextFilter())

Giới hạn đã biết (ghi vào báo cáo): một số đuôi file trùng TLD thật (.zip, .sh, .py, .pl, .so) bị
coi là đuôi file nên domain thuộc các TLD này sẽ bị bỏ sót; IPv6 chưa được hỗ trợ.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Ioc:
    type: str  # ip | domain | url | hash
    value: str
    start: int
    end: int
    hash_type: str | None = None


# ---------------------------------------------------------------- khử defang
_REFANG_RULES = [
    (re.compile(r"(?i)\bhxxp(s?)(?=[^a-z0-9]|$)"), lambda m: "http" + m.group(1)),
    (re.compile(r"(?i)\bfxp(s?)(?=[^a-z0-9]|$)"), lambda m: "ftp" + m.group(1)),
    (re.compile(r"(?i)\[\s*://\s*\]"), "://"),
    (re.compile(r"(?i)\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}"), "."),
    (re.compile(r"(?i)\[\s*/\s*\]"), "/"),
]


def refang(text: str) -> str:
    """Đưa IoC bị làm mờ (hxxp, [.], (dot)...) về dạng chuẩn."""
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


# ---------------------------------------------------------------- regex ứng viên
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
_DOMAIN = re.compile(
    r"(?i)(?<![\w@.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w\-]|\.[a-z0-9])"
)
_HASH = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9A-Za-z])")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

# Đuôi file hay bị nhầm thành TLD
FILE_EXTENSIONS = {
    "exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z", "txt", "js", "py",
    "php", "html", "htm", "css", "png", "jpg", "jpeg", "gif", "bat", "ps1", "sh", "json", "xml", "csv", "log",
    "tmp", "lnk", "iso", "img", "msi", "vbs", "jar", "apk", "bin", "dat", "sys", "so", "pl", "rb", "cpp", "go",
    "rs", "md", "yml", "yaml", "ini", "cfg", "conf", "db", "sql", "bak", "dmp", "pcap", "eml", "msg", "rtf",
    "odt", "swf", "ko", "elf", "scr", "cab", "tar", "gz", "bz2", "sct", "hta", "wsf", "vbe", "jse",
}
RESERVED_TLDS = {"local", "localhost", "test", "invalid", "example", "internal", "lan", "home", "arpa"}

# Hash của file rỗng (không phải IoC)
EMPTY_FILE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

_VERSION_WORDS = {"version", "ver", "v", "release", "build", "kb", "rev", "revision"}

# Trang tham khảo thường xuất hiện trong báo cáo, không phải IoC. Khớp cả tên miền cha.
BENIGN_REFERENCE_DOMAINS = {
    "example.com", "example.org", "example.net", "mitre.org", "virustotal.com", "github.com", "twitter.com",
    "x.com", "linkedin.com", "facebook.com", "microsoft.com", "google.com", "wikipedia.org", "cisa.gov",
    "nist.gov", "youtube.com", "medium.com", "abuse.ch", "anthropic.com",
}


class ContextFilter:
    """Lọc ngữ cảnh: bỏ domain/URL tham khảo, IP không công khai, domain thuộc Tranco top-N (khớp chính xác)."""

    def __init__(self, benign_domains: set[str] | None = None, tranco_path: str | Path | None = None, tranco_top: int = 10000):
        self.benign = {d.lower() for d in (benign_domains if benign_domains is not None else BENIGN_REFERENCE_DOMAINS)}
        self.tranco: set[str] = set()
        if tranco_path and Path(tranco_path).exists():
            with open(tranco_path, encoding="utf-8", newline="") as f:
                for i, row in enumerate(csv.reader(f)):
                    if i >= tranco_top:
                        break
                    if len(row) >= 2:
                        self.tranco.add(row[1].strip().lower())

    def is_benign_domain(self, domain: str) -> bool:
        d = domain.lower().strip(".")
        labels = d.split(".")
        # khớp tên miền cha trong danh sách tham khảo cố định
        for i in range(len(labels) - 1):
            if ".".join(labels[i:]) in self.benign:
                return True
        # Tranco: chỉ khớp chính xác, vì hosting dùng chung (pages.dev, ...) có thể nằm trong top
        return d in self.tranco

    def is_benign_ip(self, ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_global
        except ValueError:
            return True

    def is_benign_url(self, url: str) -> bool:
        host = _url_host(url)
        if not host:
            return True
        try:
            ipaddress.ip_address(host)
            return self.is_benign_ip(host)
        except ValueError:
            return self.is_benign_domain(host)


# ---------------------------------------------------------------- tiện ích
def _url_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _clean_url(raw: str) -> str:
    url = raw
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in ")]}":
            opener = {")": "(", "]": "[", "}": "{"}[last]
            if url.count(last) > url.count(opener):
                url = url[:-1]
            else:
                break
        else:
            break
    return url


def normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme or not parts.netloc:
        return url
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    if parts.username:
        netloc = f"{parts.username}@{netloc}"
    rebuilt = f"{parts.scheme.lower()}://{netloc}{parts.path}"
    if parts.query:
        rebuilt += "?" + parts.query
    return rebuilt


def _prev_word(text: str, start: int) -> str:
    m = re.search(r"(\w+)\W{0,3}$", text[max(0, start - 14):start])
    return m.group(1).lower() if m else ""


def _inside(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(s <= start and end <= e for s, e in spans)


# ---------------------------------------------------------------- trích xuất chính
def extract_iocs(
    text: str,
    *,
    context_filter: ContextFilter | None = None,
    refang_input: bool = True,
    validate: bool = True,
    url_hosts: bool = False,
) -> list[Ioc]:
    """Trả về danh sách IoC duy nhất (theo loại và giá trị), sắp theo vị trí xuất hiện.

    Vị trí start/end tính trên văn bản SAU khi khử defang.
    url_hosts=False: IP/domain nằm trong một URL đã trích thì không tách riêng.
    """
    if refang_input:
        text = refang(text)
    found: list[Ioc] = []

    # URL
    url_spans: list[tuple[int, int]] = []
    for m in _URL.finditer(text):
        raw = _clean_url(m.group(0))
        end = m.start() + len(raw)
        if validate and not _url_host(raw):
            continue
        url_spans.append((m.start(), end))
        if context_filter and context_filter.is_benign_url(raw):
            continue
        found.append(Ioc("url", normalize_url(raw) if validate else raw, m.start(), end))

    # IPv4
    for m in _IPV4.finditer(text):
        s, e = m.start(), m.end()
        if not url_hosts and _inside(url_spans, s, e):
            continue
        val = m.group(0)
        if validate:
            if _prev_word(text, s) in _VERSION_WORDS:
                continue
            try:
                ip = ipaddress.IPv4Address(val)
            except ValueError:
                continue
            val = str(ip)
            if context_filter and context_filter.is_benign_ip(val):
                continue
        found.append(Ioc("ip", val, s, e))

    # Domain
    for m in _DOMAIN.finditer(text):
        s, e = m.start(), m.end()
        if not url_hosts and _inside(url_spans, s, e):
            continue
        val = m.group(0)
        if validate:
            val = val.lower()
            tld = val.rsplit(".", 1)[-1]
            if tld in FILE_EXTENSIONS or tld in RESERVED_TLDS:
                continue
            if context_filter and context_filter.is_benign_domain(val):
                continue
        found.append(Ioc("domain", val, s, e))

    # Hash
    for m in _HASH.finditer(text):
        val = m.group(0)
        if validate:
            val = val.lower()
            if val in EMPTY_FILE_HASHES or val.isdigit() or len(set(val)) < 5:
                continue
        found.append(Ioc("hash", val, m.start(), m.end(), _HASH_TYPES[len(m.group(0))]))

    found.sort(key=lambda i: i.start)
    seen: set[tuple[str, str]] = set()
    unique: list[Ioc] = []
    for ioc in found:
        key = (ioc.type, ioc.value)
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique


def extract_by_type(text: str, **kwargs) -> dict[str, set[str]]:
    """Tiện cho việc so với nhãn tay: {'ip': {...}, 'domain': {...}, 'url': {...}, 'hash': {...}}."""
    out: dict[str, set[str]] = {"ip": set(), "domain": set(), "url": set(), "hash": set()}
    for ioc in extract_iocs(text, **kwargs):
        out[ioc.type].add(ioc.value)
    return out
