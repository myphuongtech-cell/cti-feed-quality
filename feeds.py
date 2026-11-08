"""Đọc bản thô của 7 feed thành một bảng IoC thống nhất.

Cột chuẩn: ioc_type, ioc_value, hash_type, port, source_first_seen, status, threat, malware, tags, sample_id

Chạy kiểm tra trên dữ liệu thật đã thu:
    python -m src.feeds --check
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import ipaddress
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"

STD_COLS = [
    "ioc_type", "ioc_value", "hash_type", "port", "source_first_seen",
    "status", "threat", "malware", "tags", "sample_id",
]

URLHAUS_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
THREATFOX_COLS = [
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias",
    "malware_printable", "last_seen_utc", "confidence_level", "is_compromised", "reference", "tags",
    "anonymous", "reporter",
]
MALWAREBAZAAR_COLS = [
    "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess",
    "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh",
]
_IDENT = re.compile(r"[a-z_0-9]+")


def read_text(path: str | Path) -> str:
    p = Path(path)
    if p.suffix == ".gz":
        with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    return p.read_text(encoding="utf-8", errors="replace")


def _row(**kw) -> dict:
    r = {c: None for c in STD_COLS}
    r.update(kw)
    return r


def _df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=STD_COLS)


def _read_abusech_csv(text: str, fallback_cols: list[str], key_col: str) -> list[dict]:
    """Đọc CSV của abuse.ch: dòng bắt đầu bằng # là chú thích; tiêu đề có thể nằm trong chú thích."""
    header: list[str] | None = None
    data_lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            cand = [c.strip().strip('"').lower() for c in s.lstrip("#").strip().split(",")]
            if len(cand) >= 5 and all(_IDENT.fullmatch(c) for c in cand):
                header = cand
            continue
        data_lines.append(line)
    rows = list(csv.reader(data_lines, skipinitialspace=True))
    if rows and key_col in [c.strip().lower() for c in rows[0]]:
        header = [c.strip().lower() for c in rows[0]]
        rows = rows[1:]
    cols = header or fallback_cols
    out = []
    for r in rows:
        r = [c.strip() for c in r]
        if len(r) < len(cols):
            r += [""] * (len(cols) - len(r))
        out.append(dict(zip(cols, r)))
    return out


def _clean(v):
    if v is None:
        return None
    v = str(v).strip()
    return v if v and v.lower() not in {"none", "n/a", "null"} else None


def _to_ip(token: str) -> str | None:
    try:
        return str(ipaddress.ip_address(token.strip()))
    except ValueError:
        return None


# ---------------------------------------------------------------- từng feed
def parse_ip_list(text: str) -> pd.DataFrame:
    """Blocklist.de, CINS, Emerging Threats: mỗi dòng một IP (có thể kèm chú thích)."""
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        token = re.split(r"[\s;,#]", s, maxsplit=1)[0]
        ip = _to_ip(token)
        if ip:
            rows.append(_row(ioc_type="ip", ioc_value=ip))
    return _df(rows)


def parse_openphish(text: str) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith(("http://", "https://")):
            rows.append(_row(ioc_type="url", ioc_value=s))
    return _df(rows)


def parse_urlhaus(text: str) -> pd.DataFrame:
    rows = []
    for r in _read_abusech_csv(text, URLHAUS_COLS, "url"):
        url = _clean(r.get("url"))
        if not url:
            continue
        rows.append(_row(
            ioc_type="url", ioc_value=url, source_first_seen=_clean(r.get("dateadded")),
            status=_clean(r.get("url_status")), threat=_clean(r.get("threat")), tags=_clean(r.get("tags")),
        ))
    return _df(rows)


def parse_threatfox(text: str) -> pd.DataFrame:
    rows = []
    for r in _read_abusech_csv(text, THREATFOX_COLS, "ioc_value"):
        value = _clean(r.get("ioc_value"))
        kind = (_clean(r.get("ioc_type")) or "").lower()
        if not value:
            continue
        common = dict(
            source_first_seen=_clean(r.get("first_seen_utc")), threat=_clean(r.get("threat_type")),
            malware=_clean(r.get("malware_printable")), tags=_clean(r.get("tags")),
        )
        if kind == "ip:port":
            host, _, port = value.rpartition(":")
            ip = _to_ip(host)
            if ip:
                rows.append(_row(ioc_type="ip", ioc_value=ip, port=port or None, **common))
        elif kind == "domain":
            rows.append(_row(ioc_type="domain", ioc_value=value.lower().rstrip("."), **common))
        elif kind == "url":
            rows.append(_row(ioc_type="url", ioc_value=value, **common))
        elif kind in {"md5_hash", "sha1_hash", "sha256_hash"}:
            rows.append(_row(ioc_type="hash", ioc_value=value.lower(), hash_type=kind.split("_")[0], **common))
    return _df(rows)


def parse_malwarebazaar(text: str) -> pd.DataFrame:
    rows = []
    for r in _read_abusech_csv(text, MALWAREBAZAAR_COLS, "sha256_hash"):
        sha256 = (_clean(r.get("sha256_hash")) or "").lower()
        md5 = (_clean(r.get("md5_hash")) or "").lower()
        common = dict(
            source_first_seen=_clean(r.get("first_seen_utc")), malware=_clean(r.get("signature")),
            tags=_clean(r.get("file_type_guess")), sample_id=sha256 or None,
        )
        if sha256:
            rows.append(_row(ioc_type="hash", ioc_value=sha256, hash_type="sha256", **common))
        if md5:
            rows.append(_row(ioc_type="hash", ioc_value=md5, hash_type="md5", **common))
    return _df(rows)


PARSERS = {
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "malwarebazaar": parse_malwarebazaar,
    "openphish": parse_openphish,
    "blocklist_de": parse_ip_list,
    "cins": parse_ip_list,
    "et_compromised": parse_ip_list,
}


def parse_snapshot(feed_id: str, path: str | Path) -> pd.DataFrame:
    df = PARSERS[feed_id](read_text(path))
    df["source_first_seen"] = pd.to_datetime(df["source_first_seen"], utc=True, errors="coerce")
    return df


# ---------------------------------------------------------------- kiểm tra trên dữ liệu thật
def check() -> None:
    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)
    pd.set_option("display.max_colwidth", 60)
    for feed_id in PARSERS:
        files = sorted(RAW.glob(f"{feed_id}/*/*.gz"))
        print(f"\n=== {feed_id} ===")
        if not files:
            print("  (chưa có file)")
            continue
        path = files[-1]
        df = parse_snapshot(feed_id, path)
        print(f"  file: {path.name} | số dòng IoC: {len(df)}")
        if df.empty:
            print("  !! Không đọc được dòng nào, cần kiểm tra định dạng.")
            continue
        print("  theo loại:", df["ioc_type"].value_counts().to_dict())
        have_time = df["source_first_seen"].notna().mean()
        print(f"  có thời gian nguồn: {have_time:.0%}")
        print(df.head(3).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="đọc file mới nhất của mỗi feed và in tóm tắt")
    args = ap.parse_args()
    if args.check:
        check()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
