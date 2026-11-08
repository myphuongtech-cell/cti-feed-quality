"""Chuyển IoC (bảng chuẩn từ src.feeds) sang STIX 2.1.

Mỗi dòng IoC của một feed -> một Indicator. Nếu nguồn có họ mã độc -> thêm Malware (is_family) và
Relationship (Indicator --indicates--> Malware). Toàn bộ gắn nhãn TLP, created_by_ref và external_references
(nguồn feed) để giữ provenance.

ID là UUIDv5 xác định (cùng feed + cùng pattern -> cùng ID), nên chạy lại không sinh bản ghi trùng.

Dùng:
    python -m src.to_stix --feed urlhaus --limit 2000     # bản mới nhất của feed, 2000 IoC đầu
    python -m src.to_stix --all --limit 2000
    python -m src.to_stix --all --limit 0                 # chuyển toàn bộ (file lớn)

TLP: dữ liệu từ feed công khai nên dùng TLP:CLEAR (TLP 2.0). Thư viện stix2 chỉ có sẵn đối tượng marking
của TLP 1.0 (TLP:WHITE, cùng ý nghĩa "chia sẻ không hạn chế") nên dùng đối tượng đó.
"""
from __future__ import annotations

import argparse
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import stix2

from src.feeds import PARSERS, RAW, parse_snapshot

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "processed" / "stix"

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/myphuongtech-cell/cti-feed-quality")

# Thời gian sống khởi đầu (ngày) theo loại IoC: giả định ban đầu trong đề cương, sẽ được hiệu chỉnh từ dữ liệu.
DEFAULT_TTL_DAYS = {"hash": 90, "domain": 30, "ip": 14, "url": 7}
HASH_ALGO = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
TLP_MARKINGS = {"white": stix2.TLP_WHITE, "clear": stix2.TLP_WHITE, "green": stix2.TLP_GREEN,
                "amber": stix2.TLP_AMBER, "red": stix2.TLP_RED}


def det_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, '|'.join((kind,) + parts))}"


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def make_pattern(ioc_type: str, value: str, hash_type: str | None = None) -> str:
    if ioc_type == "ip":
        obj = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{obj}:value = '{_esc(value)}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{_esc(value)}']"
    if ioc_type == "url":
        return f"[url:value = '{_esc(value)}']"
    if ioc_type == "hash":
        algo = HASH_ALGO[(hash_type or "").lower()]
        return f"[file:hashes.'{algo}' = '{_esc(value)}']"
    raise ValueError(f"loại IoC không hỗ trợ: {ioc_type}")


_VALUE_PATTERN = re.compile(r"^\[(ipv4-addr|ipv6-addr|domain-name|url):value = '((?:[^'\\]|\\.)*)'\]$")
_HASH_PATTERN = re.compile(r"^\[file:hashes\.'(MD5|SHA-1|SHA-256)' = '((?:[^'\\]|\\.)*)'\]$")


def pattern_to_ioc(pattern: str) -> tuple[str, str, str | None]:
    """Đảo ngược make_pattern: trả về (ioc_type, value, hash_type). Dùng cho kiểm tra khứ hồi."""
    m = _VALUE_PATTERN.match(pattern)
    if m:
        kind = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}[m.group(1)]
        return kind, re.sub(r"\\(.)", r"\1", m.group(2)), None
    m = _HASH_PATTERN.match(pattern)
    if m:
        inverse = {v: k for k, v in HASH_ALGO.items()}
        return "hash", re.sub(r"\\(.)", r"\1", m.group(2)), inverse[m.group(1)]
    raise ValueError(f"pattern không nhận dạng được: {pattern}")


def confidence_from_score(score: float) -> int:
    """Điểm tin cậy S (0-1) của mô hình chấm điểm -> trường confidence của STIX (0-100)."""
    return max(0, min(100, round(score * 100)))


def _clean_labels(tags) -> list[str]:
    if not tags or (isinstance(tags, float) and pd.isna(tags)):
        return []
    out = []
    for t in str(tags).split(","):
        t = t.strip()
        if t and t.lower() not in {"none", "null"}:
            out.append(t[:60])
    return out[:10]


def _is_missing(v) -> bool:
    return v is None or (isinstance(v, float) and pd.isna(v)) or v is pd.NaT or (isinstance(v, str) and not v.strip())


def build_bundle(
    df: pd.DataFrame,
    feed_id: str,
    snapshot_ts: datetime,
    *,
    confidence: int | dict[str, int] = 50,
    ttl_days: dict[str, int] | None = None,
    tlp: str = "white",
    operator: str | None = None,
) -> stix2.Bundle:
    """Tạo Bundle STIX 2.1 từ bảng IoC của một bản chụp feed."""
    ttl = {**DEFAULT_TTL_DAYS, **(ttl_days or {})}
    marking = TLP_MARKINGS[tlp.lower()]
    identity = stix2.Identity(
        id=det_id("identity", "cti-feed-quality"),
        name="CTI Feed Quality (student research project)",
        identity_class="organization",
        created=snapshot_ts, modified=snapshot_ts,
    )
    objects: list = [marking, identity]
    malware_seen: dict[str, str] = {}

    df = df.drop_duplicates(subset=["ioc_type", "ioc_value", "hash_type"], keep="first")
    for row in df.itertuples(index=False):
        ioc_type, value = row.ioc_type, row.ioc_value
        hash_type = None if _is_missing(row.hash_type) else row.hash_type
        pattern = make_pattern(ioc_type, value, hash_type)

        valid_from = snapshot_ts
        if not _is_missing(row.source_first_seen):
            ts = pd.Timestamp(row.source_first_seen)
            valid_from = (ts.tz_localize("UTC") if ts.tzinfo is None else ts).to_pydatetime()
        valid_until = valid_from + timedelta(days=ttl[ioc_type])
        if valid_until <= snapshot_ts:  # IoC cũ hơn TTL: vẫn phải có valid_until > valid_from
            valid_until = snapshot_ts + timedelta(days=1)

        conf = confidence.get(feed_id, 50) if isinstance(confidence, dict) else confidence
        desc_parts = []
        if not _is_missing(row.threat):
            desc_parts.append(f"threat={row.threat}")
        if not _is_missing(row.status):
            desc_parts.append(f"status={row.status}")
        if not _is_missing(row.port):
            desc_parts.append(f"port={row.port}")

        ind_id = det_id("indicator", feed_id, pattern)
        kwargs = dict(
            id=ind_id,
            name=f"{feed_id}: {value}"[:200],
            pattern=pattern, pattern_type="stix",
            valid_from=valid_from, valid_until=valid_until,
            indicator_types=["malicious-activity"],
            confidence=conf,
            created=snapshot_ts, modified=snapshot_ts,
            created_by_ref=identity.id,
            object_marking_refs=[marking.id],
            external_references=[stix2.ExternalReference(
                source_name=feed_id,
                description=f"Quan sát trong feed {feed_id}" + (f" ({operator})" if operator else ""),
            )],
        )
        if desc_parts:
            kwargs["description"] = "; ".join(desc_parts)
        labels = _clean_labels(row.tags)
        if labels:
            kwargs["labels"] = labels
        indicator = stix2.Indicator(**kwargs)
        objects.append(indicator)

        if not _is_missing(row.malware):
            name = str(row.malware).strip()
            if name not in malware_seen:
                mal_id = det_id("malware", name.lower())
                malware_seen[name] = mal_id
                objects.append(stix2.Malware(
                    id=mal_id, name=name, is_family=True,
                    created=snapshot_ts, modified=snapshot_ts,
                    created_by_ref=identity.id, object_marking_refs=[marking.id],
                ))
            objects.append(stix2.Relationship(
                id=det_id("relationship", ind_id, malware_seen[name]),
                relationship_type="indicates", source_ref=ind_id, target_ref=malware_seen[name],
                created=snapshot_ts, modified=snapshot_ts,
                created_by_ref=identity.id, object_marking_refs=[marking.id],
            ))
    return stix2.Bundle(objects=objects, allow_custom=False)


# ---------------------------------------------------------------- CLI
_TS = re.compile(r"_(\d{8}T\d{6}Z)\.")


def snapshot_time(path: Path) -> datetime:
    m = _TS.search(path.name)
    if not m:
        return datetime.now(timezone.utc)
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)


def convert_latest(feed_id: str, limit: int) -> Path | None:
    files = sorted(RAW.glob(f"{feed_id}/*/*.gz"))
    if not files:
        print(f"{feed_id}: chưa có file")
        return None
    path = files[-1]
    df = parse_snapshot(feed_id, path)
    if limit:
        df = df.drop_duplicates(subset=["ioc_type", "ioc_value", "hash_type"]).head(limit)
    ts = snapshot_time(path)
    bundle = build_bundle(df, feed_id, ts)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{feed_id}_{ts:%Y%m%dT%H%M%SZ}.json"
    out.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    print(f"{feed_id}: {len(df)} IoC -> {len(bundle.objects)} đối tượng STIX -> {out.relative_to(ROOT)}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feed", choices=sorted(PARSERS))
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--limit", type=int, default=2000, help="số IoC tối đa mỗi feed, 0 = toàn bộ")
    args = ap.parse_args()
    feeds = sorted(PARSERS) if args.all else ([args.feed] if args.feed else [])
    if not feeds:
        ap.print_help()
        return
    for f in feeds:
        convert_latest(f, args.limit)


if __name__ == "__main__":
    main()
