"""Kiểm tra bundle STIX 2.1 (thí nghiệm E2).

Hai lớp kiểm tra:
1. stix2-validator (theo đặc tả OASIS 2.1): đếm lỗi (errors) và cảnh báo (warnings).
2. Khứ hồi: parse lại bằng stix2, rồi đảo ngược từng pattern ra IoC và so với đối tượng gốc.

Dùng:
    python -m src.validate_stix                      # tất cả file trong data/processed/stix
    python -m src.validate_stix path/to/bundle.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import stix2
from stix2validator import ValidationOptions, validate_string

from src.to_stix import OUT_DIR, make_pattern, pattern_to_ioc

ROOT = Path(__file__).resolve().parents[1]


def validate_file(path: str | Path) -> dict:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    result = validate_string(text, ValidationOptions(version="2.1"))
    errors = [str(e) for e in (getattr(result, "errors", None) or [])]
    warnings = [str(w) for w in (getattr(result, "warnings", None) or [])]

    data = json.loads(text)
    objects = data.get("objects", [])
    indicators = [o for o in objects if o.get("type") == "indicator"]

    # khứ hồi: parse lại và đảo ngược pattern
    roundtrip_ok = 0
    roundtrip_fail: list[str] = []
    try:
        parsed = stix2.parse(text, allow_custom=False, version="2.1")
        parsed_objects = len(parsed.objects)
    except Exception as exc:  # noqa: BLE001
        parsed_objects = 0
        roundtrip_fail.append(f"parse lỗi: {exc}")
    for ind in indicators:
        try:
            ioc_type, value, hash_type = pattern_to_ioc(ind["pattern"])
            if make_pattern(ioc_type, value, hash_type) == ind["pattern"]:
                roundtrip_ok += 1
            else:
                roundtrip_fail.append(f"không khứ hồi được: {ind['pattern'][:120]}")
        except (ValueError, KeyError) as exc:
            roundtrip_fail.append(str(exc))

    return {
        "file": path.name,
        "valid": bool(result.is_valid),
        "errors": errors,
        "warnings": warnings,
        "objects": len(objects),
        "indicators": len(indicators),
        "parsed_objects": parsed_objects,
        "roundtrip_ok": roundtrip_ok,
        "roundtrip_fail": roundtrip_fail,
    }


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or sorted(OUT_DIR.glob("*.json"))
    if not paths:
        print("Chưa có file STIX nào. Chạy trước: python -m src.to_stix --all")
        return 1
    bad = 0
    for p in paths:
        r = validate_file(p)
        status = "HỢP LỆ" if r["valid"] and not r["roundtrip_fail"] else "CÓ LỖI"
        print(f"\n{r['file']}: {status}")
        print(f"  đối tượng: {r['objects']} | indicator: {r['indicators']} | parse lại được: {r['parsed_objects']}")
        print(f"  lỗi validator: {len(r['errors'])} | cảnh báo: {len(r['warnings'])} | "
              f"khứ hồi đạt: {r['roundtrip_ok']}/{r['indicators']}")
        for e in r["errors"][:5]:
            print("   LỖI:", e[:300])
        for e in r["roundtrip_fail"][:5]:
            print("   KHỨ HỒI:", e[:300])
        if not r["valid"] or r["roundtrip_fail"]:
            bad += 1
    print(f"\nTổng: {len(paths)} file, {bad} file có lỗi.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
