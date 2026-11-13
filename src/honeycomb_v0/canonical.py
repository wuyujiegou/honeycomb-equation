from __future__ import annotations
from dataclasses import asdict, is_dataclass
from enum import Enum
from fractions import Fraction
import hashlib, json, math
from pathlib import Path
from typing import Any

CANON_VERSION = "hc-canon-v2"
HASH_SCHEME = "sha256"

def canonical_data(x: Any) -> Any:
    if is_dataclass(x):
        x = asdict(x)
    if isinstance(x, Enum):
        return x.value
    if isinstance(x, Fraction):
        return {"__fraction__": [x.numerator, x.denominator]}
    if isinstance(x, Path):
        return x.as_posix()
    if isinstance(x, bytes):
        return {"__bytes_hex__": x.hex()}
    if isinstance(x, dict):
        if any(not isinstance(k, str) for k in x):
            raise TypeError("Canonical dict keys must be strings")
        return {k: canonical_data(x[k]) for k in sorted(x)}
    if isinstance(x, (set, frozenset)):
        vals = [canonical_data(v) for v in x]
        return sorted(vals, key=lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    if isinstance(x, (list, tuple)):
        return [canonical_data(v) for v in x]
    if isinstance(x, float):
        if not math.isfinite(x):
            raise TypeError("Non-finite floats are not canonical")
        return {"__float_hex__": x.hex()}
    if x is None or isinstance(x, (str, int, bool)):
        return x
    raise TypeError(f"Unsupported canonical type: {type(x)!r}")

def canonical_json(x: Any) -> str:
    payload = {"canon": CANON_VERSION, "data": canonical_data(x)}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def content_id(x: Any) -> str:
    return hashlib.sha256(canonical_json(x).encode("utf-8")).hexdigest()

def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
