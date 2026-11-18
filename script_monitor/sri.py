"""Subresource Integrity helpers (https://www.w3.org/TR/SRI/)."""
from __future__ import annotations

import base64
import hashlib
import re

ALGOS = ("sha256", "sha384", "sha512")
_TOKEN = re.compile(r"^(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})(\?.*)?$")


def integrity(body: bytes, algo: str = "sha384") -> str:
    digest = hashlib.new(algo, body).digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


def parse_integrity(value: str) -> list[tuple[str, str]]:
    """Return [(algo, b64digest)] for valid tokens. Unknown tokens are ignored, like browsers do."""
    out = []
    for token in (value or "").split():
        m = _TOKEN.match(token)
        if m:
            out.append((m.group(1), m.group(2).replace("-", "+").replace("_", "/")))
    return out


def check(value: str | None, body: bytes | None) -> str:
    """Return one of: missing, invalid, unfetched, ok, mismatch."""
    if value is None or not value.strip():
        return "missing"
    tokens = parse_integrity(value)
    if not tokens:
        return "invalid"
    if body is None:
        return "unfetched"
    # Browsers only use the strongest algorithm present.
    strongest = max(ALGOS.index(a) for a, _ in tokens)
    wanted = [d for a, d in tokens if ALGOS.index(a) == strongest]
    actual = integrity(body, ALGOS[strongest]).split("-", 1)[1]
    return "ok" if actual in wanted else "mismatch"
