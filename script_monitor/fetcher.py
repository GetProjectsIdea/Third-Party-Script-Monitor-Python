"""Fetchers return (status, headers, body_bytes, final_url) for a URL.

HttpFetcher talks to real websites with urllib (read-only GET requests).
FixtureFetcher serves files from a local folder so the demo and the tests
work offline: https://host/path -> <root>/host/path.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

USER_AGENT = "ThirdPartyScriptMonitor/1.0 (+https://github.com/GetProjectsIdea/Third-Party-Script-Monitor-Python)"
MAX_BYTES = 5 * 1024 * 1024  # never download more than 5 MB per file


@dataclass
class FetchResult:
    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def header(self, name: str) -> str | None:
        name = name.lower()
        values = [v for k, v in self.headers.items() if k.lower() == name]
        return ", ".join(values) if values else None


class HttpFetcher:
    """Plain HTTP(S) GET with a timeout and a size limit."""

    def __init__(self, timeout: float = 15.0, max_bytes: int = MAX_BYTES):
        self.timeout = timeout
        self.max_bytes = max_bytes

    def fetch(self, url: str) -> FetchResult:
        scheme = urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            return FetchResult(url, 0, error=f"unsupported scheme: {scheme or 'none'}")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (http/https only)
                body = resp.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    return FetchResult(resp.geturl(), resp.status, dict(resp.headers.items()), b"",
                                       error="file larger than size limit")
                return FetchResult(resp.geturl(), resp.status, dict(resp.headers.items()), body)
        except urllib.error.HTTPError as exc:
            return FetchResult(url, exc.code, dict(exc.headers.items()) if exc.headers else {}, b"",
                               error=f"HTTP {exc.code}")
        except Exception as exc:  # network errors, timeouts, TLS errors
            return FetchResult(url, 0, error=f"{type(exc).__name__}: {exc}")


class FixtureFetcher:
    """Offline fetcher used by the demo and the tests.

    Files live at <root>/<host>/<path>. Optional response headers for a host
    are read from <root>/<host>/_headers.json as {"/path": {"Header": "value"}}.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def fetch(self, url: str) -> FetchResult:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path or "/"
        if path.endswith("/"):
            path += "index.html"
        target = (self.root / host / path.lstrip("/")).resolve()
        if self.root not in target.parents or not target.is_file():
            return FetchResult(url, 404, error="HTTP 404")
        headers = {"Content-Type": _guess_type(target.name)}
        hfile = self.root / host / "_headers.json"
        if hfile.is_file():
            table = json.loads(hfile.read_text(encoding="utf-8"))
            headers.update(table.get(parts.path or "/", {}))
        return FetchResult(url, 200, headers, target.read_bytes())


def _guess_type(name: str) -> str:
    if name.endswith(".js"):
        return "application/javascript"
    if name.endswith(".css"):
        return "text/css"
    return "text/html; charset=utf-8"
