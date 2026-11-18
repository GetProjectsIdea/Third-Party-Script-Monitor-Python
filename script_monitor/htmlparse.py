"""Extract scripts, stylesheets, preloads and CSP meta tags from HTML."""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
from urllib.parse import urljoin

LINK_RELS = {"stylesheet", "modulepreload", "preload"}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources: list[dict] = []
        self.inline_scripts: list[dict] = []
        self.meta_csp: list[str] = []
        self.base_href: str | None = None
        self._in_script = False
        self._script_attrs: dict = {}
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "base" and a.get("href") and self.base_href is None:
            self.base_href = a["href"]
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            if a.get("content"):
                self.meta_csp.append(a["content"])
        elif tag == "script":
            # data-rocket-src / data-src: lazy-loaded scripts (WP Rocket and similar plugins)
            src = a.get("src") or a.get("data-rocket-src") or a.get("data-src")
            if src:
                self.resources.append({"kind": "script", "src": src, "attrs": a})
            else:
                self._in_script, self._script_attrs, self._buf = True, a, []
        elif tag == "link":
            rels = set(a.get("rel", "").lower().split())
            if a.get("href") and rels & LINK_RELS:
                if "preload" in rels and a.get("as", "").lower() not in ("script", "style"):
                    return
                kind = "stylesheet" if ("stylesheet" in rels or a.get("as") == "style") else "script-preload"
                self.resources.append({"kind": kind, "src": a["href"], "attrs": a})

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            code = "".join(self._buf)
            stype = self._script_attrs.get("type", "").lower()
            if code.strip() and stype in ("", "text/javascript", "module", "application/javascript"):
                self.inline_scripts.append({
                    "sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
                    "size": len(code),
                    "has_nonce": "nonce" in self._script_attrs,
                })
            self._in_script = False


def parse_html(html: str, page_url: str) -> dict:
    c = _Collector()
    c.feed(html)
    c.close()
    base = urljoin(page_url, c.base_href) if c.base_href else page_url
    for r in c.resources:
        r["url"] = urljoin(base, r["src"].strip())
    return {"resources": c.resources, "inline_scripts": c.inline_scripts, "meta_csp": c.meta_csp}
