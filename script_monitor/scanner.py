"""Scan a page: inventory resources, hash them, check SRI and CSP."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import csp as csp_mod
from . import sri
from .findings import Finding, score, sort_findings, verdict
from .htmlparse import parse_html

# Patterns that are common in malicious loaders and skimmers. They are also used
# by honest scripts, so they are "review hints", never proof of anything.
HINTS = {
    "eval": re.compile(r"\beval\s*\("),
    "new Function": re.compile(r"\bnew\s+Function\s*\("),
    "atob (base64 decode)": re.compile(r"\batob\s*\("),
    "sendBeacon": re.compile(r"\bsendBeacon\s*\("),
    "document.cookie": re.compile(r"document\.cookie"),
    "creates <script> tags": re.compile(r"createElement\(\s*['\"]script['\"]\s*\)"),
    "clipboard access": re.compile(r"navigator\.clipboard"),
}
URL_IN_JS = re.compile(r"""(?:https?:)?//([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)""", re.I)
TWO_LEVEL_SUFFIXES = {"co", "com", "org", "net", "gov", "ac", "edu", "nic", "res", "gen", "ind", "firm"}


def site_of(host: str) -> str:
    """Approximate registrable domain: news.bbc.co.uk -> bbc.co.uk, cdn.example.com -> example.com."""
    labels = [x for x in (host or "").lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_third_party(host: str, page_host: str, first_party: tuple[str, ...] = ()) -> bool:
    site = site_of(host)
    if site == site_of(page_host):
        return False
    return not any(host == fp or host.endswith("." + fp) for fp in first_party)


def referenced_hosts(text: str, own_host: str) -> list[str]:
    hosts = {m.group(1).lower().rstrip(".") for m in URL_IN_JS.finditer(text)}
    hosts.discard(own_host)
    return sorted(h for h in hosts if h.rsplit(".", 1)[-1].isalpha() and len(h.rsplit(".", 1)[-1]) >= 2)[:50]


def hints_for(text: str) -> list[str]:
    return [name for name, rx in HINTS.items() if rx.search(text)]


def scan_page(url: str, fetcher, fetch_resources: bool = True, first_party: tuple[str, ...] = ()) -> dict:
    page = fetcher.fetch(url)
    snap: dict = {
        "url": url,
        "final_url": page.url,
        "status": page.status,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "error": page.error,
        "resources": [],
        "inline_scripts": [],
        "csp": {"enforced": None, "report_only": None, "source": None},
        "findings": [],
    }
    if not page.ok:
        snap["findings"] = [Finding("high", "PAGE_FETCH_FAILED", "Could not fetch the page", page.error or "").to_dict()]
        return _finish(snap)

    page_parts = urlsplit(page.url)
    page_host = (page_parts.hostname or "").lower()
    html = page.body.decode("utf-8", errors="replace")
    parsed = parse_html(html, page.url)

    # CSP: header first, then <meta>
    header = page.header("content-security-policy")
    ro = page.header("content-security-policy-report-only")
    snap["csp"] = {"enforced": header, "report_only": ro, "source": "header" if header else None}
    if not header and parsed["meta_csp"]:
        snap["csp"].update(enforced=parsed["meta_csp"][0], source="meta")
    if not snap["csp"]["source"] and ro:
        snap["csp"]["source"] = "header"
    policy = csp_mod.parse_policy(snap["csp"]["enforced"])
    _, script_sources = csp_mod.effective(policy, "script-src-elem") if snap["csp"]["enforced"] else (None, None)

    findings: list[Finding] = csp_mod.analyze(snap["csp"])
    snap["inline_scripts"] = parsed["inline_scripts"]

    seen = set()
    for r in parsed["resources"]:
        rurl = r["url"]
        if rurl in seen:
            continue
        seen.add(rurl)
        parts = urlsplit(rurl)
        host = (parts.hostname or "").lower()
        attrs = r["attrs"]
        tp = is_third_party(host, page_host, first_party)
        item = {
            "kind": r["kind"],
            "url": rurl,
            "host": host,
            "third_party": tp,
            "integrity": attrs.get("integrity") or None,
            "crossorigin": attrs.get("crossorigin") if "crossorigin" in attrs else None,
            "sha256": None,
            "sri_sha384": None,
            "size": None,
            "sri_status": None,
            "referenced_hosts": [],
            "hints": [],
            "fetch_error": None,
        }
        body = None
        if fetch_resources and parts.scheme in ("http", "https"):
            res = fetcher.fetch(rurl)
            if res.ok:
                body = res.body
                item["sha256"] = hashlib.sha256(body).hexdigest()
                item["sri_sha384"] = sri.integrity(body)
                item["size"] = len(body)
                if r["kind"] != "stylesheet":
                    text = body.decode("utf-8", errors="replace")
                    item["referenced_hosts"] = referenced_hosts(text, host)
                    item["hints"] = hints_for(text)
            else:
                item["fetch_error"] = res.error
        item["sri_status"] = sri.check(item["integrity"], body)
        snap["resources"].append(item)
        findings.extend(_resource_findings(item, page_parts.scheme, page_host, script_sources))

    tp_hosts = sorted({r["host"] for r in snap["resources"] if r["third_party"]})
    if tp_hosts:
        findings.append(Finding("info", "THIRD_PARTY_HOSTS", f"{len(tp_hosts)} third-party host(s) load code into this page",
                                ", ".join(tp_hosts)))
    snap["findings"] = [x.to_dict() for x in findings]
    return _finish(snap)


def _resource_findings(item: dict, page_scheme: str, page_host: str, script_sources) -> list[Finding]:
    out: list[Finding] = []
    u, kind = item["url"], item["kind"]
    label = "script" if kind != "stylesheet" else "stylesheet"
    if page_scheme == "https" and u.startswith("http://"):
        out.append(Finding("high", "INSECURE_RESOURCE", f"Insecure http:// {label}", "Anyone on the network path can change it.", u))
    st = item["sri_status"]
    if st == "mismatch":
        out.append(Finding("critical", "SRI_MISMATCH", f"SRI hash does not match the {label} served now",
                           "Browsers will block this file. The file changed after the hash was written: find out why.", u))
    elif st == "invalid":
        out.append(Finding("high", "SRI_INVALID", "integrity attribute is malformed",
                           "Browsers ignore invalid tokens, so this file is not protected.", u))
    elif st == "missing" and item["third_party"]:
        sev = "medium" if kind != "stylesheet" else "low"
        out.append(Finding(sev, "SRI_MISSING", f"Third-party {label} has no SRI integrity attribute",
                           "Pin static, versioned files with integrity=\"" + (item["sri_sha384"] or "sha384-...") +
                           "\". Files that change often (A/B testing snippets, tag managers) cannot be pinned: "
                           "monitor their hash and lock them down with CSP.", u))
    if item["integrity"] and item["third_party"] and item["crossorigin"] is None:
        out.append(Finding("medium", "SRI_NO_CROSSORIGIN", "SRI used without a crossorigin attribute",
                           "Cross-origin SRI needs crossorigin=\"anonymous\"; without it the browser blocks the file.", u))
    if item["third_party"] and item["hints"]:
        out.append(Finding("low", "SCRIPT_HINTS", "Third-party script uses patterns worth reviewing",
                           ", ".join(item["hints"]) + ". Common in loaders and skimmers, but also in honest code.", u))
    if kind != "stylesheet" and script_sources is not None and item["third_party"]:
        scheme = urlsplit(u).scheme
        if not csp_mod.host_allowed(script_sources, item["host"], scheme, page_host):
            out.append(Finding("info", "CSP_WOULD_BLOCK", "Script host is not in script-src",
                               "The enforced CSP should block this script. Remove the tag or allow the host on purpose.", u))
    return out


def _finish(snap: dict) -> dict:
    snap["findings"] = sort_findings(snap["findings"])
    snap["score"] = score(snap["findings"])
    snap["verdict"] = verdict(snap["findings"])
    return snap
