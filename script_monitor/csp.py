"""Parse and review a Content Security Policy, and compare two policies.

The checks follow MDN's CSP documentation and the lessons published after the
16 Nov 2026 Optimizely incident: a restrictive script-src and connect-src
limited the damage, while 'strict-dynamic' and 'unsafe-eval' let it through.
"""
from __future__ import annotations

from .findings import Finding

SCRIPT_DIRECTIVES = ("script-src-elem", "script-src")
FETCH_FALLBACK = "default-src"
DANGEROUS_KEYWORDS = {"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'", "'strict-dynamic'"}
SCHEME_SOURCES = {"http:", "https:", "data:", "blob:", "ws:", "wss:", "filesystem:"}


def parse_policy(text: str | None) -> dict[str, list[str]]:
    """Turn 'a b; c d' into {'a': ['b'], 'c': ['d']}. First directive wins, as in browsers."""
    out: dict[str, list[str]] = {}
    if not text:
        return out
    # Several policies can be joined by commas in one header; we review the first and merge the rest.
    for policy in text.split(","):
        for part in policy.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if name not in out:
                out[name] = tokens[1:]
    return out


def effective(directives: dict[str, list[str]], name: str) -> tuple[str | None, list[str] | None]:
    """Return (directive actually used, sources) with the default-src fallback."""
    chain = {"script-src-elem": ["script-src-elem", "script-src", FETCH_FALLBACK],
             "script-src": ["script-src", FETCH_FALLBACK],
             "connect-src": ["connect-src", FETCH_FALLBACK],
             "img-src": ["img-src", FETCH_FALLBACK],
             "style-src": ["style-src", FETCH_FALLBACK],
             "object-src": ["object-src", FETCH_FALLBACK]}.get(name, [name, FETCH_FALLBACK])
    for d in chain:
        if d in directives:
            return d, directives[d]
    return None, None


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)


def analyze(csp: dict) -> list[Finding]:
    """Review the policy a page sends. csp = {'enforced': str|None, 'report_only': str|None, 'source': ...}."""
    f: list[Finding] = []
    enforced, report_only = csp.get("enforced"), csp.get("report_only")
    if not enforced and not report_only:
        f.append(Finding("high", "CSP_MISSING", "No Content Security Policy",
                         "Any script injected into a trusted third-party file can load more code and send data "
                         "anywhere. Start with a Content-Security-Policy-Report-Only header, then enforce it."))
        return f
    if not enforced:
        f.append(Finding("medium", "CSP_REPORT_ONLY", "CSP is report-only (not enforced)",
                         "Report-only mode detects violations but blocks nothing. Enforce the policy once reports are clean."))
    d = parse_policy(enforced or report_only)
    label = "" if enforced else " (report-only policy)"

    used, script = effective(d, "script-src")
    if script is None:
        f.append(Finding("high", "CSP_NO_SCRIPT_SRC", "No script-src or default-src" + label,
                         "The policy does not restrict where scripts load from."))
    else:
        low = [s.lower() for s in script]
        if "*" in low:
            f.append(Finding("high", "CSP_SCRIPT_WILDCARD", f"{used} allows '*'" + label,
                             "Scripts can load from any host, so the policy gives no supply-chain protection."))
        schemes = sorted(set(low) & SCHEME_SOURCES)
        if schemes:
            f.append(Finding("high", "CSP_SCRIPT_SCHEME", f"{used} allows scheme sources {' '.join(schemes)}" + label,
                             "A bare scheme such as https: acts as a wildcard for every host on that scheme."))
        if "'unsafe-inline'" in low and not _has_nonce_or_hash(low) and "'strict-dynamic'" not in low:
            f.append(Finding("high", "CSP_UNSAFE_INLINE", f"{used} allows 'unsafe-inline'" + label,
                             "Inline script injection (XSS) is not blocked. Use nonces or hashes instead."))
        if "'unsafe-eval'" in low:
            f.append(Finding("high", "CSP_UNSAFE_EVAL", f"{used} allows 'unsafe-eval'" + label,
                             "eval() and new Function() are allowed. In the Optimizely incident an inline eval() "
                             "fallback still ran on a site that blocked the remote payload because of this keyword."))
        if "'strict-dynamic'" in low:
            f.append(Finding("medium", "CSP_STRICT_DYNAMIC", f"{used} uses 'strict-dynamic'" + label,
                             "Any script added by a trusted script is also trusted and host allow-lists are ignored. "
                             "If a trusted vendor script is compromised, the scripts it injects run too."))
        broad = [s for s in script if s.startswith("*.") or "://*." in s]
        if broad:
            f.append(Finding("low", "CSP_SCRIPT_HOST_WILDCARD", f"{used} allows wildcard hosts: {', '.join(broad[:5])}" + label,
                             "Prefer exact hostnames so a takeover of one sub-domain cannot serve scripts."))

    used_c, connect = effective(d, "connect-src")
    if connect is None:
        f.append(Finding("medium", "CSP_NO_CONNECT_SRC", "No connect-src or default-src" + label,
                         "fetch(), XHR, WebSocket and navigator.sendBeacon() can send data to any host. A tight "
                         "connect-src stopped card data leaving the page on 17 affected sites (Report URI)."))
    else:
        lowc = [s.lower() for s in connect]
        if "*" in lowc or set(lowc) & {"https:", "http:", "wss:", "ws:"}:
            f.append(Finding("medium", "CSP_CONNECT_BROAD", f"{used_c} allows any host" + label,
                             "Data can be sent to any destination. List only the APIs your pages really use."))

    if effective(d, "object-src")[1] is None:
        f.append(Finding("low", "CSP_NO_OBJECT_SRC", "No object-src (or default-src)" + label,
                         "Add object-src 'none' to block plugin content."))
    if "base-uri" not in d:
        f.append(Finding("low", "CSP_NO_BASE_URI", "No base-uri" + label,
                         "Add base-uri 'self' (or 'none') so injected <base> tags cannot redirect relative script URLs."))
    if "report-uri" not in d and "report-to" not in d:
        f.append(Finding("low", "CSP_NO_REPORTING", "No report-uri or report-to" + label,
                         "Without reporting you will not hear about blocked scripts or new destinations."))
    if csp.get("source") == "meta" and enforced:
        f.append(Finding("info", "CSP_META_ONLY", "CSP is set only by a <meta> tag",
                         "Meta-tag policies cannot use report-uri or frame-ancestors. Prefer an HTTP header."))
    return f


def host_allowed(sources: list[str] | None, url_host: str, scheme: str, page_host: str) -> bool:
    """Rough check: would this script host be allowed by the given source list?"""
    if sources is None:
        return True
    low = [s.lower() for s in sources]
    if "*" in low or f"{scheme}:" in low or "'strict-dynamic'" in low:
        return True
    if "'self'" in low and url_host == page_host:
        return True
    for s in low:
        if s.startswith("'") or s.endswith(":") and "//" not in s:
            continue
        hostpart = s.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if hostpart.startswith("*."):
            if url_host.endswith(hostpart[1:]):
                return True
        elif hostpart == url_host:
            return True
    return False


WATCHED = ("default-src", "script-src", "script-src-elem", "connect-src", "object-src", "base-uri", "img-src")


def compare(old: dict, new: dict) -> list[Finding]:
    """Compare two csp dicts (as stored in snapshots) and report weakening changes."""
    f: list[Finding] = []
    if old.get("enforced") and not new.get("enforced"):
        if new.get("report_only"):
            f.append(Finding("high", "CSP_NOW_REPORT_ONLY", "CSP changed from enforced to report-only",
                             "The browser no longer blocks anything."))
        else:
            f.append(Finding("critical", "CSP_REMOVED", "Content Security Policy was removed",
                             "The page used to send a CSP header and now sends none."))
        return f
    if not old.get("enforced") and new.get("enforced"):
        f.append(Finding("info", "CSP_ADDED", "An enforced CSP was added", "Good change."))
        return f
    od, nd = parse_policy(old.get("enforced")), parse_policy(new.get("enforced"))
    for name in WATCHED:
        if name in od and name not in nd:
            sev = "high" if name in ("default-src", "script-src", "connect-src", "object-src") else "medium"
            f.append(Finding(sev, "CSP_DIRECTIVE_REMOVED", f"CSP directive {name} was removed",
                             f"Old value: {name} {' '.join(od[name])}"))
            continue
        if name not in od and name in nd:
            f.append(Finding("info", "CSP_DIRECTIVE_ADDED", f"CSP directive {name} was added",
                             f"New value: {name} {' '.join(nd[name])}"))
            continue
        if name not in nd:
            continue
        added = [s for s in nd[name] if s not in od[name]]
        removed = [s for s in od[name] if s not in nd[name]]
        for s in added:
            ls = s.lower()
            risky = ls in DANGEROUS_KEYWORDS or ls == "*" or ls in SCHEME_SOURCES
            f.append(Finding("high" if risky else "medium", "CSP_WEAKENED" if risky else "CSP_SOURCE_ADDED",
                             f"{name} now allows {s}",
                             "This keyword or scheme weakens the policy." if risky
                             else "A new source was allowed. Confirm who added it and why."))
        if removed:
            f.append(Finding("info", "CSP_SOURCE_REMOVED", f"{name} no longer allows {' '.join(removed)}",
                             "Sources removed (usually a tightening change)."))
    return f
