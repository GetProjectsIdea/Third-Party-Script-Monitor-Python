"""Store snapshots as a JSON baseline and report what changed since then."""
from __future__ import annotations

import json
from pathlib import Path

from . import csp as csp_mod
from .findings import Finding, score, sort_findings, verdict

VERSION = 1
SNAPSHOT_KEYS = ("url", "final_url", "status", "scanned_at", "resources", "inline_scripts", "csp")


def load(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"version": VERSION, "pages": {}}
    data = json.loads(p.read_text(encoding="utf-8"))
    data.setdefault("pages", {})
    return data


def save(path: str | Path, snapshots: list[dict], existing: dict | None = None) -> None:
    data = existing or {"version": VERSION, "pages": {}}
    for s in snapshots:
        if s.get("error"):
            continue  # never overwrite a good baseline with a failed fetch
        data["pages"][s["url"]] = {k: s[k] for k in SNAPSHOT_KEYS}
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def diff(old: dict, new: dict) -> list[dict]:
    """Return change findings (as dicts) between two snapshots of the same page."""
    f: list[Finding] = []
    o = {r["url"]: r for r in old.get("resources", [])}
    n = {r["url"]: r for r in new.get("resources", [])}
    old_hosts = {r["host"] for r in o.values()}
    new_tp_hosts = sorted({r["host"] for r in n.values() if r["third_party"] and r["host"] not in old_hosts})
    for h in new_tp_hosts:
        f.append(Finding("high", "NEW_THIRD_PARTY_HOST", f"New third-party host: {h}",
                         "This page now loads code from a host it never used before. Confirm who added it."))
    for url in sorted(n.keys() - o.keys()):
        r = n[url]
        if r["third_party"] and r["host"] in new_tp_hosts:
            continue  # already reported via the host
        sev = "medium" if r["third_party"] else "low"
        f.append(Finding(sev, "NEW_RESOURCE", f"New {r['kind']} added", "", url))
    for url in sorted(o.keys() - n.keys()):
        f.append(Finding("info", "RESOURCE_REMOVED", f"{o[url]['kind'].capitalize()} removed", "", url))
    for url in sorted(o.keys() & n.keys()):
        a, b = o[url], n[url]
        if a.get("sha256") and b.get("sha256") and a["sha256"] != b["sha256"]:
            sev = "medium" if b["third_party"] else "low"
            f.append(Finding(sev, "CONTENT_CHANGED", f"{b['kind'].capitalize()} content changed (same URL)",
                             f"sha256 {a['sha256'][:12]}… → {b['sha256'][:12]}…, size {a.get('size')} → {b.get('size')} bytes.", url))
            new_refs = sorted(set(b.get("referenced_hosts", [])) - set(a.get("referenced_hosts", [])))
            if new_refs:
                f.append(Finding("high", "NEW_REFERENCED_HOST", "Changed script now references new host(s)",
                                 ", ".join(new_refs) + ". A loader added to a trusted file usually looks like this.", url))
            new_hints = sorted(set(b.get("hints", [])) - set(a.get("hints", [])))
            if new_hints:
                f.append(Finding("high" if b["third_party"] else "medium", "NEW_RISKY_PATTERN",
                                 "Changed script gained risky patterns", ", ".join(new_hints), url))
        if a.get("integrity") and not b.get("integrity"):
            f.append(Finding("high", "SRI_REMOVED", "SRI integrity attribute was removed", "", url))
        elif not a.get("integrity") and b.get("integrity"):
            f.append(Finding("info", "SRI_ADDED", "SRI integrity attribute was added", "", url))
    oi = {s["sha256"] for s in old.get("inline_scripts", [])}
    ni = {s["sha256"] for s in new.get("inline_scripts", [])}
    if ni - oi:
        f.append(Finding("low", "INLINE_SCRIPT_CHANGED", f"{len(ni - oi)} new or changed inline script(s)",
                         "Inline code changed since the baseline."))
    f.extend(csp_mod.compare(old.get("csp", {}), new.get("csp", {})))
    return [x.to_dict() for x in f]


def apply_diff(snapshot: dict, baseline_page: dict | None) -> dict:
    """Attach 'changes' to a snapshot and recompute score/verdict with them."""
    if baseline_page is None:
        snapshot["changes"] = None
        return snapshot
    changes = sort_findings(diff(baseline_page, snapshot))
    snapshot["changes"] = changes
    snapshot["baseline_scanned_at"] = baseline_page.get("scanned_at")
    allf = snapshot["findings"] + changes
    snapshot["score"] = score(allf)
    snapshot["verdict"] = verdict(allf)
    return snapshot
