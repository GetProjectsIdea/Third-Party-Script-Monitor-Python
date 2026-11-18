"""Command-line interface.

  python -m script_monitor scan https://example.com --baseline baseline.json
  python -m script_monitor demo
  python -m script_monitor csp "default-src 'self'; script-src 'self'"
  python -m script_monitor sri path/or/url/to/file.js
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, baseline, report, sri
from .csp import analyze
from .fetcher import FixtureFetcher, HttpFetcher
from .findings import SEVERITIES, sort_findings
from .scanner import scan_page

DEMO_ROOT = Path(__file__).resolve().parent.parent / "examples" / "demo-site"
DEMO_URL = "https://shop.demo.example/"


def run_scan(urls, fetcher, baseline_path=None, update=False, fetch_resources=True, first_party=()):
    base = baseline.load(baseline_path) if baseline_path else None
    snaps = []
    for u in urls:
        s = scan_page(u, fetcher, fetch_resources=fetch_resources, first_party=tuple(first_party))
        if base is not None:
            baseline.apply_diff(s, base["pages"].get(u))
        snaps.append(s)
    if baseline_path and (update or not Path(baseline_path).is_file()):
        baseline.save(baseline_path, snaps, base if Path(baseline_path).is_file() else None)
    return snaps


def worst(snaps) -> str | None:
    sevs = [f["severity"] for s in snaps for f in s["findings"] + (s.get("changes") or [])]
    return min(sevs, key=SEVERITIES.index) if sevs else None


def _outputs(snaps, args):
    print(report.text_report(snaps, color=report.use_color() and not args.no_color))
    if args.json:
        Path(args.json).write_text(report.json_report(snaps), encoding="utf-8")
        print(f"\nJSON report: {args.json}")
    if args.html:
        Path(args.html).write_text(report.html_report(snaps), encoding="utf-8")
        print(f"HTML report: {args.html}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="script-monitor",
                                 description="Monitor third-party scripts, SRI and CSP on your web pages (read-only).")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan one or more pages")
    sc.add_argument("urls", nargs="*", help="page URLs to scan")
    sc.add_argument("--urls-file", help="text file with one URL per line")
    sc.add_argument("--baseline", help="baseline JSON file (created on first run)")
    sc.add_argument("--update-baseline", action="store_true", help="save this scan as the new baseline")
    sc.add_argument("--first-party", action="append", default=[], metavar="DOMAIN",
                    help="extra domain you own, e.g. your CDN (repeatable)")
    sc.add_argument("--no-fetch", action="store_true", help="do not download scripts (no hashes or SRI check)")
    sc.add_argument("--fixtures", help="read pages from a local fixture folder instead of the network")
    sc.add_argument("--timeout", type=float, default=15.0)

    dm = sub.add_parser("demo", help="offline demo: baseline v1 of a fake shop, then detect changes in v2")
    for p in (sc, dm):
        p.add_argument("--json", help="write a JSON report")
        p.add_argument("--html", help="write an HTML report")
        p.add_argument("--fail-on", choices=SEVERITIES[:-1], help="exit 1 if a finding of this severity or worse exists")
        p.add_argument("--no-color", action="store_true")

    cp = sub.add_parser("csp", help="review a CSP string")
    cp.add_argument("policy")
    sr = sub.add_parser("sri", help="print SRI integrity values for a local file or URL")
    sr.add_argument("target")

    args = ap.parse_args(argv)

    if args.cmd == "csp":
        fs = sort_findings([f.to_dict() for f in analyze({"enforced": args.policy, "source": "header"})])
        for f in fs:
            print(f"[{f['severity'].upper()}] {f['code']}: {f['title']}\n    {f['detail']}")
        if not fs:
            print("No issues found.")
        return 0

    if args.cmd == "sri":
        if args.target.startswith(("http://", "https://")):
            res = HttpFetcher().fetch(args.target)
            if not res.ok:
                print(f"Could not fetch: {res.error}", file=sys.stderr)
                return 2
            body = res.body
        else:
            body = Path(args.target).read_bytes()
        for algo in ("sha256", "sha384", "sha512"):
            print(sri.integrity(body, algo))
        print('\nUse it like: <script src="..." integrity="' + sri.integrity(body) + '" crossorigin="anonymous"></script>')
        return 0

    if args.cmd == "demo":
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bpath = Path(tmp) / "baseline.json"
            print("Step 1: scanning version 1 of the demo shop and saving a baseline...\n")
            v1 = run_scan([DEMO_URL], FixtureFetcher(DEMO_ROOT / "v1"), bpath)
            print(f"  v1 score {v1[0]['score']}/100, verdict {v1[0]['verdict']}, "
                  f"{len(v1[0]['resources'])} resources baselined.\n")
            print("Step 2: scanning version 2 (a vendor file changed, SRI removed, new script, weaker CSP)...\n")
            snaps = run_scan([DEMO_URL], FixtureFetcher(DEMO_ROOT / "v2"), bpath)
    else:
        urls = list(args.urls)
        if args.urls_file:
            urls += [ln.strip() for ln in Path(args.urls_file).read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
        if not urls:
            ap.error("give at least one URL or --urls-file")
        fetcher = FixtureFetcher(args.fixtures) if args.fixtures else HttpFetcher(timeout=args.timeout)
        snaps = run_scan(urls, fetcher, args.baseline, args.update_baseline, not args.no_fetch, args.first_party)

    _outputs(snaps, args)
    if args.fail_on:
        w = worst(snaps)
        if w and SEVERITIES.index(w) <= SEVERITIES.index(args.fail_on):
            return 1
    return 0
