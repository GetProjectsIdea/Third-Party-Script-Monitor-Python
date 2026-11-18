"""Optional Flask web UI for Third-Party Script Monitor.

Run:  python app.py   then open http://127.0.0.1:5000
It binds to 127.0.0.1 only. Do not expose it to the internet: it fetches URLs you type.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, render_template, request
from markupsafe import Markup

from script_monitor import __version__, baseline, report
from script_monitor.cli import DEMO_ROOT, DEMO_URL, run_scan
from script_monitor.fetcher import FixtureFetcher, HttpFetcher

app = Flask(__name__)
app.config["BASELINE"] = os.environ.get("SCRIPT_MONITOR_BASELINE", str(Path(__file__).with_name("web-baseline.json")))
app.config["ALLOW_PRIVATE"] = os.environ.get("SCRIPT_MONITOR_ALLOW_PRIVATE") == "1"
MAX_URLS = 10


def url_problem(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "Only http:// and https:// URLs are allowed."
    if app.config["ALLOW_PRIVATE"]:
        return None
    try:
        infos = socket.getaddrinfo(parts.hostname, None)
    except socket.gaierror:
        return "Host name does not resolve."
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return "Private, loopback and reserved addresses are blocked (set SCRIPT_MONITOR_ALLOW_PRIVATE=1 to allow)."
    return None


@app.get("/")
def index():
    return render_template("index.html", version=__version__, error=None, urls="")


@app.post("/scan")
def scan():
    action = request.form.get("action", "scan")
    if action in ("demo-v1", "demo-v2"):
        bpath = Path(app.config["BASELINE"]).with_name("demo-baseline.json")
        if action == "demo-v1" and bpath.exists():
            bpath.unlink()
        if action == "demo-v2" and not bpath.exists():
            run_scan([DEMO_URL], FixtureFetcher(DEMO_ROOT / "v1"), bpath)
        snaps = run_scan([DEMO_URL], FixtureFetcher(DEMO_ROOT / ("v1" if action == "demo-v1" else "v2")), bpath)
        title = "Demo shop: version 1 (baseline)" if action == "demo-v1" else "Demo shop: version 2 compared with the baseline"
    else:
        raw = request.form.get("urls", "")
        urls = [u.strip() for u in raw.splitlines() if u.strip()][:MAX_URLS]
        if not urls:
            return render_template("index.html", version=__version__, error="Enter at least one URL.", urls=raw), 400
        for u in urls:
            problem = url_problem(u)
            if problem:
                return render_template("index.html", version=__version__, error=f"{u}: {problem}", urls=raw), 400
        snaps = run_scan(urls, HttpFetcher(), app.config["BASELINE"],
                         update=action == "baseline", fetch_resources=True)
        title = "Scan saved as the new baseline" if action == "baseline" else "Scan results"
    body = Markup("".join(report.page_html(s) for s in snaps))
    return render_template("report.html", version=__version__, title=title, body=body, css=Markup(report.CSS),
                           json_text=report.json_report(snaps))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
