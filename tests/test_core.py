import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from script_monitor import baseline, csp, sri
from script_monitor.cli import DEMO_ROOT, DEMO_URL, main, run_scan
from script_monitor.fetcher import FixtureFetcher, HttpFetcher
from script_monitor.htmlparse import parse_html
from script_monitor.scanner import is_third_party, scan_page, site_of

V1, V2 = FixtureFetcher(DEMO_ROOT / "v1"), FixtureFetcher(DEMO_ROOT / "v2")


def codes(findings):
    return {f["code"] for f in findings}


# ---------- SRI ----------
def test_sri_roundtrip_and_mismatch():
    body = b"console.log('hi')"
    value = sri.integrity(body)
    assert value.startswith("sha384-")
    assert sri.check(value, body) == "ok"
    assert sri.check(value, body + b" ") == "mismatch"
    assert sri.check(None, body) == "missing"
    assert sri.check("md5-abc", body) == "invalid"
    assert sri.check(value, None) == "unfetched"


def test_sri_uses_strongest_algorithm():
    body = b"x"
    wrong512 = "sha512-" + "A" * 86 + "=="
    # sha384 matches but the stronger sha512 token is wrong -> browsers fail it
    assert sri.check(f"{sri.integrity(body)} {wrong512}", body) == "mismatch"


# ---------- HTML parsing ----------
def test_parse_html_finds_scripts_links_inline_and_meta():
    html = """<html><head><base href="https://cdn.site.example/assets/">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self'">
    <script src="a.js" integrity="sha384-x"></script>
    <link rel="stylesheet" href="//fonts.other.example/f.css">
    <link rel="preload" as="image" href="hero.png">
    <link rel="modulepreload" href="/m.js">
    <script>var a = 1;</script><script type="application/ld+json">{"a":1}</script></head></html>"""
    p = parse_html(html, "https://www.site.example/page")
    urls = [r["url"] for r in p["resources"]]
    assert "https://cdn.site.example/assets/a.js" in urls
    assert "https://fonts.other.example/f.css" in urls
    assert "https://cdn.site.example/m.js" in urls
    assert not any(u.endswith("hero.png") for u in urls)
    assert len(p["inline_scripts"]) == 1  # JSON-LD is ignored
    assert p["meta_csp"] == ["script-src 'self'"]


def test_third_party_detection():
    assert site_of("news.bbc.co.uk") == "bbc.co.uk"
    assert site_of("www.getprojects.org") == "getprojects.org"
    assert not is_third_party("static.shop.example", "www.shop.example")
    assert is_third_party("cdn.vendor.example", "www.shop.example")
    assert not is_third_party("assets.mycdn.example", "www.shop.example", ("mycdn.example",))


# ---------- CSP ----------
def test_csp_missing_is_high():
    f = [x.to_dict() for x in csp.analyze({"enforced": None, "report_only": None})]
    assert codes(f) == {"CSP_MISSING"}


def test_csp_weak_policy_flags():
    pol = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: *.vendor.example"
    c = codes(x.to_dict() for x in csp.analyze({"enforced": pol, "source": "header"}))
    assert {"CSP_UNSAFE_INLINE", "CSP_UNSAFE_EVAL", "CSP_SCRIPT_SCHEME", "CSP_SCRIPT_HOST_WILDCARD",
            "CSP_NO_CONNECT_SRC", "CSP_NO_OBJECT_SRC", "CSP_NO_BASE_URI", "CSP_NO_REPORTING"} <= c


def test_csp_strict_policy_is_clean():
    pol = ("default-src 'self'; script-src 'self' https://cdn.vendor.example; connect-src 'self'; "
           "object-src 'none'; base-uri 'self'; report-to csp")
    assert csp.analyze({"enforced": pol, "source": "header"}) == []


def test_csp_unsafe_inline_ignored_with_nonce():
    pol = "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'; report-to x"
    assert "CSP_UNSAFE_INLINE" not in codes(x.to_dict() for x in csp.analyze({"enforced": pol}))


def test_csp_report_only_and_strict_dynamic():
    c = codes(x.to_dict() for x in csp.analyze({"enforced": None, "report_only": "script-src 'nonce-a' 'strict-dynamic'"}))
    assert "CSP_REPORT_ONLY" in c and "CSP_STRICT_DYNAMIC" in c


def test_csp_compare_detects_weakening_and_removal():
    old = {"enforced": "script-src 'self'; connect-src 'self'"}
    new = {"enforced": "script-src 'self' 'unsafe-eval' https://new.example"}
    c = codes(x.to_dict() for x in csp.compare(old, new))
    assert {"CSP_WEAKENED", "CSP_SOURCE_ADDED", "CSP_DIRECTIVE_REMOVED"} <= c
    assert codes(x.to_dict() for x in csp.compare(old, {"enforced": None})) == {"CSP_REMOVED"}
    assert codes(x.to_dict() for x in csp.compare(old, {"enforced": None, "report_only": "x"})) == {"CSP_NOW_REPORT_ONLY"}


# ---------- Scanner on fixtures ----------
def test_scan_v1_is_mostly_clean():
    s = scan_page(DEMO_URL, V1)
    assert s["status"] == 200 and s["csp"]["source"] == "header"
    lib = next(r for r in s["resources"] if "tinylib" in r["url"])
    assert lib["sri_status"] == "ok" and lib["third_party"]
    assert "SRI_MISMATCH" not in codes(s["findings"])
    assert s["verdict"] in ("REVIEW", "LOOKS GOOD")
    assert len(s["inline_scripts"]) == 1 and s["inline_scripts"][0]["has_nonce"]


def test_scan_v2_flags_sri_mismatch_and_csp():
    s = scan_page(DEMO_URL, V2)
    c = codes(s["findings"])
    assert {"SRI_MISMATCH", "CSP_UNSAFE_EVAL", "CSP_STRICT_DYNAMIC", "CSP_CONNECT_BROAD", "SRI_MISSING"} <= c
    assert s["verdict"] == "INVESTIGATE NOW"


def test_no_fetch_mode_skips_hashes():
    s = scan_page(DEMO_URL, V1, fetch_resources=False)
    assert all(r["sha256"] is None for r in s["resources"])
    lib = next(r for r in s["resources"] if "tinylib" in r["url"])
    assert lib["sri_status"] == "unfetched"


def test_missing_page_reports_error():
    s = scan_page("https://shop.demo.example/nope.html", V1)
    assert codes(s["findings"]) == {"PAGE_FETCH_FAILED"}


# ---------- Baseline + diff ----------
def test_baseline_diff_detects_supply_chain_changes(tmp_path):
    b = tmp_path / "b.json"
    run_scan([DEMO_URL], V1, b)
    assert b.is_file()
    s = run_scan([DEMO_URL], V2, b)[0]
    c = codes(s["changes"])
    assert {"NEW_THIRD_PARTY_HOST", "CONTENT_CHANGED", "NEW_REFERENCED_HOST", "NEW_RISKY_PATTERN",
            "SRI_REMOVED", "CSP_WEAKENED", "CSP_SOURCE_ADDED"} <= c
    ref = next(f for f in s["changes"] if f["code"] == "NEW_REFERENCED_HOST")
    assert "stats-collector.example" in ref["detail"]
    # baseline is not overwritten unless asked
    data = json.loads(b.read_text())
    lib = next(r for r in data["pages"][DEMO_URL]["resources"] if "tinylib" in r["url"])
    assert lib["sri_status"] == "ok"


def test_same_scan_twice_has_no_changes(tmp_path):
    b = tmp_path / "b.json"
    run_scan([DEMO_URL], V1, b)
    s = run_scan([DEMO_URL], V1, b)[0]
    assert s["changes"] == []


def test_update_baseline(tmp_path):
    b = tmp_path / "b.json"
    run_scan([DEMO_URL], V1, b)
    run_scan([DEMO_URL], V2, b, update=True)
    s = run_scan([DEMO_URL], V2, b)[0]
    assert s["changes"] == []


def test_failed_scan_does_not_overwrite_baseline(tmp_path):
    b = tmp_path / "b.json"
    run_scan([DEMO_URL], V1, b)
    before = b.read_text()
    run_scan([DEMO_URL], FixtureFetcher(tmp_path), b, update=True)
    assert b.read_text() == before


# ---------- Fetchers ----------
def test_fixture_fetcher_blocks_path_escape():
    assert V1.fetch("https://shop.demo.example/../../../../etc/passwd").status == 404


def test_http_fetcher_rejects_non_http():
    assert HttpFetcher().fetch("file:///etc/passwd").error.startswith("unsupported scheme")


@pytest.fixture()
def local_site():
    root = DEMO_ROOT / "v1" / "shop.demo.example"
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_http_fetcher_real_local_server(local_site):
    s = scan_page(local_site, HttpFetcher(timeout=5))
    assert s["status"] == 200
    app_js = next(r for r in s["resources"] if r["url"].endswith("/static/app.js"))
    assert app_js["sha256"] and not app_js["third_party"]
    assert "CSP_MISSING" in codes(s["findings"])  # SimpleHTTPRequestHandler sends no CSP


# ---------- CLI ----------
def test_cli_demo_and_fail_on(tmp_path, capsys):
    out_json, out_html = tmp_path / "r.json", tmp_path / "r.html"
    rc = main(["demo", "--json", str(out_json), "--html", str(out_html), "--fail-on", "high", "--no-color"])
    assert rc == 1
    text = capsys.readouterr().out
    assert "NEW_THIRD_PARTY_HOST" in text and "SRI_MISMATCH" in text
    assert json.loads(out_json.read_text())["pages"][0]["verdict"] == "INVESTIGATE NOW"
    html = out_html.read_text()
    assert "<script" not in html.lower()  # report never embeds scripts
    assert "cdn.chatwidget.example" in html


def test_cli_scan_fixtures_and_csp_and_sri(tmp_path, capsys):
    rc = main(["scan", DEMO_URL, "--fixtures", str(DEMO_ROOT / "v1"), "--baseline", str(tmp_path / "b.json"), "--no-color"])
    assert rc == 0 and (tmp_path / "b.json").is_file()
    main(["csp", "script-src *"])
    assert "CSP_SCRIPT_WILDCARD" in capsys.readouterr().out
    f = tmp_path / "x.js"
    f.write_bytes(b"alert(1)")
    main(["sri", str(f)])
    assert sri.integrity(b"alert(1)") in capsys.readouterr().out


def test_report_escapes_html():
    from script_monitor.report import html_report
    s = scan_page(DEMO_URL, V1)
    s["resources"][0]["url"] = "https://x.example/<img src=x onerror=alert(1)>"
    assert "<img src=x" not in html_report([s])
