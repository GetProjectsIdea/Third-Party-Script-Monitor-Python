import pytest

flask = pytest.importorskip("flask")

import app as webapp  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    webapp.app.config.update(TESTING=True, BASELINE=str(tmp_path / "web-baseline.json"), ALLOW_PRIVATE=False)
    return webapp.app.test_client()


def test_home_page(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Third-Party Script Monitor" in r.data


def test_demo_flow(client):
    r1 = client.post("/scan", data={"action": "demo-v1"})
    assert r1.status_code == 200 and b"version 1" in r1.data
    r2 = client.post("/scan", data={"action": "demo-v2"})
    assert r2.status_code == 200
    assert b"NEW_THIRD_PARTY_HOST" in r2.data and b"INVESTIGATE NOW" in r2.data


def test_rejects_bad_and_private_urls(client):
    assert client.post("/scan", data={"urls": "", "action": "scan"}).status_code == 400
    assert client.post("/scan", data={"urls": "file:///etc/passwd", "action": "scan"}).status_code == 400
    r = client.post("/scan", data={"urls": "http://127.0.0.1:5000/", "action": "scan"})
    assert r.status_code == 400 and b"blocked" in r.data
