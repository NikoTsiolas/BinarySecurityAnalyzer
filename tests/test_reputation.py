"""VirusTotal client tests. No network - the HTTP call is faked."""

import requests

from bintriage import reputation


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def stats_payload(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected,
    }}}}


def test_no_api_key_returns_none(monkeypatch):
    # None means "nobody asked", which is different from "asked and found nothing"
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert reputation.check_hash("a" * 64) is None


def test_known_bad_hash(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, stats_payload(malicious=47, undetected=23)))

    r = reputation.check_hash("a" * 64)
    assert r["status"] == "found"
    assert r["malicious"] == 47
    assert r["engines"] == 47 + 0 + 60 + 23


def test_unknown_hash_is_an_answer_not_an_error(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404))

    assert reputation.check_hash("a" * 64) == {"status": "not_found"}


def test_rate_limit_is_reported(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(429))

    r = reputation.check_hash("a" * 64)
    assert r["status"] == "error"
    assert "rate limited" in r["detail"]


def test_network_failure_does_not_raise(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key")

    def boom(*a, **k):
        raise requests.ConnectionError("no route to host")

    monkeypatch.setattr(requests, "get", boom)

    r = reputation.check_hash("a" * 64)
    assert r["status"] == "error"
    assert "ConnectionError" in r["detail"]


def test_api_key_is_sent_in_the_header(monkeypatch):
    """The key must travel as a header, never in the URL where it would be logged."""
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    captured = {}

    def spy(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs.get("headers", {})
        return FakeResponse(200, stats_payload())

    monkeypatch.setattr(requests, "get", spy)
    reputation.check_hash("a" * 64)

    assert captured["headers"]["x-apikey"] == "fake-key"
    assert "fake-key" not in captured["url"]
