import json

from bintriage.indicators import Indicator, Verdict
from bintriage.report import to_html, to_json

FACTS = {
    "path": "samples/thing.exe",
    "fileinfo": {"size": 1234, "magic_hex": "4d5a9000", "description": "PE32 executable"},
    "hashes": {"sha256": "a" * 64, "md5": "b" * 32},
    "entropy": 7.4,
    "strings_count": 42,
    "iocs": {"ipv4": ["10.0.0.5"], "url": [], "domain": [], "windows_path": []},
    "errors": {},
    "pe": {
        "timestamp": 1700000000,
        "timestamp_iso": "2023-11-14T22:13:20+00:00",
        "sections": [{"name": "UPX1", "raw_size": 900, "virtual_size": 900,
                      "entropy": 7.9, "executable": True, "writable": True}],
        "imports": {"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
    },
    "scoring": {
        "score": 45,
        "verdict": Verdict.REVIEW,
        "indicators": [Indicator("likely_packed", "sections", 35, "UPX1 is W+X", "It is packed.")],
    },
}


def test_json_is_valid_and_verdict_is_a_string(tmp_path):
    out = tmp_path / "r.json"
    to_json(FACTS, out)
    loaded = json.loads(out.read_text())
    assert loaded["scoring"]["verdict"] == "REVIEW"
    assert loaded["scoring"]["indicators"][0]["weight"] == 35


def test_html_is_self_contained(tmp_path):
    out = tmp_path / "r.html"
    to_html(FACTS, out)
    html = out.read_text()

    assert "REVIEW" in html
    assert "likely_packed" in html
    assert "It is packed." in html

    # nothing may be loaded from the internet - the report must render air-gapped
    for offender in ("http://", "https://", "<script"):
        assert offender not in html
