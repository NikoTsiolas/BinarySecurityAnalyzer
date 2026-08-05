from pathlib import Path

import pytest

from bintriage.pe_analysis import analyze_pe

SAMPLE = Path("samples/putty.exe")
PACKED = Path("samples/putty-packed.exe")

# samples are gitignored, so skip rather than fail on a fresh clone
needs_sample = pytest.mark.skipif(not SAMPLE.exists(), reason="samples/putty.exe not present")
needs_packed = pytest.mark.skipif(not PACKED.exists(), reason="samples/putty-packed.exe not present")


def test_non_pe_returns_none(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes(b"just some text, definitely not a PE")
    assert analyze_pe(f) is None


@needs_sample
def test_clean_binary_shape():
    r = analyze_pe(SAMPLE)
    names = [s["name"] for s in r["sections"]]
    assert ".text" in names
    assert r["timestamp"] > 0
    assert "kernel32.dll" in r["imports"]


@needs_sample
def test_clean_code_section_is_not_random():
    # real compiled code sits around 6 - nowhere near packed territory
    text = next(s for s in r["sections"] if s["name"] == ".text") if (r := analyze_pe(SAMPLE)) else None
    assert 5.0 < text["entropy"] < 7.0
    assert text["executable"] and not text["writable"]      # W^X respected


@needs_packed
def test_packed_binary_trips_every_signal():
    r = analyze_pe(PACKED)
    names = [s["name"] for s in r["sections"]]
    assert any(n.startswith("UPX") for n in names)          # packer renamed the sections

    upx1 = next(s for s in r["sections"] if s["name"] == "UPX1")
    assert upx1["entropy"] > 7.2                            # compressed payload
    assert upx1["executable"] and upx1["writable"]          # W^X violated - the loading dock

    total_imports = sum(len(v) for v in r["imports"].values())
    assert total_imports < 50                               # manifest gutted vs 348 clean
