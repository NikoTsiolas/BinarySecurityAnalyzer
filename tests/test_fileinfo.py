from bintriage.fileinfo import identify_file


def test_detects_mz_signature(tmp_path):
    # exe bytes wearing a pdf name — the exact lie this module exists to catch
    f = tmp_path / "sneaky.pdf"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 50)
    result = identify_file(f)
    assert result["magic_hex"].startswith("4d5a")


def test_empty_file(tmp_path):
    # ruling: empty file -> size 0, empty hex string, no crash, no guard needed
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = identify_file(f)
    assert result["size"] == 0
    assert result["magic_hex"] == ""


def test_short_file(tmp_path):
    # 3-byte file: read(6) just returns what exists — graceful, no padding
    f = tmp_path / "tiny.bin"
    f.write_bytes(b"abc")
    result = identify_file(f)
    assert result["magic_hex"] == "616263"


def test_returns_all_keys(tmp_path):
    f = tmp_path / "any.bin"
    f.write_bytes(b"hello")
    result = identify_file(f)
    for key in ("size", "magic_hex", "description"):
        assert key in result
