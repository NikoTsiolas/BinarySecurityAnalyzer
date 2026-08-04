from bintriage.hashing import hash_file

# known-answer vectors: sha256/md5 of the exact bytes "abc", from the
# official test vectors — if these pass, the plumbing is right
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"


def test_known_answer(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"abc")
    result = hash_file(f)
    assert result["sha256"] == ABC_SHA256
    assert result["md5"] == ABC_MD5


def test_empty_file(tmp_path):
    # empty input is legal and has a well-known hash — shouldn't crash
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = hash_file(f)
    assert result["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_large_file_spans_chunks(tmp_path):
    # 3 MiB file forces the read loop through multiple chunks —
    # catches bugs that only appear at chunk boundaries
    f = tmp_path / "big.bin"
    f.write_bytes(b"\xab" * (3 * 1024 * 1024))
    import hashlib
    expected = hashlib.sha256(b"\xab" * (3 * 1024 * 1024)).hexdigest()
    assert hash_file(f)["sha256"] == expected
