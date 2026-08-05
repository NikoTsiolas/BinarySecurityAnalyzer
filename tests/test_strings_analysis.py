from bintriage.strings_analysis import extract_strings, find_iocs


def test_finds_string_between_junk():
    assert extract_strings(b"\x00\x01hello\xff\x02hi!") == ["hello"]


def test_too_short_is_dropped():
    # 3 chars, default min_len 4 — noise filter should eat it
    assert extract_strings(b"abc") == []


def test_min_len_is_tunable():
    assert extract_strings(b"abc", min_len=3) == ["abc"]


def test_string_at_end_of_data_is_kept():
    # ends mid-run, never hits a wall — the after-loop check earns its keep here
    assert extract_strings(b"junk\x00hello") == ["junk", "hello"]


def test_runs_do_not_smear_together():
    # short tossed run must not contaminate the next one (the reset-placement bug)
    assert extract_strings(b"ab\x00cdef") == ["cdef"]


def test_no_printables_at_all():
    assert extract_strings(b"\x00\x01\x02\xff" * 10) == []


def test_iocs_are_categorized():
    found = find_iocs(["beacon to 10.0.0.5", "fetch https://evil.top/x", "drop C:\\Temp\\a.exe"])
    assert found["ipv4"] == ["10.0.0.5"]
    assert found["url"] == ["https://evil.top/x"]
    assert found["windows_path"] == ["C:\\Temp\\a.exe"]


def test_duplicate_iocs_reported_once():
    found = find_iocs(["hit 10.0.0.5", "again 10.0.0.5", "and again 10.0.0.5"])
    assert found["ipv4"] == ["10.0.0.5"]


def test_clean_strings_give_empty_lists():
    found = find_iocs(["hello world", "no leads here"])
    assert all(v == [] for v in found.values())
