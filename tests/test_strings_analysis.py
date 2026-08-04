from bintriage.strings_analysis import extract_strings


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
