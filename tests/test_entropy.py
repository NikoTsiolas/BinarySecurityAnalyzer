from bintriage.entropy import shannon_entropy


def test_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_uniform_bytes_are_zero():
    # one repeated value = perfectly predictable = no surprise at all
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_coin_flip_is_one_bit():
    # two values, equally likely — the answer we derived by hand
    assert shannon_entropy(b"aabb") == 1.0


def test_all_byte_values_once_is_max():
    # every value 0..255 exactly once: nothing is guessable, full 8 bits
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_english_text_is_moderate():
    text = b"the quick brown fox jumps over the lazy dog and keeps running"
    result = shannon_entropy(text)
    assert 3.5 < result < 5.0
