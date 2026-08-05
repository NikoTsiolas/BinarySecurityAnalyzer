from bintriage.indicators import Verdict
from bintriage.scoring import score


def make_facts(**overrides):
    """A clean, boring file. Tests override just the part they care about."""
    facts = {
        "path": "clean.exe",
        "fileinfo": {"size": 100000, "magic_hex": "4d5a9000", "description": "PE32"},
        "hashes": {"sha256": "abc", "md5": "def"},
        "entropy": 6.1,
        "iocs": {"ipv4": [], "url": [], "domain": [], "windows_path": []},
        "strings_count": 500,
        "errors": {},
        "pe": {
            "timestamp": 1700000000,
            "sections": [
                {"name": ".text", "raw_size": 50000, "virtual_size": 50000,
                 "entropy": 6.4, "executable": True, "writable": False},
                {"name": ".data", "raw_size": 4096, "virtual_size": 8192,
                 "entropy": 2.1, "executable": False, "writable": True},
            ],
            # 40 distinct names - a realistic manifest, not a suspiciously small one
            "imports": {"kernel32.dll": [f"SomeApiFunction{n}" for n in range(40)]},
        },
    }
    facts.update(overrides)
    return facts


def test_clean_file_allows():
    r = score(make_facts())
    assert r["verdict"] == Verdict.ALLOW
    assert r["score"] == 0


def test_disguised_executable_is_heavy():
    r = score(make_facts(path="invoice.pdf"))
    names = [i.name for i in r["indicators"]]
    assert "extension_mismatch" in names
    assert r["verdict"] == Verdict.REVIEW


def test_packed_profile_collapses_to_one_indicator():
    facts = make_facts()
    facts["pe"]["sections"] = [
        {"name": "UPX0", "raw_size": 0, "virtual_size": 786432,
         "entropy": 0.0, "executable": True, "writable": True},
        {"name": "UPX1", "raw_size": 900000, "virtual_size": 900000,
         "entropy": 7.88, "executable": True, "writable": True},
    ]
    r = score(facts)
    packed = [i for i in r["indicators"] if i.name == "likely_packed"]
    # one finding, not four - packing is a single conclusion
    assert len(packed) == 1
    assert packed[0].weight == 35


def test_injection_imports_fire():
    facts = make_facts()
    facts["pe"]["imports"] = {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        + [f"SomeApiFunction{n}" for n in range(40)]
    }
    r = score(facts)
    assert any(i.name == "imports_process_injection" for i in r["indicators"])


def test_virustotal_consensus_blocks_alone():
    r = score(make_facts(virustotal={"status": "found", "malicious": 47,
                                     "suspicious": 0, "harmless": 0,
                                     "undetected": 23, "engines": 70}))
    assert r["verdict"] == Verdict.BLOCK


def test_every_indicator_explains_itself():
    """No opaque scoring: each point must carry evidence and a reason."""
    facts = make_facts(path="fake.pdf")
    for i in score(facts)["indicators"]:
        assert i.evidence and i.explanation
        assert i.weight > 0


def test_score_is_sum_of_weights():
    r = score(make_facts(path="fake.pdf"))
    assert r["score"] == sum(i.weight for i in r["indicators"])
