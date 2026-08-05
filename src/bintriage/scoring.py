
""" The scoring file for action on the analysis"""

from bintriage.indicators import Indicator, Verdict

# entropy at or above this in an exe section means the bytes are not
# ordinary code. clean putty .text measured 6.45, upx-packed measured 7.88,
# so 7.2 sits between them with margin on both sides.
PACKED_ENTROPY = 7.2

# section names real compilers emit. anything else means the table was rewritten.
KNOWN_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata",
    ".edata", ".tls", ".bss", ".didat", ".gfids", ".gxfg", ".00cfg", "_RDATA",
}

# capability categories. weights reflect how often the capability shows up in
# legitimate software: injection and credential theft are rare and damning,
# persistence and network are everywhere and only matter as corroboration.

IMPORT_CATEGORIES = {
    "process_injection": {
        "weight": 25,
        "explanation": "Can write code into another running process and execute it. Legitimate uses exist (debuggers, security tools) but are rare.",
        "functions": {
            "virtualallocex", "writeprocessmemory", "createremotethread",
            "ntunmapviewofsection", "queueuserapc", "setwindowshookexw",
            "ntwritevirtualmemory", "rtlcreateuserthread",
        },
    },
    "credential_access": {
        "weight": 25,
        "explanation": "Reads stored credentials - browser-saved passwords or Windows secrets. Almost nothing outside a password manager needs this.",
        "functions": {
            "cryptunprotectdata", "lsaretrieveprivatedata", "credenumeratew",
            "credreadw", "lsaopenpolicy",
        },
    },
    "anti_analysis": {
        "weight": 15,
        "explanation": "Checks whether it is being debugged or analyzed. Some commercial software does this as anti-piracy, but it is standard malware behaviour.",
        "functions": {
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "outputdebugstringa", "queryperformancecounter",
        },
    },
    "persistence": {
        "weight": 10,
        "explanation": "Can survive a reboot by writing to the registry or installing a service. Very common in legitimate software - only meaningful alongside other signals.",
        "functions": {
            "regsetvalueexw", "regsetvalueexa", "regcreatekeyexw",
            "createservicew", "createservicea", "startservicew",
        },
    },
    "network": {
        "weight": 10,
        "explanation": "Can reach the network to download or exfiltrate. Extremely common in legitimate software - only meaningful alongside other signals.",
        "functions": {
            "urldownloadtofile", "urldownloadtofilew", "internetopenw",
            "internetopena", "httpsendrequestw", "winhttpopen", "connect",
            "wsastartup", "send", "recv",
        },
    },
}

# packing shows up as several section-table symptoms at once. they are one
# finding, not several, so they collapse into a single capped indicator.
PACKER_PROFILE_WEIGHT = 35

# below this many detections it is usually a heuristic false positive.
# at or above it, the industry has already decided and we defer.
VT_CONSENSUS = 5

# verdict bands. wide REVIEW because ambiguity is the normal case.
REVIEW_AT = 20
BLOCK_AT = 50


def check_identity(facts: dict) -> list[Indicator]:
    """Does the file's extension match what its bytes say it is essentiall"""
    info = facts.get("fileinfo")
    if not info:
        return []

    magic = info.get("magic_hex", "")
    ext = facts["path"].rsplit(".", 1)[-1].lower() if "." in facts["path"] else ""

    # MZ bytes but not named like an executable: something is disguised
    if magic.startswith("4d5a") and ext not in {"exe", "dll", "sys", "scr", "msi", "com", "ocx", ""}:
        return [Indicator(
            name="extension_mismatch",
            category="identity",
            weight=30,
            evidence=f"magic bytes 4d5a (Windows executable) but filename ends in .{ext}",
            explanation="The file is a Windows executable disguised with a non-executable extension. There is no innocent reason to do this.",
        )]
    return []


def check_section_flags(facts: dict) -> list[Indicator]:
    """W+X sections, unknown names, size gaps - reported as one packer finding.

    These all come from the same phenomenon, so scoring them separately would
    count one fact six times. If enough of them agree we emit a single
    "likely packed" indicator, which is the conclusion an analyst would draw.
    """
    pe = facts.get("pe")
    if not pe:
        return []

    wx = [s["name"] for s in pe["sections"] if s["executable"] and s["writable"]]
    unknown = [s["name"] for s in pe["sections"] if s["name"] not in KNOWN_SECTIONS]
    hollow = [s["name"] for s in pe["sections"] if s["raw_size"] == 0 and s["virtual_size"] > 4096]
    high_entropy_code = [
        s["name"] for s in pe["sections"]
        if s["executable"] and s["entropy"] >= PACKED_ENTROPY
    ]

    signs = []
    if wx:
        signs.append(f"writable+executable: {', '.join(wx)}")
    if unknown:
        signs.append(f"unrecognised names: {', '.join(unknown)}")
    if hollow:
        signs.append(f"empty on disk but large in memory: {', '.join(hollow)}")
    if high_entropy_code:
        signs.append(f"high entropy code: {', '.join(high_entropy_code)}")

    # two or more agreeing means packed, and packed is one conclusion
    if len(signs) >= 2:
        return [Indicator(
            name="likely_packed",
            category="sections",
            weight=PACKER_PROFILE_WEIGHT,
            evidence="; ".join(signs),
            explanation="The section table shows the marks of a packer: the real code is compressed and only unpacked in memory at runtime. Legitimate software does this too, so it means the file cannot be inspected statically - not that it is malicious.",
        )]

    # only one sign fired - weaker on its own, but still worth reporting
    if wx:
        return [Indicator(
            name="writable_executable_section",
            category="sections",
            weight=25,
            evidence=f"section(s) {', '.join(wx)} are both writable and executable",
            explanation="Compilers do not emit memory that is both writable and executable, because it defeats DEP. An unpacking stub needs it: it writes code out at runtime and jumps into it.",
        )]
    if high_entropy_code:
        return [Indicator(
            name="packed_code_section",
            category="entropy",
            weight=20,
            evidence=f"section(s) {', '.join(high_entropy_code)} are executable and measure over {PACKED_ENTROPY} bits/byte",
            explanation=f"Compiled code normally measures around 6. Above {PACKED_ENTROPY} the bytes are compressed or encrypted, so the real code is hidden until runtime.",
        )]
    return []


def check_imports(facts: dict) -> list[Indicator]:
    """Match the import table against capability categories."""
    pe = facts.get("pe")
    if not pe:
        return []

    # flatten the whole manifest to lowercase names for matching
    imported = {fn.lower() for funcs in pe["imports"].values() for fn in funcs}
    total = len(imported)

    found = []
    for name, cat in IMPORT_CATEGORIES.items():
        hits = sorted(imported & cat["functions"])
        if hits:
            found.append(Indicator(
                name=f"imports_{name}",
                category="imports",
                weight=cat["weight"],
                evidence=f"imports {', '.join(hits[:6])}" + (f" (+{len(hits) - 6} more)" if len(hits) > 6 else ""),
                explanation=cat["explanation"],
            ))

    # a real program imports hundreds of functions. a handful means the real
    # imports are resolved at runtime to keep them off the manifest.
    if 0 < total < 15:
        found.append(Indicator(
            name="minimal_import_table",
            category="imports",
            weight=10,
            evidence=f"only {total} imported functions across {len(pe['imports'])} DLLs",
            explanation="Legitimate software declares hundreds of imports. A near-empty table means the program resolves what it needs at runtime, hiding its capabilities from static analysis.",
        ))
    return found


def check_timestamp(facts: dict) -> list[Indicator]:
    """Zeroed or impossible compile timestamps are deliberate."""
    pe = facts.get("pe")
    if not pe:
        return []

    ts = pe["timestamp"]
    if ts == 0:
        return [Indicator(
            name="zeroed_timestamp",
            category="metadata",
            weight=10,
            evidence="compile timestamp is 0 (1970-01-01)",
            explanation="The build timestamp was wiped. Compilers always write a real one, so its absence is deliberate - build times fingerprint a campaign.",
        )]
    return []


def check_iocs(facts: dict) -> list[Indicator]:
    """Hardcoded IPs are worth a look. Legitimate software uses domain names."""
    iocs = facts.get("iocs") or {}

    # ignore the version-number false positives our own regex admits
    ips = [ip for ip in iocs.get("ipv4", []) if not ip.startswith(("0.", "1.2.3", "6.0.0", "127."))]
    if ips:
        return [Indicator(
            name="hardcoded_ip_addresses",
            category="strings",
            weight=10,
            evidence=f"embedded IP addresses: {', '.join(ips[:5])}",
            explanation="Legitimate software almost always connects by domain name. A hardcoded IP is a lead worth checking, though version strings can also match this pattern.",
        )]
    return []


def check_reputation(facts: dict) -> list[Indicator]:
    """What the AV industry already knows about this hash.
    The one place a single indicator can BLOCK on its own - if dozens of
    engines agree, the question is already settled and our heuristics are
    not adding anything.
    """
    vt = facts.get("virustotal")
    if not vt or vt.get("status") != "found":
        return []

    hits = vt["malicious"] + vt["suspicious"]

    if hits >= VT_CONSENSUS:
        return [Indicator(
            name="virustotal_consensus",
            category="reputation",
            weight=60,
            evidence=f"{hits} of {vt['engines']} engines flag this file",
            explanation="A broad consensus across independent antivirus engines. This is the strongest signal available and does not need corroboration.",
        )]

    if hits >= 1:
        return [Indicator(
            name="virustotal_minority",
            category="reputation",
            weight=15,
            evidence=f"only {hits} of {vt['engines']} engines flag this file",
            explanation="A small number of detections is often a heuristic false positive - engines flag packers and obscure software routinely. Worth a look, not a conviction.",
        )]
    return []


CHECKS = (
    check_identity,
    check_section_flags,
    check_imports,
    check_timestamp,
    check_iocs,
    check_reputation,
)


def score(facts: dict) -> dict:
    """Run every check, sum the weights, return indicators plus a verdict."""
    indicators = []
    for check in CHECKS:
        indicators.extend(check(facts))

    total = sum(i.weight for i in indicators)

    if total >= BLOCK_AT:
        verdict = Verdict.BLOCK
    elif total >= REVIEW_AT:
        verdict = Verdict.REVIEW
    else:
        verdict = Verdict.ALLOW

    return {
        "score": total,
        "verdict": verdict,
        "indicators": sorted(indicators, key=lambda i: i.weight, reverse=True),
    }