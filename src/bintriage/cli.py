"""Command line entry point: runs each collector, prints what they found.

Each collector runs independently - one failing is recorded as a fact, not a
crash, because malformed files are expected input for a triage tool.
"""


import argparse
import sys
from pathlib import Path

from bintriage.entropy import shannon_entropy
from bintriage.fileinfo import identify_file
from bintriage.hashing import hash_file
from bintriage.pe_analysis import analyze_pe
from bintriage.report import to_html, to_json
from bintriage.reputation import check_hash
from bintriage.scoring import score
from bintriage.strings_analysis import extract_strings, find_iocs


def collect(path: Path) -> dict:
    """Run every collector over the file. Failures land in facts["errors"]."""
    facts = {"path": str(path), "errors": {}}

    for name, fn in (
        ("hashes", lambda: hash_file(path)),
        ("fileinfo", lambda: identify_file(path)),
    ):
        try:
            facts[name] = fn()
        except Exception as e:
            facts[name] = None
            facts["errors"][name] = f"{type(e).__name__}: {e}"

    data = path.read_bytes()
    facts["entropy"] = round(shannon_entropy(data), 2)

    strings = extract_strings(data)
    facts["strings_count"] = len(strings)
    facts["iocs"] = find_iocs(strings)

    try:
        facts["pe"] = analyze_pe(path)
    except Exception as e:
        # a PE that breaks the parser is itself suspicious - keep it as a fact
        facts["pe"] = None
        facts["errors"]["pe"] = f"{type(e).__name__}: {e}"

    return facts


def print_report(facts: dict) -> None:
    print(f"\n=== {facts['path']} ===")

    info = facts.get("fileinfo") or {}
    print(f"size        : {info.get('size', '?'):,} bytes")
    print(f"type        : {info.get('description', '?')}")
    print(f"magic bytes : {info.get('magic_hex', '?')}")

    hashes = facts.get("hashes") or {}
    print(f"sha256      : {hashes.get('sha256', '?')}")
    print(f"md5         : {hashes.get('md5', '?')}")
    print(f"entropy     : {facts['entropy']} (whole file)")

    pe = facts.get("pe")
    if pe:
        print(f"compiled    : {pe['timestamp_iso']}")
        print(f"\nsections ({len(pe['sections'])}):")
        print(f"  {'name':10} {'raw':>10} {'virtual':>10} {'entropy':>8}  flags")
        for s in pe["sections"]:
            flags = ("X" if s["executable"] else "-") + ("W" if s["writable"] else "-")
            print(f"  {s['name']:10} {s['raw_size']:>10,} {s['virtual_size']:>10,} {s['entropy']:>8}  {flags}")

        total = sum(len(v) for v in pe["imports"].values())
        print(f"\nimports: {len(pe['imports'])} DLLs, {total} functions")
        for dll, funcs in sorted(pe["imports"].items()):
            print(f"  {dll:20} {len(funcs):>4}")
    else:
        print("\nPE analysis : not a PE file")

    print(f"\nstrings     : {facts['strings_count']:,} extracted")
    for category, hits in facts["iocs"].items():
        if hits:
            shown = ", ".join(hits[:5])
            more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
            print(f"  {category:13}: {shown}{more}")

    if facts["errors"]:
        print("\nerrors:")
        for where, msg in facts["errors"].items():
            print(f"  {where}: {msg}")

    result = facts["scoring"]
    print(f"\n{'=' * 60}")
    print(f"VERDICT: {result['verdict'].value}   (risk score {result['score']})")
    print(f"{'=' * 60}")
    for i in result["indicators"]:
        print(f"\n  [{i.weight:>3}] {i.name}  ({i.category})")
        print(f"        evidence : {i.evidence}")
        print(f"        why      : {i.explanation}")
    if not result["indicators"]:
        print("\n  no indicators fired")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bintriage",
        description="Static triage of a binary/installer: ALLOW, REVIEW, or BLOCK.",
    )
    p.add_argument("file", type=Path, help="file to analyze")
    p.add_argument("--json", type=Path, metavar="PATH", help="write JSON report here")
    p.add_argument("--html", type=Path, metavar="PATH", help="write HTML report here")
    p.add_argument("--vt", action="store_true", help="look up hash on VirusTotal (needs VT_API_KEY)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.file.is_file():
        print(f"error: {args.file} is not a file", file=sys.stderr)
        return 2

    facts = collect(args.file)

    if args.vt:
        sha256 = (facts.get("hashes") or {}).get("sha256")
        if sha256:
            facts["virustotal"] = check_hash(sha256)
            if facts["virustotal"] is None:
                print("note: VT_API_KEY not set, skipping VirusTotal lookup", file=sys.stderr)

    facts["scoring"] = score(facts)
    print_report(facts)

    if args.json:
        to_json(facts, args.json)
        print(f"wrote {args.json}")

    if args.html:
        to_html(facts, args.html)
        print(f"wrote {args.html}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
