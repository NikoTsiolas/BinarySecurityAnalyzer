import argparse
import sys
from pathlib import Path


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

    # TODO: run collectors -> score -> report
    print(f"analyzing {args.file} (pipeline not wired up yet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
