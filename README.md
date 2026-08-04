# bintriage

CLI tool that does the static triage an IT security analyst would do before
approving software for install on a corporate machine. Point it at a binary
or installer and it produces a verdict — ALLOW, REVIEW, or BLOCK — where
every point of the risk score traces back to a named indicator with evidence
and a plain-English explanation. Nothing is ever executed; analysis is fully
static.

## Checks

- SHA256 / MD5 hashes
- File type, size, magic bytes
- Shannon entropy (whole file + per PE section) to spot packing/encryption
- String extraction with IOC matching: IPs, URLs, domains, file paths
- PE analysis: compile timestamp, sections, imported DLLs and functions
- Suspicious import categories: injection, network, persistence,
  anti-analysis, credential access
- Optional VirusTotal hash lookup (`VT_API_KEY` env var)

## Usage

```
uv run bintriage <file> --json report.json --html report.html
```

Test samples live in `samples/` and are never committed.
