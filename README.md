# bintriage

A static triage tool for software awaiting install approval. Without executing
the file, it collects independent evidence (hashes, magic bytes, entropy per PE
section, strings and IOCs, section flags, import tables, VirusTotal reputation)
and weighs each finding into a traceable risk score that returns ALLOW, REVIEW,
or BLOCK, so an analyst only spends attention on what is genuinely ambiguous.

Every point of the score maps to a named indicator carrying the evidence that
produced it and a plain-English explanation. There is no opaque number.

## Usage

```
uv run bintriage <file> --html report.html --json report.json
```

Add `--vt` to query VirusTotal (reads `VT_API_KEY` from the environment; only
the SHA256 is sent, never the file).

## Checks

| check | what it looks for |
|---|---|
| hashing | SHA256 and MD5, computed in one streaming pass so memory stays constant |
| fileinfo | size, magic bytes, and libmagic's opinion, to catch files lying about their type |
| entropy | Shannon entropy whole-file and per PE section, to spot compression or encryption |
| strings | printable runs of 4+ chars, then regex for IPs, URLs, domains, Windows paths |
| pe_analysis | compile timestamp, section table with per-section entropy and W/X flags, import table |
| scoring | turns facts into weighted indicators and a verdict |
| reputation | VirusTotal hash lookup, optional |

## Worked example

`samples/putty.exe` is the genuine PuTTY release. `samples/putty-packed.exe` is
the same binary compressed with UPX, so the ground truth is known: benign, but
concealed.

```
                        clean              UPX-packed
sections                10, conventional   3: UPX0, UPX1, .rsrc
code section entropy    .text  6.45        UPX1  7.88
code section flags      X-                 XW
imports                 348 functions      11 functions
verdict                 REVIEW (25)        REVIEW (45)
```

The packed copy trips four section-table symptoms at once (writable+executable
sections, unrecognised names, a section that is empty on disk but claims 786 KB
of memory, and high entropy in executable code). Those are four observations of
one phenomenon, so they collapse into a single `likely_packed` indicator rather
than being counted four times. An earlier version scored them separately and
put a known-benign file at BLOCK 110, which is the kind of false positive that
makes analysts stop reading a tool's output.

## Scoring model

Two rules shape every weight:

- **No single indicator reaches BLOCK alone**, except a VirusTotal consensus,
  where the industry has already decided. Corroboration is the whole thesis:
  each signal individually has an innocent explanation, but several agreeing
  at once does not.
- **When unsure, prefer REVIEW.** A false alarm costs an analyst ten minutes;
  a miss costs an incident. The ALLOW band is deliberately narrow and the
  REVIEW band deliberately wide.

Thresholds: ALLOW under 20, REVIEW 20-49, BLOCK 50 and above. The entropy
threshold of 7.2 sits between the measured 6.45 of real compiled code and the
7.88 of the packed copy. All thresholds and weights live as named constants at
the top of `scoring.py`.

## Limitations

Static analysis only. It detects concealment, not malice: a legitimately packed
commercial installer trips the same wires as a packed trojan, which is why the
verdict feeds a human workflow rather than an automatic block. A low score means
no checked-for indicator was present, not that the file is safe. Well-written
malware that is signed, unpacked, and imports only mundane functions can score
zero.

## Development

```
uv sync
uv run pytest
```

Samples live in `samples/` and are gitignored. Tests that need a real PE skip
cleanly when it is absent.
