"""Render results as JSON and a self-contained HTML report. No analysis logic here.

The HTML has no external CSS, fonts or scripts, so it renders identically on
an air-gapped machine and screenshots cleanly into a ticket.
"""


import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

VERDICT_COLOURS = {
    "ALLOW": ("#0f5132", "#d1e7dd"),
    "REVIEW": ("#664d03", "#fff3cd"),
    "BLOCK": ("#842029", "#f8d7da"),
}

TEMPLATE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>bintriage - {{ filename }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         margin: 0; padding: 2rem; background: #f6f7f9; color: #212529; line-height: 1.5; }
  .wrap { max-width: 60rem; margin: 0 auto; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  .sub { color: #6c757d; font-size: .85rem; margin-bottom: 1.5rem; word-break: break-all; }
  .verdict { background: {{ bg }}; color: {{ fg }}; border-radius: .5rem;
             padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
  .verdict .word { font-size: 2rem; font-weight: 700; letter-spacing: .05em; }
  .verdict .score { font-size: .9rem; opacity: .85; }
  h2 { font-size: .95rem; text-transform: uppercase; letter-spacing: .05em;
       color: #6c757d; margin: 2rem 0 .75rem; }
  .card { background: #fff; border: 1px solid #dee2e6; border-radius: .5rem;
          padding: 1rem 1.25rem; margin-bottom: .75rem; }
  .ind-head { display: flex; align-items: baseline; gap: .75rem; margin-bottom: .5rem; }
  .weight { background: #212529; color: #fff; border-radius: .25rem;
            padding: .1rem .5rem; font-size: .8rem; font-weight: 700; }
  .ind-name { font-weight: 600; }
  .cat { color: #6c757d; font-size: .8rem; }
  .label { color: #6c757d; font-size: .8rem; text-transform: uppercase;
           letter-spacing: .04em; margin-top: .5rem; }
  code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .85rem; }
  table { border-collapse: collapse; width: 100%; background: #fff;
          border: 1px solid #dee2e6; border-radius: .5rem; overflow: hidden; }
  th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eee;
           font-size: .85rem; }
  th { background: #f1f3f5; font-weight: 600; }
  td.num { text-align: right; font-family: ui-monospace, Menlo, Consolas, monospace; }
  tr:last-child td { border-bottom: none; }
  .flag-bad { color: #842029; font-weight: 700; }
  dl { display: grid; grid-template-columns: 10rem 1fr; gap: .35rem 1rem; margin: 0; }
  dt { color: #6c757d; font-size: .85rem; }
  dd { margin: 0; font-size: .85rem; word-break: break-all; }
  .none { color: #6c757d; font-style: italic; }
  footer { color: #6c757d; font-size: .75rem; margin-top: 2.5rem;
           border-top: 1px solid #dee2e6; padding-top: 1rem; }
</style>
</head>
<body>
<div class="wrap">

  <h1>Static triage report</h1>
  <div class="sub mono">{{ path }}</div>

  <div class="verdict">
    <div class="word">{{ verdict }}</div>
    <div class="score">risk score {{ score }}
      &nbsp;&middot;&nbsp; {{ indicators|length }} indicator{{ '' if indicators|length == 1 else 's' }} fired
      &nbsp;&middot;&nbsp; thresholds: REVIEW at {{ review_at }}, BLOCK at {{ block_at }}</div>
  </div>

  <h2>Why</h2>
  {% for i in indicators %}
  <div class="card">
    <div class="ind-head">
      <span class="weight">+{{ i.weight }}</span>
      <span class="ind-name">{{ i.name }}</span>
      <span class="cat">{{ i.category }}</span>
    </div>
    <div class="label">Evidence</div>
    <div class="mono">{{ i.evidence }}</div>
    <div class="label">What it means</div>
    <div>{{ i.explanation }}</div>
  </div>
  {% else %}
  <div class="card none">No indicators fired. Nothing this tool checks for was present.</div>
  {% endfor %}

  <h2>File</h2>
  <div class="card">
    <dl>
      <dt>Size</dt><dd>{{ "{:,}".format(size) }} bytes</dd>
      <dt>Type</dt><dd>{{ filetype }}</dd>
      <dt>Magic bytes</dt><dd class="mono">{{ magic }}</dd>
      <dt>SHA256</dt><dd class="mono">{{ sha256 }}</dd>
      <dt>MD5</dt><dd class="mono">{{ md5 }}</dd>
      <dt>Entropy</dt><dd>{{ entropy }} bits/byte (whole file)</dd>
      {% if compiled %}<dt>Compiled</dt><dd>{{ compiled }}</dd>{% endif %}
      <dt>Strings</dt><dd>{{ "{:,}".format(strings_count) }} printable runs extracted</dd>
      {% if vt %}<dt>VirusTotal</dt><dd>{{ vt }}</dd>{% endif %}
    </dl>
  </div>

  {% if sections %}
  <h2>PE sections</h2>
  <table>
    <tr><th>Name</th><th>Raw size</th><th>Virtual size</th><th>Entropy</th><th>Flags</th></tr>
    {% for s in sections %}
    <tr>
      <td class="mono">{{ s.name }}</td>
      <td class="num">{{ "{:,}".format(s.raw_size) }}</td>
      <td class="num">{{ "{:,}".format(s.virtual_size) }}</td>
      <td class="num">{{ s.entropy }}</td>
      <td class="mono {% if s.executable and s.writable %}flag-bad{% endif %}">
        {{ 'X' if s.executable else '-' }}{{ 'W' if s.writable else '-' }}
      </td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if imports %}
  <h2>Imports ({{ import_total }} functions across {{ imports|length }} DLLs)</h2>
  <table>
    <tr><th>DLL</th><th>Count</th><th>Functions</th></tr>
    {% for dll, funcs in imports %}
    <tr>
      <td class="mono">{{ dll }}</td>
      <td class="num">{{ funcs|length }}</td>
      <td class="mono">{{ funcs[:12]|join(', ') }}{% if funcs|length > 12 %} &hellip;{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if iocs %}
  <h2>Indicators of compromise</h2>
  <table>
    <tr><th>Type</th><th>Found</th></tr>
    {% for kind, hits in iocs %}
    <tr>
      <td>{{ kind }}</td>
      <td class="mono">{{ hits[:10]|join(', ') }}{% if hits|length > 10 %} (+{{ hits|length - 10 }} more){% endif %}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if errors %}
  <h2>Collector errors</h2>
  <table>
    <tr><th>Stage</th><th>Error</th></tr>
    {% for where, msg in errors %}
    <tr><td>{{ where }}</td><td class="mono">{{ msg }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  <footer>
    Generated by bintriage on {{ generated }}. Static analysis only - the file was never executed.
    A low score means no checked-for indicator was present, not proof the file is safe.
  </footer>

</div>
</body>
</html>
""")


def to_json(facts: dict, path: Path) -> None:
    """Write the machine-readable report."""
    payload = dict(facts)
    scoring = payload.get("scoring")
    if scoring:
        payload["scoring"] = {
            "score": scoring["score"],
            "verdict": scoring["verdict"].value,
            "indicators": [asdict(i) for i in scoring["indicators"]],
        }
    path.write_text(json.dumps(payload, indent=2))


def to_html(facts: dict, path: Path) -> None:
    """Write the human-readable report, self-contained, no external assets."""
    from bintriage.scoring import BLOCK_AT, REVIEW_AT

    scoring = facts.get("scoring") or {"score": 0, "verdict": None, "indicators": []}
    verdict = scoring["verdict"].value if scoring["verdict"] else "UNKNOWN"
    fg, bg = VERDICT_COLOURS.get(verdict, ("#212529", "#e9ecef"))

    info = facts.get("fileinfo") or {}
    hashes = facts.get("hashes") or {}
    pe = facts.get("pe") or {}
    imports = pe.get("imports", {})
    vt = facts.get("virustotal")

    vt_summary = None
    if vt:
        if vt.get("status") == "found":
            vt_summary = f"{vt['malicious']} of {vt['engines']} engines flag this file"
        elif vt.get("status") == "not_found":
            vt_summary = "hash not seen by VirusTotal before"
        else:
            vt_summary = f"lookup failed: {vt.get('detail', 'unknown')}"

    html = TEMPLATE.render(
        path=facts["path"],
        filename=Path(facts["path"]).name,
        verdict=verdict,
        score=scoring["score"],
        indicators=scoring["indicators"],
        review_at=REVIEW_AT,
        block_at=BLOCK_AT,
        fg=fg,
        bg=bg,
        size=info.get("size", 0),
        filetype=info.get("description", "unknown"),
        magic=info.get("magic_hex", "?"),
        sha256=hashes.get("sha256", "?"),
        md5=hashes.get("md5", "?"),
        entropy=facts.get("entropy", "?"),
        compiled=pe.get("timestamp_iso"),
        strings_count=facts.get("strings_count", 0),
        vt=vt_summary,
        sections=pe.get("sections", []),
        imports=sorted(imports.items()),
        import_total=sum(len(v) for v in imports.values()),
        iocs=[(k, v) for k, v in (facts.get("iocs") or {}).items() if v],
        errors=sorted((facts.get("errors") or {}).items()),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    path.write_text(html)
