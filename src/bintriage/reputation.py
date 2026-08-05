"""VirusTotal hash lookup. Key comes from VT_API_KEY env var, skipped if unset.
Only the hash is sent, never the file, so nothing confidential leaves the
machine. The free tier allows 4 requests a minute.
"""

import os

import requests

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
TIMEOUT = 15


def check_hash(sha256: str) -> dict | None:
    """Ask VirusTotal what it knows about this hash.
    Returns None when the check could not run at all (no API key), so the
    caller can tell "nobody asked" apart from "asked and found nothing".
    """
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None

    try:
        r = requests.get(
            VT_URL.format(sha256),
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return {"status": "error", "detail": f"{type(e).__name__}: {e}"}

    # a hash VT has never seen is a real answer, not a failure
    if r.status_code == 404:
        return {"status": "not_found"}

    if r.status_code == 429:
        return {"status": "error", "detail": "rate limited (free tier allows 4/min)"}

    if r.status_code != 200:
        return {"status": "error", "detail": f"HTTP {r.status_code}"}

    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    engines = sum(stats.values())

    return {
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "engines": engines,
    }
