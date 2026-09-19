"""VirusTotal SHA256 reputation lookup (optional, stdlib only)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def lookup_sha256(sha256: str, api_key: str, timeout: int = 20) -> str:
    """Return a short verdict like ``12/72 malicious (3 suspicious)``, or a status.

    Status strings: ``no api key``, ``unseen`` (404), ``bad key`` (401),
    ``http <code>``, or ``error: <msg>``.
    """
    if not api_key:
        return "no api key"
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "unseen"
        if exc.code == 401:
            return "bad key"
        return f"http {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"

    stats = payload["data"]["attributes"]["last_analysis_stats"]
    total = sum(stats.values())
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    return f"{mal}/{total} malicious ({sus} suspicious)"
