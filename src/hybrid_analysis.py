"""Hybrid Analysis API client for file scanning."""

import os
from datetime import datetime

import requests

from src.rate_limiter import RateLimiter

HA_API_URL = "https://www.hybrid-analysis.com/api/v2/overview"
HA_SAMPLE_URL = "https://www.hybrid-analysis.com/sample"

VERDICT_MAP = {
    "no specific threat": "clean",
    "no verdict": "unknown",
    "whitelisted": "clean",
    "suspicious": "suspicious",
    "malicious": "malicious",
    "ransomware": "malicious",
}

ha_limiter = RateLimiter(max_requests=100, window_seconds=60)


def format_iso_timestamp(iso_string):
    """Convert ISO 8601 timestamp string to readable date format."""
    if not iso_string:
        return "N/A"
    try:
        return datetime.fromisoformat(iso_string).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "N/A"


def check_file_hash(file_hash: str) -> dict:
    """
    Look up a file by SHA-256 hash in Hybrid Analysis database.

    Args:
        file_hash: SHA-256 hash string

    Returns:
        dict with keys:
            - 'status': 'known' | 'unknown' | 'error'
            - 'verdict': 'clean' | 'suspicious' | 'malicious' (if known)
            - 'threat_score': int (if known)
            - 'av_detect': int (if known)
            - 'environment': str (if known)
            - 'family': str (if known)
            - 'file_type': str (if known)
            - 'tags': list (if known)
            - 'error': str (if error)
    """
    api_key = os.environ.get("HA_API_KEY")
    if not api_key:
        return {"status": "error", "error": "HA_API_KEY not set in .env"}

    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",
    }

    url = f"{HA_API_URL}/{file_hash}"

    ha_limiter.wait_if_needed()
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as e:
        return {"status": "error", "error": f"Network error: {e}"}

    if response.status_code == 404:
        return {
            "status": "unknown",
            "message": "File is not in Hybrid Analysis database",
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
        }

    data = response.json()

    verdict_raw = data.get("verdict", "")
    verdict = VERDICT_MAP.get(verdict_raw.lower(), verdict_raw)

    scanners = data.get("scanners", [])
    total_scanners = len(scanners)
    positive_scanners = sum(1 for s in scanners if s.get("status") == "malicious")

    return {
        "status": "known",
        "verdict": verdict,
        "threat_score": data.get("threat_score") or 0,
        "scanners_count": f"{positive_scanners}/{total_scanners}",
        "file_type": data.get("type", "N/A"),
        "family": data.get("vx_family") or "N/A",
        "tags": data.get("tags", []),
        "whitelisted": data.get("whitelisted", False),
        "first_seen": format_iso_timestamp(data.get("submitted_at")),
        "link": f"{HA_SAMPLE_URL}/{file_hash}",
    }
