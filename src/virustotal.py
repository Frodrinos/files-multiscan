"""VirusTotal API client for file scanning."""

from datetime import datetime

import os
import requests

VT_API_URL = "https://www.virustotal.com/api/v3/files"
VT_SAMPLE_URL = "https://www.virustotal.com/gui/file"


def format_timestamp(unix_timestamp):
    """Convert Unix timestamp to readable date string."""
    if not unix_timestamp:
        return "N/A"
    try:
        return datetime.fromtimestamp(unix_timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "N/A"


def check_file_hash(file_hash: str) -> dict:
    """
    Look up a file by hash in VirusTotal database.

    Args:
        file_hash: SHA-256, MD5, or SHA-1 hash string

    Returns:
        dict with keys:
            - 'status': 'known' | 'unknown' | 'error'
            - 'detections': str like '0/72' (if known)
            - 'verdict': 'clean' | 'suspicious' | 'malicious' (if known)
            - 'reputation': int (if known)
            - 'first_seen': str | None (if known)
            - 'last_analyzed': str | None (if known)
            - 'link': str (VirusTotal GUI URL)
            - 'error': str (if error)
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {"status": "error", "error": "VT_API_KEY not set in .env"}

    url = f"{VT_API_URL}/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        return {"status": "error", "error": f"Network error: {e}"}

    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "status": "known",
            "detections": f"{malicious + suspicious}/{total}",
            "verdict": verdict,
            "reputation": data["data"]["attributes"].get("reputation", 0),
            "first_seen": format_timestamp(attributes.get("first_submission_date")),
            "link": f"{VT_SAMPLE_URL}/{file_hash}",
        }

    elif response.status_code == 404:
        return {
            "status": "unknown",
            "message": "File not in VirusTotal database",
        }

    else:
        return {
            "status": "error",
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
        }
