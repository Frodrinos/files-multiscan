"""Local hash-based cache to reduce API calls."""

import json
from datetime import datetime, timedelta
from pathlib import Path

CACHE_DIR = Path("cache")
CACHE_FILE = CACHE_DIR / "files_cache.json"

DEFAULT_TTL_DAYS = 7


def ensure_cache_dir():
    """Create cache directory if it doesn't exist."""
    CACHE_DIR.mkdir(exist_ok=True)


def load_cache() -> dict:
    """Load cache from disk or return empty cache if not exists."""
    ensure_cache_dir()

    if not CACHE_FILE.exists():
        return {
            "files": {},
            "metadata": {
                "version": 1,
                "created": datetime.now().isoformat(),
                "total_entries": 0,
            },
        }

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "files": {},
            "metadata": {
                "version": 1,
                "created": datetime.now().isoformat,
                "total_entries": 0,
            },
        }


def save_cache(cache: dict):
    """Save cache to disk."""
    ensure_cache_dir()

    cache["metadata"]["total_entries"] = len(cache["files"])

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def get_cached_result(file_hash: str) -> dict | None:
    """
    Get cached result for a file hash.

    Returns:
        Cached entry dict if valid, None if not in cache or expired
    """
    cache = load_cache()
    entry = cache["files"].get(file_hash)

    if not entry:
        return None

    cached_at = datetime.fromisoformat(entry["cached_at"])
    ttl_days = entry.get("ttl_days", DEFAULT_TTL_DAYS)
    expires_at = cached_at + timedelta(days=ttl_days)

    if datetime.now() > expires_at:
        return None

    return entry


def save_to_cache(
    file_hash: str,
    vt_result: dict,
    mb_result: dict,
    ha_result: dict,
    verdict: dict,
    ttl_days: int = DEFAULT_TTL_DAYS,
):
    """Save scan results to cache."""
    cache = load_cache()

    cache["files"][file_hash] = {
        "cached_at": datetime.now().isoformat(),
        "ttl_days": ttl_days,
        "results": {
            "virustotal": vt_result,
            "malware_bazaar": mb_result,
            "hybrid_analysis": ha_result,
        },
        "verdict": verdict,
    }

    save_cache(cache)


def cleanup_expired():
    """Remove expired entries from cache."""
    cache = load_cache()
    now = datetime.now()

    removed = 0
    valid_entries = {}

    for file_hash, entry in cache["files"].items():
        cached_at = datetime.fromisoformat(entry["cached_at"])
        ttl_days = entry.get("ttl_days", DEFAULT_TTL_DAYS)
        expires_at = cached_at + timedelta(days=ttl_days)

        if now <= expires_at:
            valid_entries[file_hash] = entry
        else:
            removed += 1

    cache["files"] = valid_entries
    save_cache(cache)

    return removed
