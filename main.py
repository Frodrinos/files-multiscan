"""files-multiscan — CLI for scanning files via multiple antivirus services"""

import sys
import hashlib
from pathlib import Path
from dotenv import load_dotenv

from src.virustotal import check_file_hash as check_vt
from src.malware_bazaar import check_file_hash as check_mb
from src.hybrid_analysis import check_file_hash as check_ha
from src.aggregator import aggregate_results
from src.colors import color_level, color_verdict, header, error_text
from src.logger import save_single_file_scan, save_directory_scan
from src.cache import get_cached_result, save_to_cache, cleanup_expired, load_cache

load_dotenv()


def compute_hashes(file_path: Path) -> dict:
    """
    Compute SHA-256, MD5, and SHA-1 hashes of a file.

    Returns:
        dict with keys 'sha256', 'md5', 'sha1'
    """
    with open(file_path, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    sha256.update(data)
    md5.update(data)
    sha1.update(data)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
    }


def print_results(
    vt_result: dict,
    mb_result: dict,
    ha_result: dict,
    verdict: dict,
):
    """
    Print scan results in standard format.
    Used both for fresh scans and cached results.
    """
    # VirusTotal
    print()
    print(header("=== VirusTotal ==="))
    if vt_result["status"] == "known":
        print(f"Detections: {vt_result['detections']}")
        print(f"Verdict: {color_verdict(vt_result['verdict'])}")
        print(f"Reputation: {vt_result['reputation']}")
        print(f"First seen: {vt_result['first_seen']}")
        print(f"Link: {vt_result['link']}")
    elif vt_result["status"] == "unknown":
        print(f"{vt_result['message']}")
        print("Upload manually via https://www.virustotal.com/gui/home/upload")
    else:
        print(error_text(f"Error: {vt_result['error']}"))

    # MalwareBazaar
    print()
    print(header("=== MalwareBazaar ==="))
    if mb_result["status"] == "known":
        print(f"Signature: {mb_result['signature']}")
        print(f"File name: {mb_result['file_name']}")
        tags = ", ".join(mb_result["tags"]) if mb_result["tags"] else "none"
        print(f"Tags: {tags}")
        print(f"First seen: {mb_result['first_seen']}")
        print(f"Reporter: {mb_result['reporter']}")
        print(f"Link: {mb_result['link']}")
    elif mb_result["status"] == "unknown":
        print(f"{mb_result['message']}")
    else:
        print(error_text(f"Error: {mb_result['error']}"))

    # Hybrid Analysis
    print()
    print(header("=== Hybrid Analysis ==="))
    if ha_result["status"] == "known":
        print(f"Verdict: {color_verdict(ha_result['verdict'])}")
        print(f"Threat score: {ha_result['threat_score']}/100")
        print(f"Scanners: {ha_result['scanners_count']} flagged as malicious")
        print(f"Family: {ha_result['family']}")
        print(f"File type: {ha_result['file_type']}")
        print(f"Whitelisted: {ha_result['whitelisted']}")
        tags = ", ".join(ha_result["tags"]) if ha_result["tags"] else "none"
        print(f"Tags: {tags}")
        print(f"First seen: {ha_result['first_seen']}")
        print(f"Link: {ha_result['link']}")
    elif ha_result["status"] == "unknown":
        print(ha_result["message"])
    else:
        print(error_text(f"Error: {ha_result['error']}"))

    # Combined Verdict
    print()
    print(header("=== Combined Verdict ==="))
    print(f"Risk level: {color_level(verdict['level'])} {verdict['icon']}")
    print(f"Confidence: {verdict['confidence']}")
    print(f"Recommendation: {verdict['recommendation']}")


def scan_single_file(file_path: Path) -> dict:
    """
    Scan a single file via all API sources (or cache).
    Saves result to JSON log.

    Returns:
        dict with file info and aggregated verdict
    """
    hashes = compute_hashes(file_path)
    file_size = file_path.stat().st_size

    print(f"File: {file_path}")
    print(f"Size: {file_size} bytes")
    print(f"SHA-256: {hashes['sha256']}")
    print(f"MD5:     {hashes['md5']}")
    print(f"SHA-1:   {hashes['sha1']}")

    cached = get_cached_result(hashes["sha256"])

    if cached:
        print()
        print(f"📦 Using cached results (cached {cached['cached_at']})")

        vt_result = cached["results"]["virustotal"]
        mb_result = cached["results"]["malware_bazaar"]
        ha_result = cached["results"]["hybrid_analysis"]
        verdict = cached["verdict"]

        print_results(vt_result, mb_result, ha_result, verdict)
    else:
        vt_result = check_vt(hashes["sha256"])
        mb_result = check_mb(hashes["sha256"])
        ha_result = check_ha(hashes["sha256"])

        aggregate = aggregate_results(vt_result, mb_result, ha_result)
        verdict = aggregate["verdict"]

        print_results(vt_result, mb_result, ha_result, verdict)

        save_to_cache(
            file_hash=hashes["sha256"],
            vt_result=vt_result,
            mb_result=mb_result,
            ha_result=ha_result,
            verdict=verdict,
        )

    log_path = save_single_file_scan(
        file_path=file_path,
        file_size=file_size,
        hashes=hashes,
        vt_result=vt_result,
        mb_result=mb_result,
        ha_result=ha_result,
        verdict=verdict,
    )
    print()
    print(f"📁 Results saved to: {log_path}")

    return {
        "file_path": file_path,
        "verdict": verdict,
    }


def scan_file_compact(file_path: Path) -> dict:
    """
    Scan a single file silently and return aggregated result.
    Uses cache if available.
    Used for directory scanning.
    """
    try:
        hashes = compute_hashes(file_path)

        cached = get_cached_result(hashes["sha256"])

        if cached:
            return {
                "file_path": file_path,
                "verdict": cached["verdict"],
                "from_cache": True,
            }

        vt_result = check_vt(hashes["sha256"])
        mb_result = check_mb(hashes["sha256"])
        ha_result = check_ha(hashes["sha256"])
        aggregate = aggregate_results(vt_result, mb_result, ha_result)

        save_to_cache(
            file_hash=hashes["sha256"],
            vt_result=vt_result,
            mb_result=mb_result,
            ha_result=ha_result,
            verdict=aggregate["verdict"],
        )

        return {
            "file_path": file_path,
            "verdict": aggregate["verdict"],
            "from_cache": False,
        }
    except Exception as e:
        return {
            "file_path": file_path,
            "verdict": {
                "level": "UNKNOWN",
                "icon": "⚪",
                "confidence": f"Error: {e}",
                "recommendation": "Could not scan",
            },
            "from_cache": False,
        }


def scan_directory(directory: Path) -> None:
    """
    Recursively scan all files in a directory.
    Uses cache and saves results to JSON log.
    """
    print(f"files-multiscan: Directory scan mode")
    print(f"Scanning: {directory}")

    all_files = [f for f in directory.rglob("*") if f.is_file()]
    total = len(all_files)

    if total == 0:
        print(f"No files found in {directory}")
        return

    print(f"Found {total} files.")
    print()

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    high_risk_files = []
    all_results = []
    cache_hits = 0

    for i, file_path in enumerate(all_files, start=1):
        result = scan_file_compact(file_path)
        verdict = result["verdict"]

        if result.get("from_cache"):
            cache_hits += 1

        counts[verdict["level"]] = counts.get(verdict["level"], 0) + 1
        all_results.append(result)

        if verdict["level"] == "HIGH":
            high_risk_files.append(
                {"path": file_path, "confidence": verdict["confidence"]}
            )

        cache_indicator = " 📦" if result.get("from_cache") else ""
        print(
            f"[{i}/{total}] {file_path.name} - {verdict['icon']} {color_level(verdict['level'])}{cache_indicator}"
        )

    print()
    print(header("=== Scan Summary ==="))
    print(f"Total files scanned: {total}")
    print(f"Cache hits: {cache_hits}/{total}")
    print(f"🔴 HIGH risk: {counts['HIGH']}")
    print(f"🟠 MEDIUM risk: {counts['MEDIUM']}")
    print(f"🟢 LOW risk: {counts['LOW']}")
    print(f"⚪ UNKNOWN: {counts['UNKNOWN']}")

    if high_risk_files:
        print()
        print(error_text("Details for HIGH risk files:"))
        for entry in high_risk_files:
            print(f"- {entry['path']} ({entry['confidence']})")

    log_path = save_directory_scan(
        directory=directory,
        total_files=total,
        counts=counts,
        files_results=all_results,
    )
    print()
    print(f"📁 Results saved to: {log_path}")


def print_usage():
    """Print CLI usage information."""
    print("Usage:")
    print("  python main.py <file_or_directory>     Scan a file or directory")
    print("  python main.py --cleanup-cache         Remove expired cache entries")
    print("  python main.py --cache-stats           Show cache statistics")


def main():
    """Entry point."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "--cleanup-cache":
        removed = cleanup_expired()
        print(f"Removed {removed} expired entries from cache.")
        sys.exit(0)

    if arg == "--cache-stats":
        cache = load_cache()
        print(f"Cache entries: {len(cache['files'])}")
        print(f"Cache created: {cache['metadata']['created']}")
        sys.exit(0)

    target = Path(arg)

    if not target.exists():
        print(f"Path not found: {target}")
        sys.exit(1)

    if target.is_file():
        scan_single_file(target)
    elif target.is_dir():
        scan_directory(target)
    else:
        print(f"Path is neither file nor directory: {target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
