"""files-multiscan — CLI for scanning files via multiple antivirus services"""

import sys
import hashlib
import time
from pathlib import Path
from dotenv import load_dotenv

from src.virustotal import check_file_hash as check_vt
from src.malware_bazaar import check_file_hash as check_mb
from src.hybrid_analysis import check_file_hash as check_ha
from src.aggregator import aggregate_results

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


def scan_single_file(file_path: Path) -> dict:
    """
    Scan a single file via all API sources.

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

    # VirusTotal file check
    print()
    print("=== VirusTotal ===")

    vt_result = check_vt(hashes["sha256"])

    if vt_result["status"] == "known":
        print(f"Detections: {vt_result['detections']}")
        print(f"Verdict: {vt_result['verdict']}")
        print(f"Reputation: {vt_result['reputation']}")
        print(f"First seen: {vt_result['first_seen']}")
        print(f"Link: {vt_result['link']}")
    elif vt_result["status"] == "unknown":
        print(f"{vt_result['message']}")
        print("Upload manually via https://www.virustotal.com/gui/home/upload")
    else:
        print(f"Error: {vt_result['error']}")

    # MalwareBazaar file check
    print()
    print("=== MalwareBazaar ===")

    mb_result = check_mb(hashes["sha256"])

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
        print(f"Error: {mb_result['error']}")

    # Hybrid Analysis file check
    print()
    print("=== Hybrid Analysis ===")

    ha_result = check_ha(hashes["sha256"])

    if ha_result["status"] == "known":
        print(f"Verdict: {ha_result['verdict']}")
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
        print(f"Error: {ha_result['error']}")

    # Combined verdict
    print()
    print("=== Combined Verdict ===")

    aggregate = aggregate_results(vt_result, mb_result, ha_result)
    verdict = aggregate["verdict"]

    print(f"Risk level: {verdict['level']} {verdict['icon']}")
    print(f"Confidence: {verdict['confidence']}")
    print(f"Recommendation: {verdict['recommendation']}")

    return {
        "file_path": file_path,
        "verdict": verdict,
    }


def scan_directory(directory: Path) -> None:
    """
    Recursively scan all files in a directory.
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

    for i, file_path in enumerate(all_files, start=1):
        result = scan_file_compact(file_path)
        verdict = result["verdict"]

        counts[verdict["level"]] = counts.get(verdict["level"], 0) + 1

        if verdict["level"] == "HIGH":
            high_risk_files.append(
                {"path": file_path, "confidence": verdict["confidence"]}
            )

        print(f"[{i}/{total}] {file_path.name} - {verdict['icon']} {verdict['level']}")

        if i < total:
            time.sleep(2)

    print()
    print("=== Scan Summary ===")
    print(f"Total files scanned: {total}")
    print(f"🔴 HIGH risk: {counts['HIGH']}")
    print(f"🟠 MEDIUM risk: {counts['MEDIUM']}")
    print(f"🟢 LOW risk: {counts['LOW']}")
    print(f"⚪ UNKNOWN: {counts['UNKNOWN']}")

    if high_risk_files:
        print()
        print("Details for HIGH risk files:")
        for entry in high_risk_files:
            print(f"- {entry['path']} ({entry['confidence']})")


def scan_file_compact(file_path: Path) -> dict:
    """
    Scan a single file silently and return aggregated result.
    Used for directory scanning.
    """
    try:
        hashes = compute_hashes(file_path)
        vt_result = check_vt(hashes["sha256"])
        mb_result = check_mb(hashes["sha256"])
        ha_result = check_ha(hashes["sha256"])
        aggregate = aggregate_results(vt_result, mb_result, ha_result)

        return {
            "file_path": file_path,
            "verdict": aggregate["verdict"],
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
        }


def main():
    """Entry point."""

    if len(sys.argv) < 2:
        print("Usage: python main.py <file_or_directory>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if not target.exists():
        print(f"Path not found: {target}")
        sys.exit(1)

    if target.is_file():
        scan_single_file(target)
    elif target.is_dir():
        scan_directory(target)
    else:
        print(f"Path is neither file or directory: {target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
