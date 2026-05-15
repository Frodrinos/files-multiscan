"""files-multiscan — CLI for scanning files via multiple antivirus services"""

import sys
import hashlib
from pathlib import Path
from dotenv import load_dotenv

from src.virustotal import check_file_hash as check_vt
from src.malware_bazaar import check_file_hash as check_mb
from src.hybrid_analysis import check_file_hash as check_ha

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


def main():
    """Entry point."""

    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>")
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"File not found: {file_path}")
        sys.exit(1)

    if not file_path.is_file():
        print(f"Not a file: {file_path}")
        sys.exit(1)

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
    print(f"Status: {ha_result['status']}")

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


if __name__ == "__main__":
    main()
