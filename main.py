"""files-multiscan — CLI for scanning files via multiple antivirus services"""

import sys
import hashlib
from pathlib import Path
from dotenv import load_dotenv

from src.virustotal import check_file_hash as check_vt
from src.malware_bazaar import check_file_hash as check_mb

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
        print(f"Status: known")
        print(f"Detections: {vt_result['detections']}")
        print(f"Verdict: {vt_result['verdict']}")
        print(f"Reputation: {vt_result['reputation']}")
        print(f"First seen: {vt_result['first_seen']}")
        print(f"Link: {vt_result['link']}")
    elif vt_result["status"] == "unknown":
        print(f"Status: unknown")
        print(f"{vt_result['message']}")
        print(f"Upload manually via https://www.virustotal.com/gui/home/upload")
    else:
        print(f"Status: error")
        print(f"Error: {vt_result['error']}")


if __name__ == "__main__":
    main()
