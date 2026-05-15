"""Save scan results to JSON files for history and analysis."""

import json
from datetime import datetime
from pathlib import Path

SCAN_RESULTS_DIR = Path("scan-results")


def ensure_results_dir():
    """Create scan-results directory if it doesn't exist."""
    SCAN_RESULTS_DIR.mkdir(exist_ok=True)


def save_single_file_scan(
    file_path: Path,
    file_size: int,
    hashes: dict,
    vt_result: dict,
    mb_result: dict,
    ha_result: dict,
    verdict: dict,
) -> Path:
    """
    Save a single file scan result to JSON.

    Returns:
        Path to the created JSON file
    """
    ensure_results_dir()

    timestamp = datetime.now()
    filename = timestamp.strftime("%Y-%m-%d_%H-%M-%S") + ".json"
    output_path = SCAN_RESULTS_DIR / filename

    data = {
        "timestamp": timestamp.isoformat(),
        "scan_type": "single_file",
        "file": {
            "path": str(file_path),
            "size": file_size,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
        },
        "results": {
            "virustotal": vt_result,
            "malware_bazaar": mb_result,
            "hybrid_analysis": ha_result,
        },
        "verdict": verdict,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return output_path


def save_directory_scan(
    directory: Path,
    total_files: int,
    counts: dict,
    files_results: list,
) -> Path:
    """
    Save a directory scan result to JSON.

    Args:
        files_results: list of dicts with 'path' and 'verdict' keys

    Returns:
        Path to the created JSON file
    """
    ensure_results_dir()

    timestamp = datetime.now()
    filename = timestamp.strftime("%Y-%m-%d_%H-%M-%S") + "_dir.json"
    output_path = SCAN_RESULTS_DIR / filename

    # Convert Path objects to strings for JSON
    serializable_files = [
        {
            "path": str(entry["file_path"]),
            "verdict": entry["verdict"],
        }
        for entry in files_results
    ]

    data = {
        "timestamp": timestamp.isoformat(),
        "scan_type": "directory",
        "directory": str(directory),
        "total_files": total_files,
        "summary": counts,
        "files": serializable_files,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return output_path
