"""Aggregate results from multiple scanning sources into a final verdict."""


def count_verdicts(results: list) -> dict:
    """
    Count verdicts across multiple scan results.

    Args:
        results: list of scan result dicts (from check_vt, check_mb, check_ha)

    Returns:
        dict with counts:
            - 'malicious': int
            - 'suspicious': int
            - 'clean': int
            - 'unknown': int
            - 'error': int
            - 'known_total': int (sources that had data)
    """
    counts = {
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "unknown": 0,
        "error": 0,
        "known_total": 0,
    }

    for result in results:
        status = result.get("status")

        if status == "error":
            counts["error"] += 1
            continue

        if status == "unknown":
            counts["unknown"] += 1
            continue

        counts["known_total"] += 1
        verdict = result.get("verdict")

        if verdict == "malicious":
            counts["malicious"] += 1
        elif verdict == "suspicious":
            counts["suspicious"] += 1
        elif verdict == "clean":
            counts["clean"] += 1

    return counts


def determine_risk_level(counts: dict) -> dict:
    """
    Determine overall risk level based on verdict counts.

    Args:
        counts: dict from count_verdicts

    Returns:
        dict with keys:
            - 'level': 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
            - 'icon': emoji
            - 'recommendation': str
            - 'confidence': str (description)
    """
    if counts["malicious"] >= 2:
        return {
            "level": "HIGH",
            "icon": "🔴",
            "recommendation": "Do NOT open this file",
            "confidence": f"{counts['malicious']}/3 sources confirm malicious",
        }

    if counts["suspicious"] >= 1:
        return {
            "level": "MEDIUM",
            "icon": "🟠",
            "recommendation": "Investigate before opening",
            "confidence": f"{counts['suspicious']}/3 sources flagged as suspicious",
        }

    if counts["known_total"] == 0:
        return {
            "level": "UNKNOWN",
            "icon": "⚪",
            "recommendation": "Cannot verify, consider analyzing in a sandbox",
            "confidence": f"No sources have data on this file",
        }

    return {
        "level": "LOW",
        "icon": "🟢",
        "recommendation": "File appears safe",
        "confidence": f"{counts['clean']}/{counts['known_total']} sources confirm clean",
    }


def aggregate_results(vt_result: dict, mb_result: dict, ha_result: dict) -> dict:
    """
    Aggregate results from VirusTotal, MalwareBazaar, and Hybrid Analysis.

    Returns:
        dict with 'counts' and 'verdict' keys
    """
    results = [vt_result, mb_result, ha_result]
    counts = count_verdicts(results)
    verdict = determine_risk_level(counts)

    return {
        "counts": counts,
        "verdict": verdict,
    }
