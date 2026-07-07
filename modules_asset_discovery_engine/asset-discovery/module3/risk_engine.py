"""
Module 3 — Composite Risk Scoring Engine
===========================================
Combines 4 signals into a single 0-100 risk score per finding:
  1. CVSS base score       — how severe is the worst matched CVE
  2. CISA KEV bonus        — is it being actively exploited RIGHT NOW
  3. Exposure context      — how reachable/dangerous is this specific asset
  4. Asset criticality     — is this prod/admin/payment or just a dev box

This mirrors how real vulnerability-management platforms (Qualys, Tenable,
Rapid7) prioritize findings — CVSS alone is a bad prioritization signal on
its own, because a 9.8 CVSS bug on an internal dev server matters far less
than a 6.5 on a public-facing admin panel that's also in active KEV use.
"""
import re
from config import WEIGHTS, EXPOSURE_SCORES, CRITICALITY_PATTERNS, DEFAULT_CRITICALITY, RISK_BANDS


def score_to_level(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "INFO"


def compute_criticality(subdomain: str) -> float:
    """Scores 0-10 based on subdomain naming patterns."""
    sub_lower = subdomain.lower()
    best = DEFAULT_CRITICALITY
    for pattern, score in CRITICALITY_PATTERNS.items():
        if pattern in sub_lower:
            best = max(best, score)
    return best


def compute_exposure(exposure_flags: list) -> tuple[float, str]:
    """
    `exposure_flags` = list of strings like ["admin_panel_public", "outdated_tls"]
    detected by Module 1/2.5 for this specific subdomain.
    Returns (score 0-10, human-readable notes).
    """
    if not exposure_flags:
        return EXPOSURE_SCORES["default"], "No specific exposure signals detected"

    best_score = 0
    notes = []
    for flag in exposure_flags:
        score = EXPOSURE_SCORES.get(flag, EXPOSURE_SCORES["default"])
        best_score = max(best_score, score)
        notes.append(flag.replace("_", " "))

    return best_score, ", ".join(notes)


def compute_finding_score(cve_list: list, in_kev: bool, exposure_flags: list, subdomain: str) -> dict:
    """
    Main scoring function. Returns:
        {score: float, level: str, breakdown: {...}}
    """
    # 1. CVSS component (0-10 scale -> weighted)
    max_cvss = max((c["cvss"] for c in cve_list), default=0.0)
    cvss_component = (max_cvss / 10.0) * 100 * WEIGHTS["cvss_base"]

    # 2. KEV bonus (flat points, only if actively exploited)
    kev_component = WEIGHTS["kev_bonus"] if in_kev else 0

    # 3. Exposure context (0-10 scale -> weighted)
    exposure_score, exposure_notes = compute_exposure(exposure_flags)
    exposure_component = (exposure_score / 10.0) * 100 * WEIGHTS["exposure_context"]

    # 4. Asset criticality (0-10 scale -> weighted)
    criticality_score = compute_criticality(subdomain)
    criticality_component = (criticality_score / 10.0) * 100 * WEIGHTS["asset_criticality"]

    # 5. CVE count bonus — diminishing returns via log-ish curve, capped
    cve_count_component = min(len(cve_list) * 3, 15) * WEIGHTS["cve_count_bonus"]

    total = cvss_component + kev_component + exposure_component + criticality_component + cve_count_component
    total = min(round(total, 1), 100.0)

    return {
        "score": total,
        "level": score_to_level(total),
        "breakdown": {
            "max_cvss":            max_cvss,
            "cvss_points":         round(cvss_component, 1),
            "kev_points":          kev_component,
            "exposure_score":      exposure_score,
            "exposure_points":     round(exposure_component, 1),
            "exposure_notes":      exposure_notes,
            "criticality_score":   criticality_score,
            "criticality_points":  round(criticality_component, 1),
            "cve_count":           len(cve_list),
            "cve_count_points":    round(cve_count_component, 1),
        }
    }


def detect_exposure_flags(subdomain_record: dict, leak_findings: list = None) -> list:
    """
    Derives exposure flags from a Module 1 subdomain record + optional
    Module 2.5 leak findings for the same host.
    """
    flags = []
    open_ports = subdomain_record.get("open_ports", []) or []
    technologies = subdomain_record.get("technologies", []) or []
    title = (subdomain_record.get("title") or "").lower()

    dangerous_ports = {
        6379: "database_port_open", 27017: "database_port_open",
        9200: "database_port_open", 5432: "database_port_open",
        3306: "database_port_open", 2375: "docker_api_open",
    }
    for port in open_ports:
        if port in dangerous_ports:
            flags.append(dangerous_ports[port])

    if any("admin" in t.lower() or "admin" in title for t in technologies):
        flags.append("admin_panel_public")

    for t in technologies:
        tl = t.lower()
        if "missing hsts" in tl or "missing csp" in tl or "missing x-frame" in tl:
            flags.append("missing_security_headers")

    # Cross-reference Module 2.5 leak findings for this exact subdomain
    if leak_findings:
        host = subdomain_record.get("subdomain", "")
        for leak in leak_findings:
            leak_url = leak.get("url", "")
            if host in leak_url:
                leak_type = leak.get("type", "").lower()
                if "git" in leak_type:
                    flags.append("git_exposed")
                elif "env" in leak_type:
                    flags.append("env_file_exposed")
                elif "backup" in leak_type or "zip" in leak_type or "sql" in leak_type:
                    flags.append("backup_file_exposed")

    return list(set(flags))
