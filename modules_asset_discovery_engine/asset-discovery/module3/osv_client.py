"""
Module 3 — OSV.dev Client (Open Source Vulnerabilities)
===========================================================
Maintained by Google: https://osv.dev — fully free, no API key/signup at all.

Best coverage for open-source PACKAGE ecosystems (npm, PyPI, Packagist,
RubyGems, Go, crates.io) — often has CVEs that NVD hasn't indexed yet,
since maintainers report straight to OSV.

Limitation (honest): OSV is ecosystem-based, so it works well for things
like "Django 4.1" (PyPI) or "Express 4.17" (npm), but has no data for
non-package software like raw Nginx/Apache binaries — those stay covered
by NVD instead. This module returns an empty list gracefully in that case,
it does not error out.
"""
import requests
from config import OSV_BASE_URL, OSV_REQUEST_TIMEOUT, USER_AGENT
import database as db

# Best-effort mapping: product name (as parsed by tech_parser) -> OSV ecosystem
# Extend this table any time you notice a product OSV should cover.
ECOSYSTEM_MAP = {
    "django":          "PyPI",
    "flask":           "PyPI",
    "requests":        "PyPI",
    "express.js":      "npm",
    "vue.js":          "npm",
    "react":           "npm",
    "angular":         "npm",
    "next.js":         "npm",
    "nuxt.js":         "npm",
    "laravel":         "Packagist",
    "symfony":         "Packagist",
    "wordpress":       "Packagist",   # some WP core/plugin CVEs are indexed under Packagist mirrors
    "ruby on rails":   "RubyGems",
    "jekyll":          "RubyGems",
}


def query_osv(product: str, version: str = None) -> list:
    """
    Returns list of {cve_id, cvss, summary, url} — same shape as nvd_client
    so risk_engine can merge them transparently. Returns [] (not an error)
    if the product has no known OSV ecosystem mapping.
    """
    if not product:
        return []

    ecosystem = ECOSYSTEM_MAP.get(product.lower())
    if not ecosystem:
        return []  # not a package-ecosystem product — OSV has no data path for this

    query_key = f"osv|{product}|{version or ''}"
    cached = db.get_cached_cves(query_key)
    if cached is not None:
        return cached

    body = {"package": {"name": product, "ecosystem": ecosystem}}
    if version:
        body["version"] = version

    try:
        resp = requests.post(
            OSV_BASE_URL, json=body,
            headers={"User-Agent": USER_AGENT},
            timeout=OSV_REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []

    if resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    results = []
    for vuln in data.get("vulns", []):
        osv_id = vuln.get("id", "")
        if not osv_id:
            continue

        # OSV aliases often include the matching CVE ID — prefer that for
        # cross-source deduplication with NVD/Vulners; fall back to OSV's
        # own ID (e.g. "GHSA-xxxx") if no CVE alias exists.
        cve_id = osv_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        cvss = 0.0
        for severity in vuln.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                try:
                    # OSV stores the CVSS VECTOR string, not a bare score —
                    # extract score from the accompanying 'score' field if present
                    cvss = float(severity.get("score", 0.0))
                except (ValueError, TypeError):
                    pass

        results.append({
            "cve_id":  cve_id,
            "cvss":    cvss,
            "summary": (vuln.get("summary") or vuln.get("details", ""))[:300],
            "url":     f"https://osv.dev/vulnerability/{osv_id}",
            "source":  "OSV.dev",
        })

    results.sort(key=lambda x: x["cvss"], reverse=True)
    db.set_cached_cves(query_key, results)
    return results
