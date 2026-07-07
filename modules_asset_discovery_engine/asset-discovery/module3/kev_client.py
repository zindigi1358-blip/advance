"""
Module 3 — CISA KEV (Known Exploited Vulnerabilities) Client
================================================================
Official US government catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Free, no key required, no auth required.

This is the single strongest publicly available signal that a CVE is
being actively exploited RIGHT NOW — not "theoretically exploitable" but
"CISA has confirmed real-world attacks using this". Any matched CVE that
appears here should be treated as top remediation priority.
"""
import time
import requests

from config import KEV_FEED_URL, KEV_CACHE_MAX_AGE, USER_AGENT
import database as db


def refresh_kev_cache(force: bool = False) -> int:
    """
    Downloads and caches the full CISA KEV catalog.
    Returns number of entries cached (0 on failure — caller should treat
    that as 'KEV check unavailable' rather than crash the whole scan).
    """
    if not force and not db.is_kev_cache_stale(KEV_CACHE_MAX_AGE):
        return -1  # cache is fresh, no refresh needed

    try:
        resp = requests.get(KEV_FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        if resp.status_code != 200:
            return 0
        data = resp.json()
        entries = data.get("vulnerabilities", [])
        db.replace_kev_cache(entries)
        return len(entries)
    except requests.exceptions.Timeout:
        return 0
    except Exception:
        return 0


def check_kev(cve_id: str) -> dict | None:
    """Returns KEV entry details if this CVE is in the catalog, else None."""
    return db.is_cve_in_kev(cve_id)


def enrich_with_kev(cve_list: list) -> tuple[list, bool]:
    """
    Takes a list of {cve_id, cvss, summary} dicts from NVD and adds a
    'kev' field to each. Returns (enriched_list, any_in_kev).
    """
    any_in_kev = False
    for cve in cve_list:
        kev_entry = check_kev(cve["cve_id"])
        if kev_entry:
            cve["kev"] = {
                "date_added": kev_entry.get("date_added"),
                "due_date":   kev_entry.get("due_date"),
                "ransomware_use": kev_entry.get("ransomware"),
            }
            any_in_kev = True
        else:
            cve["kev"] = None
    return cve_list, any_in_kev
