"""
Module 3 — NVD (National Vulnerability Database) Client
===========================================================
Official US government CVE database: https://nvd.nist.gov
Free, no key required (but a free key gives 10x the rate limit).

This module ONLY reads public vulnerability metadata (CVE ID, CVSS score,
description) — it does not generate or fetch exploit code.
"""
import time
import threading
import requests

import config          # BUG FIX: was "from config import NVD_API_KEY, ..."
                        # which copies the value ONCE at import time. When
                        # run_module3.py later did config.NVD_API_KEY = key
                        # (from --nvd-key or config.py edit read after
                        # import), this module never saw it — always sent
                        # requests with the empty key it had at import.
                        # Fix: import the module itself and read
                        # config.NVD_API_KEY fresh on every call.
import database as db


class RateLimiter:
    """Sliding-window rate limiter — recomputes its own limit every call
    based on whether an API key is currently configured, so it stays
    correct even if the key gets set after this module was imported."""
    def __init__(self):
        self.timestamps = []
        self.lock       = threading.Lock()

    def wait_if_needed(self):
        max_requests = config.NVD_MAX_REQ_WITH_KEY if config.NVD_API_KEY else config.NVD_MAX_REQ_NO_KEY
        with self.lock:
            now = time.time()
            self.timestamps = [t for t in self.timestamps if now - t < config.NVD_WINDOW_SECONDS]
            if len(self.timestamps) >= max_requests:
                sleep_for = config.NVD_WINDOW_SECONDS - (now - self.timestamps[0]) + 0.5
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.time()
                self.timestamps = [t for t in self.timestamps if now - t < config.NVD_WINDOW_SECONDS]
            self.timestamps.append(time.time())


_limiter = RateLimiter()


def _extract_cvss(cve_item: dict) -> float:
    """NVD 2.0 API can return CVSS v3.1, v3.0, or v2 metrics — try in order of preference."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return float(entries[0]["cvssData"]["baseScore"])
    return 0.0


def _extract_summary(cve_item: dict) -> str:
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:300]
    return ""


def query_nvd(product: str, version: str = None, results_limit: int = 10) -> list:
    """
    Queries NVD using keyword search (product name, optionally + version).
    Returns a list of {cve_id, cvss, summary} dicts, sorted by CVSS descending.

    Uses NVD's `keywordSearch` param — simpler and more robust than full CPE
    matching (which requires an exact, versioned CPE string that's hard to
    derive reliably from a banner string alone).
    """
    if not product:
        return []

    query_key = f"{product}|{version or ''}"
    cached = db.get_cached_cves(query_key)
    if cached is not None:
        return cached

    keyword = f"{product} {version}" if version else product
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_limit,
    }
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    _limiter.wait_if_needed()

    try:
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers,
                            timeout=NVD_REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []

    if resp.status_code == 429:
        # Respect NVD's own rate-limit signal — back off and retry once
        time.sleep(NVD_WINDOW_SECONDS)
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=headers,
                                timeout=NVD_REQUEST_TIMEOUT)
        except Exception:
            return []

    if resp.status_code != 200:
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id   = cve_item.get("id", "")
        if not cve_id:
            continue
        results.append({
            "cve_id":  cve_id,
            "cvss":    _extract_cvss(cve_item),
            "summary": _extract_summary(cve_item),
            "url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    results.sort(key=lambda x: x["cvss"], reverse=True)
    results = results[:results_limit]

    db.set_cached_cves(query_key, results)
    return results
