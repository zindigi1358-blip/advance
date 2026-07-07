"""
Module 3 — Risk Scoring & CVE Matching Engine
Configuration
================================================
Sab settings yahan — env vars se override ho sakti hain.
"""
import os

# ── NVD (National Vulnerability Database) API ───────────────────────────────
# Free, official US government CVE database. Works WITHOUT a key too, but:
#   - No key : 5 requests / rolling 30s window
#   - With key: 50 requests / rolling 30s window  (10x faster)
# Get a free key (instant, just email): https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")          # ← apni key yahan ya env var mein daalo
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting (NVD hard limits — mat badlo warna IP temporarily ban ho sakti hai)
NVD_WINDOW_SECONDS   = 30
NVD_MAX_REQ_NO_KEY   = 5
NVD_MAX_REQ_WITH_KEY = 50
NVD_REQUEST_TIMEOUT  = 25

# ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────────────────
# Free, no key needed. This is CISA's official catalog of CVEs that are
# CONFIRMED to be actively exploited in the wild right now — the single
# strongest "fix this immediately" signal that exists publicly.
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_MAX_AGE = 12 * 60 * 60   # refresh every 12 hours

# ── Local cache (avoids re-querying NVD for the same product+version) ───────
CACHE_DB_PATH   = os.environ.get("MODULE3_CACHE_DB", "module3_cache.db")
CVE_CACHE_TTL   = 7 * 24 * 60 * 60   # 7 days — CVE data doesn't change often

# ── Risk scoring weights ─────────────────────────────────────────────────────
# Final score (0-100) = weighted combination of these factors.
WEIGHTS = {
    "cvss_base":        0.45,   # highest CVSS among matched CVEs
    "kev_bonus":         25,    # flat points added if ANY matched CVE is in CISA KEV
    "exposure_context":  0.20,  # how exposed is the asset (admin panel, db port, etc.)
    "asset_criticality": 0.15,  # prod/api/admin subdomains weigh more than dev/staging
    "cve_count_bonus":   0.20,  # more matched CVEs = slightly higher risk
}

# Exposure context scores (0-10) based on what Module 1/2.5 detected
EXPOSURE_SCORES = {
    "admin_panel_public":     10,
    "database_port_open":     10,
    "git_exposed":            10,
    "env_file_exposed":       10,
    "backup_file_exposed":     9,
    "docker_api_open":        10,
    "outdated_tls":            5,
    "missing_security_headers":3,
    "directory_listing":       6,
    "default":                 2,
}

# Asset criticality by subdomain naming pattern (simple heuristic)
CRITICALITY_PATTERNS = {
    "prod":     10, "www":  9, "api":   9, "admin": 10, "portal": 8,
    "payment":  10, "auth": 10, "sso":  9, "vpn":    9, "db":     10,
    "staging":   4, "dev":  3, "test":  3, "qa":     3, "demo":   3,
    "internal":  6, "backup": 7,
}
DEFAULT_CRITICALITY = 5

# Risk level bands (0-100 composite score)
RISK_BANDS = [
    (85, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0,  "INFO"),
]

USER_AGENT = "Mozilla/5.0 (compatible; ASM-Module3-RiskEngine/1.0)"
OUTPUT_DIR = "module3_reports"
