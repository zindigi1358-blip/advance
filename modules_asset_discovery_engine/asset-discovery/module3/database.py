"""
Module 3 — Database Layer
===========================
SQLite cache for CVE lookups (avoids re-querying NVD for the same
product+version pair) plus storage for final risk-scored findings.
"""
import sqlite3
import json
import time
from config import CACHE_DB_PATH, CVE_CACHE_TTL


def get_conn():
    conn = sqlite3.connect(CACHE_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cve_cache (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        query_key    TEXT    NOT NULL UNIQUE,   -- "product|version"
        cve_data     TEXT    NOT NULL,          -- JSON blob of matched CVEs
        cached_at    REAL    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS kev_cache (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id       TEXT    NOT NULL UNIQUE,
        vendor       TEXT,
        product      TEXT,
        date_added   TEXT,
        due_date     TEXT,
        ransomware   TEXT,
        cached_at    REAL    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS risk_findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id         TEXT    NOT NULL,
        domain          TEXT    NOT NULL,
        subdomain       TEXT    NOT NULL,
        technology      TEXT,
        version         TEXT,
        matched_cves    TEXT,        -- JSON list of {cve_id, cvss, summary}
        in_kev          INTEGER DEFAULT 0,
        risk_score      REAL    NOT NULL,
        risk_level      TEXT    NOT NULL,
        exposure_notes  TEXT,
        created_at      REAL    NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_risk_scan ON risk_findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_cve_key    ON cve_cache(query_key);
    """)
    conn.commit()
    conn.close()


# ── CVE cache ─────────────────────────────────────────────────────────────

def get_cached_cves(query_key: str):
    """Returns cached CVE list if fresh (within TTL), else None."""
    conn = get_conn()
    row = conn.execute(
        "SELECT cve_data, cached_at FROM cve_cache WHERE query_key=?", (query_key,)
    ).fetchone()
    conn.close()
    if row and (time.time() - row["cached_at"]) < CVE_CACHE_TTL:
        return json.loads(row["cve_data"])
    return None


def set_cached_cves(query_key: str, cve_list: list):
    conn = get_conn()
    conn.execute("""
        INSERT INTO cve_cache (query_key, cve_data, cached_at)
        VALUES (?,?,?)
        ON CONFLICT(query_key) DO UPDATE SET cve_data=excluded.cve_data, cached_at=excluded.cached_at
    """, (query_key, json.dumps(cve_list), time.time()))
    conn.commit()
    conn.close()


# ── KEV cache ─────────────────────────────────────────────────────────────

def is_kev_cache_stale(max_age: int) -> bool:
    conn = get_conn()
    row = conn.execute("SELECT MAX(cached_at) as last FROM kev_cache").fetchone()
    conn.close()
    if not row or not row["last"]:
        return True
    return (time.time() - row["last"]) > max_age


def replace_kev_cache(entries: list):
    conn = get_conn()
    conn.execute("DELETE FROM kev_cache")
    now = time.time()
    conn.executemany("""
        INSERT OR IGNORE INTO kev_cache (cve_id, vendor, product, date_added, due_date, ransomware, cached_at)
        VALUES (?,?,?,?,?,?,?)
    """, [
        (e.get("cveID"), e.get("vendorProject"), e.get("product"),
         e.get("dateAdded"), e.get("dueDate"), e.get("knownRansomwareCampaignUse"), now)
        for e in entries
    ])
    conn.commit()
    conn.close()


def is_cve_in_kev(cve_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM kev_cache WHERE cve_id=?", (cve_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Risk findings ─────────────────────────────────────────────────────────

def save_finding(scan_id, domain, subdomain, technology, version,
                  matched_cves, in_kev, risk_score, risk_level, exposure_notes):
    conn = get_conn()
    conn.execute("""
        INSERT INTO risk_findings
        (scan_id, domain, subdomain, technology, version, matched_cves,
         in_kev, risk_score, risk_level, exposure_notes, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (scan_id, domain, subdomain, technology, version,
          json.dumps(matched_cves), int(in_kev), risk_score, risk_level,
          exposure_notes, time.time()))
    conn.commit()
    conn.close()


def get_findings(scan_id):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM risk_findings WHERE scan_id=? ORDER BY risk_score DESC", (scan_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
