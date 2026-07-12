"""
Module 2: Continuous Monitoring + Change Detection
===================================================
Authorized use only. Always obtain explicit written permission before scanning.

Requires: module1/discovery_engine.py (with AssetDiscoveryEngine)
"""

import asyncio
import aiohttp
import aiofiles
import json
import hashlib
import smtplib
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import logging


# ══════════════════════════════════════════════════════════════════
#  DEFAULT CONFIGURATION
#  ─────────────────────
#  Fill these in once so you don't have to type flags every time.
#  Any command-line flag you pass to run_monitor.py takes priority
#  over the values below. Leave a slot as "" (empty string) to skip
#  it — empty slots are silently ignored, never cause an error.
# ══════════════════════════════════════════════════════════════════

# GitHub / passive-DNS API keys (all optional)
DEFAULT_GITHUB_TOKEN    = ""     # e.g. "ghp_xxxxxxxxxxxxxxxxxxxx"
DEFAULT_OTX_API_KEY     = ""     # AlienVault OTX  — otx.alienvault.com/api
DEFAULT_URLSCAN_API_KEY = ""     # URLScan.io      — urlscan.io/user/profile

# Up to 5 webhook URLs (Discord, Slack, or any custom JSON endpoint).
# Every non-empty entry receives every alert.
DEFAULT_WEBHOOKS = [
    "",   # webhook 1
    "",   # webhook 2
    "",   # webhook 3
    "",   # webhook 4
    "",   # webhook 5
]

# Up to 5 recipient email addresses. Every non-empty entry receives every alert.
DEFAULT_EMAIL_TO = [
    "",   # recipient 1
    "",   # recipient 2
    "",   # recipient 3
    "",   # recipient 4
    "",   # recipient 5
]

# Up to 5 sender accounts. Used in order — if account 1 fails to send
# (bad password, connection error, etc.) account 2 is tried automatically,
# and so on. Only entries with BOTH email_from and smtp_password filled
# are used; the rest are ignored.
DEFAULT_EMAIL_ACCOUNTS = [
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
]

# Minimum severity that triggers an alert: "info" | "warning" | "critical"
DEFAULT_MIN_SEVERITY = "warning"


# ── Auto-search for discovery_engine.py — works regardless of folder structure
def _find_discovery_engine() -> Path:
    """Walk up from this file and search sibling folders for discovery_engine.py."""
    start = Path(__file__).resolve().parent
    for parent in [start] + list(start.parents)[:5]:
        for candidate in parent.rglob("discovery_engine.py"):
            return candidate.parent
    return start.parent / "module1"   # fallback

_MODULE1 = _find_discovery_engine()
if str(_MODULE1) not in sys.path:
    sys.path.insert(0, str(_MODULE1))

from discovery_engine import (
    AssetDiscoveryEngine,
    DiscoveryReport,
    SubdomainResult,
    CloudAsset,
    LeakedCredential,
)

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────

_LOG_DIR = Path.home() / "asset-discovery-logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("monitor")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    _sh  = logging.StreamHandler()
    _sh.setFormatter(_fmt)
    _fh  = logging.FileHandler(_LOG_DIR / "monitor.log")
    _fh.setFormatter(_fmt)
    logger.addHandler(_sh)
    logger.addHandler(_fh)


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class ChangeEvent:
    event_type:  str   # new_subdomain | subdomain_removed | port_opened | port_closed
                       # cert_changed  | status_changed   | tech_added
                       # new_cloud_asset | new_credential_leak
    domain:      str
    asset:       str   # FQDN, bucket URL, etc.
    severity:    str   # info | warning | critical
    description: str
    old_value:   Optional[str] = None
    new_value:   Optional[str] = None
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class WeeklyDigest:
    domain:               str
    week_start:           str
    week_end:             str
    total_scans:          int        = 0
    total_changes:        int        = 0
    attack_surface_delta: int        = 0
    new_subdomains:       List[str]  = field(default_factory=list)
    removed_subdomains:   List[str]  = field(default_factory=list)
    new_ports_opened:     List[dict] = field(default_factory=list)
    cert_changes:         List[dict] = field(default_factory=list)
    new_cloud_assets:     List[str]  = field(default_factory=list)
    new_credential_leaks: int        = 0


# ─────────────────────────────────────────────
# Snapshot Manager
# ─────────────────────────────────────────────

class SnapshotManager:
    """
    Saves scan results to disk so consecutive runs can be diffed
    even after a server restart.

    ~/asset-discovery-data/<domain>/
        snapshot_latest.json           — diff baseline (always current)
        snapshot_YYYYMMDD_HHMMSS.json  — timestamped archive
        scan_history.jsonl             — one summary line per scan
        events_YYYY-MM-DD.jsonl        — change events per day
        digest_YYYY-MM-DD.json         — weekly digest
    """

    def __init__(self, domain: str, data_dir: Optional[str] = None):
        safe          = domain.replace(".", "_").replace("-", "_")
        base          = Path(data_dir) if data_dir else Path.home() / "asset-discovery-data"
        self.data_dir = base / safe
        self.data_dir.mkdir(parents=True, exist_ok=True)

    async def save_snapshot(
        self, report: DiscoveryReport, label: str = "latest", write_history: bool = False
    ) -> Path:
        path = self.data_dir / f"snapshot_{label}.json"
        try:
            async with aiofiles.open(path, "w") as f:
                await f.write(json.dumps(asdict(report), indent=2, default=str))
            logger.info(f"[Snapshot] Saved → {path.name}")
        except Exception as e:
            logger.error(f"[Snapshot] Save failed: {e}")
            raise

        if write_history:
            summary = {
                "scanned_at":       report.scan_completed or datetime.utcnow().isoformat(),
                "total_subdomains": report.total_subdomains,
                "alive_subdomains": report.alive_subdomains,
                "cloud_assets":     len(report.cloud_assets),
                "leaked_creds":     len(report.leaked_credentials),
                "duration_s":       report.scan_duration_seconds,
            }
            try:
                async with aiofiles.open(self.data_dir / "scan_history.jsonl", "a") as f:
                    await f.write(json.dumps(summary) + "\n")
            except Exception as e:
                logger.warning(f"[Snapshot] History append failed: {e}")

        return path

    async def load_snapshot(self, label: str = "latest") -> Optional[DiscoveryReport]:
        path = self.data_dir / f"snapshot_{label}.json"
        if not path.exists():
            return None
        try:
            async with aiofiles.open(path, "r") as f:
                raw = json.loads(await f.read())
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"[Snapshot] Corrupt file {path.name}: {e} — treating as missing")
            return None

        report                       = DiscoveryReport(domain=raw["domain"])
        report.scan_started          = raw.get("scan_started", "")
        report.scan_completed        = raw.get("scan_completed", "")
        report.total_subdomains      = raw.get("total_subdomains", 0)
        report.alive_subdomains      = raw.get("alive_subdomains", 0)
        report.scan_duration_seconds = raw.get("scan_duration_seconds", 0.0)

        subs, clouds, leaks = [], [], []
        for s in raw.get("subdomains", []):
            try:   subs.append(SubdomainResult(**s))
            except Exception: pass
        for c in raw.get("cloud_assets", []):
            try:   clouds.append(CloudAsset(**c))
            except Exception: pass
        for l in raw.get("leaked_credentials", []):
            try:   leaks.append(LeakedCredential(**l))
            except Exception: pass

        report.subdomains         = subs
        report.cloud_assets       = clouds
        report.leaked_credentials = leaks
        return report

    async def load_history(self) -> List[dict]:
        path = self.data_dir / "scan_history.jsonl"
        if not path.exists():
            return []
        try:
            async with aiofiles.open(path, "r") as f:
                lines = await f.readlines()
            return [json.loads(l) for l in lines if l.strip()]
        except Exception as e:
            logger.warning(f"[Snapshot] History read failed: {e}")
            return []

    async def append_events(self, events: List[ChangeEvent]):
        if not events:
            return
        path = self.data_dir / f"events_{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"
        try:
            async with aiofiles.open(path, "a") as f:
                for e in events:
                    await f.write(json.dumps(asdict(e)) + "\n")
        except Exception as e:
            logger.warning(f"[Snapshot] Event append failed: {e}")

    async def save_weekly_digest(self, digest: WeeklyDigest) -> Path:
        path = self.data_dir / f"digest_{digest.week_start[:10]}.json"
        async with aiofiles.open(path, "w") as f:
            await f.write(json.dumps(asdict(digest), indent=2))
        logger.info(f"[Digest] Saved → {path.name}")
        return path


# ─────────────────────────────────────────────
# Change Detector
# ─────────────────────────────────────────────

_CRITICAL_PORTS = {21, 23, 3389, 5900, 27017, 6379, 9200, 2375, 11211, 5432, 1433}


class ChangeDetector:
    """Pure diff — no I/O, no side effects."""

    def __init__(self, domain: str):
        self.domain = domain

    @staticmethod
    def _cert_fp(cert: Optional[dict]) -> str:
        if not cert:
            return ""
        return hashlib.sha256(json.dumps(cert, sort_keys=True).encode()).hexdigest()[:16]

    @staticmethod
    def _status(r: SubdomainResult) -> Optional[int]:
        return r.https_status or r.http_status

    def detect(self, old: DiscoveryReport, new: DiscoveryReport) -> List[ChangeEvent]:
        events:  List[ChangeEvent]          = []
        old_map: Dict[str, SubdomainResult] = {s.subdomain: s for s in old.subdomains}
        new_map: Dict[str, SubdomainResult] = {s.subdomain: s for s in new.subdomains}

        # 1 — New subdomains
        for sub, r in new_map.items():
            if sub not in old_map:
                events.append(ChangeEvent(
                    event_type  = "new_subdomain",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "warning" if r.is_alive else "info",
                    description = f"New subdomain detected: {sub}",
                    new_value   = f"alive={r.is_alive}  ip={r.ip_addresses}",
                ))

        # 2 — Removed subdomains
        for sub in old_map:
            if sub not in new_map:
                sev = "warning" if old_map[sub].is_alive else "info"
                events.append(ChangeEvent(
                    event_type  = "subdomain_removed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = sev,
                    description = f"Subdomain no longer resolves: {sub}",
                    old_value   = f"was_alive={old_map[sub].is_alive}",
                ))

        # 3 — Per-subdomain changes
        for sub in new_map:
            if sub not in old_map:
                continue
            o, n = old_map[sub], new_map[sub]

            # Ports
            old_ports = set(o.open_ports or [])
            new_ports = set(n.open_ports or [])
            for port in sorted(new_ports - old_ports):
                events.append(ChangeEvent(
                    event_type  = "port_opened",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "critical" if port in _CRITICAL_PORTS else "warning",
                    description = f"Port {port} newly open on {sub}",
                    new_value   = str(port),
                ))
            for port in sorted(old_ports - new_ports):
                events.append(ChangeEvent(
                    event_type  = "port_closed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "info",
                    description = f"Port {port} closed on {sub}",
                    old_value   = str(port),
                ))

            # SSL certificate
            old_fp = self._cert_fp(o.certificate_info)
            new_fp = self._cert_fp(n.certificate_info)
            if old_fp and new_fp and old_fp != new_fp:
                events.append(ChangeEvent(
                    event_type  = "cert_changed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "warning",
                    description = f"SSL certificate rotated on {sub}",
                    old_value   = f"expiry={(o.certificate_info or {}).get('not_after','?')}",
                    new_value   = f"expiry={(n.certificate_info or {}).get('not_after','?')}",
                ))

            # HTTP status
            old_st, new_st = self._status(o), self._status(n)
            if old_st != new_st and (old_st is not None or new_st is not None):
                events.append(ChangeEvent(
                    event_type  = "status_changed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "warning",
                    description = f"HTTP status changed on {sub}: {old_st} → {new_st}",
                    old_value   = str(old_st),
                    new_value   = str(new_st),
                ))

            # New technologies
            added = set(n.technologies or []) - set(o.technologies or [])
            if added:
                events.append(ChangeEvent(
                    event_type  = "tech_added",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "warning",
                    description = f"New tech detected on {sub}: {', '.join(sorted(added))}",
                    new_value   = ", ".join(sorted(added)),
                ))

        # 4 — Cloud assets
        old_cloud = {a.url for a in old.cloud_assets}
        for asset in new.cloud_assets:
            if asset.url not in old_cloud:
                events.append(ChangeEvent(
                    event_type  = "new_cloud_asset",
                    domain      = self.domain,
                    asset       = asset.url,
                    severity    = "critical" if asset.is_public else "warning",
                    description = f"New {'PUBLIC' if asset.is_public else 'private'} "
                                  f"{asset.provider} {asset.asset_type} bucket found",
                    new_value   = f"url={asset.url}  public={asset.is_public}",
                ))

        # 5 — Credential leaks
        delta = len(new.leaked_credentials) - len(old.leaked_credentials)
        if delta > 0:
            events.append(ChangeEvent(
                event_type  = "new_credential_leak",
                domain      = self.domain,
                asset       = self.domain,
                severity    = "critical",
                description = f"{delta} new credential leak(s) detected on GitHub",
                old_value   = str(len(old.leaked_credentials)),
                new_value   = str(len(new.leaked_credentials)),
            ))

        return events


# ─────────────────────────────────────────────
# Alert Configuration
# ─────────────────────────────────────────────

_SEV_RANK  = {"info": 0, "warning": 1, "critical": 2}
_SEV_EMOJI = {"info": "ℹ️ ", "warning": "⚠️ ", "critical": "🔴"}


def _clean_str_list(items: Optional[List[str]]) -> List[str]:
    """Strip whitespace and drop empty entries. Never raises on bad input."""
    if not items:
        return []
    return [str(i).strip() for i in items if i and str(i).strip()]


def _clean_accounts(accounts: Optional[List[dict]]) -> List[dict]:
    """Keep only accounts that have BOTH email_from and smtp_password filled in."""
    cleaned = []
    for a in (accounts or []):
        if not isinstance(a, dict):
            continue
        email_from = str(a.get("email_from") or "").strip()
        password   = str(a.get("smtp_password") or "").strip()
        if email_from and password:
            cleaned.append({
                "email_from":    email_from,
                "smtp_password": password,
                "smtp_host":     str(a.get("smtp_host") or "smtp.gmail.com").strip(),
                "smtp_port":     int(a.get("smtp_port") or 587),
            })
    return cleaned


class AlertConfig:
    """
    Holds every alert-channel setting. Supports multiple webhooks, multiple
    recipient emails, and multiple sender accounts (failover order).

    Build it three ways:
      AlertConfig()                          — uses the DEFAULT_* constants above
      AlertConfig(webhooks=[...], ...)        — pass values explicitly
      AlertConfig.from_config(overrides={..}) — defaults + selective overrides
                                                 (this is what the CLI uses)
    """

    def __init__(
        self,
        webhooks:       Optional[List[str]]  = None,
        email_to:       Optional[List[str]]  = None,
        email_accounts: Optional[List[dict]] = None,
        min_severity:   str                  = DEFAULT_MIN_SEVERITY,
    ):
        self.webhooks       = _clean_str_list(webhooks if webhooks is not None else DEFAULT_WEBHOOKS)
        self.email_to       = _clean_str_list(email_to if email_to is not None else DEFAULT_EMAIL_TO)
        self.email_accounts = _clean_accounts(email_accounts if email_accounts is not None else DEFAULT_EMAIL_ACCOUNTS)
        self.min_severity   = min_severity if min_severity in _SEV_RANK else DEFAULT_MIN_SEVERITY

    @property
    def email_enabled(self) -> bool:
        return bool(self.email_to and self.email_accounts)

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhooks)

    @classmethod
    def from_config(cls, overrides: Optional[dict] = None) -> "AlertConfig":
        """
        Start from the DEFAULT_* constants at the top of this file, then apply
        only the keys present in `overrides` (used by run_monitor.py's CLI).
        Any key not present in overrides keeps its hardcoded default.
        """
        overrides = overrides or {}
        return cls(
            webhooks       = overrides.get("webhooks",       DEFAULT_WEBHOOKS),
            email_to       = overrides.get("email_to",       DEFAULT_EMAIL_TO),
            email_accounts = overrides.get("email_accounts", DEFAULT_EMAIL_ACCOUNTS),
            min_severity   = overrides.get("min_severity",   DEFAULT_MIN_SEVERITY),
        )

    @classmethod
    def from_env(cls) -> "AlertConfig":
        """Optional: build purely from environment variables (legacy support)."""
        webhook = os.getenv("ALERT_WEBHOOK_URL")
        email_to = os.getenv("ALERT_EMAIL_TO")
        return cls(
            webhooks       = [webhook] if webhook else None,
            email_to       = [email_to] if email_to else None,
            email_accounts = [{
                "email_from":    os.getenv("ALERT_EMAIL_FROM", ""),
                "smtp_password": os.getenv("SMTP_PASSWORD", ""),
                "smtp_host":     os.getenv("SMTP_HOST", "smtp.gmail.com"),
                "smtp_port":     int(os.getenv("SMTP_PORT", "587")),
            }],
            min_severity   = os.getenv("ALERT_MIN_SEVERITY", DEFAULT_MIN_SEVERITY),
        )


# ─────────────────────────────────────────────
# Low-level senders (module-level, reused by AlertSender and WeeklyDigestBuilder)
# ─────────────────────────────────────────────

def _send_email_via_accounts(
    accounts: List[dict], to_list: List[str], subject: str, body: str
) -> bool:
    """
    Try each account in order until one succeeds in sending a single email
    addressed to every recipient in to_list. Returns True on success.
    Never raises — all failures are logged and the function returns False.
    """
    if not accounts:
        logger.debug("[Email] No sender account configured — skipping")
        return False
    if not to_list:
        logger.debug("[Email] No recipients configured — skipping")
        return False

    for acct in accounts:
        try:
            msg            = MIMEMultipart()
            msg["From"]    = acct["email_from"]
            msg["To"]      = ", ".join(to_list)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(acct["smtp_host"], acct["smtp_port"], timeout=20) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(acct["email_from"], acct["smtp_password"])
                srv.send_message(msg)

            logger.info(f"[Email] Sent via {acct['email_from']} → {', '.join(to_list)}")
            return True
        except smtplib.SMTPAuthenticationError:
            logger.warning(f"[Email] Auth failed for {acct['email_from']} — trying next account")
        except (smtplib.SMTPConnectError, OSError) as e:
            logger.warning(f"[Email] Cannot connect via {acct['email_from']}: {e} — trying next account")
        except Exception as e:
            logger.warning(f"[Email] Error via {acct['email_from']}: {e} — trying next account")

    logger.error("[Email] All configured accounts failed — alert not delivered by email")
    return False


async def _send_webhook(url: str, payload: dict) -> bool:
    """
    POST a JSON payload to one webhook URL with 3 retries + backoff.
    Compatible with Discord (content field) and Slack (text field).
    """
    short = url[:60] + ("..." if len(url) > 60 else "")
    for attempt in range(3):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.post(
                    url, json=payload, headers={"Content-Type": "application/json"}
                ) as resp:
                    if resp.status in (200, 204):
                        logger.info(f"[Webhook] Sent → {short} (HTTP {resp.status})")
                        return True
                    body_text = await resp.text()
                    logger.warning(
                        f"[Webhook] {short} HTTP {resp.status} "
                        f"(attempt {attempt+1}/3): {body_text[:120]}"
                    )
                    if resp.status in (401, 403, 404):
                        logger.error(f"[Webhook] Permanent error for {short} — check the URL")
                        return False
        except aiohttp.ClientConnectorError as e:
            logger.warning(f"[Webhook] Connection error {short} attempt {attempt+1}/3: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"[Webhook] Timeout {short} attempt {attempt+1}/3")
        except Exception as e:
            logger.error(f"[Webhook] Unexpected error for {short}: {e}")
            return False

        if attempt < 2:
            await asyncio.sleep(5 * (attempt + 1))

    logger.error(f"[Webhook] All 3 attempts failed for {short}")
    return False


# ─────────────────────────────────────────────
# Alert Sender
# ─────────────────────────────────────────────

class AlertSender:

    def __init__(self, cfg: AlertConfig):
        self.cfg = cfg

    def _filter(self, events: List[ChangeEvent]) -> List[ChangeEvent]:
        min_rank = _SEV_RANK.get(self.cfg.min_severity, 1)
        return [e for e in events if _SEV_RANK.get(e.severity, 0) >= min_rank]

    # ── Console (always available, no configuration needed) ─────

    def alert_console(self, events: List[ChangeEvent], domain: str):
        filtered = self._filter(events)
        if not filtered:
            return
        n_crit = sum(1 for e in filtered if e.severity == "critical")
        n_warn = sum(1 for e in filtered if e.severity == "warning")
        header = "🚨 CRITICAL CHANGES DETECTED" if n_crit else "⚠️  CHANGES DETECTED"

        print("\n" + "═" * 64)
        print(f"  {header}")
        print(f"  Domain : {domain}")
        print(f"  Time   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"  Total  : {len(filtered)} change(s)  ({n_crit} critical, {n_warn} warning)")
        print("─" * 64)
        for e in filtered:
            emoji = _SEV_EMOJI.get(e.severity, " ")
            print(f"  {emoji} [{e.severity.upper():<8}] {e.description}")
            if e.old_value and e.new_value:
                print(f"              Before : {e.old_value}")
                print(f"              After  : {e.new_value}")
        print("═" * 64 + "\n")

    # ── Email — broadcasts to every configured recipient ─────────

    def _build_email_body(self, filtered: List[ChangeEvent], domain: str) -> Tuple[str, str]:
        n_crit  = sum(1 for e in filtered if e.severity == "critical")
        n_warn  = sum(1 for e in filtered if e.severity == "warning")
        subject = (
            f"🔴 [{domain}] {n_crit} CRITICAL security change(s) detected"
            if n_crit else
            f"⚠️  [{domain}] {len(filtered)} change(s) detected"
        )
        body = [
            f"Security Change Alert — {domain}",
            f"Time    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"Changes : {len(filtered)}  ({n_crit} critical, {n_warn} warning)",
            "",
        ]
        for e in filtered:
            body.append(f"{_SEV_EMOJI.get(e.severity,'')} [{e.severity.upper()}] {e.description}")
            if e.old_value and e.new_value:
                body += [f"   Before : {e.old_value}", f"   After  : {e.new_value}"]
        body += ["", "─" * 52, "Asset Discovery Engine — Module 2"]
        return subject, "\n".join(body)

    def alert_email(self, events: List[ChangeEvent], domain: str):
        """Synchronous by design — called through run_in_executor from async code."""
        filtered = self._filter(events)
        if not filtered:
            return
        if not self.cfg.email_enabled:
            logger.debug("[Email] Not configured — skipping")
            return
        subject, body = self._build_email_body(filtered, domain)
        _send_email_via_accounts(self.cfg.email_accounts, self.cfg.email_to, subject, body)

    # ── Webhook — broadcasts to every configured URL concurrently ─

    def _build_webhook_payload(self, filtered: List[ChangeEvent], domain: str) -> dict:
        n_crit = sum(1 for e in filtered if e.severity == "critical")
        n_warn = sum(1 for e in filtered if e.severity == "warning")
        summary_lines = "\n".join(
            f"  {_SEV_EMOJI.get(e.severity,'')} {e.description}" for e in filtered[:10]
        )
        return {
            "domain":         domain,
            "timestamp":      datetime.utcnow().isoformat(),
            "total_changes":  len(filtered),
            "critical_count": n_crit,
            "warning_count":  n_warn,
            # Discord reads "content", Slack reads "text" — both included, harmless either way
            "content": f"{'🔴' if n_crit else '⚠️'} **{domain}** — {n_crit} critical, {n_warn} warning change(s)\n{summary_lines}",
            "text":    f"{'🔴' if n_crit else '⚠️'} *{domain}* — {n_crit} critical, {n_warn} warning change(s)\n{summary_lines}",
            "events":  [asdict(e) for e in filtered],
        }

    async def alert_webhook(self, events: List[ChangeEvent], domain: str):
        filtered = self._filter(events)
        if not filtered or not self.cfg.webhook_enabled:
            return
        payload = self._build_webhook_payload(filtered, domain)
        await asyncio.gather(*[_send_webhook(url, payload) for url in self.cfg.webhooks])

    # ── Fire every channel ────────────────────────────────────────

    async def send_all(self, events: List[ChangeEvent], domain: str):
        self.alert_console(events, domain)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.alert_email, events, domain)
        await self.alert_webhook(events, domain)


# ─────────────────────────────────────────────
# Weekly Digest Builder
# ─────────────────────────────────────────────

_W = 64   # box inner width


class WeeklyDigestBuilder:

    def __init__(self, domain: str, snapshot_mgr: SnapshotManager):
        self.domain       = domain
        self.snapshot_mgr = snapshot_mgr

    async def build(self, events: List[ChangeEvent]) -> WeeklyDigest:
        now     = datetime.utcnow()
        history = await self.snapshot_mgr.load_history()
        digest  = WeeklyDigest(
            domain      = self.domain,
            week_start  = (now - timedelta(days=7)).isoformat(),
            week_end    = now.isoformat(),
            total_scans = len(history),
        )
        for e in events:
            digest.total_changes += 1
            if   e.event_type == "new_subdomain":
                digest.new_subdomains.append(e.asset);       digest.attack_surface_delta += 1
            elif e.event_type == "subdomain_removed":
                digest.removed_subdomains.append(e.asset);   digest.attack_surface_delta -= 1
            elif e.event_type == "port_opened":
                digest.new_ports_opened.append({"asset": e.asset, "port": e.new_value})
                digest.attack_surface_delta += 1
            elif e.event_type == "cert_changed":
                digest.cert_changes.append({"asset": e.asset, "expiry": e.new_value})
            elif e.event_type == "new_cloud_asset":
                digest.new_cloud_assets.append(e.asset);     digest.attack_surface_delta += 1
            elif e.event_type == "new_credential_leak":
                try:
                    digest.new_credential_leaks += int(e.new_value or 0) - int(e.old_value or 0)
                except (ValueError, TypeError):
                    pass
        return digest

    def render(self, digest: WeeklyDigest) -> str:
        d     = digest.attack_surface_delta
        d_str = f"+{d}" if d > 0 else str(d)

        def row(text: str) -> str:
            if len(text) > _W - 2:
                text = text[:_W - 5] + "…"
            return f"║  {text:<{_W-2}}║"

        def sep() -> str:
            return "╠" + "═" * _W + "╣"

        lines = [
            "╔" + "═" * _W + "╗",
            row("WEEKLY SECURITY DIGEST"),
            row(f"Domain  : {self.domain}"),
            row(f"Period  : {digest.week_start[:10]}  →  {digest.week_end[:10]}"),
            sep(),
            row(f"Scans completed    : {digest.total_scans}"),
            row(f"Total changes      : {digest.total_changes}"),
            row(f"Attack surface Δ   : {d_str}"),
            sep(),
        ]

        def section(title: str, items: list, fmt=None, limit: int = 8):
            if not items:
                return
            lines.append(row(f"{title}  ({len(items)})"))
            for item in items[:limit]:
                text = fmt(item) if fmt else str(item)
                lines.append(row(f"  • {text}"))
            if len(items) > limit:
                lines.append(row(f"  … and {len(items)-limit} more"))

        section("New Subdomains",      digest.new_subdomains)
        section("Removed Subdomains",  digest.removed_subdomains)
        section("New Ports Opened",    digest.new_ports_opened,
                fmt=lambda p: f"{p['asset']} → port {p['port']}")
        section("Certificate Changes", digest.cert_changes,
                fmt=lambda c: f"{c['asset']}  ({c.get('expiry','')})")
        section("New Cloud Assets",    digest.new_cloud_assets)

        if digest.new_credential_leaks > 0:
            lines.append(row(f"🚨 New Credential Leaks : {digest.new_credential_leaks}"))

        lines.append("╚" + "═" * _W + "╝")
        return "\n".join(lines)

    def send_digest_email(self, digest: WeeklyDigest, cfg: AlertConfig):
        """
        Synchronous by design (no `await` needed inside) so it can be safely
        run via run_in_executor without wrapping in asyncio.run().
        Bypasses the severity filter — digests always go out if email is configured.
        """
        if not cfg.email_enabled:
            return
        text    = self.render(digest)
        subject = f"📋 [{digest.domain}] Weekly Security Digest — {digest.week_start[:10]}"
        _send_email_via_accounts(cfg.email_accounts, cfg.email_to, subject, text)


# ─────────────────────────────────────────────
# Continuous Monitor
# ─────────────────────────────────────────────

class ContinuousMonitor:
    """
    Runs daily scans, diffs against the previous result,
    sends alerts on any change, and generates weekly digests.

    Daemon:  await monitor.run_forever()
    Cron:    await monitor.run_once()
    """

    def __init__(
        self,
        domain:              str,
        alert_config:        Optional[AlertConfig] = None,
        github_token:        Optional[str]         = None,
        otx_api_key:         Optional[str]         = None,
        urlscan_api_key:     Optional[str]         = None,
        scan_interval_hours: int                   = 24,
        data_dir:            Optional[str]         = None,
        scan_ports:          bool                  = True,
        scan_cloud:          bool                  = True,
    ):
        self.domain              = domain.lower().strip()
        self.alert_config        = alert_config or AlertConfig.from_config()
        # Fall back to the hardcoded defaults if nothing was explicitly passed in
        self.github_token        = github_token    if github_token    else (DEFAULT_GITHUB_TOKEN or None)
        self.otx_api_key         = otx_api_key     if otx_api_key     else DEFAULT_OTX_API_KEY
        self.urlscan_api_key     = urlscan_api_key if urlscan_api_key else DEFAULT_URLSCAN_API_KEY
        self.scan_interval_hours = scan_interval_hours
        self.scan_ports          = scan_ports
        self.scan_cloud          = scan_cloud

        self._snap    = SnapshotManager(domain, data_dir)
        self._detect  = ChangeDetector(domain)
        self._alert   = AlertSender(self.alert_config)
        self._digest  = WeeklyDigestBuilder(domain, self._snap)
        self._weekly: List[ChangeEvent] = []
        self._count:  int               = 0

    async def run_once(self) -> Tuple[DiscoveryReport, List[ChangeEvent]]:
        self._count += 1
        logger.info("=" * 64)
        logger.info(f"[Monitor] Scan #{self._count}  —  {self.domain}")
        logger.info(f"[Monitor] {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        logger.info("=" * 64)

        old = await self._snap.load_snapshot("latest")
        if old:
            logger.info(f"[Monitor] Baseline: {old.total_subdomains} subdomains "
                        f"from {(old.scan_completed or '')[:10]}")
        else:
            logger.info("[Monitor] No baseline yet — saving now. Alerts begin from scan #2.")

        engine = AssetDiscoveryEngine(
            domain          = self.domain,
            github_token    = self.github_token,
            otx_api_key     = self.otx_api_key,
            urlscan_api_key = self.urlscan_api_key,
            scan_ports      = self.scan_ports,
            scan_cloud      = self.scan_cloud,
            scan_github     = bool(self.github_token),
        )
        new = await engine.run()

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        await self._snap.save_snapshot(new, "latest", write_history=True)
        await self._snap.save_snapshot(new, ts,       write_history=False)

        events: List[ChangeEvent] = []
        if old:
            events = self._detect.detect(old, new)
            logger.info(f"[Monitor] {len(events)} change(s) detected")
            if events:
                await self._snap.append_events(events)
                await self._alert.send_all(events, self.domain)
                self._weekly.extend(events)
            else:
                logger.info("[Monitor] No changes — all clear ✓")
        else:
            logger.info("[Monitor] Baseline saved. Next scan will diff.")

        if self._count % 7 == 0:
            await self._run_weekly_digest()

        logger.info(f"[Monitor] Done — {new.alive_subdomains} alive, {len(events)} change(s)")
        return new, events

    async def _run_weekly_digest(self):
        logger.info("[Monitor] Building weekly digest...")
        digest = await self._digest.build(self._weekly)
        print("\n" + self._digest.render(digest) + "\n")
        await self._snap.save_weekly_digest(digest)

        # send_digest_email is synchronous (blocking smtplib calls) —
        # run it in a thread pool so it never blocks the event loop.
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._digest.send_digest_email, digest, self.alert_config)

        self._weekly.clear()

    async def run_forever(self):
        logger.info("=" * 64)
        logger.info(f"[Monitor] Started — target: {self.domain}")
        logger.info(f"[Monitor] Interval : every {self.scan_interval_hours}h")
        logger.info(f"[Monitor] Data dir : {self._snap.data_dir}")
        logger.info(f"[Monitor] Alerts   : min_severity={self.alert_config.min_severity}")
        logger.info("[Monitor] Ctrl+C to stop")
        logger.info("=" * 64)

        while True:
            try:
                await self.run_once()
            except KeyboardInterrupt:
                logger.info("[Monitor] Stopped by user.")
                break
            except Exception as exc:
                logger.error(f"[Monitor] Scan failed: {exc}", exc_info=True)
                logger.info("[Monitor] Will retry next interval.")

            nxt = datetime.utcnow() + timedelta(hours=self.scan_interval_hours)
            logger.info(f"[Monitor] Next scan → {nxt.strftime('%Y-%m-%d %H:%M UTC')}")
            logger.info(f"[Monitor] Sleeping {self.scan_interval_hours}h...")
            try:
                await asyncio.sleep(self.scan_interval_hours * 3600)
            except (asyncio.CancelledError, KeyboardInterrupt):
                logger.info("[Monitor] Shutting down.")
                break
