"""
Module 2: Continuous Monitoring + Change Detection
===================================================
Authorized use only. Always obtain explicit written permission before scanning.

Components:
  SnapshotManager     — Persists scan state between runs (JSON on disk)
  ChangeDetector      — Diffs two snapshots and emits typed ChangeEvents
  AlertConfig         — All alert channel settings in one place
  AlertSender         — Delivers alerts via console / email / webhook
  WeeklyDigestBuilder — Aggregates weekly changes into a formatted digest
  ContinuousMonitor   — Orchestrates everything; runs daily, alerts on changes
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

# ── Resolve module1 path regardless of working directory
_MODULE1 = Path(__file__).resolve().parent.parent / "module1"
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
# Logging — always writes to ~/asset-discovery-logs/
# ─────────────────────────────────────────────
import logging

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
    """One detected difference between two consecutive scans."""
    event_type:  str            # new_subdomain | subdomain_removed | port_opened |
                                # port_closed | cert_changed | status_changed |
                                # tech_added | new_cloud_asset | new_credential_leak
    domain:      str
    asset:       str            # subdomain FQDN, bucket URL, etc.
    severity:    str            # info | warning | critical
    description: str
    old_value:   Optional[str] = None
    new_value:   Optional[str] = None
    detected_at: str           = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class WeeklyDigest:
    """Aggregated summary of all changes over a 7-scan (~1 week) window."""
    domain:               str
    week_start:           str
    week_end:             str
    total_scans:          int       = 0
    total_changes:        int       = 0
    attack_surface_delta: int       = 0   # net +/- in exposed assets vs previous week
    new_subdomains:       List[str] = field(default_factory=list)
    removed_subdomains:   List[str] = field(default_factory=list)
    new_ports_opened:     List[dict]= field(default_factory=list)
    cert_changes:         List[dict]= field(default_factory=list)
    new_cloud_assets:     List[str] = field(default_factory=list)
    new_credential_leaks: int       = 0


# ─────────────────────────────────────────────
# Snapshot Manager
# ─────────────────────────────────────────────

class SnapshotManager:
    """
    Persists scan reports to disk so the monitor can diff consecutive runs
    even after a server restart.

    Data lives under ~/asset-discovery-data/<domain>/
        snapshot_latest.json          — always-current baseline for diffing
        snapshot_YYYYMMDD_HHMMSS.json — timestamped archive copy
        scan_history.jsonl            — one-line summary per completed scan
        events_YYYY-MM-DD.jsonl       — all ChangeEvents for that calendar day
        digest_YYYY-MM-DD.json        — weekly digest JSON
    """

    def __init__(self, domain: str, data_dir: Optional[str] = None):
        safe          = domain.replace(".", "_").replace("-", "_")
        base          = Path(data_dir) if data_dir else Path.home() / "asset-discovery-data"
        self.data_dir = base / safe
        self.data_dir.mkdir(parents=True, exist_ok=True)

    # ── Snapshots ──────────────────────────────────────────────────────

    async def save_snapshot(
        self, report: DiscoveryReport, label: str = "latest", write_history: bool = False
    ) -> Path:
        """
        Save a snapshot.  Set write_history=True only for the canonical 'latest'
        save to avoid duplicate rows in scan_history.jsonl.
        """
        path = self.data_dir / f"snapshot_{label}.json"
        try:
            async with aiofiles.open(path, "w") as f:
                await f.write(json.dumps(asdict(report), indent=2, default=str))
            logger.info(f"[Snapshot] Saved → {path.name}")
        except Exception as e:
            logger.error(f"[Snapshot] Failed to save {path.name}: {e}")
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
                logger.warning(f"[Snapshot] Could not append to scan_history.jsonl: {e}")

        return path

    async def load_snapshot(self, label: str = "latest") -> Optional[DiscoveryReport]:
        """Load a snapshot by label. Returns None if it doesn't exist yet."""
        path = self.data_dir / f"snapshot_{label}.json"
        if not path.exists():
            return None
        try:
            async with aiofiles.open(path, "r") as f:
                raw = json.loads(await f.read())
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"[Snapshot] Corrupt snapshot {path.name}: {e} — treating as missing")
            return None

        report                       = DiscoveryReport(domain=raw["domain"])
        report.scan_started          = raw.get("scan_started", "")
        report.scan_completed        = raw.get("scan_completed", "")
        report.total_subdomains      = raw.get("total_subdomains", 0)
        report.alive_subdomains      = raw.get("alive_subdomains", 0)
        report.scan_duration_seconds = raw.get("scan_duration_seconds", 0.0)

        # Safely reconstruct dataclass lists — skip malformed entries
        subs, clouds, leaks = [], [], []
        for s in raw.get("subdomains", []):
            try:    subs.append(SubdomainResult(**s))
            except Exception: pass
        for c in raw.get("cloud_assets", []):
            try:    clouds.append(CloudAsset(**c))
            except Exception: pass
        for l in raw.get("leaked_credentials", []):
            try:    leaks.append(LeakedCredential(**l))
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
            logger.warning(f"[Snapshot] Could not read scan_history.jsonl: {e}")
            return []

    async def append_events(self, events: List[ChangeEvent]):
        if not events:
            return
        today = datetime.utcnow().strftime("%Y-%m-%d")
        path  = self.data_dir / f"events_{today}.jsonl"
        try:
            async with aiofiles.open(path, "a") as f:
                for e in events:
                    await f.write(json.dumps(asdict(e)) + "\n")
        except Exception as e:
            logger.warning(f"[Snapshot] Could not append events: {e}")

    async def save_weekly_digest(self, digest: WeeklyDigest) -> Path:
        path = self.data_dir / f"digest_{digest.week_start[:10]}.json"
        async with aiofiles.open(path, "w") as f:
            await f.write(json.dumps(asdict(digest), indent=2))
        logger.info(f"[Digest] Saved → {path.name}")
        return path

    def list_snapshots(self) -> List[Path]:
        return sorted(self.data_dir.glob("snapshot_2*.json"))


# ─────────────────────────────────────────────
# Change Detector
# ─────────────────────────────────────────────

_RISKY_PORTS   = {21, 23, 3389, 5900, 27017, 6379, 9200, 2375, 11211, 5432, 1433}
_PORT_SEVERITY = {p: "critical" for p in _RISKY_PORTS}


class ChangeDetector:
    """
    Pure diff engine — compares two DiscoveryReport objects and returns a list
    of ChangeEvents.  No I/O, no side effects.
    """

    def __init__(self, domain: str):
        self.domain = domain

    @staticmethod
    def _cert_fp(cert_info: Optional[dict]) -> str:
        if not cert_info:
            return ""
        return hashlib.sha256(
            json.dumps(cert_info, sort_keys=True).encode()
        ).hexdigest()[:16]

    @staticmethod
    def _http_status(r: SubdomainResult) -> Optional[int]:
        return r.https_status or r.http_status

    def detect(self, old: DiscoveryReport, new: DiscoveryReport) -> List[ChangeEvent]:
        events:  List[ChangeEvent] = []
        old_map: Dict[str, SubdomainResult] = {s.subdomain: s for s in old.subdomains}
        new_map: Dict[str, SubdomainResult] = {s.subdomain: s for s in new.subdomains}

        # ── 1. New subdomains
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

        # ── 2. Removed subdomains
        for sub in old_map:
            if sub not in new_map:
                events.append(ChangeEvent(
                    event_type  = "subdomain_removed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "info",
                    description = f"Subdomain no longer resolves: {sub}",
                    old_value   = f"was_alive={old_map[sub].is_alive}",
                ))

        # ── 3. Per-subdomain changes
        for sub in new_map:
            if sub not in old_map:
                continue
            o, n = old_map[sub], new_map[sub]

            # 3a — Ports
            old_ports = set(o.open_ports or [])
            new_ports = set(n.open_ports or [])
            for port in sorted(new_ports - old_ports):
                events.append(ChangeEvent(
                    event_type  = "port_opened",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = _PORT_SEVERITY.get(port, "warning"),
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

            # 3b — SSL certificate
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

            # 3c — HTTP status
            old_st = self._http_status(o)
            new_st = self._http_status(n)
            if old_st != new_st and (old_st is not None or new_st is not None):
                events.append(ChangeEvent(
                    event_type  = "status_changed",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "warning" if new_st == 200 and old_st != 200 else "info",
                    description = f"HTTP status changed on {sub}: {old_st} → {new_st}",
                    old_value   = str(old_st),
                    new_value   = str(new_st),
                ))

            # 3d — New technologies
            added = set(n.technologies or []) - set(o.technologies or [])
            if added:
                events.append(ChangeEvent(
                    event_type  = "tech_added",
                    domain      = self.domain,
                    asset       = sub,
                    severity    = "info",
                    description = f"New tech detected on {sub}: {', '.join(sorted(added))}",
                    new_value   = ", ".join(sorted(added)),
                ))

        # ── 4. Cloud assets
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

        # ── 5. Credential leaks
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

_SEVERITY_RANK  = {"info": 0, "warning": 1, "critical": 2}
_SEVERITY_EMOJI = {"info": "ℹ️ ", "warning": "⚠️ ", "critical": "🔴"}


class AlertConfig:
    """
    Holds all alert channel settings.
    Use AlertConfig.from_env() to load from environment variables.
    """

    def __init__(
        self,
        email_to:      Optional[str] = None,
        email_from:    Optional[str] = None,
        smtp_host:     str           = "smtp.gmail.com",
        smtp_port:     int           = 587,
        smtp_password: Optional[str] = None,
        webhook_url:   Optional[str] = None,
        min_severity:  str           = "warning",
    ):
        self.email_to      = email_to
        self.email_from    = email_from
        self.smtp_host     = smtp_host
        self.smtp_port     = smtp_port
        self.smtp_password = smtp_password
        self.webhook_url   = webhook_url
        self.min_severity  = min_severity

    @classmethod
    def from_env(cls) -> "AlertConfig":
        return cls(
            email_to      = os.getenv("ALERT_EMAIL_TO"),
            email_from    = os.getenv("ALERT_EMAIL_FROM"),
            smtp_host     = os.getenv("SMTP_HOST", "smtp.gmail.com"),
            smtp_port     = int(os.getenv("SMTP_PORT", "587")),
            smtp_password = os.getenv("SMTP_PASSWORD"),
            webhook_url   = os.getenv("ALERT_WEBHOOK_URL"),
            min_severity  = os.getenv("ALERT_MIN_SEVERITY", "warning"),
        )


# ─────────────────────────────────────────────
# Alert Sender
# ─────────────────────────────────────────────

class AlertSender:
    """Delivers ChangeEvent alerts via console, email, and webhook."""

    def __init__(self, cfg: AlertConfig):
        self.cfg = cfg

    def _passes(self, sev: str) -> bool:
        return _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK.get(self.cfg.min_severity, 1)

    def _filter(self, events: List[ChangeEvent]) -> List[ChangeEvent]:
        return [e for e in events if self._passes(e.severity)]

    # ── Console ───────────────────────────────────────────────────────

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
        print(f"  Total  : {len(filtered)} change(s)  "
              f"({n_crit} critical, {n_warn} warning)")
        print("─" * 64)
        for e in filtered:
            emoji = _SEVERITY_EMOJI.get(e.severity, " ")
            print(f"  {emoji} [{e.severity.upper():<8}] {e.description}")
            if e.old_value and e.new_value:
                print(f"              Before : {e.old_value}")
                print(f"              After  : {e.new_value}")
        print("═" * 64 + "\n")

    # ── Email ─────────────────────────────────────────────────────────

    def alert_email(self, events: List[ChangeEvent], domain: str, subject_override: str = ""):
        """
        Send an email alert.  Runs synchronously (called from async via executor
        to avoid blocking the event loop).
        """
        filtered = self._filter(events)
        if not filtered:
            return
        if not all([self.cfg.email_to, self.cfg.email_from, self.cfg.smtp_password]):
            logger.debug("[Email] Not fully configured — skipping")
            return

        n_crit = sum(1 for e in filtered if e.severity == "critical")
        subject = subject_override or (
            f"🔴 [{domain}] {n_crit} CRITICAL security change(s) detected"
            if n_crit else
            f"⚠️  [{domain}] {len(filtered)} change(s) detected"
        )

        body_lines = [
            f"Security Change Alert — {domain}",
            f"Time    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"Changes : {len(filtered)}  "
            f"({n_crit} critical, "
            f"{sum(1 for e in filtered if e.severity=='warning')} warning)",
            "",
        ]
        for e in filtered:
            emoji = _SEVERITY_EMOJI.get(e.severity, " ")
            body_lines.append(f"{emoji} [{e.severity.upper()}] {e.description}")
            if e.old_value and e.new_value:
                body_lines.append(f"   Before : {e.old_value}")
                body_lines.append(f"   After  : {e.new_value}")
        body_lines += ["", "─" * 52, "Asset Discovery Engine — Module 2"]

        try:
            msg            = MIMEMultipart()
            msg["From"]    = self.cfg.email_from
            msg["To"]      = self.cfg.email_to
            msg["Subject"] = subject
            msg.attach(MIMEText("\n".join(body_lines), "plain"))

            with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(self.cfg.email_from, self.cfg.smtp_password)
                srv.send_message(msg)
            logger.info(f"[Email] Alert sent → {self.cfg.email_to}")
        except smtplib.SMTPAuthenticationError:
            logger.error("[Email] Authentication failed — check SMTP credentials")
        except smtplib.SMTPConnectError as e:
            logger.error(f"[Email] Could not connect to {self.cfg.smtp_host}: {e}")
        except Exception as e:
            logger.error(f"[Email] Unexpected error: {e}")

    # ── Webhook ───────────────────────────────────────────────────────

    async def alert_webhook(self, events: List[ChangeEvent], domain: str):
        """
        POST a JSON payload to the configured webhook URL.
        Compatible with Slack, Discord, and any custom endpoint.
        Falls back to a simplified Slack-style text message if needed.
        """
        filtered = self._filter(events)
        if not filtered or not self.cfg.webhook_url:
            return

        n_crit = sum(1 for e in filtered if e.severity == "critical")
        n_warn = sum(1 for e in filtered if e.severity == "warning")

        # Build payload — try generic JSON first, Slack text as fallback
        payload = {
            "domain":         domain,
            "timestamp":      datetime.utcnow().isoformat(),
            "total_changes":  len(filtered),
            "critical_count": n_crit,
            "warning_count":  n_warn,
            "events": [asdict(e) for e in filtered],
            # Slack-compatible text field (ignored by non-Slack webhooks)
            "text": (
                f"🔴 *{domain}* — {n_crit} CRITICAL + {n_warn} warning change(s)\n"
                + "\n".join(
                    f"  {_SEVERITY_EMOJI.get(e.severity,'')} {e.description}"
                    for e in filtered[:10]
                )
            ),
        }

        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as session:
                    async with session.post(
                        self.cfg.webhook_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        if resp.status in (200, 204):
                            logger.info(f"[Webhook] Alert sent → HTTP {resp.status}")
                            return
                        body = await resp.text()
                        logger.warning(
                            f"[Webhook] HTTP {resp.status} on attempt {attempt+1}/3: {body[:120]}"
                        )
                        if resp.status in (401, 403, 404):
                            logger.error("[Webhook] Permanent error — check webhook URL")
                            return
            except aiohttp.ClientConnectorError as e:
                logger.warning(f"[Webhook] Connection error attempt {attempt+1}/3: {e}")
            except asyncio.TimeoutError:
                logger.warning(f"[Webhook] Timeout on attempt {attempt+1}/3")
            except Exception as e:
                logger.error(f"[Webhook] Unexpected error: {e}")
                return

            if attempt < 2:
                await asyncio.sleep(5 * (attempt + 1))

        logger.error("[Webhook] All 3 attempts failed — alert not delivered")

    # ── Send all channels ─────────────────────────────────────────────

    async def send_all(self, events: List[ChangeEvent], domain: str):
        """Fire all configured alert channels concurrently."""
        self.alert_console(events, domain)

        # Email is synchronous — run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.alert_email, events, domain, "")

        await self.alert_webhook(events, domain)


# ─────────────────────────────────────────────
# Weekly Digest Builder
# ─────────────────────────────────────────────

_BOX_WIDTH = 64   # total inner width of the digest box


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
            if e.event_type == "new_subdomain":
                digest.new_subdomains.append(e.asset)
                digest.attack_surface_delta += 1
            elif e.event_type == "subdomain_removed":
                digest.removed_subdomains.append(e.asset)
                digest.attack_surface_delta -= 1
            elif e.event_type == "port_opened":
                digest.new_ports_opened.append({"asset": e.asset, "port": e.new_value})
                digest.attack_surface_delta += 1
            elif e.event_type == "cert_changed":
                digest.cert_changes.append({"asset": e.asset, "expiry": e.new_value})
            elif e.event_type == "new_cloud_asset":
                digest.new_cloud_assets.append(e.asset)
                digest.attack_surface_delta += 1
            elif e.event_type == "new_credential_leak":
                try:
                    digest.new_credential_leaks += int(e.new_value or 0) - int(e.old_value or 0)
                except (ValueError, TypeError):
                    pass
        return digest

    def render(self, digest: WeeklyDigest) -> str:
        """Render the digest as a box-drawing ASCII table."""
        W      = _BOX_WIDTH
        delta  = digest.attack_surface_delta
        d_str  = f"+{delta}" if delta > 0 else str(delta)

        def row(text: str) -> str:
            """Pad text to exactly W chars and wrap in ║ ║."""
            return f"║  {text:<{W-2}}║"

        def separator() -> str:
            return "╠" + "═" * W + "╣"

        def trunc(s: str, n: int) -> str:
            return s[:n-1] + "…" if len(s) > n else s

        lines = [
            "╔" + "═" * W + "╗",
            row("WEEKLY SECURITY DIGEST"),
            row(f"Domain  : {self.domain}"),
            row(f"Period  : {digest.week_start[:10]}  →  {digest.week_end[:10]}"),
            separator(),
            row(f"Scans completed    : {digest.total_scans}"),
            row(f"Total changes      : {digest.total_changes}"),
            row(f"Attack surface Δ   : {d_str}"),
            separator(),
        ]

        def section(title: str, items: list, fmt=None, limit: int = 8):
            if not items:
                return
            lines.append(row(f"{title}  ({len(items)})"))
            for item in items[:limit]:
                text = fmt(item) if fmt else str(item)
                lines.append(row(f"  • {trunc(text, W-6)}"))
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

        lines.append("╚" + "═" * W + "╝")
        return "\n".join(lines)

    async def email_digest(self, digest: WeeklyDigest, alerter: "AlertSender"):
        """Send the weekly digest as an email (bypasses severity filter)."""
        if not all([alerter.cfg.email_to, alerter.cfg.email_from, alerter.cfg.smtp_password]):
            return
        digest_text = self.render(digest)
        subject     = f"📋 [{digest.domain}] Weekly Security Digest — {digest.week_start[:10]}"
        try:
            msg            = MIMEMultipart()
            msg["From"]    = alerter.cfg.email_from
            msg["To"]      = alerter.cfg.email_to
            msg["Subject"] = subject
            msg.attach(MIMEText(digest_text, "plain"))
            with smtplib.SMTP(alerter.cfg.smtp_host, alerter.cfg.smtp_port) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(alerter.cfg.email_from, alerter.cfg.smtp_password)
                srv.send_message(msg)
            logger.info(f"[Email] Weekly digest sent → {alerter.cfg.email_to}")
        except Exception as e:
            logger.error(f"[Email] Digest send failed: {e}")


# ─────────────────────────────────────────────
# Continuous Monitor
# ─────────────────────────────────────────────

class ContinuousMonitor:
    """
    Orchestrates daily re-scans, change detection, alerting, and weekly digests.

    Daemon mode (runs forever):
        monitor = ContinuousMonitor("example.com", alert_config=AlertConfig.from_env())
        asyncio.run(monitor.run_forever())

    Single scan + diff (cron-friendly):
        asyncio.run(monitor.run_once())
    """

    def __init__(
        self,
        domain:              str,
        alert_config:        Optional[AlertConfig] = None,
        github_token:        Optional[str]         = None,
        api_keys:            Optional[dict]         = None,
        scan_interval_hours: int                   = 24,
        data_dir:            Optional[str]         = None,
        scan_ports:          bool                  = True,
        scan_cloud:          bool                  = True,
    ):
        """
        Parameters
        ----------
        domain               : Target domain, e.g. "example.com"
        alert_config         : AlertConfig instance (email / webhook settings)
        github_token         : GitHub personal access token for credential scanning
        api_keys             : Optional dict for passive DNS API keys:
                                 {
                                   "hackertarget":   "key",  # unlimited scans
                                   "securitytrails": "key",  # 50 req/month free
                                   "virustotal":     "key",  # 500 req/day free
                                 }
        scan_interval_hours  : Hours between scans in daemon mode (default: 24)
        data_dir             : Override for data storage (default: ~/asset-discovery-data/)
        scan_ports           : Enable TCP port scanning (default: True)
        scan_cloud           : Enable cloud bucket discovery (default: True)
        """
        self.domain              = domain.lower().strip()
        self.alert_config        = alert_config or AlertConfig()
        self.github_token        = github_token
        self.api_keys            = api_keys or {}
        self.scan_interval_hours = scan_interval_hours
        self.scan_ports          = scan_ports
        self.scan_cloud          = scan_cloud

        self._snapshot_mgr   = SnapshotManager(domain, data_dir)
        self._detector       = ChangeDetector(domain)
        self._alerter        = AlertSender(self.alert_config)
        self._digest_builder = WeeklyDigestBuilder(domain, self._snapshot_mgr)
        self._weekly_events: List[ChangeEvent] = []
        self._scan_count:    int               = 0

    # ── Single cycle ──────────────────────────────────────────────────

    async def run_once(self) -> Tuple[DiscoveryReport, List[ChangeEvent]]:
        """
        One full cycle: scan → save snapshot → diff vs previous → alert.
        Returns (new_report, list_of_changes).
        """
        self._scan_count += 1
        logger.info("=" * 64)
        logger.info(f"[Monitor] Scan #{self._scan_count}  —  {self.domain}")
        logger.info(f"[Monitor] Started : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        logger.info("=" * 64)

        # Load baseline before scanning
        old_report = await self._snapshot_mgr.load_snapshot("latest")
        if old_report:
            logger.info(
                f"[Monitor] Baseline : {old_report.total_subdomains} subdomains "
                f"from {(old_report.scan_completed or '')[:10]}"
            )
        else:
            logger.info(
                "[Monitor] No baseline found — saving baseline now. "
                "Alerts begin from scan #2."
            )

        # ── Run full discovery
        engine = AssetDiscoveryEngine(
            domain       = self.domain,
            github_token = self.github_token,
            api_keys     = self.api_keys,
            scan_ports   = self.scan_ports,
            scan_cloud   = self.scan_cloud,
            scan_github  = bool(self.github_token),
        )
        new_report = await engine.run()

        # ── Persist snapshots
        # Only write_history=True on the 'latest' save to avoid duplicate rows
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        await self._snapshot_mgr.save_snapshot(new_report, "latest",    write_history=True)
        await self._snapshot_mgr.save_snapshot(new_report, ts,          write_history=False)

        # ── Diff + alert
        events: List[ChangeEvent] = []
        if old_report:
            events = self._detector.detect(old_report, new_report)
            logger.info(f"[Monitor] {len(events)} change(s) detected")
            if events:
                await self._snapshot_mgr.append_events(events)
                await self._alerter.send_all(events, self.domain)
                self._weekly_events.extend(events)
            else:
                logger.info("[Monitor] No changes since last scan — all clear ✓")
        else:
            logger.info("[Monitor] Baseline saved. Next scan will produce a diff.")

        # ── Weekly digest every 7 scans
        if self._scan_count % 7 == 0:
            await self._run_weekly_digest()

        logger.info(
            f"[Monitor] Cycle complete — "
            f"{new_report.alive_subdomains} alive subdomains, "
            f"{len(new_report.cloud_assets)} cloud assets, "
            f"{len(events)} change(s)"
        )
        return new_report, events

    # ── Weekly digest ─────────────────────────────────────────────────

    async def _run_weekly_digest(self):
        logger.info("[Monitor] Generating weekly digest...")
        digest      = await self._digest_builder.build(self._weekly_events)
        digest_text = self._digest_builder.render(digest)
        print("\n" + digest_text + "\n")
        await self._snapshot_mgr.save_weekly_digest(digest)

        # Send digest email directly (not through event filter)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._digest_builder.email_digest, digest, self._alerter
        )

        self._weekly_events.clear()

    # ── Daemon loop ───────────────────────────────────────────────────

    async def run_forever(self):
        """Runs indefinitely, sleeping scan_interval_hours between cycles."""
        logger.info("=" * 64)
        logger.info("[Monitor] Continuous monitoring started")
        logger.info(f"[Monitor] Target   : {self.domain}")
        logger.info(f"[Monitor] Interval : every {self.scan_interval_hours}h")
        logger.info(f"[Monitor] Data dir : {self._snapshot_mgr.data_dir}")
        logger.info(f"[Monitor] Min alert: {self.alert_config.min_severity}")
        logger.info("[Monitor] Press Ctrl+C to stop cleanly")
        logger.info("=" * 64)

        while True:
            try:
                await self.run_once()
            except KeyboardInterrupt:
                logger.info("[Monitor] Keyboard interrupt — shutting down cleanly.")
                break
            except Exception as exc:
                logger.error(f"[Monitor] Scan cycle failed: {exc}", exc_info=True)
                logger.info("[Monitor] Will retry on next interval.")

            next_scan = datetime.utcnow() + timedelta(hours=self.scan_interval_hours)
            logger.info(f"[Monitor] Next scan → {next_scan.strftime('%Y-%m-%d %H:%M UTC')}")
            logger.info(f"[Monitor] Sleeping {self.scan_interval_hours}h ...")

            try:
                await asyncio.sleep(self.scan_interval_hours * 3600)
            except (asyncio.CancelledError, KeyboardInterrupt):
                logger.info("[Monitor] Shutting down cleanly.")
                break
