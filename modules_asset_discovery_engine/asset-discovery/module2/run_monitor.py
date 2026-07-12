"""
Module 2 — CLI Entry Point
===========================
Authorized use only. Written permission required before scanning.

By default this reads all settings (webhooks, emails, API keys) from the
DEFAULT_* constants at the top of monitor.py — edit those once and just run:

    python3 run_monitor.py --domain example.com --once --confirm

Any flag you pass here overrides the corresponding default for that run only.

Usage:
  python3 run_monitor.py --domain example.com --confirm
  python3 run_monitor.py --domain example.com --once --confirm
"""

import asyncio
import argparse
import os
import sys
from pathlib import Path
from typing import Optional, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from monitor import ContinuousMonitor, AlertConfig

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║            ASSET DISCOVERY ENGINE — MODULE 2                     ║
║            Continuous Monitoring + Change Detection              ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠  Authorized use only. Written permission required.            ║
╚══════════════════════════════════════════════════════════════════╝
"""


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    """Split a comma-separated CLI value into a clean list. None if not given."""
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items or None


def parse_args():
    p = argparse.ArgumentParser(
        description="Continuous asset monitoring — daily scans, instant alerts on changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
All alert settings can be pre-filled inside monitor.py (DEFAULT_WEBHOOKS,
DEFAULT_EMAIL_TO, DEFAULT_EMAIL_ACCOUNTS, DEFAULT_GITHUB_TOKEN, etc.) so you
never have to type them again. Any flag below overrides its default for
just this run.

Examples:
  # Everything pre-configured in monitor.py — just run it:
  python3 run_monitor.py --domain example.com --once --confirm

  # Override with one-off webhook/email for a single run:
  python3 run_monitor.py --domain example.com --once --confirm \\
      --webhook "https://discord.com/api/webhooks/XXX/YYY"

  # Multiple webhooks / recipients in one run (comma-separated):
  python3 run_monitor.py --domain example.com --once --confirm \\
      --webhook "https://discord.com/api/webhooks/A,https://hooks.slack.com/B" \\
      --email-to "alice@company.com,bob@company.com"

  # Run forever (daemon), scanning every 12 hours:
  python3 run_monitor.py --domain example.com --interval 12 --confirm
        """,
    )

    # Required
    p.add_argument("--domain",  required=True,
                   help="Target domain  (e.g. example.com)")
    p.add_argument("--confirm", action="store_true",
                   help="Certify you have explicit written authorization to scan this domain")

    # Scan control
    scan = p.add_argument_group("Scan control")
    scan.add_argument("--once",     action="store_true",
                      help="Run one scan+diff cycle then exit  (ideal for cron)")
    scan.add_argument("--interval", type=int, default=24, metavar="HOURS",
                      help="Hours between scans in daemon mode  (default: 24)")
    scan.add_argument("--no-ports", action="store_true", help="Skip port scanning")
    scan.add_argument("--no-cloud", action="store_true", help="Skip cloud bucket discovery")

    # API keys — leave unset to use the DEFAULT_* values inside monitor.py
    keys = p.add_argument_group("API keys  (optional — defaults live in monitor.py)")
    keys.add_argument("--github-token", default=None, metavar="TOKEN",
                      help="GitHub personal access token — overrides DEFAULT_GITHUB_TOKEN")
    keys.add_argument("--otx-key",      default=None, metavar="KEY",
                      help="AlienVault OTX API key — overrides DEFAULT_OTX_API_KEY")
    keys.add_argument("--urlscan-key",  default=None, metavar="KEY",
                      help="URLScan.io API key — overrides DEFAULT_URLSCAN_API_KEY")

    # Alert channels — leave unset to use the DEFAULT_* lists inside monitor.py
    alerts = p.add_argument_group("Alert channels  (optional — defaults live in monitor.py)")
    alerts.add_argument("--min-severity", default=None,
                        choices=["info", "warning", "critical"],
                        help="Minimum severity to trigger an alert — overrides DEFAULT_MIN_SEVERITY")
    alerts.add_argument("--webhook",       default=None, metavar="URL[,URL2,...]",
                        help="One or more webhook URLs (comma-separated) — "
                             "overrides the entire DEFAULT_WEBHOOKS list for this run")
    alerts.add_argument("--email-to",      default=None, metavar="ADDR[,ADDR2,...]",
                        help="One or more recipient emails (comma-separated) — "
                             "overrides the entire DEFAULT_EMAIL_TO list for this run")
    alerts.add_argument("--email-from",    default=None, metavar="ADDR",
                        help="Sender Gmail address — combined with --smtp-password, "
                             "overrides the entire DEFAULT_EMAIL_ACCOUNTS list with just this one account")
    alerts.add_argument("--smtp-password", default=None, metavar="PASS",
                        help="Gmail App Password paired with --email-from (NOT your login password)")
    alerts.add_argument("--smtp-host",     default="smtp.gmail.com", metavar="HOST",
                        help="SMTP host for --email-from  (default: smtp.gmail.com)")
    alerts.add_argument("--smtp-port",     type=int, default=587, metavar="PORT",
                        help="SMTP port for --email-from  (default: 587)")
    return p.parse_args()


async def main():
    print(BANNER)
    args = parse_args()

    if not args.confirm:
        print("ERROR: Add --confirm to certify you have authorization to scan this domain.\n")
        print(f"  python3 run_monitor.py --domain {args.domain} --confirm\n")
        sys.exit(1)

    # ── Build alert config: start from monitor.py defaults, apply only
    #    the overrides the user actually passed on the command line.
    overrides = {}

    webhooks = _split_csv(args.webhook)
    if webhooks:
        overrides["webhooks"] = webhooks

    email_to = _split_csv(args.email_to)
    if email_to:
        overrides["email_to"] = email_to

    if args.email_from and args.smtp_password:
        overrides["email_accounts"] = [{
            "email_from":    args.email_from,
            "smtp_password": args.smtp_password,
            "smtp_host":     args.smtp_host,
            "smtp_port":     args.smtp_port,
        }]
    elif args.email_from or args.smtp_password:
        print("  WARNING: --email-from and --smtp-password must both be given together.")
        print("           Ignoring the one provided and using monitor.py defaults instead.\n")

    if args.min_severity:
        overrides["min_severity"] = args.min_severity

    alert_cfg = AlertConfig.from_config(overrides)

    # ── Show what's actually active
    channels = []
    if alert_cfg.webhook_enabled:
        channels.append(f"Webhook×{len(alert_cfg.webhooks)}")
    if alert_cfg.email_enabled:
        channels.append(f"Email→{len(alert_cfg.email_to)} recipient(s) via {len(alert_cfg.email_accounts)} account(s)")
    channels.append("Console")
    print(f"  Alert channels : {', '.join(channels)}")
    print(f"  Min severity   : {alert_cfg.min_severity}")

    active_keys = []
    if args.github_token: active_keys.append("GitHub")
    if args.otx_key:      active_keys.append("OTX")
    if args.urlscan_key:  active_keys.append("URLScan")
    if active_keys:
        print(f"  API overrides  : {', '.join(active_keys)}")
    print()

    monitor = ContinuousMonitor(
        domain              = args.domain,
        alert_config        = alert_cfg,
        github_token        = args.github_token,
        otx_api_key         = args.otx_key,
        urlscan_api_key     = args.urlscan_key,
        scan_interval_hours = args.interval,
        scan_ports          = not args.no_ports,
        scan_cloud          = not args.no_cloud,
    )

    if args.once:
        report, events = await monitor.run_once()
        print(f"\nDone — {report.alive_subdomains} alive subdomains, "
              f"{len(events)} change(s) detected.\n")
    else:
        await monitor.run_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
