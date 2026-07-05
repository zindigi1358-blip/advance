"""
Module 2 — CLI Entry Point
===========================
Authorized use only. Written permission required before scanning.

Usage:
  python3 run_monitor.py --domain example.com --confirm
  python3 run_monitor.py --domain example.com --once --confirm
"""

import asyncio
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "module1"))
from monitor import ContinuousMonitor, AlertConfig

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║            ASSET DISCOVERY ENGINE — MODULE 2                     ║
║            Continuous Monitoring + Change Detection              ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠  Authorized use only. Written permission required.            ║
╚══════════════════════════════════════════════════════════════════╝
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Continuous asset monitoring — daily scans, instant alerts on changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables (set once — no need to type flags every time):
  GITHUB_TOKEN          GitHub personal access token
  OTX_API_KEY           AlienVault OTX API key  (free at otx.alienvault.com)
  URLSCAN_API_KEY       URLScan.io API key       (free at urlscan.io)
  ALERT_EMAIL_TO        Alert recipient email
  ALERT_EMAIL_FROM      Sender Gmail address
  SMTP_PASSWORD         Gmail App Password (NOT your login password)
  ALERT_WEBHOOK_URL     Slack / Discord / custom webhook URL
  ALERT_MIN_SEVERITY    info | warning | critical  (default: warning)

Examples:
  # Save baseline — first run, no alerts yet:
  python3 run_monitor.py --domain example.com --once --confirm

  # Second run — change detection active:
  python3 run_monitor.py --domain example.com --once --confirm

  # Run forever with Slack + email alerts:
  python3 run_monitor.py --domain example.com \\
      --webhook "https://discord.com/api/webhooks/XXX/YYY" \\
      --email-to    security@company.com \\
      --email-from  you@gmail.com \\
      --smtp-password "xxxx xxxx xxxx xxxx" \\
      --confirm

  # Every 12 hours using env vars:
  export GITHUB_TOKEN=ghp_xxx
  export OTX_API_KEY=your_otx_key
  export ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/...
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

    # API keys — same names as module 1
    keys = p.add_argument_group("API keys  (all optional)")
    keys.add_argument("--github-token",  default=os.getenv("GITHUB_TOKEN"),    metavar="TOKEN",
                      help="GitHub personal access token  (env: GITHUB_TOKEN)")
    keys.add_argument("--otx-key",       default=os.getenv("OTX_API_KEY", ""), metavar="KEY",
                      help="AlienVault OTX API key — more subdomain results  (env: OTX_API_KEY)")
    keys.add_argument("--urlscan-key",   default=os.getenv("URLSCAN_API_KEY", ""), metavar="KEY",
                      help="URLScan.io API key  (env: URLSCAN_API_KEY)")

    # Alert channels
    alerts = p.add_argument_group("Alert channels")
    alerts.add_argument("--min-severity", default=os.getenv("ALERT_MIN_SEVERITY", "warning"),
                        choices=["info", "warning", "critical"],
                        help="Minimum severity to trigger an alert  (default: warning)")
    alerts.add_argument("--webhook",       default=os.getenv("ALERT_WEBHOOK_URL"), metavar="URL",
                        help="Discord / Slack / custom webhook URL  (env: ALERT_WEBHOOK_URL)")
    alerts.add_argument("--email-to",      default=os.getenv("ALERT_EMAIL_TO"),    metavar="ADDR",
                        help="Alert recipient email  (env: ALERT_EMAIL_TO)")
    alerts.add_argument("--email-from",    default=os.getenv("ALERT_EMAIL_FROM"),  metavar="ADDR",
                        help="Sender Gmail address  (env: ALERT_EMAIL_FROM)")
    alerts.add_argument("--smtp-password", default=os.getenv("SMTP_PASSWORD"),     metavar="PASS",
                        help="Gmail App Password — NOT your login password  (env: SMTP_PASSWORD)")
    alerts.add_argument("--smtp-host",     default=os.getenv("SMTP_HOST", "smtp.gmail.com"),
                        metavar="HOST",    help="SMTP host  (default: smtp.gmail.com)")
    alerts.add_argument("--smtp-port",     type=int,
                        default=int(os.getenv("SMTP_PORT", "587")), metavar="PORT",
                        help="SMTP port  (default: 587)")
    return p.parse_args()


async def main():
    print(BANNER)
    args = parse_args()

    if not args.confirm:
        print("ERROR: Add --confirm to certify you have authorization to scan this domain.\n")
        print(f"  python3 run_monitor.py --domain {args.domain} --confirm\n")
        sys.exit(1)

    # Show active API keys
    active_keys = []
    if args.github_token:  active_keys.append("GitHub")
    if args.otx_key:       active_keys.append("OTX")
    if args.urlscan_key:   active_keys.append("URLScan")
    if active_keys:
        print(f"  API keys    : {', '.join(active_keys)}")

    # Alert config
    alert_cfg = AlertConfig(
        email_to      = args.email_to,
        email_from    = args.email_from,
        smtp_host     = args.smtp_host,
        smtp_port     = args.smtp_port,
        smtp_password = args.smtp_password,
        webhook_url   = args.webhook,
        min_severity  = args.min_severity,
    )

    channels = []
    if alert_cfg.webhook_url: channels.append("Webhook")
    if alert_cfg.email_to:    channels.append(f"Email({alert_cfg.email_to})")
    channels.append("Console")
    print(f"  Alert channels : {', '.join(channels)}")
    print(f"  Min severity   : {alert_cfg.min_severity}\n")

    monitor = ContinuousMonitor(
        domain              = args.domain,
        alert_config        = alert_cfg,
        github_token        = args.github_token,
        otx_api_key         = args.otx_key     or "",
        urlscan_api_key     = args.urlscan_key  or "",
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
