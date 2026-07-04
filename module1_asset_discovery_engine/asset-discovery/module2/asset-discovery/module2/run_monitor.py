"""
Module 2 — CLI Entry Point
===========================
Authorized use only. Written permission required before scanning.

Usage:
  python3 run_monitor.py --domain example.com --confirm
  python3 run_monitor.py --domain example.com --once --confirm
  python3 run_monitor.py --domain example.com --interval 12 --confirm
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
Environment variables (set once, no need to type flags every time):
  GITHUB_TOKEN              GitHub personal access token
  HACKERTARGET_API_KEY      Removes 5/day free limit on HackerTarget
  SECURITYTRAILS_API_KEY    Enables SecurityTrails subdomain lookup
  VIRUSTOTAL_API_KEY        Enables VirusTotal authenticated subdomain API
  ALERT_EMAIL_TO            Recipient email address
  ALERT_EMAIL_FROM          Sender Gmail address
  SMTP_PASSWORD             Gmail App Password (NOT your login password)
  ALERT_WEBHOOK_URL         Slack / Discord / custom webhook URL
  ALERT_MIN_SEVERITY        Minimum level to alert: info | warning | critical

Examples:
  # Save baseline (first run, no alerts yet):
  python3 run_monitor.py --domain example.com --once --confirm

  # Second run — detects and prints any changes:
  python3 run_monitor.py --domain example.com --once --confirm

  # Run forever (daemon), alert on Slack and email:
  python3 run_monitor.py --domain example.com \\
      --webhook "https://hooks.slack.com/services/XXX/YYY/ZZZ" \\
      --email-to security@company.com \\
      --email-from you@gmail.com \\
      --smtp-password "xxxx xxxx xxxx xxxx" \\
      --confirm

  # Scan every 12 hours with all API keys via env vars:
  export GITHUB_TOKEN=ghp_xxx
  export HACKERTARGET_API_KEY=ht_xxx
  export ALERT_WEBHOOK_URL=https://hooks.slack.com/...
  python3 run_monitor.py --domain example.com --interval 12 --confirm
        """,
    )

    # ── Required
    p.add_argument("--domain",  required=True, help="Target domain  (e.g. example.com)")
    p.add_argument("--confirm", action="store_true",
                   help="Certify you have explicit written authorization to scan this domain")

    # ── Scan control
    scan = p.add_argument_group("Scan control")
    scan.add_argument("--once",     action="store_true",
                      help="Run one scan+diff cycle then exit  (ideal for cron jobs)")
    scan.add_argument("--interval", type=int, default=24, metavar="HOURS",
                      help="Hours between scans in daemon mode  (default: 24)")
    scan.add_argument("--no-ports", action="store_true", help="Skip port scanning")
    scan.add_argument("--no-cloud", action="store_true", help="Skip cloud bucket discovery")

    # ── API keys
    keys = p.add_argument_group("API keys  (all optional — tool works without them)")
    keys.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN"),
                      metavar="TOKEN",
                      help="GitHub personal access token  (env: GITHUB_TOKEN)")
    keys.add_argument("--ht-key",  default=os.getenv("HACKERTARGET_API_KEY"),
                      metavar="KEY",
                      help="HackerTarget API key — removes 5/day free limit  "
                           "(env: HACKERTARGET_API_KEY)")
    keys.add_argument("--st-key",  default=os.getenv("SECURITYTRAILS_API_KEY"),
                      metavar="KEY",
                      help="SecurityTrails API key — 50 req/month free tier  "
                           "(env: SECURITYTRAILS_API_KEY)")
    keys.add_argument("--vt-key",  default=os.getenv("VIRUSTOTAL_API_KEY"),
                      metavar="KEY",
                      help="VirusTotal API key — 500 req/day free tier  "
                           "(env: VIRUSTOTAL_API_KEY)")

    # ── Alerts
    alerts = p.add_argument_group("Alert channels")
    alerts.add_argument("--min-severity", default=os.getenv("ALERT_MIN_SEVERITY", "warning"),
                        choices=["info", "warning", "critical"],
                        help="Minimum severity that triggers an alert  (default: warning)")
    alerts.add_argument("--webhook",      default=os.getenv("ALERT_WEBHOOK_URL"),
                        metavar="URL",
                        help="Slack / Discord / custom webhook URL  (env: ALERT_WEBHOOK_URL)")
    alerts.add_argument("--email-to",     default=os.getenv("ALERT_EMAIL_TO"),
                        metavar="ADDRESS", help="Alert recipient email  (env: ALERT_EMAIL_TO)")
    alerts.add_argument("--email-from",   default=os.getenv("ALERT_EMAIL_FROM"),
                        metavar="ADDRESS", help="Sender Gmail address  (env: ALERT_EMAIL_FROM)")
    alerts.add_argument("--smtp-password",default=os.getenv("SMTP_PASSWORD"),
                        metavar="PASS",
                        help="Gmail App Password — NOT your login password  (env: SMTP_PASSWORD)")
    alerts.add_argument("--smtp-host",    default=os.getenv("SMTP_HOST", "smtp.gmail.com"),
                        metavar="HOST",   help="SMTP host  (default: smtp.gmail.com)")
    alerts.add_argument("--smtp-port",    type=int,
                        default=int(os.getenv("SMTP_PORT", "587")),
                        metavar="PORT",   help="SMTP port  (default: 587)")

    return p.parse_args()


async def main():
    print(BANNER)
    args = parse_args()

    if not args.confirm:
        print("ERROR: Add --confirm to certify you have authorization to scan this domain.\n")
        print(f"  python3 run_monitor.py --domain {args.domain} --confirm\n")
        sys.exit(1)

    # ── Build API keys dict
    api_keys = {}
    if args.ht_key:  api_keys["hackertarget"]   = args.ht_key
    if args.st_key:  api_keys["securitytrails"] = args.st_key
    if args.vt_key:  api_keys["virustotal"]     = args.vt_key
    if api_keys:
        print(f"  API keys loaded : {', '.join(api_keys.keys())}")

    # ── Alert config
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
    if alert_cfg.webhook_url:   channels.append("Webhook")
    if alert_cfg.email_to:      channels.append(f"Email → {alert_cfg.email_to}")
    channels.append("Console")
    print(f"  Alert channels  : {', '.join(channels)}")
    print(f"  Min severity    : {alert_cfg.min_severity}")
    print()

    # ── Build monitor
    monitor = ContinuousMonitor(
        domain              = args.domain,
        alert_config        = alert_cfg,
        github_token        = args.github_token,
        api_keys            = api_keys,
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
