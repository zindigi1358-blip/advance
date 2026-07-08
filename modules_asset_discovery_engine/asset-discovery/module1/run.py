"""
Asset Discovery Engine — CLI Runner
Usage: python run.py --domain example.com [--github-token ghp_xxx] [--no-ports] [--no-cloud]
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path
from discovery_engine import AssetDiscoveryEngine


def print_banner():
    print("""
╔═══════════════════════════════════════════════════╗
║         ASSET DISCOVERY ENGINE  v1.0              ║
║      Authorized Penetration Testing Tool          ║
╚═══════════════════════════════════════════════════╝
  ⚠  Use only with explicit written permission.
""")


def print_summary(report):
    print("\n" + "═" * 55)
    print("  DISCOVERY SUMMARY")
    print("═" * 55)
    print(f"  Domain         : {report.domain}")
    print(f"  Duration       : {report.scan_duration_seconds}s")
    print(f"  Subdomains     : {report.total_subdomains} found, {report.alive_subdomains} alive")
    print(f"  Cloud Assets   : {len(report.cloud_assets)}")
    print(f"  Leaked Creds   : {len(report.leaked_credentials)}")

    print("\n  TOP ALIVE SUBDOMAINS:")
    alive = [s for s in report.subdomains if s.is_alive]
    for sub in sorted(alive, key=lambda x: (x.https_status or x.http_status or 999))[:20]:
        status = sub.https_status or sub.http_status or "?"
        techs = ", ".join(sub.technologies[:3]) if sub.technologies else ""
        ports = f"  ports:{sub.open_ports}" if sub.open_ports else ""
        print(f"    [{status}] {sub.subdomain:<40} {techs}{ports}")

    if report.cloud_assets:
        print("\n  CLOUD ASSETS:")
        for asset in report.cloud_assets:
            flag = "🔴 PUBLIC" if asset.is_public else "🟡 Private"
            print(f"    {flag}  {asset.provider}/{asset.asset_type}: {asset.url}")

    if report.leaked_credentials:
        print("\n  POTENTIAL CREDENTIAL LEAKS:")
        for leak in report.leaked_credentials[:10]:
            print(f"    [{leak.credential_type}] {leak.repo_url}")
            print(f"      File: {leak.file_path}")

    # Risk flags
    risks = []
    for sub in report.subdomains:
        title_lower = (sub.title or "").lower()
        if any(w in title_lower for w in ["admin", "login", "dashboard", "control panel"]):
            risks.append(f"⚠  Admin panel exposed: {sub.subdomain}")
        for tech in sub.technologies:
            if "missing" in tech.lower():
                risks.append(f"⚠  {tech}: {sub.subdomain}")
        if sub.open_ports:
            risky = [p for p in sub.open_ports if p in [21, 23, 3389, 5900, 27017, 6379, 9200]]
            if risky:
                risks.append(f"⚠  Risky ports {risky} open: {sub.subdomain}")

    if risks:
        print("\n  RISK FLAGS (preview — see Module 3 for full scoring):")
        for r in risks[:10]:
            print(f"    {r}")

    print("\n  JSON report saved to ./reports/")
    print("═" * 55 + "\n")


async def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Asset Discovery Engine")
    parser.add_argument("--domain",      required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN"), help="GitHub API token (env: GITHUB_TOKEN)")
    # ── API keys — optional but give much higher rate limits ────────────────
    # AlienVault OTX : free key at otx.alienvault.com/api  (env: OTX_API_KEY)
    # URLScan.io     : free key at urlscan.io/user/profile/ (env: URLSCAN_API_KEY)
    parser.add_argument("--otx-key",      default=os.getenv("OTX_API_KEY",     ""), help="AlienVault OTX API key")
    parser.add_argument("--urlscan-key",  default=os.getenv("URLSCAN_API_KEY", ""), help="URLScan.io API key")
    # ────────────────────────────────────────────────────────────────────────
    parser.add_argument("--no-ports",  action="store_true", help="Skip port scanning")
    parser.add_argument("--no-cloud",  action="store_true", help="Skip cloud asset discovery")
    parser.add_argument("--no-github", action="store_true", help="Skip GitHub scanning")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")
    parser.add_argument("--confirm", action="store_true",   help="Confirm you have authorization to scan this domain")
    args = parser.parse_args()

    if not args.confirm:
        print("ERROR: You must confirm authorization with --confirm flag.")
        print(f"  python run.py --domain {args.domain} --confirm")
        print("\n  By using --confirm you certify that you have explicit written")
        print("  permission to scan this domain.")
        sys.exit(1)

    engine = AssetDiscoveryEngine(
        domain           = args.domain,
        github_token     = args.github_token,
        otx_api_key      = args.otx_key,
        urlscan_api_key  = args.urlscan_key,
        scan_ports       = not args.no_ports,
        scan_cloud       = not args.no_cloud,
        scan_github      = not args.no_github,
        output_dir       = args.output_dir,
    )

    report = await engine.run()
    print_summary(report)


if __name__ == "__main__":
    asyncio.run(main())
