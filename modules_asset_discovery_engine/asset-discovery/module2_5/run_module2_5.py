#!/usr/bin/env python3
"""
Module 2.5 — Async Directory Fuzzer & Leak Scanner
======================================================
Consumes a Module 1 JSON report, extracts only alive (HTTP 200) subdomains,
and checks each one for exposed .git/.env/backup/credential files using
async requests + content-validation (not just status codes).

Usage:
    python3 run_module2_5.py --report reports/example.com_latest.json --confirm
"""
import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import config
import scanner


RESET, BOLD, RED, YELLOW, GREEN, CYAN = (
    "\033[0m", "\033[1m", "\033[91m", "\033[93m", "\033[92m", "\033[96m"
)
RISK_COLOR = {"critical": RED, "high": RED, "medium": YELLOW, "low": GREEN}


def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════╗
║   MODULE 2.5 — Async Directory Fuzzer & Leak Scanner      ║
║   Authorized Security Testing Tool                        ║
╚══════════════════════════════════════════════════════════╝{RESET}
  ⚠  Use only with explicit written permission / valid bug bounty scope.
""")


def load_alive_subdomains(report_path: str) -> tuple[str, list]:
    """Extracts domain + only is_alive/200-status subdomains from Module 1 report."""
    if not os.path.isfile(report_path):
        print(f"{RED}ERROR: Report not found at {report_path}{RESET}")
        sys.exit(1)

    with open(report_path) as f:
        report = json.load(f)

    domain = report.get("domain", "unknown")
    alive  = []

    for sub in report.get("subdomains", []):
        is_alive    = sub.get("is_alive", False)
        https_code  = sub.get("https_status")
        http_code   = sub.get("http_status")
        if is_alive or https_code == 200 or http_code == 200:
            alive.append(sub.get("subdomain"))

    return domain, [s for s in alive if s]


def print_finding(host: str, finding: dict):
    color = RISK_COLOR.get(finding["risk"], CYAN)
    print(f"{color}{BOLD}[{finding['risk'].upper()}]{RESET} Leak Found: {finding['url']}")
    print(f"    {color}└ Type: {finding['type']}  |  {finding['evidence']}{RESET}")


def progress(done, total, host):
    bar_width = 30
    filled = int(bar_width * done / max(total, 1))
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"\r  {host[:35]:<35} [{bar}] {done}/{total}", end="", flush=True)
    if done >= total:
        print()


async def run_scan(report_path: str, output_dir: str, hosts_override: list = None) -> dict:
    banner()

    domain, alive_hosts = load_alive_subdomains(report_path)
    if hosts_override:
        alive_hosts = hosts_override

    print(f"{CYAN}[*] Domain: {domain}{RESET}")
    print(f"{CYAN}[*] Alive subdomains to scan: {len(alive_hosts)}{RESET}")

    wordlist = scanner.build_wordlist(domain)
    print(f"{CYAN}[*] Wordlist size: {len(wordlist)} paths "
          f"(static + domain-specific dynamic entries){RESET}\n")

    all_findings = []
    start_time = time.time()

    for host in alive_hosts:
        base_url = host if host.startswith("http") else f"https://{host}"

        def _progress_cb(done, total, h=host):
            progress(done, total, h)

        findings = await scanner.scan_host(base_url, wordlist, _progress_cb)

        for f in findings:
            f["subdomain"] = host
            print_finding(host, f)
            all_findings.append(f)

    duration = round(time.time() - start_time, 1)

    # ── Save report ────────────────────────────────────────────────────────
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(output_dir, f"{domain}_leaks_{int(time.time())}.json")

    summary = {
        "domain":         domain,
        "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_seconds": duration,
        "hosts_scanned":  len(alive_hosts),
        "wordlist_size":  len(wordlist),
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f["risk"] == "critical"),
        "high_count":     sum(1 for f in all_findings if f["risk"] == "high"),
        "medium_count":   sum(1 for f in all_findings if f["risk"] == "medium"),
        "findings":       all_findings,
    }

    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}SCAN SUMMARY{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"  Hosts scanned    : {summary['hosts_scanned']}")
    print(f"  Duration         : {duration}s")
    print(f"  Total findings   : {summary['total_findings']}")
    print(f"  {RED}Critical         : {summary['critical_count']}{RESET}")
    print(f"  {RED}High             : {summary['high_count']}{RESET}")
    print(f"  {YELLOW}Medium           : {summary['medium_count']}{RESET}")
    print(f"\n  Report saved: {out_path}")
    print(f"{CYAN}{'='*60}{RESET}\n")

    notify_if_critical(summary)
    return summary


def notify_if_critical(summary: dict):
    """
    Placeholder hook — wire your existing Discord webhook / email notifier
    here (same pattern as Module 3). Kept as a separate function for a
    clean one-line integration point.

    Example:
        if summary["critical_count"] > 0:
            send_discord_alert(summary)   # <- your existing function
    """
    if summary["critical_count"] > 0:
        print(f"{RED}{BOLD}[ALERT HOOK] {summary['critical_count']} critical leak(s) found — "
              f"wire your notifier into notify_if_critical(){RESET}")
    # TODO: hook up webhook/email here


def main():
    parser = argparse.ArgumentParser(description="Module 2.5 — Async Directory Fuzzer & Leak Scanner")
    parser.add_argument("--report", required=True, help="Path to Module 1 JSON report")
    parser.add_argument("--output-dir", default=config.OUTPUT_DIR, help="Where to save findings report")
    parser.add_argument("--host", action="append", default=None,
                        help="Scan a specific host instead of using the report (repeatable)")
    parser.add_argument("--confirm", action="store_true",
                        help="Confirm you have authorization to scan this domain")
    args = parser.parse_args()

    if not args.confirm:
        print(f"{RED}ERROR: You must confirm authorization with --confirm flag.{RESET}")
        print(f"  python3 run_module2_5.py --report {args.report} --confirm")
        sys.exit(1)

    asyncio.run(run_scan(args.report, args.output_dir, args.host))


if __name__ == "__main__":
    main()
