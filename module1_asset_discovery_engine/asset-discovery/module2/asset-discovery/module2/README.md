# Module 2 — Continuous Monitoring & Change Detection

> **Authorization required.** Only scan domains you own or have explicit written permission to test.

---

## Overview

Module 2 sits on top of Module 1's discovery engine and turns it into a **persistent watchdog**.
Every time it runs, it:

1. Performs a full asset discovery scan (subdomains, ports, certificates, cloud, GitHub)
2. Compares the result against the previous scan stored on disk
3. Emits a structured **ChangeEvent** for every difference found
4. Delivers alerts via console, email, and/or webhook
5. After every 7 scans, generates a **Weekly Digest** summarising the week's changes

---

## Architecture

```
run_monitor.py          ← CLI entry point
└── ContinuousMonitor   ← Orchestrator (run_once / run_forever)
    ├── AssetDiscoveryEngine  (Module 1)   ← Full scan
    ├── SnapshotManager       ← Persist state to disk (JSON)
    ├── ChangeDetector        ← Diff old vs new report → ChangeEvents
    ├── AlertSender           ← Console / Email / Webhook
    └── WeeklyDigestBuilder   ← 7-scan aggregate summary
```

### Change types detected

| Event Type | Severity | Description |
|---|---|---|
| `new_subdomain` | warning | A subdomain appeared that was not in the previous scan |
| `subdomain_removed` | info | A subdomain stopped resolving |
| `port_opened` | warning / critical | A new port is reachable (critical for RDP, Redis, MongoDB etc.) |
| `port_closed` | info | A previously open port is now closed |
| `cert_changed` | warning | SSL certificate was rotated or replaced |
| `status_changed` | info / warning | HTTP status code changed (e.g. 403 → 200) |
| `tech_added` | info | New technology fingerprinted on a host |
| `new_cloud_asset` | warning / critical | New storage bucket found (critical if publicly readable) |
| `new_credential_leak` | critical | Additional credential leaks detected on GitHub |

---

## File & Directory Layout

```
module2/
├── monitor.py          ← All classes (import this in your own code)
├── run_monitor.py      ← CLI runner
└── README.md           ← This file

~/asset-discovery-data/<domain>/
├── snapshot_latest.json         ← Most recent scan (diff baseline)
├── snapshot_YYYYMMDD_HHMMSS.json ← Timestamped archive copies
├── scan_history.jsonl           ← One-line summary per completed scan
├── events_YYYY-MM-DD.jsonl      ← All ChangeEvents for that day
└── digest_YYYY-MM-DD.json       ← Weekly digest files

~/asset-discovery-logs/
└── monitor.log                  ← Full runtime log
```

---

## Step-by-Step Setup

### Step 1 — Fix permissions (run once)

```bash
sudo chown -R ubuntu:ubuntu ~/project/
chmod -R 755 ~/project/advance/asset-discovery/
```

### Step 2 — Install dependencies

```bash
pip3 install aiohttp aiofiles dnspython
```

### Step 3 — Run your first (baseline) scan

The first scan saves a baseline with no alerts — alerts begin from scan #2 onwards.

```bash
cd ~/project/advance/asset-discovery/module2
python3 run_monitor.py --domain example.com --once --confirm
```

### Step 4 — Run a second scan to see change detection

```bash
python3 run_monitor.py --domain example.com --once --confirm
```

If anything changed since the baseline, you will see a structured alert in the terminal.

### Step 5 — Start continuous daemon (runs every 24 hours)

```bash
python3 run_monitor.py --domain example.com --confirm
```

Press `Ctrl+C` to stop cleanly.

---

## All CLI Options

```
python3 run_monitor.py --domain <domain> [options] --confirm

Required:
  --domain DOMAIN         Target domain  (e.g. example.com)
  --confirm               Certify that you have authorization to scan

Scan control:
  --once                  Run one scan+diff then exit  (ideal for cron)
  --interval HOURS        Hours between scans in daemon mode  (default: 24)
  --no-ports              Skip port scanning
  --no-cloud              Skip cloud bucket discovery

Alerts:
  --min-severity LEVEL    info | warning | critical  (default: warning)
  --webhook URL           Slack / Discord / custom webhook URL
  --email-to ADDRESS      Alert recipient email
  --email-from ADDRESS    Sender Gmail address
  --smtp-password PASS    Gmail app password (NOT your login password)
  --smtp-host HOST        SMTP host  (default: smtp.gmail.com)
  --smtp-port PORT        SMTP port  (default: 587)

GitHub:
  --github-token TOKEN    Personal access token for credential-leak scanning
```

---

## Alert Channels

### Console (always on)
Every change is printed to the terminal with severity colour-coding.

### Email (Gmail)
Uses Gmail's SMTP with an **App Password** (not your normal Gmail password).

To create a Gmail App Password:
1. Go to your Google Account → Security → 2-Step Verification → App passwords
2. Create a new app password for "Mail"
3. Use the 16-character code as `--smtp-password`

```bash
python3 run_monitor.py --domain example.com \
  --email-to   alerts@yourcompany.com \
  --email-from you@gmail.com \
  --smtp-password "xxxx xxxx xxxx xxxx" \
  --confirm
```

### Webhook (Slack / Discord / custom)
Sends a JSON POST to any webhook URL on every alert.

**Slack:** Create an Incoming Webhook in your Slack workspace settings, then:
```bash
python3 run_monitor.py --domain example.com \
  --webhook "https://hooks.slack.com/services/XXX/YYY/ZZZ" \
  --confirm
```

**Discord:** Create a webhook in any channel, then:
```bash
python3 run_monitor.py --domain example.com \
  --webhook "https://discord.com/api/webhooks/XXX/YYY" \
  --confirm
```

---

## Environment Variables

Instead of typing flags every time, export these variables:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
export ALERT_EMAIL_TO="security@company.com"
export ALERT_EMAIL_FROM="alerts@gmail.com"
export SMTP_PASSWORD="xxxx xxxx xxxx xxxx"
export ALERT_WEBHOOK_URL="https://hooks.slack.com/..."
export ALERT_MIN_SEVERITY="warning"

python3 run_monitor.py --domain example.com --confirm
```

---

## Running with Cron (recommended for production)

For a reliable daily scan, use cron instead of the daemon mode:

```bash
crontab -e
```

Add this line (runs every day at 2:00 AM):

```cron
0 2 * * * cd /home/ubuntu/project/advance/asset-discovery/module2 && python3 run_monitor.py --domain example.com --once --confirm >> /home/ubuntu/asset-discovery-logs/cron.log 2>&1
```

---

## Using as a Python Library

```python
import asyncio
from monitor import ContinuousMonitor, AlertConfig

async def main():
    config = AlertConfig(
        email_to      = "you@company.com",
        email_from    = "alerts@gmail.com",
        smtp_password = "xxxx xxxx xxxx xxxx",
        webhook_url   = "https://hooks.slack.com/...",
        min_severity  = "warning",
    )

    monitor = ContinuousMonitor(
        domain              = "example.com",
        alert_config        = config,
        github_token        = "ghp_xxx",
        scan_interval_hours = 24,
    )

    # Single scan + diff (for cron or testing)
    report, events = await monitor.run_once()
    print(f"Found {len(events)} changes")

    # Or run forever as a daemon
    # await monitor.run_forever()

asyncio.run(main())
```

---

## Weekly Digest Example

Every 7 scans the monitor automatically prints and saves a digest:

```
╔════════════════════════════════════════════════════════════╗
║  WEEKLY SECURITY DIGEST                                    ║
║  Domain  : example.com                                     ║
║  Period  : 2025-07-01  →  2025-07-08                       ║
╠════════════════════════════════════════════════════════════╣
║  Scans completed    : 7                                    ║
║  Total changes      : 11                                   ║
║  Attack surface Δ   : +3                                   ║
╠════════════════════════════════════════════════════════════╣
║  New Subdomains (3)                                        ║
║    • staging2.example.com                                  ║
║    • internal-api.example.com                              ║
║    • dev-portal.example.com                                ║
║  New Ports Opened (2)                                      ║
║    • api.example.com → port 8080                           ║
║    • mail.example.com → port 587                           ║
║  Certificate Changes (1)                                   ║
║    • www.example.com  (expiry=Aug 15 2025)                 ║
╚════════════════════════════════════════════════════════════╝
```

---

## Troubleshooting

| Error | Fix |
|---|---|
| `ModuleNotFoundError: discovery_engine` | Run from the `module2/` directory, or ensure `module1/` is in the same parent folder |
| `PermissionError: monitor.log` | `sudo chown -R ubuntu:ubuntu ~/project/` |
| `Command 'python' not found` | Use `python3` — Ubuntu does not alias `python` by default |
| Email not sending | Use a Gmail **App Password**, not your login password |
| No alerts on second scan | Check `--min-severity` — default is `warning` (info events are suppressed) |
| Webhook returns 400 | Verify the webhook URL format for your platform (Slack vs Discord differ) |
