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

## What's new in this version

- **Config lives inside `monitor.py`.** Fill in your webhooks and email
  settings once at the top of the file — no more retyping flags every run.
- **Multiple channels.** Up to **5 webhook URLs** and up to **5 email
  recipients** — every filled-in slot receives every alert. Empty slots are
  ignored safely; nothing breaks if you leave them blank.
- **Multiple sender accounts with failover.** Configure up to 5 sender email
  accounts. If the first account fails to send (bad password, connection
  issue), the next one is tried automatically.
- **Command-line still works.** Any `--webhook`, `--email-to`, etc. flag you
  pass overrides the hardcoded config for that run only.
- **Bug fix:** the weekly digest email no longer uses a broken
  `run_in_executor(asyncio.run(...))` pattern that could silently fail —
  it's now a clean synchronous call run safely in a thread pool.

---

## Step 1 — Configure once (recommended)

Open `monitor.py` and edit the block near the top:

```python
DEFAULT_GITHUB_TOKEN    = "ghp_xxxxxxxxxxxxxxxxxxxx"
DEFAULT_OTX_API_KEY     = ""
DEFAULT_URLSCAN_API_KEY = ""

DEFAULT_WEBHOOKS = [
    "https://discord.com/api/webhooks/AAA/BBB",   # webhook 1
    "https://hooks.slack.com/services/CCC/DDD",   # webhook 2
    "",                                            # webhook 3 (unused — fine to leave blank)
    "",                                            # webhook 4
    "",                                            # webhook 5
]

DEFAULT_EMAIL_TO = [
    "ahmadrasheed13580@gmail.com",
    "second.person@company.com",
    "",
    "",
    "",
]

DEFAULT_EMAIL_ACCOUNTS = [
    {"email_from": "", "smtp_password": "",
     "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
    {"email_from": "", "smtp_password": "", "smtp_host": "smtp.gmail.com", "smtp_port": 587},
]

DEFAULT_MIN_SEVERITY = "warning"
```

Save the file. From now on you just run:

```bash
python3 run_monitor.py --domain example.com --once --confirm
```

No flags needed — everything comes from the config block above.

---

## Step 2 — Install dependencies

```bash
pip3 install aiohttp aiofiles dnspython
```

---

## Step 3 — First (baseline) scan

```bash
cd ~/project/advance/asset-discovery/module2
python3 run_monitor.py --domain example.com --once --confirm
```

The first scan saves a baseline — no alerts yet. Alerts begin from scan #2.

---

## Step 4 — Second scan (change detection active)

```bash
python3 run_monitor.py --domain example.com --once --confirm
```

Any difference vs. the baseline now triggers alerts on every configured channel.

---

## Step 5 — Run forever (daemon mode)

```bash
python3 run_monitor.py --domain example.com --confirm
```

Press `Ctrl+C` to stop cleanly.

---

## Overriding config from the command line (optional)

You never *have* to use these — they're for one-off runs where you want
different settings than what's saved in `monitor.py`.

```
python3 run_monitor.py --domain <domain> [options] --confirm

Required:
  --domain DOMAIN          Target domain  (e.g. example.com)
  --confirm                Certify that you have authorization to scan

Scan control:
  --once                   Run one scan+diff then exit  (ideal for cron)
  --interval HOURS         Hours between scans in daemon mode  (default: 24)
  --no-ports               Skip port scanning
  --no-cloud               Skip cloud bucket discovery

API keys (override monitor.py defaults for this run only):
  --github-token TOKEN     GitHub personal access token
  --otx-key KEY            AlienVault OTX API key
  --urlscan-key KEY        URLScan.io API key

Alerts (override monitor.py defaults for this run only):
  --min-severity LEVEL     info | warning | critical
  --webhook URL[,URL2,...] One or more webhook URLs, comma-separated
  --email-to A[,B,...]     One or more recipient emails, comma-separated
  --email-from ADDR        Sender Gmail address (pairs with --smtp-password)
  --smtp-password PASS     Gmail App Password (NOT your login password)
  --smtp-host HOST         SMTP host  (default: smtp.gmail.com)
  --smtp-port PORT         SMTP port  (default: 587)
```

Example — one-off run with different webhook, without touching the config file:

```bash
python3 run_monitor.py --domain example.com --once --confirm \
  --webhook "https://discord.com/api/webhooks/XXX/YYY"
```

Example — multiple webhooks and recipients in a single run:

```bash
python3 run_monitor.py --domain example.com --once --confirm \
  --webhook "https://discord.com/api/webhooks/A,https://hooks.slack.com/B" \
  --email-to "alice@company.com,bob@company.com"
```

> **Note:** passing `--webhook` or `--email-to` replaces the *entire* list
> for that run — it does not add to the config-file list. Leave the flag
> out entirely to keep using everything configured in `monitor.py`.

---

## Alert Channels — How Each One Behaves

### Console
Always on, no configuration needed. Every change is printed with severity markers.

### Email
- Every filled slot in `DEFAULT_EMAIL_TO` receives the **same** email (sent as one message with all recipients in the To: field — efficient, single SMTP connection).
- Sender accounts in `DEFAULT_EMAIL_ACCOUNTS` are tried **in order** — if account 1 fails (wrong password, connection refused, etc.) account 2 is tried automatically, and so on.
- Leave a slot's `email_from` / `smtp_password` empty and it is skipped — no error.

To create a Gmail App Password:
1. Google Account → Security → 2-Step Verification → App passwords
2. Create a new app password for "Mail"
3. Paste the 16-character code into `smtp_password`

### Webhook
- Every filled URL in `DEFAULT_WEBHOOKS` receives the **same** alert, sent concurrently.
- Works with Discord (uses the `content` field) and Slack (uses the `text` field) automatically — no need to pick a format.
- Each webhook retries independently up to 3 times with backoff; a failure on one webhook doesn't affect the others.

---

## File & Directory Layout

```
module2/
├── monitor.py          ← Config block + all classes
├── run_monitor.py       ← CLI runner
└── README.md            ← This file

~/asset-discovery-data/<domain>/
├── snapshot_latest.json          ← Most recent scan (diff baseline)
├── snapshot_YYYYMMDD_HHMMSS.json ← Timestamped archive copies
├── scan_history.jsonl            ← One-line summary per completed scan
├── events_YYYY-MM-DD.jsonl       ← All ChangeEvents for that day
└── digest_YYYY-MM-DD.json        ← Weekly digest files

~/asset-discovery-logs/
└── monitor.log                   ← Full runtime log
```

---

## Change Types Detected

| Event Type | Severity | Description |
|---|---|---|
| `new_subdomain` | warning (info if dead) | A subdomain appeared that was not in the previous scan |
| `subdomain_removed` | warning (info if was dead) | A subdomain stopped resolving |
| `port_opened` | warning / critical | A new port is reachable (critical for RDP, Redis, MongoDB, etc.) |
| `port_closed` | info | A previously open port is now closed |
| `cert_changed` | warning | SSL certificate was rotated or replaced |
| `status_changed` | warning | HTTP status code changed (e.g. 403 → 200) |
| `tech_added` | warning | New technology fingerprinted on a host |
| `new_cloud_asset` | warning / critical | New storage bucket found (critical if publicly readable) |
| `new_credential_leak` | critical | Additional credential leaks detected on GitHub |

`--min-severity` (default: `warning`) controls which of these actually trigger an alert.

---

## Running with Cron (recommended for production)

```bash
crontab -e
```

Add this line (runs every day at 2:00 AM):

```cron
0 2 * * * cd /home/ubuntu/project/advance/asset-discovery/module2 && python3 run_monitor.py --domain example.com --once --confirm >> /home/ubuntu/asset-discovery-logs/cron.log 2>&1
```

Since all settings are pre-configured inside `monitor.py`, the cron line stays this short even with 5 webhooks and 5 email accounts active.

---

## Using as a Python Library

```python
import asyncio
from monitor import ContinuousMonitor, AlertConfig

async def main():
    # Uses everything configured inside monitor.py's DEFAULT_* block:
    monitor = ContinuousMonitor(domain="example.com")

    # Or override explicitly:
    config = AlertConfig(
        webhooks=["https://discord.com/api/webhooks/XXX"],
        email_to=["you@company.com", "teammate@company.com"],
        email_accounts=[{"email_from": "alerts@gmail.com",
                          "smtp_password": "xxxx xxxx xxxx xxxx"}],
        min_severity="warning",
    )
    monitor = ContinuousMonitor(domain="example.com", alert_config=config)

    report, events = await monitor.run_once()
    print(f"Found {len(events)} changes")

    # Or run forever as a daemon:
    # await monitor.run_forever()

asyncio.run(main())
```

---

## Weekly Digest Example

Every 7 scans the monitor automatically prints, saves, and emails a digest:

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
| `ModuleNotFoundError: discovery_engine` | monitor.py auto-searches for `discovery_engine.py` in nearby folders — make sure Module 1's files exist somewhere under the project directory |
| `PermissionError: monitor.log` | `sudo chown -R ubuntu:ubuntu ~/project/` |
| `Command 'python' not found` | Use `python3` — Ubuntu does not alias `python` by default |
| Email not sending | Use a Gmail **App Password**, not your login password; check all 5 account slots aren't all blank |
| No alerts on second scan | Check `DEFAULT_MIN_SEVERITY` / `--min-severity` — `info` events are suppressed by the default `warning` level |
| Webhook returns 400 "empty message" | Fixed in this version — payload now includes both `content` (Discord) and `text` (Slack) fields |
| Only some of my 5 webhooks/emails fire | Check for typos — blank or malformed entries are silently skipped, never error, but also never send |
