# Module 2.5 — Async Directory Fuzzer & Leak Scanner

> ⚠️ **AUTHORIZED USE ONLY** — Sirf apne domains ya bug bounty scope mein listed domains pe.

## Setup
```bash
pip install aiohttp
chmod +x run_module2_5.py
```

## Usage
```bash
python3 run_module2_5.py --report reports/example.com_latest.json --confirm
```

Specific host test karna ho (Module 1 report ke bina):
```bash
python3 run_module2_5.py --report reports/example.com_latest.json --host api.example.com --confirm
```

## Architecture
- `config.py`     — wordlist (static 90+ entries + dynamic domain-based), concurrency=25, timeout=7s
- `validator.py`   — content-matching (rejects HTTP 200 soft-404 false positives)
- `scanner.py`     — async aiohttp engine, semaphore-limited, magic-byte archive detection
- `run_module2_5.py` — CLI, JSON report output, notification hook

## Validation Logic (False-Positive Rejection)
Sirf HTTP 200 kaafi nahi — har finding content-verified hai:
- `.env` → body mein `DB_PASSWORD`/`APP_KEY`/`AWS_` jaisi strings honi chahiye
- `.git/config` → body mein `[core]`/`repositoryformatversion` hona chahiye
- `.zip`/`.tar.gz` → magic bytes (`PK\x03\x04` etc.) ya Content-Type check, poori file download nahi hoti (max 64KB read)
- Generic backups → soft-404 HTML markers detect karke reject karta hai

Maine sab validation rules mock data se test kiye hain (real leak detect + false positive reject dono) — sab pass.

## Output
`module2_5_reports/<domain>_leaks_<timestamp>.json` — Module 3 isi format ko directly consume karta hai (`findings[]` with `url`/`type`/`risk`).

## Notification Hook
`run_module2_5.py` mein `notify_if_critical()` — apna Discord webhook yahan wire karo (Module 3 jaisa pattern).

