# Module 3 — Risk Scoring & CVE Matching Engine

> ⚠️ **AUTHORIZED USE ONLY** — Sirf apne domains ya bug bounty program ke
> scope mein listed domains pe use karein.

---

## Yeh Module Kya Karta Hai

Module 1 sirf **discover** karta hai (subdomains, tech stack, open ports).
Module 3 un findings ko **actionable risk** mein convert karta hai:

1. Module 1 ke JSON report se har subdomain ki technology (jaise "Nginx 1.18.0") padhta hai
2. Har technology ko **4 alag CVE databases** se match karta hai (zyada coverage, ek source miss kare to doosra pakad le)
3. Check karta hai ke koi matched CVE **CISA KEV** (actively exploited) mein hai ya nahi
4. Sab kuch milake ek **0-100 risk score** banata hai, priority ke hisab se sorted
5. Critical/High findings **5+ Discord webhooks** par ek saath broadcast hoti hain

Yeh bilkul wahi kaam hai jo Nessus, Qualys, aur Tenable jaise commercial
($$$$) vulnerability scanners karte hain — sirf public/documented data use karke.

---

## ⚡ API Keys Aur Webhooks Kahan Lagayein (Sabse Zaroori Section)

Sab kuch **`config.py`** file ke andar, seedha quotes ke andar paste karo.
File khol ke yeh 3 jagah dhoondo:

### 1️⃣ NVD API Key (line ~15)
```python
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")   # ← yahan quotes ke andar paste karo
```
Bina key ke bhi chalta hai (5 req/30s), key ke saath 50 req/30s (10x faster).
Free key: **https://nvd.nist.gov/developers/request-an-api-key**

### 2️⃣ Vulners API Key (line ~28)
```python
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")   # ← yahan quotes ke andar paste karo
```
Bina key ke yeh source silently skip ho jaata hai (baaki 3 sources kaam karte rehte hain).
Free key: **https://vulners.com/api-keys**

### 3️⃣ Discord Webhooks (line ~36) — 5 slots pehle se bane hain
```python
DISCORD_WEBHOOKS = [
    os.environ.get("DISCORD_WEBHOOK_1", ""),   # ← webhook URL yahan
    os.environ.get("DISCORD_WEBHOOK_2", ""),   # ← webhook URL yahan
    os.environ.get("DISCORD_WEBHOOK_3", ""),   # ← webhook URL yahan
    os.environ.get("DISCORD_WEBHOOK_4", ""),   # ← webhook URL yahan
    os.environ.get("DISCORD_WEBHOOK_5", ""),   # ← webhook URL yahan
]
```
Khali ("") wale automatically ignore ho jaate hain. 5 se zyada chahiye ho to
bas list mein aur lines add kar do — koi hard limit nahi hai.

> **OSV.dev aur CISA KEV ko koi key nahi chahiye** — dono bilkul free/open hain.

### Alternative: Environment variables (agar code mein paste nahi karna)
```bash
export NVD_API_KEY="your_key"
export VULNERS_API_KEY="your_key"
export DISCORD_WEBHOOK_1="your_webhook_url"
export DISCORD_WEBHOOK_2="your_webhook_url"
```

### Alternative: CLI flags (har run pe alag key use karni ho)
```bash
python3 run_module3.py --report reports/example.com_latest.json \
  --nvd-key YOUR_KEY --vulners-key YOUR_KEY \
  --discord-webhook URL1 --discord-webhook URL2
```

**Priority order:** CLI flag > environment variable > `config.py` mein direct
paste kiya hua. Teeno tareeqe kaam karte hain, jo aasan lage woh use karo.

---

## Architecture

```
run_module3.py                    ← CLI entry point, orchestration
│
├── tech_parser.py                 ← "Nginx 1.18.0" → {product: nginx, version: 1.18.0}
│
├── nvd_client.py                   ← NIST NVD API (US govt) — official CVE database
│   ├── Rate limiter (dynamic — key set anytime, sahi limit turant apply hoti hai)
│   └── SQLite cache (7-day TTL)
│
├── osv_client.py                    ← OSV.dev (Google) — FREE, no key
│   └── npm/PyPI/Packagist/RubyGems package ecosystems ke liye best coverage
│
├── vulners_client.py                 ← Vulners.com — aggregated CVE + exploit-availability flag
│
├── kev_client.py                      ← CISA KEV — "actively exploited right now" confirmation
│
├── risk_engine.py                      ← Composite scoring + multi-source merge/dedupe
│   ├── merge_cve_sources()               → same CVE 2 sources se mile to duplicate count nahi hota
│   ├── CVSS base score               (45% weight)
│   ├── KEV bonus                      (+25 points flat)
│   ├── Exposure context              (20% weight)
│   └── Asset criticality             (15% weight)
│
├── discord_notifier.py                  ← 5+ webhooks ko ek saath broadcast
├── database.py                            ← SQLite: CVE cache + saved findings
└── config.py                               ← SAB KEYS YAHAN (upar wala section dekho)
```

---

## Setup

```bash
pip install requests
chmod +x run_module3.py
```

---

## Usage

### Basic scan:
```bash
python3 run_module3.py --report reports/example.com_latest.json
```

### Module 2.5 ke leak findings bhi shamil karo:
```bash
python3 run_module3.py \
  --report reports/example.com_latest.json \
  --leaks module2_5_reports/example.com_leaks.json
```

### Sab keys CLI se (config.py edit kiye bina):
```bash
python3 run_module3.py \
  --report reports/example.com_latest.json \
  --nvd-key YOUR_NVD_KEY \
  --vulners-key YOUR_VULNERS_KEY \
  --discord-webhook URL1 --discord-webhook URL2
```

### Concurrent threads adjust karo (default: 4):
```bash
python3 run_module3.py --report reports/example.com_latest.json --workers 6
```

> **Note:** Workers zyada badhane se speed nahi badhti — NVD ka rate limiter
> shared resource hai, saare threads usi limiter pe wait karte hain. 4-6 optimal hain.

---

## Output Format

`module3_reports/<domain>_risk_report_<timestamp>.json`:

```json
{
  "scan_id": "example.com_a1b2c3d4",
  "domain": "example.com",
  "total_findings": 12,
  "critical_count": 2,
  "high_count": 4,
  "kev_matches": 1,
  "findings": [
    {
      "subdomain": "api.example.com",
      "technology": "nginx",
      "version": "1.18.0",
      "risk_score": 100.0,
      "risk_level": "CRITICAL",
      "in_kev": true,
      "matched_cves": [
        {
          "cve_id": "CVE-2021-23017",
          "cvss": 9.4,
          "sources": ["NVD", "OSV.dev"],
          "summary": "Nginx resolver off-by-one heap write vulnerability...",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
          "kev": {"date_added": "2022-05-03", "due_date": "2022-05-24"}
        }
      ]
    }
  ]
}
```

---

## Risk Scoring Formula

```
Final Score (0-100) =
    (max CVSS / 10 × 100 × 0.45)              ← software kitna severe hai
  + (25 agar KEV mein hai, warna 0)           ← actively exploited hone ka bonus
  + (exposure score / 10 × 100 × 0.20)        ← kitna reachable/dangerous hai
  + (criticality score / 10 × 100 × 0.15)     ← prod hai ya dev
  + (CVE count bonus, max 15 × 0.20)          ← kitne alag bugs hain (deduped)
```

| Score | Level |
|-------|-------|
| 85-100 | 🔴 CRITICAL — turant fix karo |
| 65-84  | 🟠 HIGH — is hafte fix karo |
| 40-64  | 🟡 MEDIUM — is mahine fix karo |
| 15-39  | 🟢 LOW — backlog mein daalo |
| 0-14   | ⚪ INFO — documentation ke liye |

---

## Data Sources (100% Public / Documented, No Scraping)

| Source | Kya deta hai | Key chahiye? |
|--------|-------------|---------------|
| **NIST NVD** | CVE ID, CVSS, description | Optional (10x rate limit ke liye) |
| **CISA KEV** | "Actively exploited" confirmation | Nahi, kabhi nahi |
| **OSV.dev** | Open-source package CVEs (npm/PyPI/etc) | Nahi, kabhi nahi |
| **Vulners.com** | Extra CVE coverage + exploit-availability flag | Haan (free tier available) |

---

## Bug Fixed in This Version

**Problem:** `nvd_client.py` mein `from config import NVD_API_KEY` likha tha —
yeh value ko **import ke waqt hi copy** kar leta hai. Jab CLI se ya baad mein
key set hoti thi (`config.NVD_API_KEY = args.nvd_key`), `nvd_client.py` ko
purani (khali) value hi dikhti rehti thi — key kabhi effect nahi karti thi.

**Fix:** Ab `import config` karke `config.NVD_API_KEY` ko har request se
pehle **fresh read** karta hai, chahe key kahin se bhi set hui ho (config.py
edit, environment variable, ya CLI flag) — sab jagah se ab sahi kaam karta hai.

---

## Coming Next

- **Module 4**: Professional PDF report generator
- **Module 5**: Multi-tenant SaaS dashboard + billing
