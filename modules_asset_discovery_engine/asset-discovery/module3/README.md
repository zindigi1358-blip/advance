# Module 3 — Risk Scoring & CVE Matching Engine

> ⚠️ **AUTHORIZED USE ONLY** — Sirf apne domains ya bug bounty program ke
> scope mein listed domains pe use karein.

---

## Yeh Module Kya Karta Hai

Module 1 sirf **discover** karta hai (subdomains, tech stack, open ports).
Module 3 un findings ko **actionable risk** mein convert karta hai:

1. Module 1 ke JSON report se har subdomain ki technology (jaise "Nginx 1.18.0") padhta hai
2. Har technology ko **NIST NVD** (National Vulnerability Database — US government ki official CVE database) se match karta hai
3. Check karta hai ke koi matched CVE **CISA KEV** (Known Exploited Vulnerabilities) mein hai ya nahi — matlab "yeh bug sirf theoretical nahi, real duniya mein active attacks ho rahe hain isse"
4. Sab kuch milake ek **0-100 risk score** banata hai per finding, priority ke hisab se sorted

Yeh bilkul wahi kaam hai jo Nessus, Qualys, aur Tenable jaise commercial ($$$$) vulnerability scanners karte hain — sirf public, free government data use karke.

---

## Architecture

```
run_module3.py                 ← CLI entry point, orchestration
│
├── tech_parser.py              ← "Nginx 1.18.0" → {product: nginx, version: 1.18.0}
│
├── nvd_client.py                ← NIST NVD API client
│   ├── Rate limiter (5 req/30s without key, 50 req/30s with key)
│   └── SQLite cache (7-day TTL — same version dobara query nahi hoti)
│
├── kev_client.py                ← CISA KEV catalog client
│   └── "Actively exploited right now" flag
│
├── risk_engine.py                ← Composite scoring formula
│   ├── CVSS base score       (45% weight)
│   ├── KEV bonus              (+25 points flat, agar actively exploited hai)
│   ├── Exposure context      (20% weight — admin panel? database port open?)
│   └── Asset criticality     (15% weight — prod/admin > dev/staging)
│
├── database.py                   ← SQLite: CVE cache + saved findings
└── config.py                      ← Saari settings, API keys yahan
```

---

## Setup

### Step 1 — Dependencies
```bash
pip install requests
```
(Baaki sab Python stdlib hai — koi aur dependency nahi chahiye)

### Step 2 — File permissions
```bash
chmod +x run_module3.py
```

### Step 3 — (Optional lekin recommended) NVD API Key
Bina key ke bhi kaam karta hai, lekin sirf **5 requests/30 seconds** — bade domains
(100+ subdomains) pe scan bohat slow ho jayega.

Free key (instant, sirf email chahiye): **https://nvd.nist.gov/developers/request-an-api-key**

Key ke saath: **50 requests/30 seconds** — 10x faster.

---

## Usage

### Basic scan (Module 1 ka report use karke):
```bash
python3 run_module3.py --report reports/example.com_latest.json --confirm
```

### NVD key ke saath (much faster):
```bash
python3 run_module3.py \
  --report reports/example.com_latest.json \
  --nvd-key YOUR_NVD_KEY_HERE
```

### Module 2.5 ke leak findings bhi shamil karo:
```bash
python3 run_module3.py \
  --report reports/example.com_latest.json \
  --leaks module2_5_reports/example.com_leaks.json \
  --nvd-key YOUR_NVD_KEY_HERE
```

### Environment variable se key (permanent, dobara type nahi karna):
```bash
echo 'export NVD_API_KEY="your_key_here"' >> ~/.bashrc
source ~/.bashrc
python3 run_module3.py --report reports/example.com_latest.json
```

### Concurrent processing threads adjust karo (default: 4):
```bash
python3 run_module3.py --report reports/example.com_latest.json --workers 6
```

> **Note:** Workers zyada badhane se speed nahi badhti — NVD ka rate limiter
> ek shared resource hai, saare threads usi limiter pe wait karte hain.
> 4-6 workers optimal hain.

---

## Output Format

Report `module3_reports/<domain>_risk_report_<timestamp>.json` mein save hoti hai:

```json
{
  "scan_id": "example.com_a1b2c3d4",
  "domain": "example.com",
  "generated_at": "2026-07-06T10:00:00Z",
  "total_findings": 12,
  "critical_count": 2,
  "high_count": 4,
  "medium_count": 5,
  "low_count": 1,
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
          "summary": "Nginx resolver off-by-one heap write vulnerability...",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
          "kev": {
            "date_added": "2022-05-03",
            "due_date": "2022-05-24",
            "ransomware_use": "Unknown"
          }
        }
      ],
      "breakdown": {
        "max_cvss": 9.4,
        "exposure_notes": "database port open, admin panel public",
        "criticality_score": 9
      }
    }
  ]
}
```

---

## Risk Scoring Formula Samjho

```
Final Score (0-100) =
    (max CVSS / 10 × 100 × 0.45)              ← software kitna severe hai
  + (25 agar KEV mein hai, warna 0)           ← actively exploited hone ka bonus
  + (exposure score / 10 × 100 × 0.20)        ← kitna reachable/dangerous hai
  + (criticality score / 10 × 100 × 0.15)     ← prod hai ya dev
  + (CVE count bonus, max 15 × 0.20)          ← kitne alag bugs hain
```

**Kyun sirf CVSS pe depend nahi karte:** Ek 9.8 CVSS bug kisi internal
dev server pe utna important nahi jitna 6.5 CVSS bug kisi public admin
panel pe jo abhi CISA KEV mein bhi hai. Yeh formula real-world priority
dikhata hai, sirf raw severity nahi.

### Risk Bands:
| Score | Level |
|-------|-------|
| 85-100 | 🔴 CRITICAL — turant fix karo |
| 65-84  | 🟠 HIGH — is hafte fix karo |
| 40-64  | 🟡 MEDIUM — is mahine fix karo |
| 15-39  | 🟢 LOW — backlog mein daalo |
| 0-14   | ⚪ INFO — sirf documentation ke liye |

---

## Notification Hook

`run_module3.py` ke andar `notify_if_critical()` function hai — yahan apna
existing Discord webhook / email / Slack alert wire karo (jaisa honeypot
monitor project mein tha):

```python
def notify_if_critical(summary: dict):
    if summary["kev_matches"] > 0:
        send_discord_alert(summary)   # ← apna function yahan call karo
```

---

## Data Sources (100% Public, Official, Free)

| Source | Kya deta hai | Key chahiye? |
|--------|-------------|---------------|
| **NIST NVD** | CVE ID, CVSS score, description | Optional (10x rate limit ke liye) |
| **CISA KEV** | "Actively exploited" confirmation | Nahi, kabhi nahi |

Dono US government ki official, free APIs hain — koi scraping, koi
unauthorized access nahi.

---

## Testing

Maine yeh module mock data se test kiya hai (parsing, scoring, database
round-trip) bina live NVD call ke — sab pass hua. Real domain pe pehli
baar chalane se pehle chhota sa test (5-10 subdomains wala) try karo taake
apni NVD key/rate-limit behavior dekh sako.

---

## Coming Next

- **Module 4**: Professional PDF report generator (executive summary + technical findings)
- **Module 5**: Multi-tenant SaaS dashboard + billing
