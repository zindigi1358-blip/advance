# Asset Discovery Engine — Module 1

> ⚠️ **AUTHORIZED USE ONLY** — Sirf un domains pe use karein jinka aapke paas explicit written permission ho.

---

## Architecture Overview

```
AssetDiscoveryEngine
├── SubdomainDiscovery         ← 4 parallel sources
│   ├── Certificate Transparency (crt.sh)
│   ├── Passive DNS (HackerTarget)
│   ├── AlienVault OTX + URLScan.io + RapidDNS
│   └── DNS Bruteforce (wordlist)
│
├── SubdomainProber            ← Per-subdomain analysis
│   ├── DNS Resolution (A, CNAME)
│   ├── HTTP/HTTPS Probing
│   ├── Technology Fingerprinting (Wappalyzer-style)
│   └── SSL Certificate Extraction
│
├── PortScanner                ← 35+ common ports
│   └── Async TCP connect scan
│
├── CloudAssetDiscovery        ← 3 providers
│   ├── AWS S3 Buckets
│   ├── Azure Blob Storage
│   └── GCP Cloud Storage
│
└── GitHubLeakScanner          ← 14 credential patterns
    ├── Code search queries
    └── Content pattern matching (redacted)
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan (your own domain):
```bash
cd module1
python run.py --domain yourdomain.com --confirm
```

### Full scan with GitHub token:
```bash
export GITHUB_TOKEN=ghp_yourtoken
python run.py --domain yourdomain.com --confirm
```

### Skip specific modules:
```bash
python run.py --domain yourdomain.com --no-ports --no-github --confirm
```

### Programmatic usage:
```python
import asyncio
from module1.discovery_engine import AssetDiscoveryEngine

async def scan():
    engine = AssetDiscoveryEngine(
        domain="yourdomain.com",
        github_token="ghp_xxx",   # optional
        scan_ports=True,
        scan_cloud=True,
        scan_github=True,
    )
    report = await engine.run()
    
    # Access results
    print(f"Found {report.total_subdomains} subdomains")
    print(f"Alive: {report.alive_subdomains}")
    
    for sub in report.subdomains:
        if sub.is_alive:
            print(f"{sub.subdomain}: {sub.technologies}")
    
    return report

asyncio.run(scan())
```

---

## Output Format

JSON report saved to `reports/<domain>_<timestamp>.json`:

```json
{
  "domain": "example.com",
  "scan_started": "2025-01-15T10:00:00",
  "scan_completed": "2025-01-15T10:08:32",
  "scan_duration_seconds": 512.4,
  "total_subdomains": 47,
  "alive_subdomains": 23,
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ip_addresses": ["1.2.3.4"],
      "is_alive": true,
      "https_status": 200,
      "title": "API Gateway",
      "server": "nginx/1.18.0",
      "technologies": ["Nginx 1.18.0", "Node.js", "⚠ Missing HSTS"],
      "open_ports": [22, 80, 443, 8080],
      "certificate_info": {
        "issuer": {"O": "Let's Encrypt"},
        "not_after": "Apr 15 2025"
      }
    }
  ],
  "cloud_assets": [
    {
      "asset_type": "s3_bucket",
      "provider": "AWS",
      "url": "https://example-backup.s3.amazonaws.com",
      "is_public": true,
      "risk_level": "critical"
    }
  ],
  "leaked_credentials": [
    {
      "source": "github",
      "credential_type": "AWS Access Key",
      "repo_url": "https://github.com/...",
      "snippet": "...AKIA****REDACTED****..."
    }
  ]
}
```

---

## Technology Fingerprinting

Detected technologies include:

| Category | Examples |
|---|---|
| Web Servers | Apache, Nginx, IIS (with version) |
| Frameworks | Laravel, Django, Flask, Rails |
| CMS | WordPress, Drupal, Joomla, Shopify |
| Frontend | React, Angular, Vue.js, Bootstrap |
| Runtime | PHP, ASP.NET, Node.js |
| Security Headers | Missing HSTS, Missing CSP, Missing X-Frame-Options |
| Cloud | AWS S3, Cloudflare |
| Analytics | Google Analytics, Stripe |

---

## Port Coverage

35+ ports scanned:

```
FTP(21)  SSH(22)  SMTP(25)  HTTP(80)  HTTPS(443)
MySQL(3306)  PostgreSQL(5432)  MongoDB(27017)
Redis(6379)  Elasticsearch(9200)  RDP(3389)
Docker(2375)  Kubernetes(6443)  Jenkins(8080)
Jupyter(8888)  Grafana(3000)  Kibana(5601)
```

---

## Rate Limits & Ethics

- GitHub API: 30 req/min unauthenticated, 5000/hr authenticated
- DNS bruteforce: async with concurrency limits
- HTTP probing: max 40 concurrent connections
- Cloud checks: 30 concurrent, exponential backoff
- All credentials in reports are **redacted**

---

## Coming Next

- **Module 2**: Continuous monitoring + change detection + weekly digests
- **Module 3**: Risk scoring engine + CVE matching
- **Module 4**: Professional PDF report generator
- **Module 5**: Multi-tenant SaaS dashboard + billing
