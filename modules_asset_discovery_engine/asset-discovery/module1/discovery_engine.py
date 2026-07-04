"""
Module 1: Asset Discovery Engine
Authorized use only — always obtain written permission before scanning.
"""

import asyncio
import aiohttp
import aiofiles
import dns.resolver
import dns.asyncresolver
import socket
import ssl
import json
import re
import hashlib
import time
import logging
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse
import concurrent.futures
import ipaddress
import base64

_LOG_DIR = Path.home() / "asset-discovery-logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("discovery_engine")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    _sh = logging.StreamHandler()
    _sh.setFormatter(_fmt)
    _fh = logging.FileHandler(_LOG_DIR / "discovery.log")
    _fh.setFormatter(_fmt)
    logger.addHandler(_sh)
    logger.addHandler(_fh)


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    cname: Optional[str] = None
    source: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    certificate_info: Optional[dict] = None


@dataclass
class CloudAsset:
    asset_type: str          # s3, azure_blob, gcp_storage
    url: str
    is_public: bool = False
    bucket_name: str = ""
    provider: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    risk_level: str = "unknown"


@dataclass
class LeakedCredential:
    source: str              # github, gitlab
    repo_url: str
    file_path: str
    credential_type: str     # api_key, password, token, etc.
    pattern_matched: str
    snippet: str             # redacted
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class DiscoveryReport:
    domain: str
    scan_started: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_completed: Optional[str] = None
    subdomains: list[SubdomainResult] = field(default_factory=list)
    cloud_assets: list[CloudAsset] = field(default_factory=list)
    leaked_credentials: list[LeakedCredential] = field(default_factory=list)
    total_subdomains: int = 0
    alive_subdomains: int = 0
    scan_duration_seconds: float = 0.0


# ─────────────────────────────────────────────
# 1. Subdomain Discovery
# ─────────────────────────────────────────────

class SubdomainDiscovery:
    """Multi-source subdomain enumeration."""

    WORDLIST = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
        "admin", "ftp", "cdn", "app", "mobile", "m", "shop", "store",
        "forum", "help", "support", "kb", "status", "monitor", "dashboard",
        "static", "assets", "media", "images", "img", "files", "backup",
        "db", "database", "prod", "production", "qa", "uat", "demo",
        "beta", "alpha", "old", "new", "v2", "v1", "legacy", "archive",
        "internal", "corp", "intranet", "extranet", "partner", "affiliates",
        "auth", "login", "sso", "oauth", "accounts", "user", "users",
        "pay", "payment", "payments", "billing", "invoice", "checkout",
        "api2", "api-v2", "gateway", "proxy", "lb", "load-balancer",
        "jenkins", "ci", "cd", "build", "deploy", "git", "repo",
        "grafana", "kibana", "elastic", "logs", "metrics", "trace",
        "redis", "mysql", "postgres", "mongo", "elastic"
    ]

    def __init__(self, domain: str, timeout: int = 10,
                 otx_api_key: str = "", urlscan_api_key: str = ""):
        self.domain          = domain
        self.timeout         = timeout
        self.found: set[str] = set()
        # Optional API keys — tool works without them but keys give much
        # higher rate limits (OTX: 10k/hr, URLScan: 1000/hr vs 60/hr free)
        # Get free keys:
        #   AlienVault OTX  → https://otx.alienvault.com/api
        #   URLScan.io      → https://urlscan.io/user/profile/
        self.otx_api_key     = otx_api_key.strip()
        self.urlscan_api_key = urlscan_api_key.strip()

    async def from_certificate_transparency(self) -> list[str]:
        """Query crt.sh + certspotter for certificate transparency logs (with retry)."""
        results = []

        # ── crt.sh — 3 retries, 60s timeout (crt.sh is slow on big domains)
        url_crt = f"https://crt.sh/?q=%.{self.domain}&output=json"
        for attempt in range(3):
            try:
                logger.info(f"[CT Logs] crt.sh attempt {attempt+1}/3...")
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=60),
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(url_crt) as resp:
                        logger.info(f"[CT Logs] crt.sh HTTP {resp.status}")
                        if resp.status == 200:
                            import json as _json
                            text = await resp.text()
                            try:
                                data = _json.loads(text)
                            except Exception as je:
                                logger.warning(f"[CT Logs] crt.sh JSON parse error: {je}")
                                break
                            before = len(results)
                            for entry in data:
                                name = entry.get("name_value", "")
                                for sub in name.split("\n"):
                                    sub = sub.strip().lstrip("*.")
                                    if sub.endswith(f".{self.domain}") or sub == self.domain:
                                        results.append(sub)
                            logger.info(f"[CT Logs] crt.sh found {len(results)-before} entries")
                            break
                        elif resp.status == 429:
                            wait = 5 * (attempt + 1)
                            logger.warning(f"[CT Logs] crt.sh rate-limited — waiting {wait}s")
                            await asyncio.sleep(wait)
                        else:
                            logger.warning(f"[CT Logs] crt.sh status {resp.status}")
                            break
            except asyncio.TimeoutError:
                logger.warning(f"[CT Logs] crt.sh TIMEOUT on attempt {attempt+1}/3")
                await asyncio.sleep(3)
            except Exception as e:
                logger.warning(f"[CT Logs] crt.sh error: {e}")
                break

        # ── certspotter — backup CT source (faster, different dataset)
        try:
            url_cs = (
                f"https://api.certspotter.com/v1/issuances"
                f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
            )
            logger.info("[CT Logs] Querying certspotter...")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(url_cs) as resp:
                    logger.info(f"[CT Logs] certspotter HTTP {resp.status}")
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        before = len(results)
                        for entry in data:
                            for name in entry.get("dns_names", []):
                                name = name.strip().lstrip("*.")
                                if name.endswith(f".{self.domain}") or name == self.domain:
                                    results.append(name)
                        logger.info(f"[CT Logs] certspotter added {len(results)-before} entries")
        except Exception as e:
            logger.warning(f"[CT Logs] certspotter error: {e}")

        unique = list(set(results))
        logger.info(f"[CT Logs] Total unique: {len(unique)}")
        return unique

    async def from_passive_dns(self) -> list[str]:
        """Query passive DNS sources (HackerTarget)."""
        results = []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            if "," in line:
                                sub = line.split(",")[0].strip()
                                if sub.endswith(f".{self.domain}"):
                                    results.append(sub)
                        logger.info(f"[Passive DNS] Found {len(results)} entries")
        except Exception as e:
            logger.warning(f"[Passive DNS] Error: {e}")
        return list(set(results))

    async def from_threatintel(self) -> list[str]:
        """
        Passive DNS intel from 3 sources.
        ThreatCrowd permanently dead — replaced with AlienVault OTX +
        URLScan.io + RapidDNS.
        VirusTotal v2 with apikey=0 also removed (returned 204, never worked).

        API keys are OPTIONAL — tool works without them but keys give much
        higher rate limits so scans complete faster and miss fewer results.
        """
        results = []

        # ── Source 1: AlienVault OTX ─────────────────────────────────────────
        # No key  : works, 4 req/min limit
        # With key: 10,000 req/hour — free at otx.alienvault.com/api
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            headers = {"User-Agent": "Mozilla/5.0"}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key
                logger.info("[AlienVault OTX] Using API key — higher rate limit active")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                headers=headers
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        before = len(results)
                        for entry in data.get("passive_dns", []):
                            host = entry.get("hostname", "").strip()
                            if host.endswith(f".{self.domain}") or host == self.domain:
                                results.append(host)
                        logger.info(f"[AlienVault OTX] Found {len(results) - before} entries")
                    elif resp.status == 403:
                        logger.warning("[AlienVault OTX] 403 — API key invalid or missing")
        except Exception as e:
            logger.warning(f"[AlienVault OTX] Error: {e}")

        # ── Source 2: URLScan.io ─────────────────────────────────────────────
        # No key  : works, 60 req/hour (public scans only)
        # With key: 1,000 req/hour — free at urlscan.io/user/profile/
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain%3A{self.domain}&size=100"
            headers = {"User-Agent": "Mozilla/5.0"}
            if self.urlscan_api_key:
                headers["API-Key"] = self.urlscan_api_key
                logger.info("[URLScan.io] Using API key — higher rate limit active")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                headers=headers
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        before = len(results)
                        for result in data.get("results", []):
                            page_domain = result.get("page", {}).get("domain", "")
                            if page_domain.endswith(f".{self.domain}") or page_domain == self.domain:
                                results.append(page_domain)
                        logger.info(f"[URLScan.io] Found {len(results) - before} entries")
                    elif resp.status == 429:
                        logger.warning("[URLScan.io] Rate limited — provide API key to increase limit")
                    elif resp.status == 401:
                        logger.warning("[URLScan.io] 401 — API key invalid")
        except Exception as e:
            logger.warning(f"[URLScan.io] Error: {e}")

        # ── Source 3: RapidDNS (no key needed) ──────────────────────────────
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1#result"
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"User-Agent": "Mozilla/5.0"}
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text  = await resp.text()
                        found = re.findall(
                            r'<td>([a-zA-Z0-9._-]+\.' + re.escape(self.domain) + r')</td>',
                            text
                        )
                        results.extend(found)
                        logger.info(f"[RapidDNS] Found {len(found)} entries")
        except Exception as e:
            logger.warning(f"[RapidDNS] Error: {e}")

        return list(set(results))

    async def dns_bruteforce(self) -> list[str]:
        """
        DNS bruteforce using wordlist — concurrency-limited via semaphore.
        BUG FIX: Previous version fired all tasks simultaneously with no
        throttle, which overwhelmed DNS resolvers and caused false negatives
        (words that DID exist appeared as not found). Semaphore of 50 fixes this.
        """
        results  = []
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0
        semaphore = asyncio.Semaphore(50)

        async def resolve_one(word: str):
            async with semaphore:
                subdomain = f"{word}.{self.domain}"
                try:
                    await resolver.resolve(subdomain, "A")
                    return subdomain
                except Exception:
                    return None

        tasks    = [resolve_one(w) for w in self.WORDLIST]
        resolved = await asyncio.gather(*tasks, return_exceptions=True)

        for r in resolved:
            if r and isinstance(r, str):
                results.append(r)

        logger.info(f"[DNS Bruteforce] Found {len(results)} subdomains")
        return results

    async def discover_all(self) -> list[str]:
        """Run all discovery methods — CT logs first, then rest in parallel."""
        logger.info(f"Starting subdomain discovery for: {self.domain}")
        all_subs = set()

        # ── Phase A: CT Logs (run alone so timeout/error is clearly visible)
        logger.info("[Phase A] Certificate Transparency Logs...")
        try:
            ct_results = await self.from_certificate_transparency()
            all_subs.update(ct_results)
            logger.info(f"[Phase A] CT total: {len(ct_results)}")
        except Exception as e:
            logger.warning(f"[Phase A] CT logs failed: {e}")

        # ── Phase B: Passive DNS + Threat Intel + Bruteforce (parallel)
        logger.info("[Phase B] Passive DNS + Threat Intel + DNS Bruteforce...")
        results = await asyncio.gather(
            self.from_passive_dns(),
            self.from_threatintel(),
            self.dns_bruteforce(),
            return_exceptions=True
        )
        for i, batch in enumerate(results):
            if isinstance(batch, list):
                all_subs.update(batch)
            elif isinstance(batch, Exception):
                logger.warning(f"[Phase B] Source {i} error: {batch}")

        # Always include base domain
        all_subs.add(self.domain)
        all_subs.add(f"www.{self.domain}")

        logger.info(f"Total unique subdomains discovered: {len(all_subs)}")
        return list(all_subs)


# ─────────────────────────────────────────────
# 2. DNS Resolution & HTTP Probing
# ─────────────────────────────────────────────

class SubdomainProber:
    """Resolve DNS and probe HTTP/HTTPS for each subdomain."""

    def __init__(self, timeout: int = 8, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def resolve_dns(self, subdomain: str) -> SubdomainResult:
        result = SubdomainResult(subdomain=subdomain)
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0

        try:
            # A records
            a_records = await resolver.resolve(subdomain, "A")
            result.ip_addresses = [str(r) for r in a_records]
        except Exception:
            pass

        try:
            # CNAME records
            cname = await resolver.resolve(subdomain, "CNAME")
            result.cname = str(cname[0].target).rstrip(".")
        except Exception:
            pass

        return result

    async def probe_http(self, result: SubdomainResult) -> SubdomainResult:
        """Probe HTTP and HTTPS, grab headers and title."""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"User-Agent": "Mozilla/5.0 (Security Scanner — Authorized)"}
        ) as session:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{result.subdomain}"
                try:
                    async with session.get(url, allow_redirects=True, max_redirects=5) as resp:
                        status = resp.status
                        body = await resp.text(errors="replace")

                        if scheme == "https":
                            result.https_status = status
                        else:
                            result.http_status = status

                        if status < 500:
                            result.is_alive = True

                        # Extract page title
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                        if title_match and not result.title:
                            result.title = title_match.group(1).strip()[:120]

                        # Extract server header
                        result.server = resp.headers.get("Server", "") or resp.headers.get("X-Powered-By", "")

                        # Technology fingerprinting
                        result.technologies = self._fingerprint_tech(resp.headers, body)

                except Exception:
                    pass

        return result

    def _fingerprint_tech(self, headers: dict, body: str) -> list[str]:
        """Wappalyzer-style tech detection from headers + body."""
        techs = []

        # Server headers
        server = headers.get("Server", "").lower()
        if "apache" in server:
            version = re.search(r"apache/(\S+)", server)
            techs.append(f"Apache{' ' + version.group(1) if version else ''}")
        if "nginx" in server:
            version = re.search(r"nginx/(\S+)", server)
            techs.append(f"Nginx{' ' + version.group(1) if version else ''}")
        if "iis" in server:
            version = re.search(r"iis/(\S+)", server)
            techs.append(f"IIS{' ' + version.group(1) if version else ''}")
        if "cloudflare" in server:
            techs.append("Cloudflare")

        # X-Powered-By
        powered = headers.get("X-Powered-By", "").lower()
        if "php" in powered:
            version = re.search(r"php/([\d.]+)", powered)
            techs.append(f"PHP{' ' + version.group(1) if version else ''}")
        if "asp.net" in powered:
            techs.append("ASP.NET")
        if "express" in powered:
            techs.append("Express.js")

        # Security headers
        if not headers.get("X-Frame-Options"):
            techs.append("⚠ Missing X-Frame-Options")
        if not headers.get("Content-Security-Policy"):
            techs.append("⚠ Missing CSP")
        if not headers.get("Strict-Transport-Security"):
            techs.append("⚠ Missing HSTS")

        # Body-based fingerprinting
        patterns = {
            "WordPress": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
            "Joomla": [r"joomla", r"/components/com_"],
            "Drupal": [r"drupal", r"/sites/default/"],
            "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
            "React": [r"react\.production\.min\.js", r"__REACT_", r"data-reactroot"],
            "Angular": [r"ng-version=", r"angular\.min\.js"],
            "Vue.js": [r"vue\.min\.js", r"__vue__"],
            "jQuery": [r"jquery[\./](\d+)", r"jQuery v(\d+)"],
            "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.bundle"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "Flask": [r"werkzeug", r"flask"],
            "Shopify": [r"cdn\.shopify\.com", r"shopify\.com/s/"],
            "Cloudflare": [r"__cf_bm", r"cloudflare"],
            "AWS S3": [r"AmazonS3", r"s3\.amazonaws\.com"],
            "Google Analytics": [r"google-analytics\.com", r"gtag\("],
            "Stripe": [r"js\.stripe\.com", r"stripe-js"],
        }

        body_lower = body.lower()
        for tech, pats in patterns.items():
            for pat in pats:
                if re.search(pat, body, re.IGNORECASE):
                    if tech not in techs:
                        techs.append(tech)
                    break

        return techs

    async def get_certificate_info(self, subdomain: str) -> Optional[dict]:
        """Extract SSL certificate information."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = asyncio.open_connection(subdomain, 443, ssl=ctx)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

            cert = writer.get_extra_info("ssl_object").getpeercert()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if cert:
                not_after = cert.get("notAfter", "")
                san = []
                for t, v in cert.get("subjectAltName", []):
                    if t == "DNS":
                        san.append(v)
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": not_after,
                    "san": san[:20],  # limit SAN list
                }
        except Exception:
            pass
        return None

    async def probe_one(self, subdomain: str) -> SubdomainResult:
        async with self.semaphore:
            result = await self.resolve_dns(subdomain)
            if result.ip_addresses or result.cname:
                result = await self.probe_http(result)
                result.certificate_info = await self.get_certificate_info(subdomain)
            return result

    async def probe_all(self, subdomains: list[str]) -> list[SubdomainResult]:
        tasks = [self.probe_one(s) for s in subdomains]
        results = []
        total = len(tasks)
        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            result = await coro
            results.append(result)
            if i % 25 == 0 or i == total:
                alive = sum(1 for r in results if r.is_alive)
                logger.info(f"Probed {i}/{total} — {alive} alive")
        return results


# ─────────────────────────────────────────────
# 3. Port Scanner
# ─────────────────────────────────────────────

class PortScanner:
    """Fast async port scanner for common service ports."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        1521: "Oracle", 2375: "Docker", 2376: "Docker-TLS",
        3000: "Node/Grafana", 3306: "MySQL", 3389: "RDP",
        4000: "Dev", 4443: "HTTPS-Alt", 5000: "Flask/Dev",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        7000: "Cassandra", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
        8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8083: "HTTP-Alt",
        8089: "Splunk", 8443: "HTTPS-Alt", 8888: "Jupyter",
        9000: "PHP-FPM", 9090: "Prometheus", 9200: "Elasticsearch",
        9300: "Elasticsearch", 27017: "MongoDB", 27018: "MongoDB",
    }

    def __init__(self, timeout: float = 1.5, concurrency: int = 200):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, ip: str, port: int) -> Optional[int]:
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

    async def scan_host(self, result: SubdomainResult) -> SubdomainResult:
        if not result.ip_addresses:
            return result

        ip = result.ip_addresses[0]
        # Skip private IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                return result
        except Exception:
            return result

        tasks = [self.scan_port(ip, port) for port in self.COMMON_PORTS]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, res in zip(self.COMMON_PORTS.keys(), port_results):
            if res == port:
                open_ports.append(port)

        result.open_ports = open_ports
        if open_ports:
            logger.info(f"[Ports] {result.subdomain}: {open_ports}")
        return result

    async def scan_all(self, results: list[SubdomainResult]) -> list[SubdomainResult]:
        alive = [r for r in results if r.is_alive and r.ip_addresses]
        logger.info(f"[Port Scan] Scanning {len(alive)} alive hosts...")

        tasks = [self.scan_host(r) for r in alive]
        scanned = await asyncio.gather(*tasks, return_exceptions=True)

        result_map = {r.subdomain: r for r in results}
        for r in scanned:
            if isinstance(r, SubdomainResult):
                result_map[r.subdomain] = r

        return list(result_map.values())


# ─────────────────────────────────────────────
# 4. Cloud Asset Discovery
# ─────────────────────────────────────────────

class CloudAssetDiscovery:
    """Discover exposed cloud storage buckets."""

    # Common bucket name patterns for a domain
    BUCKET_SUFFIXES = [
        "", "-prod", "-staging", "-dev", "-test", "-backup",
        "-data", "-assets", "-static", "-media", "-files",
        "-uploads", "-images", "-logs", "-archive", "-public",
        "-private", "-internal", "-web", "-app", "-api",
        "-resources", "-content", "-docs", "-reports",
    ]

    def __init__(self, domain: str, timeout: int = 8):
        self.domain = domain
        self.timeout = timeout
        # Generate candidate bucket names from domain
        base = domain.replace(".", "-").replace("_", "-")
        self.bucket_names = list(set([
            f"{base}{suffix}" for suffix in self.BUCKET_SUFFIXES
        ] + [
            f"{domain.split('.')[0]}{suffix}" for suffix in self.BUCKET_SUFFIXES
        ]))

    async def check_s3_bucket(self, session: aiohttp.ClientSession, name: str) -> Optional[CloudAsset]:
        """Check if an S3 bucket is publicly accessible."""
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls:
            try:
                async with session.head(url, allow_redirects=True) as resp:
                    if resp.status in [200, 403]:  # 403 = exists but private, 200 = public
                        is_public = resp.status == 200
                        risk = "critical" if is_public else "low"
                        logger.info(f"[S3] Found bucket: {name} — {'PUBLIC' if is_public else 'private'}")
                        return CloudAsset(
                            asset_type="s3_bucket",
                            url=url,
                            is_public=is_public,
                            bucket_name=name,
                            provider="AWS",
                            risk_level=risk
                        )
            except Exception:
                pass
        return None

    async def check_azure_blob(self, session: aiohttp.ClientSession, name: str) -> Optional[CloudAsset]:
        """Check Azure Blob Storage containers.
        BUG FIX: was HEAD — HEAD has no response body, so the
        'StorageErrorResponse' check was always False (dead code).
        Now uses GET so Azure's XML error body is actually readable."""
        clean = name.replace("-", "")[:24]  # Azure: lowercase alnum, max 24 chars
        url   = f"https://{clean}.blob.core.windows.net"
        try:
            async with session.get(url) as resp:
                body = await resp.text()
                if resp.status in [200, 400, 403]:
                    is_public = resp.status in [200, 400]
                    return CloudAsset(
                        asset_type="azure_blob",
                        url=url,
                        is_public=is_public,
                        bucket_name=clean,
                        provider="Azure",
                        risk_level="critical" if is_public else "low"
                    )
                # 404 + StorageErrorResponse = account exists, container not found
                if resp.status == 404 and "StorageErrorResponse" in body:
                    return CloudAsset(
                        asset_type="azure_blob",
                        url=url,
                        is_public=False,
                        bucket_name=clean,
                        provider="Azure",
                        risk_level="low"
                    )
        except Exception:
            pass
        return None

    async def check_gcp_storage(self, session: aiohttp.ClientSession, name: str) -> Optional[CloudAsset]:
        """Check GCP Cloud Storage buckets."""
        urls = [
            f"https://storage.googleapis.com/{name}",
            f"https://{name}.storage.googleapis.com",
        ]
        for url in urls:
            try:
                async with session.head(url) as resp:
                    if resp.status in [200, 403]:
                        is_public = resp.status == 200
                        risk = "critical" if is_public else "low"
                        return CloudAsset(
                            asset_type="gcp_storage",
                            url=url,
                            is_public=is_public,
                            bucket_name=name,
                            provider="GCP",
                            risk_level=risk
                        )
            except Exception:
                pass
        return None

    async def discover(self) -> list[CloudAsset]:
        found = []
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        semaphore = asyncio.Semaphore(30)

        async def check_all(name: str):
            async with semaphore:
                for checker in [self.check_s3_bucket, self.check_azure_blob, self.check_gcp_storage]:
                    result = await checker(session, name)
                    if result:
                        found.append(result)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            tasks = [check_all(name) for name in self.bucket_names]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[Cloud] Found {len(found)} cloud assets")
        return found


# ─────────────────────────────────────────────
# 5. GitHub Credential Leak Scanner
# ─────────────────────────────────────────────

class GitHubLeakScanner:
    """Search GitHub for leaked credentials related to the domain."""

    # Credential patterns (redact before storing)
    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"['\"]?aws.?secret.?key['\"]?\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "GitHub Token": r"gh[ps]_[A-Za-z0-9]{36}",
        "Slack Token": r"xox[baprs]-[A-Za-z0-9-]+",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret Key": r"sk_live_[A-Za-z0-9]{24,}",
        "Stripe Publishable Key": r"pk_live_[A-Za-z0-9]{24,}",
        "Twilio": r"SK[0-9a-fA-F]{32}",
        "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Generic API Key": r"['\"]?(api[_-]?key|apikey)['\"]?\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "Generic Secret": r"['\"]?(secret|password|passwd|pwd)['\"]?\s*[=:]\s*['\"]([^\s'\"]{8,})['\"]",
        "Bearer Token": r"[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*)",
        "Database URL": r"(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+",
        "SendGrid Key": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    }

    def __init__(self, domain: str, github_token: Optional[str] = None):
        self.domain = domain
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Security-Scanner-Authorized",
        }
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

    def _redact(self, match: str) -> str:
        """Redact sensitive values, keep first/last 4 chars."""
        if len(match) <= 8:
            return "***REDACTED***"
        return match[:4] + "*" * (len(match) - 8) + match[-4:]

    def _scan_content(self, content: str, repo_url: str, file_path: str) -> list[LeakedCredential]:
        results = []
        for cred_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                snippet_start = max(0, match.start() - 40)
                snippet_end = min(len(content), match.end() + 40)
                raw_snippet = content[snippet_start:snippet_end]
                # Redact the actual match
                redacted = re.sub(pattern, lambda m: self._redact(m.group()), raw_snippet, flags=re.IGNORECASE)
                results.append(LeakedCredential(
                    source="github",
                    repo_url=repo_url,
                    file_path=file_path,
                    credential_type=cred_type,
                    pattern_matched=pattern[:50],
                    snippet=redacted[:300]
                ))
        return results

    async def search_github(self) -> list[LeakedCredential]:
        if not self.github_token:
            logger.warning("[GitHub] No token provided — skipping GitHub scan (rate limits apply)")
            return []

        results = []
        queries = [
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" secret',
            f'"{self.domain}" aws_secret',
            f'"{self.domain}" token',
        ]

        async with aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=20)
        ) as session:
            for query in queries:
                try:
                    url = f"{self.base_url}/search/code"
                    params = {"q": query, "per_page": 10, "sort": "indexed"}
                    async with session.get(url, params=params) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            items = data.get("items", [])
                            logger.info(f"[GitHub] Query '{query[:40]}' → {len(items)} results")

                            for item in items[:5]:  # Limit to avoid rate limits
                                file_url = item.get("url", "")
                                repo_url = item.get("repository", {}).get("html_url", "")
                                file_path = item.get("path", "")

                                # Fetch file content
                                try:
                                    async with session.get(file_url) as file_resp:
                                        if file_resp.status == 200:
                                            file_data   = await file_resp.json()
                                            content_b64 = file_data.get("content", "")
                                            content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                                            leaks = self._scan_content(content, repo_url, file_path)
                                            results.extend(leaks)
                                except Exception:
                                    pass

                        elif resp.status in (403, 429):
                            # BUG FIX: sleep(10) was never enough — GitHub's
                            # rate-limit window is 60s minimum. Now reads the
                            # Retry-After header GitHub sends (when present).
                            wait = int(resp.headers.get("Retry-After", 60))
                            logger.warning(f"[GitHub] Rate limit hit — pausing {wait}s")
                            await asyncio.sleep(wait)

                    await asyncio.sleep(2)  # Respect rate limits
                except Exception as e:
                    logger.warning(f"[GitHub] Error: {e}")

        logger.info(f"[GitHub] Found {len(results)} potential credential leaks")
        return results


# ─────────────────────────────────────────────
# 6. Main Discovery Engine
# ─────────────────────────────────────────────

class AssetDiscoveryEngine:
    """
    Main orchestrator for Module 1: Asset Discovery Engine.
    
    Usage:
        engine = AssetDiscoveryEngine("example.com", github_token="ghp_xxx")
        report = await engine.run()
    """

    def __init__(
        self,
        domain:          str,
        github_token:    Optional[str] = None,
        otx_api_key:     str = "",
        urlscan_api_key: str = "",
        scan_ports:      bool = True,
        scan_cloud:      bool = True,
        scan_github:     bool = True,
        output_dir:      str = "reports",
    ):
        # BUG FIX: lstrip("https://") strips individual characters from the
        # set {'h','t','p','s',':','/'} — NOT the string "https://".
        # e.g. "smtp.example.com" → lstrip strips 's' → "mtp.example.com".
        # urlparse solves this correctly.
        domain = domain.strip()
        if "://" in domain:
            _p     = urlparse(domain)
            domain = _p.netloc or _p.path
        self.domain          = domain.lower().split("/")[0].split("?")[0]
        self.github_token    = github_token
        self.otx_api_key     = otx_api_key.strip()
        self.urlscan_api_key = urlscan_api_key.strip()
        self.scan_ports      = scan_ports
        self.scan_cloud      = scan_cloud
        self.scan_github     = scan_github
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> DiscoveryReport:
        start_time = time.time()
        report = DiscoveryReport(domain=self.domain)

        logger.info("=" * 60)
        logger.info(f"Asset Discovery Engine — Target: {self.domain}")
        logger.info(f"Started: {report.scan_started}")
        logger.info("=" * 60)

        # Step 1: Subdomain Discovery
        logger.info("\n[Phase 1] Subdomain Enumeration...")
        discovery = SubdomainDiscovery(
            self.domain,
            otx_api_key     = self.otx_api_key,
            urlscan_api_key = self.urlscan_api_key,
        )
        subdomains = await discovery.discover_all()

        # Step 2: DNS Resolution + HTTP Probing + Tech Fingerprinting
        logger.info(f"\n[Phase 2] Probing {len(subdomains)} subdomains...")
        prober = SubdomainProber(concurrency=40)
        probed = await prober.probe_all(subdomains)

        # Step 3: Port Scanning (alive hosts only)
        if self.scan_ports:
            logger.info("\n[Phase 3] Port Scanning...")
            scanner = PortScanner(concurrency=100)
            probed = await scanner.scan_all(probed)

        report.subdomains = probed
        report.total_subdomains = len(probed)
        report.alive_subdomains = sum(1 for s in probed if s.is_alive)

        # Step 4: Cloud Asset Discovery
        if self.scan_cloud:
            logger.info("\n[Phase 4] Cloud Asset Discovery...")
            cloud = CloudAssetDiscovery(self.domain)
            report.cloud_assets = await cloud.discover()

        # Step 5: GitHub Leak Scanning
        if self.scan_github:
            logger.info("\n[Phase 5] GitHub Credential Scanning...")
            gh_scanner = GitHubLeakScanner(self.domain, self.github_token)
            report.leaked_credentials = await gh_scanner.search_github()

        # Finalize
        report.scan_completed = datetime.utcnow().isoformat()
        report.scan_duration_seconds = round(time.time() - start_time, 2)

        logger.info("\n" + "=" * 60)
        logger.info("SCAN COMPLETE")
        logger.info(f"  Duration:       {report.scan_duration_seconds}s")
        logger.info(f"  Subdomains:     {report.total_subdomains} discovered, {report.alive_subdomains} alive")
        logger.info(f"  Cloud Assets:   {len(report.cloud_assets)}")
        logger.info(f"  Leaked Creds:   {len(report.leaked_credentials)}")
        logger.info("=" * 60)

        # Save JSON report
        await self._save_report(report)
        return report

    async def _save_report(self, report: DiscoveryReport):
        filename = self.output_dir / f"{self.domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        def serialize(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        async with aiofiles.open(filename, "w") as f:
            await f.write(json.dumps(asdict(report), indent=2, default=str))
        logger.info(f"Report saved: {filename}")
        return filename
