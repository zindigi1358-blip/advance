"""
Module 2.5 — Async Fuzzer Core
=================================
The actual aiohttp-based scanning engine. Kept separate from the CLI
(run_module2_5.py) so it can also be imported/used programmatically.
"""
import asyncio
import re
import time

import aiohttp

from config import (
    CONCURRENCY, REQUEST_TIMEOUT, CONNECT_TIMEOUT, MAX_BODY_READ,
    USER_AGENT, STATIC_WORDLIST, DYNAMIC_TEMPLATES,
)
import validator


# ── Wordlist assembly ─────────────────────────────────────────────────────

def build_wordlist(domain: str) -> list:
    """
    Combines the static high-value wordlist with dynamically-generated
    filenames based on the target's own domain name.
    e.g. "orgspace.xyz" -> base "orgspace" -> orgspace.zip, orgspace.sql, ...
    """
    wordlist = list(STATIC_WORDLIST)

    # Extract a clean base name from the domain (strip TLD + common subdomains)
    parts = domain.split(".")
    base = parts[0] if parts else domain
    base = re.sub(r"[^a-zA-Z0-9_-]", "", base)

    if base:
        for template in DYNAMIC_TEMPLATES:
            wordlist.append(template.format(base=base))

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for w in wordlist:
        if w not in seen:
            seen.add(w)
            deduped.append(w)

    return deduped


# ── Single-request probe ──────────────────────────────────────────────────

async def probe_path(session: aiohttp.ClientSession, base_url: str, path: str,
                     semaphore: asyncio.Semaphore) -> dict | None:
    """
    Probes a single URL (base_url + path). Returns a finding dict if a
    validated leak is found, None otherwise. Never raises — all exceptions
    are caught so one bad request can't kill the whole scan.
    """
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT)
            async with session.get(url, timeout=timeout, allow_redirects=False,
                                   ssl=False) as resp:

                content_type   = resp.headers.get("Content-Type", "")
                content_length = int(resp.headers.get("Content-Length", 0) or 0)

                # Read at most MAX_BODY_READ bytes — critical for large
                # archive files, we never want to pull a 5GB backup into RAM
                body_bytes = b""
                try:
                    async for chunk in resp.content.iter_chunked(4096):
                        body_bytes += chunk
                        if len(body_bytes) >= MAX_BODY_READ:
                            break
                except Exception:
                    pass  # partial read is fine, we validate on what we got

                result = None

                if validator.is_archive_path(path):
                    result = validator.validate_binary_signature(
                        path, resp.status, content_type, body_bytes[:32]
                    )
                else:
                    body_text = body_bytes.decode("utf-8", errors="ignore")
                    result = validator.validate_text_content(path, resp.status, body_text)

                    if result is None:
                        # No specific rule matched — try the conservative
                        # generic fallback (still requires non-trivial size
                        # and rejects soft-404 HTML pages)
                        result = validator.validate_generic_fallback(
                            path, resp.status, body_text,
                            content_length or len(body_bytes)
                        )

                if result:
                    return {
                        "url":          url,
                        "path":         path,
                        "type":         result["category"],
                        "risk":         result["risk"],
                        "evidence":     result["evidence"],
                        "status_code":  resp.status,
                        "content_type": content_type,
                        "found_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }

        except (asyncio.TimeoutError, aiohttp.ClientConnectorError,
                aiohttp.ClientSSLError, aiohttp.ClientOSError):
            return None  # target unreachable/timed out on this path — normal, skip
        except Exception:
            return None  # never let one bad probe crash the whole scan

    return None


# ── Per-host scan ──────────────────────────────────────────────────────────

async def scan_host(base_url: str, wordlist: list, progress_callback=None) -> list:
    """Scans one host against the full wordlist. Returns list of findings."""
    findings  = []
    semaphore = asyncio.Semaphore(CONCURRENCY)
    headers   = {"User-Agent": USER_AGENT}

    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        tasks = [probe_path(session, base_url, path, semaphore) for path in wordlist]

        done = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            result = await coro
            done += 1
            if progress_callback:
                progress_callback(done, total)
            if result:
                findings.append(result)

    return findings


# ── Multi-host orchestration ───────────────────────────────────────────────

async def scan_all_hosts(hosts: list, domain: str, progress_callback=None) -> dict:
    """
    `hosts` = list of alive subdomain strings (e.g. ["api.example.com", "www.example.com"])
    Returns { host: [finding, ...] } — only hosts with findings are included.
    """
    wordlist = build_wordlist(domain)
    all_findings = {}

    for host in hosts:
        base_url = host if host.startswith("http") else f"https://{host}"
        findings = await scan_host(base_url, wordlist, progress_callback)
        if findings:
            all_findings[host] = findings

    return all_findings
