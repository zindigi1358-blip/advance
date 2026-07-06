import asyncio
import aiohttp
import json
import os
import re
import argparse
import sys
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ANSI Color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Static Wordlist
STATIC_WORDLIST = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/docker-compose.yml",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/.ssh/id_rsa",
    "/config/database.yml",
    "/.npmrc",
    "/.gitattributes",
    "/web.config",
    "/.env.local",
    "/.env.backup",
    "/credentials.json",
    "/.aws/credentials"
]

# Validation Rules
VALIDATION_RULES = {
    r"\.env$": [r"DB_PASSWORD", r"APP_KEY", r"AWS_ACCESS_KEY", r"SECRET_KEY", r"DATABASE_URL"],
    r"\.git/config$": [r"\[core\]", r"repositoryformatversion", r"remote \"origin\""],
    r"\.git/HEAD$": [r"ref: refs/heads/"],
    r"\.svn/entries$": [r"dir", r"svn:"],
    r"docker-compose\.yml$": [r"version:", r"services:", r"environment:"],
    r"\.bak$": [r"<?php", r"SELECT", r"INSERT", r"define\("],
    r"id_rsa$": [r"-----BEGIN RSA PRIVATE KEY-----"],
    r"credentials\.json$": [r"\"type\"", r"\"project_id\""],
    r"web\.config$": [r"<configuration>", r"<connectionStrings>"]
}

# Constants
MAX_CONTENT_SIZE = 5 * 1024 * 1024  # 5MB
REQUEST_TIMEOUT = 15
RETRY_ATTEMPTS = 2
RETRY_DELAY = 1

def load_targets_from_json(json_path: str) -> List[str]:
    """Load targets from JSON report"""
    if not os.path.exists(json_path):
        logger.error(f"File not found: {json_path}")
        print(f"{Colors.RED}[-]{Colors.ENDC} File {json_path} not found!")
        return []
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        subdomains = []
        targets_list = data if isinstance(data, list) else data.get("subdomains", [])
        
        if not isinstance(targets_list, list):
            logger.warning("Targets list is not iterable")
            return []
        
        for target in targets_list:
            try:
                if isinstance(target, dict):
                    if target.get("is_alive") is True or target.get("status_code") == 200:
                        url = target.get("url", "").strip()
                        if url:
                            subdomains.append(url.rstrip("/"))
                elif isinstance(target, str):
                    target = target.strip()
                    if target:
                        subdomains.append(target.rstrip("/"))
            except (AttributeError, TypeError) as e:
                logger.warning(f"Error processing target: {e}")
                continue
        
        return list(set(subdomains))  # Remove duplicates
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        print(f"{Colors.RED}[-]{Colors.ENDC} JSON parsing error: {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading targets: {e}")
        return []

def generate_dynamic_paths(domain_name: str) -> List[str]:
    """Generate dynamic paths based on domain name"""
    try:
        # Sanitize domain name
        domain_name = domain_name.lower().strip()
        if not domain_name or len(domain_name) > 255:
            return []
        
        # Extract base name (e.g., 'orgspace' from 'orgspace.xyz')
        base_name = domain_name.split('.')[0]
        if not base_name or len(base_name) < 2:
            return []
        
        # Safe base name (alphanumeric and hyphens only)
        base_name = re.sub(r'[^a-z0-9\-]', '', base_name)
        
        dynamic_extensions = [".zip", ".tar.gz", ".sql", ".bak", ".rar"]
        dynamic_paths = []
        
        for ext in dynamic_extensions:
            dynamic_paths.append(f"/{base_name}{ext}")
            dynamic_paths.append(f"/{domain_name}{ext}")
            dynamic_paths.append(f"/backup{ext}")
            dynamic_paths.append(f"/db{ext}")
            dynamic_paths.append(f"/{base_name}_backup{ext}")
        
        return dynamic_paths
    except Exception as e:
        logger.warning(f"Error generating paths for {domain_name}: {e}")
        return []

def verify_content(path: str, text: str, headers: Dict) -> bool:
    """Verify content to avoid false positives"""
    try:
        # Binary file detection
        if any(ext in path for ext in [".zip", ".tar.gz", ".rar", ".sql"]):
            content_type = headers.get("Content-Type", "").lower()
            content_length = int(headers.get("Content-Length", 0))
            
            if "html" in content_type or content_length < 200:
                return False
            return True

        # Text file validation
        for pattern, signatures in VALIDATION_RULES.items():
            if re.search(pattern, path, re.IGNORECASE):
                for sig in signatures:
                    if re.search(sig, text, re.IGNORECASE):
                        return True
                return False
        
        # Check for 404 in HTML responses
        if "html" in headers.get("Content-Type", "").lower():
            if re.search(r"404|not found|does not exist", text, re.IGNORECASE):
                return False
        
        return True
    except Exception as e:
        logger.warning(f"Error verifying content for {path}: {e}")
        return False

async def send_webhook_alert(leak_url: str, leak_type: str) -> None:
    """Send webhook alert (placeholder)"""
    try:
        logger.info(f"ALERT: {leak_type} found at {leak_url}")
        # Integration point for webhook/notification system
    except Exception as e:
        logger.error(f"Error sending alert: {e}")

async def scan_path(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    path: str,
    retry_count: int = 0
) -> Optional[Dict[str, Any]]:
    """Async worker for scanning single path with retry logic"""
    
    url = f"{base_url}{path}"
    
    async with semaphore:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0"
            }
            
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=True,
                allow_redirects=False
            ) as response:
                if response.status == 200:
                    try:
                        # Read content with size limit
                        content = await response.content.read(MAX_CONTENT_SIZE)
                        
                        # Try to decode as text
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except Exception:
                            text = content.decode('latin-1', errors='ignore')
                        
                        headers_dict = dict(response.headers)
                        
                        # Verify content
                        if verify_content(path, text, headers_dict):
                            print(f"{Colors.RED}{Colors.BOLD}[CRITICAL LEAK FOUND]{Colors.ENDC} {url}")
                            await send_webhook_alert(url, path)
                            logger.critical(f"Leak found: {url}")
                            return {
                                "url": url,
                                "path": path,
                                "status": 200,
                                "verified": True,
                                "size": len(content),
                                "content_type": headers_dict.get("Content-Type")
                            }
                    except Exception as e:
                        logger.debug(f"Error reading response from {url}: {e}")
        
        except asyncio.TimeoutError:
            if retry_count < RETRY_ATTEMPTS:
                await asyncio.sleep(RETRY_DELAY)
                return await scan_path(session, semaphore, base_url, path, retry_count + 1)
            logger.debug(f"Timeout (retried) for {url}")
        
        except aiohttp.ClientSSLError:
            logger.debug(f"SSL error for {url}")
        
        except aiohttp.ClientConnectorError:
            if retry_count < RETRY_ATTEMPTS:
                await asyncio.sleep(RETRY_DELAY)
                return await scan_path(session, semaphore, base_url, path, retry_count + 1)
            logger.debug(f"Connection error for {url}")
        
        except aiohttp.ClientResponseError as e:
            logger.debug(f"HTTP error {e.status} for {url}")
        
        except aiohttp.ClientError as e:
            logger.warning(f"Client error for {url}: {type(e).__name__}")
        
        except Exception as e:
            logger.warning(f"Unexpected error scanning {url}: {e}")
    
    return None

def validate_url(url: str) -> Optional[str]:
    """Validate and normalize URL"""
    try:
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        
        if not parsed.netloc:
            logger.warning(f"Invalid URL: {url}")
            return None
        
        # Reconstruct URL with scheme and netloc
        return f"{parsed.scheme}://{parsed.netloc}"
    
    except Exception as e:
        logger.warning(f"Error validating URL {url}: {e}")
        return None

async def main_async(
    targets: List[str],
    concurrency: int,
    output_dir: str
) -> None:
    """Main async orchestrator"""
    
    semaphore = asyncio.Semaphore(concurrency)
    
    # Connection pooling
    conn = aiohttp.TCPConnector(
        limit=concurrency,
        ttl_dns_cache=300,
        ssl_context=True
    )
    
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        all_leaks = []
        
        for idx, target in enumerate(targets, 1):
            try:
                # Validate and normalize URL
                base_url = validate_url(target)
                if not base_url:
                    logger.warning(f"Skipping invalid target: {target}")
                    continue
                
                # Extract domain for dynamic paths
                parsed = urlparse(base_url)
                domain_name = parsed.netloc
                
                if not domain_name:
                    logger.warning(f"Could not extract domain from {base_url}")
                    continue
                
                # Generate wordlist
                dynamic_paths = generate_dynamic_paths(domain_name)
                full_wordlist = list(set(STATIC_WORDLIST + dynamic_paths))
                
                print(f"\n{Colors.BLUE}[*]{Colors.ENDC} [{idx}/{len(targets)}] Scanning {Colors.BOLD}{base_url}{Colors.ENDC} ({len(full_wordlist)} paths)")
                logger.info(f"Starting scan of {base_url}")
                
                # Create tasks
                tasks = [
                    scan_path(session, semaphore, base_url, path)
                    for path in full_wordlist
                ]
                
                # Run concurrently with progress
                results = await asyncio.gather(*tasks, return_exceptions=False)
                
                # Filter results
                valid_results = [r for r in results if r is not None]
                if valid_results:
                    all_leaks.extend(valid_results)
                    print(f"{Colors.GREEN}[+]{Colors.ENDC} Found {len(valid_results)} leak(s)")
                    logger.info(f"Found {len(valid_results)} leaks in {base_url}")
                else:
                    print(f"{Colors.YELLOW}[!]{Colors.ENDC} No leaks found")
            
            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
                continue
        
        # Save results
        if all_leaks:
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(output_dir, f"leaks_summary_{timestamp}.json")
            
            try:
                with open(report_file, 'w', encoding='utf-8') as rf:
                    json.dump(all_leaks, rf, indent=4, ensure_ascii=False)
                
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} Report saved: {Colors.BOLD}{report_file}{Colors.ENDC}")
                logger.info(f"Report saved to {report_file}")
                
                # Print summary
                print(f"{Colors.GREEN}[+]{Colors.ENDC} Total leaks found: {len(all_leaks)}")
            
            except Exception as e:
                logger.error(f"Error saving report: {e}")
                print(f"{Colors.RED}[-]{Colors.ENDC} Error saving report: {e}")
        else:
            print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} No confirmed leaks found.")
            logger.info("Scan completed with no leaks found")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Module 2.5: Advanced Async Leak & Source Code Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -i targets.json
  python3 scanner.py -i targets.json -c 50 -o ./reports
  python3 scanner.py -i targets.json -c 10 -o ./custom_output
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to JSON file with targets"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=25,
        help="Concurrent requests limit (default: 25, max: 100)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="module2_5_reports",
        help="Output directory for reports (default: module2_5_reports)"
    )
    
    args = parser.parse_args()
    
    # Validate concurrency
    if args.concurrency < 1 or args.concurrency > 100:
        print(f"{Colors.RED}[-]{Colors.ENDC} Concurrency must be between 1 and 100")
        sys.exit(1)
    
    print(f"{Colors.GREEN}{Colors.BOLD}=== Module 2.5: Advanced Leak Scanner ==={Colors.ENDC}\n")
    logger.info("Starting Module 2.5 Leak Scanner")
    
    # Load targets
    live_targets = load_targets_from_json(args.input)
    
    if not live_targets:
        print(f"{Colors.YELLOW}[!]{Colors.ENDC} No targets loaded. Exiting.")
        logger.warning("No targets loaded")
        sys.exit(0)
    
    print(f"{Colors.GREEN}[+]{Colors.ENDC} Total targets: {len(live_targets)}\n")
    logger.info(f"Loaded {len(live_targets)} targets")
    
    # Run scanner
    try:
        asyncio.run(main_async(live_targets, args.concurrency, args.output_dir))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} Scan interrupted by user")
        logger.info("Scan interrupted")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        print(f"{Colors.RED}[-]{Colors.ENDC} Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()