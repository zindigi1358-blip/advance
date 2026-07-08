"""
Module 2.5 — Async Directory Fuzzer & Leak Scanner
Configuration
======================================================
"""
import os

# ── Concurrency & timing ──────────────────────────────────────────────────
CONCURRENCY       = 25      # simultaneous requests — kept modest to avoid
                            # tripping WAFs (Cloudflare etc.) or crashing
                            # small/shared hosting targets
REQUEST_TIMEOUT   = 7       # seconds per request
CONNECT_TIMEOUT   = 5       # seconds to establish connection
MAX_BODY_READ     = 65536   # bytes — never read more than 64KB into memory,
                            # even for a 5GB backup.zip we only need the
                            # first few bytes (magic number) + headers

USER_AGENT = "Mozilla/5.0 (compatible; ASM-Module2.5-LeakScanner/1.0)"

OUTPUT_DIR = "module2_5_reports"

# ── Static high-value wordlist ────────────────────────────────────────────
# Curated, not thousands of junk words — every entry here is something
# that, if found, is an immediate real finding worth reporting.
STATIC_WORDLIST = [
    # Version control (near-guaranteed full source code reconstruction)
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".svn/wc.db", ".hg/store/00manifest.i",
    ".bzr/checkout/dirstate",

    # Environment / secrets files
    ".env", ".env.local", ".env.production", ".env.dev", ".env.backup",
    ".env.save", ".env~", "config.php.bak", "wp-config.php.bak",
    "wp-config.php~", "settings.py.bak", "credentials.json",
    "secrets.yml", "secrets.json", ".npmrc", ".pypirc",

    # SSH / keys
    ".ssh/id_rsa", ".ssh/id_rsa.pub", ".ssh/authorized_keys",
    "id_rsa", "server.key", "private.key", "privatekey.pem",

    # Docker / infra as code
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    ".dockercfg", ".docker/config.json", "kubeconfig",

    # Backups & archives (generic names)
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.tar",
    "site-backup.zip", "www-backup.zip", "db_backup.sql", "database.sql",
    "dump.sql", "db.sqlite3", "site.zip", "www.zip", "old.zip",
    "backup.7z", "backup.rar",

    # CI/CD & deployment configs
    ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml",
    "Jenkinsfile", "azure-pipelines.yml",

    # Common exposed admin/debug endpoints
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info", ".well-known/security.txt",

    # Editor / OS leftovers
    "index.php.bak", "index.php~", ".DS_Store", "Thumbs.db",
    "web.config.bak", ".htaccess.bak", ".htpasswd",

    # Package manager lockfiles that can leak internal package names
    "composer.json", "composer.lock", "package.json.bak",

    # Cloud provider credential files
    ".aws/credentials", ".aws/config", "gcloud/credentials.db",
    "azure/credentials",

    # Log files (can leak paths, stack traces, sometimes credentials)
    "error_log", "error.log", "debug.log", "laravel.log",
    "storage/logs/laravel.log", "npm-debug.log",
]

# ── Dynamic filename templates (filled in with the target's own name) ────
# e.g. domain "orgspace.xyz" -> base "orgspace" -> "orgspace.zip", etc.
DYNAMIC_TEMPLATES = [
    "{base}.zip", "{base}.tar.gz", "{base}.tar", "{base}.sql",
    "{base}.bak", "{base}.rar", "{base}.7z", "{base}_backup.zip",
    "{base}-backup.sql", "{base}.old", "{base}.sql.gz", "{base}.db",
    "{base}_old.zip", "{base}-prod.sql", "{base}-dev.sql",
]

# ── Content-signature validation rules ────────────────────────────────────
# Format: filename_pattern -> {contains: [...], content_type: [...], magic_bytes: [...]}
# A hit only counts as a REAL finding if these are satisfied — NOT just an
# HTTP 200 (custom 404 pages often return 200).
VALIDATION_RULES = {
    ".env": {
        "contains_any": ["DB_PASSWORD", "APP_KEY", "AWS_", "SECRET_KEY",
                         "DATABASE_URL", "API_KEY", "DB_HOST", "MAIL_PASSWORD"],
        "risk": "critical",
        "category": "env_file_exposed",
    },
    ".git/config": {
        "contains_any": ["[core]", "repositoryformatversion", "[remote"],
        "risk": "critical",
        "category": "git_exposed",
    },
    ".git/HEAD": {
        "contains_any": ["ref:", "refs/heads"],
        "risk": "critical",
        "category": "git_exposed",
    },
    ".svn/entries": {
        "contains_any": ["svn:", "dir\n"],
        "risk": "high",
        "category": "svn_exposed",
    },
    "docker-compose": {
        "contains_any": ["version:", "services:", "image:"],
        "risk": "high",
        "category": "docker_config_exposed",
    },
    "id_rsa": {
        "contains_any": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
                         "BEGIN PRIVATE KEY", "BEGIN DSA PRIVATE KEY"],
        "risk": "critical",
        "category": "private_key_exposed",
    },
    "credentials.json": {
        "contains_any": ["password", "secret", "api_key", "token"],
        "risk": "high",
        "category": "credentials_exposed",
    },
    "phpinfo": {
        "contains_any": ["PHP Version", "phpinfo()"],
        "risk": "medium",
        "category": "info_disclosure",
    },
    "wp-config": {
        "contains_any": ["DB_PASSWORD", "AUTH_KEY", "define( 'DB_"],
        "risk": "critical",
        "category": "credentials_exposed",
    },
}

# File-signature (magic bytes) checks for binary archives — verified by
# reading the response with a byte-range/stream, never the full file.
ARCHIVE_SIGNATURES = {
    b"PK\x03\x04": "zip",           # .zip, also .docx/.jar etc (harmless false-positive risk here is fine)
    b"\x1f\x8b": "gzip",            # .tar.gz
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"Rar!\x1a\x07": "rar",
    b"SQLite format 3": "sqlite",
}
ARCHIVE_CONTENT_TYPES = [
    "application/zip", "application/x-gzip", "application/gzip",
    "application/x-tar", "application/x-7z-compressed",
    "application/x-rar-compressed", "application/octet-stream",
    "application/x-sqlite3",
]
