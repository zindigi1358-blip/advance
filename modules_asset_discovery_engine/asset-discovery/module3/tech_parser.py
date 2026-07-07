"""
Module 3 — Technology String Parser
======================================
Module 1 detects technologies as free-text strings like "Nginx 1.18.0" or
"Apache/2.4.41". This module turns those into clean (product, version)
pairs so we can query the CVE databases correctly.
"""
import re

# Known product name normalizations — CVE databases use specific vendor/
# product naming that doesn't always match what a banner says.
PRODUCT_ALIASES = {
    "nginx":        "nginx",
    "apache":       "apache http server",
    "iis":          "microsoft iis",
    "microsoft-iis": "microsoft iis",
    "openssh":      "openssh",
    "wordpress":    "wordpress",
    "drupal":       "drupal",
    "joomla":       "joomla",
    "php":          "php",
    "mysql":        "mysql",
    "postgresql":   "postgresql",
    "redis":        "redis",
    "mongodb":      "mongodb",
    "elasticsearch": "elasticsearch",
    "jenkins":      "jenkins",
    "grafana":      "grafana",
    "kibana":       "kibana",
    "jupyter":      "jupyter notebook",
    "docker":       "docker",
    "weblogic":     "oracle weblogic server",
    "jboss":        "jboss",
    "tomcat":       "apache tomcat",
    "laravel":      "laravel",
    "django":       "django",
    "rails":        "ruby on rails",
    "express":      "express.js",
    "vue.js":       "vue.js",
    "react":        "react",
    "angular":      "angular",
    "openresty":    "openresty",
    "wildfly":      "wildfly",
    "phpmyadmin":   "phpmyadmin",
}

# Strings that are NOT real software (skip these — Module 1 sometimes
# includes advisory notes like "⚠ Missing HSTS" in the technologies list)
NON_PRODUCT_PATTERNS = [
    r"missing", r"^⚠", r"header", r"cookie", r"unknown",
]

_VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){1,3})")


def is_real_product(tech_string: str) -> bool:
    """Filters out advisory strings that aren't actual software names."""
    low = tech_string.lower()
    return not any(re.search(pat, low) for pat in NON_PRODUCT_PATTERNS)


def parse_technology(tech_string: str) -> dict | None:
    """
    Parses a technology string into a normalized product+version.
    Examples:
        "Nginx 1.18.0"        -> {"product": "nginx", "version": "1.18.0"}
        "Apache/2.4.41"       -> {"product": "apache http server", "version": "2.4.41"}
        "WordPress"           -> {"product": "wordpress", "version": None}
        "⚠ Missing HSTS"      -> None (not a real product)
    """
    if not tech_string or not is_real_product(tech_string):
        return None

    cleaned = tech_string.strip().replace("/", " ")
    version_match = _VERSION_RE.search(cleaned)
    version = version_match.group(1) if version_match else None

    # Product name = everything before the version number
    if version_match:
        name_part = cleaned[:version_match.start()].strip()
    else:
        name_part = cleaned.strip()

    name_part = name_part.lower().strip()
    # Normalize using alias table (partial match — "microsoft iis" contains "iis")
    product = None
    for alias_key, canonical in PRODUCT_ALIASES.items():
        if alias_key in name_part:
            product = canonical
            break

    if not product:
        product = name_part  # fall back to raw name, still useful for keyword search

    if not product:
        return None

    return {"product": product, "version": version, "raw": tech_string}


def parse_all(tech_list: list) -> list:
    """Parses a full technologies[] list from a Module 1 subdomain record."""
    parsed = []
    for t in tech_list or []:
        result = parse_technology(t)
        if result:
            parsed.append(result)
    return parsed
