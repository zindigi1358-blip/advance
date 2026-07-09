"""
Module 2.5 — Validator
=========================
Pure functions (no network) that decide whether a response is a REAL leak
or a false positive (custom 404 page returning HTTP 200, empty file, etc).
Kept separate from the async scanner so this logic can be unit-tested
without needing network access.
"""
import re

from config import VALIDATION_RULES, ARCHIVE_SIGNATURES, ARCHIVE_CONTENT_TYPES


def match_validation_rule(path: str) -> dict | None:
    """Finds the applicable validation rule for a given wordlist path."""
    path_lower = path.lower()
    for pattern, rule in VALIDATION_RULES.items():
        if pattern.lower() in path_lower:
            return rule
    return None


def validate_text_content(path: str, status_code: int, body_text: str) -> dict | None:
    """
    Validates a text-based response (env files, git configs, keys, etc.)
    against content-matching rules. Returns a finding dict if valid,
    None if it's a false positive.
    """
    if status_code != 200 or not body_text:
        return None

    rule = match_validation_rule(path)
    if not rule:
        return None  # no specific rule for this path — handled elsewhere (generic check)

    contains_any = rule.get("contains_any", [])
    if not contains_any:
        return None

    matched_strings = [s for s in contains_any if s in body_text]
    if not matched_strings:
        return None  # HTTP 200 but body doesn't contain expected markers — false positive

    return {
        "risk":     rule["risk"],
        "category": rule["category"],
        "evidence": f"Content contains: {', '.join(matched_strings[:3])}",
    }


def validate_binary_signature(path: str, status_code: int, content_type: str,
                              first_bytes: bytes) -> dict | None:
    """
    Validates archive/binary files using magic-byte signatures + Content-Type,
    NOT full-body download. `first_bytes` should be only the first ~32 bytes
    of the response body.
    """
    if status_code != 200:
        return None

    ct_lower = (content_type or "").lower()
    ct_is_archive = any(ct in ct_lower for ct in ARCHIVE_CONTENT_TYPES)

    detected_type = None
    for signature, file_type in ARCHIVE_SIGNATURES.items():
        if first_bytes.startswith(signature):
            detected_type = file_type
            break

    # Require EITHER a matching magic byte OR a matching content-type header —
    # a plain HTML 200 page will have neither, so this filters those out.
    if not detected_type and not ct_is_archive:
        return None

    return {
        "risk":     "high",
        "category": "backup_file_exposed",
        "evidence": f"Detected file type: {detected_type or 'unknown'}, "
                   f"Content-Type: {content_type or 'none'}",
    }


def is_archive_path(path: str) -> bool:
    """Quick check — does this wordlist entry look like a binary archive?"""
    return any(path.lower().endswith(ext) for ext in
              [".zip", ".tar.gz", ".tar", ".rar", ".7z", ".gz", ".sql.gz"])


def validate_generic_fallback(path: str, status_code: int, body_text: str,
                               content_length: int) -> dict | None:
    """
    For wordlist paths with no specific rule (e.g. random backup names),
    apply a conservative generic check: must be 200, must have non-trivial
    body size, and must NOT look like a generic HTML error/soft-404 page.
    """
    if status_code != 200:
        return None
    if content_length < 20:
        return None  # basically empty — likely a stub/placeholder response

    soft_404_markers = ["404", "not found", "page not found", "does not exist", "<html"]
    body_lower = (body_text or "").lower()[:500]
    looks_like_html_error = any(m in body_lower for m in soft_404_markers)

    if looks_like_html_error:
        return None

    return {
        "risk":     "medium",
        "category": "unverified_file_exposed",
        "evidence": f"HTTP 200, {content_length} bytes, no soft-404 markers detected "
                   f"(manual verification recommended)",
    }
