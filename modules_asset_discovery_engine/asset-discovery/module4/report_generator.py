"""
Module 4 — Professional PDF Report Generator  (v2 — Premium Edition)
======================================================================
Consumes JSON outputs from Module 1, 2.5, and 3 to produce a premium-grade
penetration testing report with full visual dashboard, heatmaps, attack-surface
diagrams, PDF bookmarks, and a multi-platform webhook notification system.

NEW IN v2:
  • Premium cover page with gradient branding + optional logo
  • Executive Dashboard — KPI cards, donut chart, risk trend graph
  • Risk Heatmap — findings plotted on asset × severity matrix
  • Attack Surface Diagram — domain → subdomains → services → findings
  • Severity Badges — consistent modern colour palette + icons
  • Clickable TOC + PDF bookmarks
  • Upgraded header / footer with classification label + report version
  • Webhook system — Telegram / Discord / Slack / Teams / generic HTTP
    (5 pre-configured slots; add once, reuse everywhere)

Usage:
    python3 report_generator_v2.py \\
        --module1  reports/example.com_latest.json \\
        --module3  module3_reports/example.com_risk_report.json \\
        --leaks    module2_5_reports/example.com_leaks.json \\
        --client   "Acme Corp" \\
        --assessor "Your Firm Name" \\
        --logo     /path/to/logo.png   # optional \\
        --confirm
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import json
import os
import re
import sys
import time
import io
import math
import base64
import hmac
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, List, Dict, Any

# ─────────────────────────────────────────────────────────────────────────────
#  MATPLOTLIB
# ─────────────────────────────────────────────────────────────────────────────
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from matplotlib.patches import FancyBboxPatch

# ─────────────────────────────────────────────────────────────────────────────
#  REPORTLAB
# ─────────────────────────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, BaseDocTemplate, PageTemplate, Frame, NextPageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image, KeepTogether, Flowable
)
from reportlab.platypus import ListFlowable, ListItem
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.utils import ImageReader


# ══════════════════════════════════════════════════════════════════════════════
#  BRAND / THEME  (edit these to match your firm's identity)
# ══════════════════════════════════════════════════════════════════════════════

REPORT_VERSION = "v2.0"

# Primary palette
C_DARK        = colors.HexColor("#0D1117")   # near-black
C_DARK2       = colors.HexColor("#161B22")   # slightly lighter dark
C_ACCENT      = colors.HexColor("#E84C3D")   # red accent
C_ACCENT2     = colors.HexColor("#FF6B6B")   # lighter red
C_BLUE        = colors.HexColor("#1A6EBD")   # link blue
C_BLUE_LITE   = colors.HexColor("#EBF5FB")   # pale blue bg
C_GRAY_DARK   = colors.HexColor("#2D3748")
C_GRAY_MID    = colors.HexColor("#718096")
C_GRAY_LITE   = colors.HexColor("#EDF2F7")
C_GRAY_VLIT   = colors.HexColor("#F7FAFC")
C_WHITE       = colors.white

# Severity palette (modern, accessible)
C_CRITICAL    = colors.HexColor("#C0392B")
C_CRITICAL_BG = colors.HexColor("#FDEDEC")
C_HIGH        = colors.HexColor("#D35400")
C_HIGH_BG     = colors.HexColor("#FEF0E7")
C_MEDIUM      = colors.HexColor("#D4AC0D")
C_MEDIUM_BG   = colors.HexColor("#FEFDE7")
C_LOW         = colors.HexColor("#1E8449")
C_LOW_BG      = colors.HexColor("#EAFAF1")
C_INFO        = colors.HexColor("#5D6D7E")
C_INFO_BG     = colors.HexColor("#F2F3F4")

LEVEL_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}
LEVEL_BG = {
    "CRITICAL": C_CRITICAL_BG,
    "HIGH":     C_HIGH_BG,
    "MEDIUM":   C_MEDIUM_BG,
    "LOW":      C_LOW_BG,
    "INFO":     C_INFO_BG,
}

# Severity icons (text symbols — no unicode glyphs that break fonts)
LEVEL_ICON = {
    "CRITICAL": "[!!]",
    "HIGH":     "[!]",
    "MEDIUM":   "[~]",
    "LOW":      "[i]",
    "INFO":     "[-]",
}

PAGE_W, PAGE_H = A4
MARGIN  = 2.0 * cm
INNER_W = PAGE_W - 2 * MARGIN


# ══════════════════════════════════════════════════════════════════════════════
#  WEBHOOK SYSTEM
#  ─ Configure once here; called automatically after report generation.
#  ─ 5 pre-configured slots.  Set enabled=True and fill in url/token.
#  ─ Platforms: telegram | discord | slack | teams | generic_http
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  WEBHOOK SYSTEM  —  plug in ANY platform, configure once, reuse forever
#  ──────────────────────────────────────────────────────────────────────────
#  Two ways to notify a platform when a report is generated:
#
#  1) NAMED PRESETS — ready-made payload formatters for common tools.
#     Just set enabled=True and fill in the credentials.
#     Built in: telegram | discord | slack | teams | google_chat | mattermost
#
#  2) "generic_http" — works with LITERALLY ANY webhook-based platform
#     (PagerDuty, Opsgenie, Jira, ServiceNow, Zapier, Make/n8n, ntfy.sh,
#     a custom SIEM, an internal REST API, ...). Almost every platform's
#     webhook is just "HTTP POST/PUT a JSON body, optionally with an auth
#     header" — so ONE flexible sender covers all of them. You configure:
#       - url / method            (POST, PUT, PATCH ...)
#       - auth                    (none | bearer | basic | api_key_header |
#                                   api_key_query | hmac_sha256)
#       - headers                 any custom headers the platform needs
#       - payload_template        (optional) build the EXACT JSON shape the
#                                  target platform expects using {placeholders};
#                                  if omitted, a sensible default JSON is sent
#       - payload_format          "json" (default) or "form"
#       - timeout / retries       per-slot network tuning
#
#  Available {placeholders} for payload_template / Telegram text:
#     {title} {client} {domain} {risk} {report_path} {timestamp} {generator}
#     {critical} {high} {medium} {low} {info} {total}
#
#  WEBHOOKS is just a Python list — copy any block below to add more slots.
#  Nothing here ever blocks report generation: every send is wrapped in
#  try/except inside fire_webhooks().
# ══════════════════════════════════════════════════════════════════════════════

WEBHOOKS: List[Dict[str, Any]] = [
    # ── Slot 1 — Telegram Bot ─────────────────────────────────────────────
    {
        "enabled":   False,               # <- set True to activate
        "platform":  "telegram",
        "name":      "Telegram",
        "bot_token": "YOUR_BOT_TOKEN",    # from @BotFather
        "chat_id":   "YOUR_CHAT_ID",      # group/channel/user ID
    },

    # ── Slot 2 — Discord Webhook ──────────────────────────────────────────
    {
        "enabled":  False,
        "platform": "discord",
        "name":     "Discord",
        "url":      "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN",
    },

    # ── Slot 3 — Slack Incoming Webhook ────────────────────────────────────
    {
        "enabled":  False,
        "platform": "slack",
        "name":     "Slack",
        "url":      "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
    },

    # ── Slot 4 — Microsoft Teams (Incoming Webhook / Power Automate) ───────
    {
        "enabled":  False,
        "platform": "teams",
        "name":     "MS Teams",
        "url":      "https://YOUR_ORG.webhook.office.com/webhookb2/YOUR_TEAMS_WEBHOOK",
    },

    # ── Slot 5 — Google Chat ───────────────────────────────────────────────
    {
        "enabled":  False,
        "platform": "google_chat",
        "name":     "Google Chat",
        "url":      "https://chat.googleapis.com/v1/spaces/YOUR_SPACE/messages?key=...&token=...",
    },

    # ── Slot 6 — Mattermost Incoming Webhook ────────────────────────────────
    {
        "enabled":  False,
        "platform": "mattermost",
        "name":     "Mattermost",
        "url":      "https://your-mattermost.example.com/hooks/YOUR_HOOK_ID",
    },

    # ── Slot 7 — Generic HTTP — works with ANY platform ─────────────────────
    # Default example below sends a plain JSON POST with a bearer token.
    # See the alternate examples further down for PagerDuty / Zapier / HMAC.
    {
        "enabled":  False,
        "platform": "generic_http",
        "name":     "Custom / SIEM / Internal API",
        "url":      "https://your-siem.internal/api/pentest-alerts",
        "method":   "POST",                  # POST | PUT | PATCH
        "auth": {
            "type":  "bearer",                # none | bearer | basic |
                                               # api_key_header | api_key_query |
                                               # hmac_sha256
            "token": "YOUR_TOKEN",
        },
        "headers": {                          # any extra headers, merged in
            "Content-Type": "application/json",
        },
        "payload_template": None,             # None = send the default payload
        "payload_format":   "json",           # "json" or "form"
        "timeout": 10,
        "retries": 1,                         # extra attempts after the first
    },

    # ── EXAMPLE (disabled) — PagerDuty Events API v2 ────────────────────────
    # Shows how "generic_http" adapts to ANY app's exact expected JSON shape
    # via payload_template. Duplicate + edit this block for any other tool.
    {
        "enabled":  False,
        "platform": "generic_http",
        "name":     "PagerDuty (example)",
        "url":      "https://events.pagerduty.com/v2/enqueue",
        "method":   "POST",
        "auth":     {"type": "none"},
        "headers":  {"Content-Type": "application/json"},
        "payload_format": "json",
        "payload_template": {
            "routing_key":  "YOUR_PAGERDUTY_INTEGRATION_KEY",
            "event_action": "trigger",
            "payload": {
                "summary":  "{title} — {domain} ({risk})",
                "source":   "{domain}",
                "severity": "critical",
                "custom_details": {
                    "critical": "{critical}", "high": "{high}",
                    "medium": "{medium}", "report_path": "{report_path}",
                },
            },
        },
        "timeout": 10, "retries": 1,
    },
]


def _wh_send_telegram(cfg: dict, payload: dict) -> None:
    """Send Telegram message via Bot API."""
    text = (
        f"*{payload['title']}*\n\n"
        f"Client: `{payload['client']}`\n"
        f"Domain: `{payload['domain']}`\n"
        f"Risk:   *{payload['risk']}*\n\n"
        f"Critical: {payload['counts']['CRITICAL']}  |  "
        f"High: {payload['counts']['HIGH']}  |  "
        f"Medium: {payload['counts']['MEDIUM']}\n\n"
        f"Report: `{payload['report_path']}`\n"
        f"Generated: {payload['timestamp']}"
    )
    url  = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    data = json.dumps({
        "chat_id":    cfg["chat_id"],
        "text":       text,
        "parse_mode": "Markdown",
    }).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _wh_send_discord(cfg: dict, payload: dict) -> None:
    """Send Discord embed via Incoming Webhook."""
    risk_color = {
        "CRITICAL": 0xC0392B, "HIGH": 0xD35400,
        "MEDIUM": 0xD4AC0D,   "LOW": 0x1E8449,
    }.get(payload["risk"].split("-")[0], 0x5D6D7E)

    body = json.dumps({
        "username": "PentestBot",
        "embeds": [{
            "title":       payload["title"],
            "color":       risk_color,
            "description": (
                f"**Risk:** {payload['risk']}\n"
                f"**Domain:** `{payload['domain']}`\n"
                f"**Client:** {payload['client']}"
            ),
            "fields": [
                {"name": "Critical", "value": str(payload["counts"]["CRITICAL"]), "inline": True},
                {"name": "High",     "value": str(payload["counts"]["HIGH"]),     "inline": True},
                {"name": "Medium",   "value": str(payload["counts"]["MEDIUM"]),   "inline": True},
                {"name": "Report",   "value": f"`{payload['report_path']}`",      "inline": False},
            ],
            "footer":    {"text": f"Generated {payload['timestamp']}"},
            "thumbnail": {"url": "https://www.cisa.gov/sites/default/files/images/cisa-logo-200.png"},
        }],
    }).encode()
    req = urllib.request.Request(cfg["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _wh_send_slack(cfg: dict, payload: dict) -> None:
    """Send Slack Block Kit message via Incoming Webhook."""
    emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:",
             "MEDIUM": ":large_yellow_circle:", "LOW": ":white_check_mark:"
             }.get(payload["risk"].split("-")[0], ":information_source:")
    body = json.dumps({
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": payload["title"]},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Client:*\n{payload['client']}"},
                    {"type": "mrkdwn", "text": f"*Domain:*\n`{payload['domain']}`"},
                    {"type": "mrkdwn", "text": f"*Overall Risk:*\n{emoji} {payload['risk']}"},
                    {"type": "mrkdwn", "text": (
                        f"*Findings:*\n"
                        f"Critical: {payload['counts']['CRITICAL']}  "
                        f"High: {payload['counts']['HIGH']}  "
                        f"Medium: {payload['counts']['MEDIUM']}"
                    )},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Report saved to:* `{payload['report_path']}`"},
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Generated {payload['timestamp']}"}],
            },
        ]
    }).encode()
    req = urllib.request.Request(cfg["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _wh_send_teams(cfg: dict, payload: dict) -> None:
    """Send Microsoft Teams Adaptive Card via webhook."""
    color = {"CRITICAL": "attention", "HIGH": "warning",
             "MEDIUM": "accent",      "LOW": "good"
             }.get(payload["risk"].split("-")[0], "default")
    body = json.dumps({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": payload["title"]},
                    {"type": "FactSet", "facts": [
                        {"title": "Client",   "value": payload["client"]},
                        {"title": "Domain",   "value": payload["domain"]},
                        {"title": "Risk",     "value": payload["risk"]},
                        {"title": "Critical", "value": str(payload["counts"]["CRITICAL"])},
                        {"title": "High",     "value": str(payload["counts"]["HIGH"])},
                        {"title": "Medium",   "value": str(payload["counts"]["MEDIUM"])},
                        {"title": "Report",   "value": payload["report_path"]},
                    ]},
                ],
            },
        }],
    }).encode()
    req = urllib.request.Request(cfg["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _wh_send_google_chat(cfg: dict, payload: dict) -> None:
    """Send a plain-text card to a Google Chat space webhook."""
    text = (
        f"*{payload['title']}*\n"
        f"Client: {payload['client']}\n"
        f"Domain: {payload['domain']}\n"
        f"Risk: {payload['risk']}\n"
        f"Critical: {payload['counts']['CRITICAL']}  High: {payload['counts']['HIGH']}  "
        f"Medium: {payload['counts']['MEDIUM']}\n"
        f"Report: {payload['report_path']}"
    )
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(cfg["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 10)) as r:
        r.read()


def _wh_send_mattermost(cfg: dict, payload: dict) -> None:
    """Send a Markdown message to a Mattermost incoming webhook."""
    text = (
        f"### {payload['title']}\n"
        f"**Client:** {payload['client']}  \n"
        f"**Domain:** `{payload['domain']}`  \n"
        f"**Risk:** {payload['risk']}  \n"
        f"**Critical:** {payload['counts']['CRITICAL']}  "
        f"**High:** {payload['counts']['HIGH']}  "
        f"**Medium:** {payload['counts']['MEDIUM']}  \n"
        f"**Report:** `{payload['report_path']}`"
    )
    body = json.dumps({"text": text, "username": "PentestBot"}).encode()
    req = urllib.request.Request(cfg["url"], data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 10)) as r:
        r.read()


def _render_template(node, context: dict):
    """
    Recursively substitute {placeholders} anywhere inside a template
    (str / dict / list). Lets a generic_http slot build the EXACT JSON
    shape any given platform expects, e.g. PagerDuty's Events API.
    Values that aren't strings (dict/list/int/None) are copied as-is unless
    they are strings containing {placeholders}.
    """
    if isinstance(node, str):
        try:
            return node.format(**context)
        except (KeyError, IndexError):
            return node
    if isinstance(node, dict):
        return {k: _render_template(v, context) for k, v in node.items()}
    if isinstance(node, list):
        return [_render_template(v, context) for v in node]
    return node


def _apply_generic_auth(req: urllib.request.Request, body: bytes, auth: dict) -> None:
    """Attach the configured auth scheme to an outgoing request."""
    atype = (auth.get("type") or "none").lower()
    if atype == "bearer":
        req.add_header("Authorization", f"Bearer {auth.get('token', '')}")
    elif atype == "basic":
        raw = f"{auth.get('username', '')}:{auth.get('password', '')}".encode()
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    elif atype == "api_key_header":
        req.add_header(auth.get("header_name", "X-API-Key"), auth.get("token", ""))
    elif atype == "hmac_sha256":
        sig = hmac.new(auth.get("secret", "").encode(), body, hashlib.sha256).hexdigest()
        req.add_header(auth.get("header_name", "X-Signature-256"), f"sha256={sig}")
    # "api_key_query" is applied to the URL before the request is built (see below)
    # "none" — nothing to add


def _wh_send_generic(cfg: dict, payload: dict) -> None:
    """
    Universal webhook sender — works with ANY platform that accepts an HTTP
    webhook call: REST APIs, SIEMs, ticketing systems, automation platforms
    (Zapier / Make / n8n), or a chat app without a named preset above.

    Configurable per-slot: url, method, auth (6 schemes), custom headers,
    an optional payload_template for platform-specific JSON shapes, JSON or
    form encoding, timeout, and retry count.
    """
    url     = cfg["url"]
    method  = (cfg.get("method") or "POST").upper()
    auth    = cfg.get("auth") or {}
    atype   = (auth.get("type") or "none").lower()
    timeout = cfg.get("timeout", 10)
    retries = max(0, cfg.get("retries", 1))

    if atype == "api_key_query":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{auth.get('query_param', 'api_key')}=" \
              f"{urllib.parse.quote(auth.get('token', ''))}"

    template = cfg.get("payload_template")
    body_obj = _render_template(template, payload) if template else payload

    if (cfg.get("payload_format") or "json").lower() == "form":
        body = urllib.parse.urlencode(body_obj).encode()
        content_type = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(body_obj).encode()
        content_type = "application/json"

    headers = {"Content-Type": content_type}
    headers.update(cfg.get("headers", {}))

    last_exc = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            _apply_generic_auth(req, body, auth)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                r.read()
            return
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise last_exc


_WH_DISPATCH = {
    "telegram":     _wh_send_telegram,
    "discord":      _wh_send_discord,
    "slack":        _wh_send_slack,
    "teams":        _wh_send_teams,
    "google_chat":  _wh_send_google_chat,
    "mattermost":   _wh_send_mattermost,
    "generic_http": _wh_send_generic,
}


def fire_webhooks(report_path: str, data: dict, counts: dict, risk_verdict: str) -> None:
    """
    Call every enabled webhook slot with a structured payload.
    Failures are logged but never crash report generation.
    """
    meta   = data.get("meta", {})
    client = meta.get("client_name", "Unknown")
    domain = meta.get("domain", "unknown")
    total  = sum(counts.values())

    payload = {
        "title":       f"Pentest Report Ready — {domain}",
        "client":      client,
        "domain":      domain,
        "risk":        risk_verdict,
        "counts":      counts,
        "report_path": str(report_path),
        "timestamp":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "generator":   f"Module 4 Report Generator {REPORT_VERSION}",
        # Flattened fields — handy for payload_template placeholders,
        # e.g. "{critical} critical, {high} high findings on {domain}"
        "critical":    counts.get("CRITICAL", 0),
        "high":        counts.get("HIGH", 0),
        "medium":      counts.get("MEDIUM", 0),
        "low":         counts.get("LOW", 0),
        "info":        counts.get("INFO", 0),
        "total":       total,
    }

    active = [wh for wh in WEBHOOKS if wh.get("enabled")]
    if not active:
        return

    print(f"\n  Firing {len(active)} webhook(s)…")
    for wh in active:
        platform = wh.get("platform", "generic_http")
        label    = wh.get("name", platform)
        fn       = _WH_DISPATCH.get(platform, _wh_send_generic)
        try:
            fn(wh, payload)
            print(f"    ✓ {label} ({platform})")
        except Exception as exc:
            print(f"    ✗ {label} ({platform}): {exc}")


def test_webhooks() -> None:
    """
    Fire every enabled webhook with a dummy payload, without generating a
    report. Useful for verifying credentials/URLs before a real run.
    Triggered via: python3 report_generator_v2.py --test-webhooks
    """
    dummy_counts = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 9, "LOW": 2, "INFO": 6}
    dummy_data = {"meta": {"client_name": "Test Client", "domain": "example.com"}}
    active = [wh for wh in WEBHOOKS if wh.get("enabled")]
    if not active:
        print("  No webhooks are enabled. Set enabled=True on a slot in "
              "WEBHOOKS at the top of this file first.")
        return
    print(f"  Sending a TEST notification to {len(active)} enabled webhook(s)…")
    fire_webhooks("test_report_would_go_here.pdf", dummy_data, dummy_counts, "MEDIUM-HIGH")


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITY / SANITISATION
# ══════════════════════════════════════════════════════════════════════════════

def _sanitise_score(raw) -> float:
    s = str(raw).replace("$", "").replace("`", "").strip()
    m = re.search(r"\d+(?:\.\d+)?", s)
    return float(m.group()) if m else 0.0


def merge_all_findings(m3: dict, leaks: dict) -> list:
    """
    Merge Module 3 technical findings with CRITICAL/HIGH file-leak findings
    (from Module 2.5) into one consistently-shaped list, sorted by risk
    score descending.

    Every section of the report — KPI cards, donut/bar charts, the risk
    heatmap, the attack-surface diagram, finding cards, and the remediation
    roadmap — reads from this SAME merged list, so severity counts can
    never drift out of sync between sections again.
    """
    findings = list(m3.get("findings", []))
    for lf in leaks.get("findings", []):
        lf_risk = (lf.get("risk") or "").upper().strip()
        if lf_risk in ("CRITICAL", "HIGH"):
            findings.append({
                "subdomain":      lf.get("subdomain", lf.get("url", "?")),
                "technology":     "File Exposure",
                "version":        None,
                "risk_level":     lf_risk,
                "risk_score":     _sanitise_score(
                    lf.get("risk_score", 90 if lf_risk == "CRITICAL" else 70)),
                "matched_cves":   [],
                "in_kev":         False,
                "exposure_notes": lf.get("type", ""),
                "breakdown":      {"exposure_notes": lf.get("evidence", "")},
                "_from_leak":     True,
                "_leak_url":      lf.get("url", ""),
                "_leak_path":     lf.get("path", ""),
            })
    findings.sort(key=lambda x: _sanitise_score(x.get("risk_score", 0)), reverse=True)
    return findings


def count_by_severity(findings: list) -> dict:
    """Tally risk_level across an already-merged findings list."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        lvl = (f.get("risk_level") or "INFO").upper().strip()
        if lvl in counts:
            counts[lvl] += 1
    return counts


def _normalise_flag(raw_flag: str) -> str:
    return raw_flag.lower().strip().replace(" ", "_").replace("-", "_")


def _risk_verdict(counts: dict, kev: int) -> str:
    if counts["CRITICAL"] > 0 or kev > 0:
        return "CRITICAL"
    if counts["HIGH"] > 3:
        return "HIGH"
    if counts["HIGH"] > 0:
        return "MEDIUM-HIGH"
    return "MEDIUM"


# ══════════════════════════════════════════════════════════════════════════════
#  STYLE SHEET
# ══════════════════════════════════════════════════════════════════════════════

def build_styles() -> dict:
    base = getSampleStyleSheet()
    s    = {}

    def _ps(name, **kw):
        defaults = dict(parent=base["Normal"], fontName="Helvetica",
                        textColor=C_GRAY_DARK, leading=14)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    s["cover_title"]    = _ps("cover_title",    fontSize=34, leading=40,
                               textColor=C_WHITE, fontName="Helvetica-Bold",
                               alignment=TA_LEFT)
    s["cover_sub"]      = _ps("cover_sub",      fontSize=13, leading=18,
                               textColor=colors.HexColor("#A0AEC0"), alignment=TA_LEFT)
    s["cover_meta"]     = _ps("cover_meta",     fontSize=9,  leading=13,
                               textColor=colors.HexColor("#CBD5E0"))
    s["section_h1"]     = _ps("section_h1",     fontSize=18, leading=24,
                               fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)
    s["section_h2"]     = _ps("section_h2",     fontSize=13, leading=18,
                               fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    s["section_h3"]     = _ps("section_h3",     fontSize=11, leading=15,
                               fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=2)
    s["body"]           = _ps("body",           fontSize=9.5, leading=14,
                               alignment=TA_JUSTIFY, spaceAfter=4)
    s["body_small"]     = _ps("body_small",     fontSize=8.5, leading=12, textColor=C_GRAY_MID)
    s["mono"]           = _ps("mono",           fontSize=8,   leading=11,
                               fontName="Courier",
                               textColor=colors.HexColor("#24292E"),
                               backColor=colors.HexColor("#F6F8FA"),
                               leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=4)
    s["bullet"]         = _ps("bullet",         fontSize=9.5, leading=13,
                               leftIndent=16, spaceAfter=2,
                               bulletIndent=6, bulletText="•")
    s["finding_title"]  = _ps("finding_title",  fontSize=11, leading=15,
                               textColor=C_WHITE, fontName="Helvetica-Bold")
    s["label"]          = _ps("label",          fontSize=8,  leading=10,
                               textColor=C_GRAY_MID, fontName="Helvetica-Bold", spaceAfter=1)
    s["toc_entry"]      = _ps("toc_entry",      fontSize=10, leading=16)
    s["toc_page"]       = _ps("toc_page",       fontSize=10, leading=16, alignment=TA_RIGHT)
    s["footer_text"]    = _ps("footer_text",    fontSize=7.5, leading=10, textColor=C_GRAY_MID)
    s["kpi_val"]        = _ps("kpi_val",        fontSize=26, leading=30,
                               fontName="Helvetica-Bold", textColor=C_DARK, alignment=TA_CENTER)
    s["kpi_lbl"]        = _ps("kpi_lbl",        fontSize=8,  leading=10,
                               textColor=C_GRAY_MID, alignment=TA_CENTER)
    s["badge_text"]     = _ps("badge_text",     fontSize=8,  leading=10,
                               textColor=C_WHITE, fontName="Helvetica-Bold")
    return s


# ══════════════════════════════════════════════════════════════════════════════
#  CANVAS — PREMIUM HEADER / FOOTER  (every page)
# ══════════════════════════════════════════════════════════════════════════════

class ReportCanvas(rl_canvas.Canvas):
    """
    Custom canvas with:
      • Cover page (p.1) — no header/footer
      • Inner pages — dark header bar + classification + version
                    — footer with domain / date / page N of M
    """

    def __init__(self, *args, client_name="", domain="",
                 assessor="", report_version=REPORT_VERSION, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_name    = client_name
        self.domain         = domain
        self.assessor       = assessor
        self.report_version = report_version
        self._saved_page_states = []
        self._bookmarks     = []   # (title, page_num)

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_chrome(self._pageNumber, num)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _draw_chrome(self, page_num: int, total: int) -> None:
        self.saveState()
        if page_num <= 1:           # cover — no chrome
            self.restoreState()
            return

        # ── Header bar ────────────────────────────────────────────────────
        self.setFillColor(C_DARK)
        self.rect(0, PAGE_H - 1.15 * cm, PAGE_W, 1.15 * cm, fill=1, stroke=0)

        # thin accent line at bottom of header
        self.setFillColor(C_ACCENT)
        self.rect(0, PAGE_H - 1.15 * cm, PAGE_W, 1.5, fill=1, stroke=0)

        self.setFillColor(C_WHITE)
        self.setFont("Helvetica-Bold", 7.5)
        self.drawString(MARGIN, PAGE_H - 0.70 * cm,
                        "CONFIDENTIAL SECURITY ASSESSMENT REPORT")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#A0AEC0"))
        self.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.70 * cm,
                             f"{self.client_name}  |  {self.domain}")

        # version + classification badge (right side, lower line in header)
        self.setFont("Helvetica", 6.5)
        self.setFillColor(colors.HexColor("#718096"))
        self.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.98 * cm,
                             f"{self.report_version}  ·  {self.assessor}")

        # ── Footer ────────────────────────────────────────────────────────
        # separator line
        self.setStrokeColor(C_GRAY_LITE)
        self.setLineWidth(0.5)
        self.line(MARGIN, 1.30 * cm, PAGE_W - MARGIN, 1.30 * cm)

        # left — domain + date
        self.setFont("Helvetica", 7)
        self.setFillColor(C_GRAY_MID)
        date_str = datetime.now(timezone.utc).strftime("%B %Y")
        self.drawString(MARGIN, 0.80 * cm,
                        f"Security Assessment  —  {self.domain}  —  {date_str}")

        # center — CONFIDENTIAL label
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(C_ACCENT)
        cx = PAGE_W / 2
        label = "CONFIDENTIAL"
        self.drawCentredString(cx, 0.80 * cm, label)

        # right — page N of M
        self.setFont("Helvetica", 7)
        self.setFillColor(C_GRAY_MID)
        self.drawRightString(PAGE_W - MARGIN, 0.80 * cm,
                             f"Page {page_num} of {total}")

        self.restoreState()


def make_canvas_factory(client_name: str, domain: str,
                        assessor: str, report_version: str):
    def factory(*args, **kwargs):
        return ReportCanvas(*args,
                            client_name=client_name,
                            domain=domain,
                            assessor=assessor,
                            report_version=report_version,
                            **kwargs)
    return factory


# ══════════════════════════════════════════════════════════════════════════════
#  CHART / VISUAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _fig_to_rl(fig, width_cm: float, height_cm: float) -> Image:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight",
                facecolor="white", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=width_cm * cm, height=height_cm * cm)


def chart_severity_donut(counts: dict) -> Image:
    """Premium donut chart with total count in centre."""
    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    palette = {"CRITICAL": "#C0392B", "HIGH": "#D35400",
               "MEDIUM":   "#D4AC0D", "LOW":  "#1E8449", "INFO": "#5D6D7E"}
    labels  = [k for k in order if counts.get(k, 0) > 0]
    values  = [counts[k] for k in labels]
    clrs    = [palette[l] for l in labels]

    fig, ax = plt.subplots(figsize=(4.2, 4.2), facecolor="white")
    wedges, _ = ax.pie(values, colors=clrs, startangle=90,
                       wedgeprops=dict(width=0.52, edgecolor="white", linewidth=2.5))

    total = sum(values)
    ax.text(0,  0.12, str(total),  ha="center", va="center",
            fontsize=24, fontweight="bold", color="#2D3748")
    ax.text(0, -0.18, "Findings",  ha="center", va="center",
            fontsize=9,  color="#718096")

    patches = [mpatches.Patch(color=palette[l], label=f"{l} ({counts.get(l,0)})")
               for l in order if counts.get(l, 0) > 0]
    ax.legend(handles=patches, loc="lower center", bbox_to_anchor=(0.5, -0.18),
              ncol=3, fontsize=8, frameon=False)
    ax.set_aspect("equal")
    return _fig_to_rl(fig, 9, 8.5)


def chart_risk_bars(findings: list, top_n: int = 14) -> Image:
    """Horizontal bar chart — top findings by score."""
    sorted_f  = sorted(findings, key=lambda x: _sanitise_score(x.get("risk_score", 0)),
                       reverse=True)[:top_n]
    labels    = [f"{f.get('subdomain','?')[:20]}\n{f.get('technology','?')[:14]}"
                 for f in sorted_f]
    scores    = [_sanitise_score(f.get("risk_score", 0)) for f in sorted_f]
    palette   = {"CRITICAL": "#C0392B", "HIGH": "#D35400",
                 "MEDIUM":   "#D4AC0D", "LOW":  "#1E8449", "INFO": "#5D6D7E"}
    bar_clrs  = [palette.get(f.get("risk_level", "INFO"), "#999") for f in sorted_f]

    h = max(4.0, len(labels) * 0.58)
    fig, ax = plt.subplots(figsize=(10, h), facecolor="white")
    bars = ax.barh(range(len(labels)), scores, color=bar_clrs,
                   edgecolor="none", height=0.62)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlim(0, 110)
    ax.set_xlabel("Composite Risk Score (0–100)", fontsize=8, color="#718096")
    ax.set_title("Top Findings by Risk Score", fontsize=10, fontweight="bold",
                 color="#2D3748", pad=8)
    ax.invert_yaxis()
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="x", colors="#718096", labelsize=8)
    ax.tick_params(axis="y", length=0)
    ax.xaxis.grid(True, color="#EDF2F7", linewidth=0.8, zorder=0)
    for bar, score in zip(bars, scores):
        ax.text(bar.get_width() + 1.5, bar.get_y() + bar.get_height() / 2,
                f"{score:.0f}", va="center", fontsize=7.5, color="#2D3748")
    fig.tight_layout()
    return _fig_to_rl(fig, 15, h * 0.68)


def chart_tech_distribution(findings: list) -> Optional[Image]:
    """Bar chart of vulnerable technology counts."""
    tech_counts: dict = defaultdict(int)
    for f in findings:
        t = (f.get("technology") or "Unknown").split()[0]
        if t and t.lower() not in ("n/a", "unknown", ""):
            tech_counts[t] += 1
    if not tech_counts:
        return None
    top = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    labels, vals = zip(*top)

    fig, ax = plt.subplots(figsize=(9, 3.8), facecolor="white")
    clrs = plt.cm.RdYlGn_r(np.linspace(0.05, 0.85, len(labels)))
    ax.bar(labels, vals, color=clrs, edgecolor="none", width=0.6)
    ax.set_ylabel("Findings Count", fontsize=8, color="#718096")
    ax.set_title("Vulnerable Technologies Distribution", fontsize=10,
                 fontweight="bold", color="#2D3748", pad=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="x", colors="#2D3748", labelsize=8, rotation=25)
    ax.tick_params(axis="y", colors="#718096", labelsize=8)
    ax.yaxis.grid(True, color="#EDF2F7", linewidth=0.8, zorder=0)
    fig.tight_layout()
    return _fig_to_rl(fig, 13, 5.5)


def chart_risk_heatmap(findings: list) -> Optional[Image]:
    """
    Risk Heatmap — rows = assets, columns = severity levels.
    Cell colour intensity encodes number of findings.
    """
    if not findings:
        return None

    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assets  = sorted({f.get("subdomain", "?") for f in findings})
    assets  = assets[:16]   # cap rows for readability

    matrix  = np.zeros((len(assets), len(order)), dtype=float)
    for f in findings:
        sub   = f.get("subdomain", "?")
        level = (f.get("risk_level") or "INFO").upper().strip()
        if sub in assets and level in order:
            r = assets.index(sub)
            c = order.index(level)
            matrix[r, c] += 1

    # normalize per cell for colour (0–1)
    max_val = matrix.max() if matrix.max() > 0 else 1
    norm    = matrix / max_val

    fig, ax = plt.subplots(figsize=(9, max(3.0, len(assets) * 0.45)),
                            facecolor="white")

    # Custom colour maps per severity column
    col_cmaps = [
        plt.cm.Reds, plt.cm.Oranges, plt.cm.YlOrBr,
        plt.cm.Greens, plt.cm.Greys,
    ]
    for c_idx, (level, cmap) in enumerate(zip(order, col_cmaps)):
        for r_idx, asset in enumerate(assets):
            val  = matrix[r_idx, c_idx]
            nval = norm[r_idx, c_idx]
            bg   = cmap(0.15 + nval * 0.75) if nval > 0 else (0.97, 0.97, 0.97, 1)
            rect = plt.Rectangle([c_idx - 0.5, r_idx - 0.5], 1, 1,
                                  facecolor=bg, edgecolor="white", linewidth=1.2)
            ax.add_patch(rect)
            if val > 0:
                lum = 0.299*bg[0] + 0.587*bg[1] + 0.114*bg[2]
                tc  = "white" if lum < 0.55 else "#2D3748"
                ax.text(c_idx, r_idx, int(val), ha="center", va="center",
                        fontsize=9, fontweight="bold", color=tc)

    ax.set_xlim(-0.5, len(order) - 0.5)
    ax.set_ylim(-0.5, len(assets) - 0.5)
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(order, fontsize=9, fontweight="bold")
    ax.set_yticks(range(len(assets)))
    ax.set_yticklabels([a[:32] for a in assets], fontsize=7.5)
    ax.xaxis.set_ticks_position("top")
    ax.xaxis.set_label_position("top")
    ax.set_title("Risk Heatmap — Asset × Severity", fontsize=10,
                 fontweight="bold", color="#2D3748", pad=14)
    ax.tick_params(length=0)
    ax.spines[:].set_visible(False)
    fig.tight_layout()
    return _fig_to_rl(fig, INNER_W / cm, max(4.5, len(assets) * 0.55))


def chart_attack_surface(domain: str, subdomains: list, findings: list) -> Optional[Image]:
    """
    Attack Surface Diagram — domain → subdomains → services → findings.
    Pure matplotlib drawing, no external graphviz needed.
    """
    alive = [s for s in subdomains if s.get("is_alive")][:12]
    if not alive:
        return None

    # Build per-subdomain finding counts
    f_counts: dict = defaultdict(lambda: defaultdict(int))
    for f in findings:
        sub   = f.get("subdomain", "")
        level = (f.get("risk_level") or "INFO").upper()
        f_counts[sub][level] += 1

    n_subs = len(alive)
    fig_h  = max(5.0, n_subs * 0.72)
    fig, ax = plt.subplots(figsize=(13, fig_h), facecolor="white")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, fig_h)
    ax.axis("off")

    palette = {"CRITICAL": "#C0392B", "HIGH": "#D35400",
               "MEDIUM": "#D4AC0D", "LOW": "#1E8449", "INFO": "#5D6D7E"}

    # Root domain box
    root_y = fig_h / 2
    root_box = FancyBboxPatch((0.2, root_y - 0.35), 2.1, 0.70,
                               boxstyle="round,pad=0.08",
                               facecolor="#0D1117", edgecolor="#E84C3D",
                               linewidth=2)
    ax.add_patch(root_box)
    ax.text(1.25, root_y, domain[:18], ha="center", va="center",
            fontsize=8, fontweight="bold", color="white")

    # Subdomain boxes
    step  = fig_h / (n_subs + 1)
    sub_x = 4.0
    for i, sub_d in enumerate(alive):
        sy   = fig_h - (i + 1) * step
        name = sub_d.get("subdomain", "?").replace(f".{domain}", "")[:20]
        techs = ", ".join((sub_d.get("technologies") or [])[:2])

        # connector line
        ax.annotate("", xy=(sub_x, sy), xytext=(2.3, root_y),
                    arrowprops=dict(arrowstyle="-|>", color="#CBD5E0",
                                   lw=0.8, connectionstyle="arc3,rad=0.0"))

        # subdomain box
        box = FancyBboxPatch((sub_x, sy - 0.30), 2.5, 0.60,
                              boxstyle="round,pad=0.06",
                              facecolor="#161B22", edgecolor="#2D3748",
                              linewidth=1)
        ax.add_patch(box)
        ax.text(sub_x + 1.25, sy + 0.05,  name,  ha="center", va="center",
                fontsize=7.5, fontweight="bold", color="white")
        ax.text(sub_x + 1.25, sy - 0.16, techs, ha="center", va="center",
                fontsize=6, color="#718096")

        # finding severity dots
        counts_d = f_counts.get(sub_d.get("subdomain", ""), {})
        dx = 6.7
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = counts_d.get(level, 0)
            if cnt:
                circ = plt.Circle((dx, sy), 0.18, color=palette[level], zorder=5)
                ax.add_patch(circ)
                ax.text(dx, sy, str(cnt), ha="center", va="center",
                        fontsize=6, fontweight="bold", color="white", zorder=6)
                dx += 0.50

    # Legend
    for i, (level, col) in enumerate(palette.items()):
        ax.add_patch(plt.Circle((0.35 + i * 1.6, 0.25), 0.13, color=col))
        ax.text(0.55 + i * 1.6, 0.25, level, va="center", fontsize=6.5, color="#2D3748")

    ax.set_title("Attack Surface Diagram  —  Domain → Subdomains → Findings",
                 fontsize=10, fontweight="bold", color="#2D3748", pad=6)
    fig.tight_layout()
    return _fig_to_rl(fig, INNER_W / cm, fig_h * 0.85)


# ══════════════════════════════════════════════════════════════════════════════
#  FLOWABLE COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════

class _BookmarkFlowable(Flowable):
    """
    Invisible, zero-size flowable. When ReportLab draws it, it:
      1. Registers a named PDF destination (`bookmarkPage`) — this is what
         makes internal links like <a href="#sec_risk_overview"> actually
         jump somewhere (a link with no matching destination does nothing).
      2. Optionally adds an entry to the PDF's outline/bookmarks sidebar
         (`addOutlineEntry`) so the reader can navigate via Acrobat/Preview's
         bookmark panel, not just the in-document TOC.
    Place one at the very top of a section, before anything else is drawn.
    """
    def __init__(self, key: str, title: str = "", level: int = 0):
        Flowable.__init__(self)
        self.key   = key
        self.title = title
        self.level = level
        self.width = 0
        self.height = 0

    def wrap(self, availWidth, availHeight):
        return (0, 0)

    def draw(self):
        self.canv.bookmarkPage(self.key)
        if self.title:
            self.canv.addOutlineEntry(self.title, self.key,
                                      level=self.level, closed=False)


def section_divider(styles: dict, title: str, bookmark_key: str = "") -> list:
    elems = []
    if bookmark_key:
        elems.append(_BookmarkFlowable(bookmark_key, title, level=0))
    elems += [
        Spacer(1, 0.5 * cm),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=4),
        Paragraph(title, styles["section_h1"]),
    ]
    return elems


def sub_bookmark(key: str, title: str, level: int = 1) -> _BookmarkFlowable:
    """Standalone sub-section bookmark (e.g. severity groups inside Findings)."""
    return _BookmarkFlowable(key, title, level=level)


def severity_badge(level: str) -> Table:
    """Coloured pill badge for a severity level with icon."""
    clr  = LEVEL_COLORS.get(level, C_INFO)
    icon = LEVEL_ICON.get(level, "[-]")
    tbl  = Table(
        [[Paragraph(f"<b>{icon} {level}</b>",
                    ParagraphStyle("badge", fontSize=7.5, textColor=C_WHITE,
                                   fontName="Helvetica-Bold", leading=10))]],
        colWidths=[2.0 * cm], rowHeights=[0.45 * cm],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), clr),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return tbl


def kv_table(rows: list, col_ratio=(0.28, 0.72)) -> Table:
    w1 = INNER_W * col_ratio[0]
    w2 = INNER_W * col_ratio[1]
    st = build_styles()
    data = [[Paragraph(f"<b>{k}</b>", st["body_small"]),
             Paragraph(str(v),        st["body"])]
            for k, v in rows]
    tbl  = Table(data, colWidths=[w1, w2])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_GRAY_LITE),
    ]))
    return tbl


def kpi_row(metrics: list) -> Table:
    """
    Premium KPI card row.
    metrics = [(value, label, sub, colour), ...]
    """
    n    = len(metrics)
    cw   = (INNER_W - (n - 1) * 3) / n
    st   = build_styles()

    cells = []
    for val, lbl, sub, clr in metrics:
        inner = Table(
            [[Paragraph(str(val), st["kpi_val"])],
             [Paragraph(lbl,      st["kpi_lbl"])],
             [Paragraph(sub or "",
                        ParagraphStyle("ks", fontSize=7, leading=9,
                                       textColor=C_GRAY_MID, alignment=TA_CENTER))]],
            colWidths=[cw],
        )
        inner.setStyle(TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        cells.append(inner)

    tbl = Table([cells], colWidths=[cw] * n, rowHeights=[2.6 * cm])
    cmds = [
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",     (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 0),
        ("BOX",            (0, 0), (-1, -1), 0.5, C_GRAY_LITE),
        ("INNERGRID",      (0, 0), (-1, -1), 0.5, C_GRAY_LITE),
    ]
    for i, (_, _, _, clr) in enumerate(metrics):
        cmds.append(("LINEABOVE", (i, 0), (i, 0), 3, clr))
    tbl.setStyle(TableStyle(cmds))
    return tbl


# ══════════════════════════════════════════════════════════════════════════════
#  REMEDIATION DATABASE
# ══════════════════════════════════════════════════════════════════════════════

REMEDIATIONS: Dict[str, dict] = {
    "git_exposed": {
        "title":       "Exposed .git Directory",
        "priority":    "CRITICAL — fix within 24 hours",
        "description": (
            "A publicly accessible .git directory allows any attacker to reconstruct "
            "the full source code and commit history, revealing credentials, "
            "API keys, database connection strings, and internal business logic."
        ),
        "steps": [
            "Block web access to .git immediately in your web server config.",
            "Rotate ALL credentials, API keys, and secrets found in git history.",
            "Audit full commit history with `git log -p` or truffleHog for leaked secrets.",
            "Add `.git` to your WAF block list at the CDN level as a defence-in-depth measure.",
        ],
        "code": {
            "Apache (.htaccess)": "RedirectMatch 404 /\\.git",
            "Nginx":              "location ~ /\\.git { deny all; return 404; }",
        },
    },
    "env_file_exposed": {
        "title":       "Exposed .env / Secrets File",
        "priority":    "CRITICAL — fix within 24 hours",
        "description": (
            "Environment files contain database credentials, API keys, encryption "
            "salts, and service tokens in plain text. Exposure is equivalent to "
            "direct database access and full service account compromise."
        ),
        "steps": [
            "Remove or block the file via web server config immediately.",
            "Rotate every secret listed in the file — assume all are compromised.",
            "Never store .env files in the web root; move them one level above public_html.",
            "Use a secrets manager (AWS Secrets Manager, Vault, Doppler) instead of flat files.",
        ],
        "code": {"Nginx": "location ~ /\\.env { deny all; return 404; }"},
    },
    "backup_file_exposed": {
        "title":       "Exposed Backup / Archive File",
        "priority":    "HIGH — fix within 48 hours",
        "description": (
            "Publicly downloadable backup archives commonly contain full database dumps, "
            "source code, or configuration including credentials."
        ),
        "steps": [
            "Remove or move backup files outside of the web root immediately.",
            "Audit backup naming conventions — avoid predictable names like domain.zip.",
            "Configure web server to block common archive extensions.",
            "Store backups in private cloud storage (private S3 bucket, etc.).",
        ],
        "code": {
            "Nginx": 'location ~* \\.(zip|tar\\.gz|sql|bak|rar|7z)$ { deny all; return 404; }',
        },
    },
    "database_port_open": {
        "title":       "Database Port Exposed to Internet",
        "priority":    "CRITICAL — restrict immediately",
        "description": (
            "Database services listening on public interfaces are directly exposed to "
            "brute-force, credential stuffing, and unauthenticated exploitation of known CVEs."
        ),
        "steps": [
            "Immediately restrict DB ports (3306, 5432, 27017, 6379, 9200) with firewall rules.",
            "Allow only application server IPs via security group / iptables.",
            "Enable authentication on all database services.",
            "Place database servers in a private subnet with no public IP.",
        ],
        "code": {
            "iptables": (
                "iptables -A INPUT -p tcp --dport 6379 -s <APP_SERVER_IP> -j ACCEPT\n"
                "iptables -A INPUT -p tcp --dport 6379 -j DROP"
            ),
        },
    },
    "admin_panel_public": {
        "title":       "Admin Panel Exposed to Public Internet",
        "priority":    "HIGH — restrict within 48 hours",
        "description": (
            "Administrative interfaces exposed publicly are prime targets for "
            "credential stuffing and brute-force attacks."
        ),
        "steps": [
            "Restrict admin paths (/admin, /dashboard, /wp-admin) by IP allowlist.",
            "Enforce Multi-Factor Authentication on all admin accounts.",
            "Move admin access behind a VPN or private network.",
            "Implement account lockout after 5 failed login attempts.",
        ],
        "code": {
            "Nginx IP allowlist": "location /admin {\n  allow <YOUR_OFFICE_IP>;\n  deny all;\n}",
        },
    },
    "missing_security_headers": {
        "title":       "Missing HTTP Security Headers",
        "priority":    "MEDIUM — fix within 1 week",
        "description": (
            "Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) "
            "leave users vulnerable to clickjacking, MIME-type sniffing attacks, and "
            "downgrade attacks on HTTPS connections."
        ),
        "steps": [
            "Add the recommended headers below to your web server or application.",
            "Validate headers at securityheaders.com after deployment.",
            "Implement a Content Security Policy (CSP) to restrict resource origins.",
            "Set HSTS max-age to at least 31536000 (1 year) and include subdomains.",
        ],
        "code": {
            "Nginx": (
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
                'add_header X-Frame-Options "SAMEORIGIN" always;\n'
                'add_header X-Content-Type-Options "nosniff" always;\n'
                "add_header Content-Security-Policy \"default-src 'self'\" always;"
            ),
        },
    },
    "docker_api_open": {
        "title":       "Docker API Exposed",
        "priority":    "CRITICAL — isolate immediately",
        "description": (
            "An exposed Docker daemon API grants unauthenticated root-equivalent access "
            "to the host system."
        ),
        "steps": [
            "Immediately apply firewall rules to port 2375/2376.",
            "Never expose the Docker socket or API to a public interface.",
            "Use TLS mutual authentication if the API must be remotely accessible.",
            "Audit for container escapes and lateral movement.",
        ],
        "code": {
            "iptables block": (
                "iptables -I INPUT -p tcp --dport 2375 -j DROP\n"
                "iptables -I INPUT -p tcp --dport 2376 -j DROP"
            ),
        },
    },
    "outdated_tls": {
        "title":       "Outdated TLS Protocol in Use",
        "priority":    "MEDIUM — fix within 1 week",
        "description": "TLS 1.0 and 1.1 are deprecated and vulnerable to protocol downgrade attacks.",
        "steps": [
            "Disable TLS 1.0 and TLS 1.1 in web server configuration.",
            "Enable only TLS 1.2 and TLS 1.3.",
            "Use a strong cipher suite — refer to Mozilla SSL Configuration Generator.",
            "Validate configuration at ssllabs.com/ssltest after deployment.",
        ],
        "code": {
            "Nginx": (
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n"
                "ssl_prefer_server_ciphers off;"
            ),
        },
    },
}

_PATCH_TECHNOLOGIES = {
    "apache", "nginx", "iis", "lighttpd",
    "php", "python", "ruby", "perl",
    "wordpress", "joomla", "drupal",
    "openssl", "libssl",
}
_FRONTEND_ONLY = {"bootstrap", "jquery", "react", "vue", "angular", "ember"}


def get_remediation(exposure_flags: list, technology: str, cves: list) -> dict:
    """
    Priority order:
      1. Real server/runtime software (Apache, PHP, nginx…) with its OWN
         matched CVEs -> patching advice. This wins even if the finding's
         exposure_notes ALSO mention an unrelated flag like 'git_exposed'
         (Module 3 tags exposure context per-asset, so that flag can be
         echoed onto every finding for that asset — but THIS finding's
         actual problem is the vulnerable software version).
      2. Frontend-only libraries (Bootstrap, jQuery…) with matched CVEs ->
         CPE-scoped false-positive warning, same reasoning as above.
      3. No CVEs on this finding -> the exposure flag itself (git_exposed,
         env_file_exposed, etc.) IS the actual problem — use its remediation.
      4. Missing-headers flag with nothing more specific matched.
      5. Generic low-priority review.
    """
    normalised = [_normalise_flag(f) for f in (exposure_flags or []) if f.strip()]
    tech_lower = (technology or "").lower().split()[0]
    _SKIP_FLAGS = {"missing_security_headers"}

    if cves and tech_lower in _PATCH_TECHNOLOGIES:
        max_cvss  = max((_sanitise_score(c.get("cvss", 0)) for c in cves), default=0)
        priority  = (
            "CRITICAL — patch within 24 hours" if max_cvss >= 9.0 else
            "HIGH — patch within 1 week"       if max_cvss >= 7.0 else
            "MEDIUM — patch within 30 days"
        )
        return {
            "title":       f"Update {technology} to latest stable version",
            "priority":    priority,
            "description": (
                f"The detected version of {technology} is affected by {len(cves)} "
                f"known CVE(s) (highest CVSS: {max_cvss:.1f}). "
                "Upgrading to the latest stable release resolves all matched vulnerabilities."
            ),
            "steps": [
                f"Update {technology} to the latest stable version immediately.",
                "Review CVE details at nvd.nist.gov for configuration-level mitigations.",
                "Subscribe to the vendor's security advisory mailing list.",
                "Re-scan after patching to confirm all matched CVEs are resolved.",
            ],
            "code": {},
        }

    if cves and tech_lower in _FRONTEND_ONLY:
        return {
            "title":       f"Verify {technology} CVE Applicability and Harden Headers",
            "priority":    "MEDIUM — review within 30 days",
            "description": (
                f"CVEs were matched for '{technology}' via keyword search. Many may be "
                "false positives — the NVD keyword matches unrelated projects. "
                f"Confirm applicability using CPE (cpe:2.3:a:getbootstrap:{tech_lower}:*) "
                "before treating these as confirmed findings."
            ),
            "steps": [
                f"Cross-check each CVE against the official {technology} changelog and CPE entries.",
                "Discard any CVE whose CPE does not match the correct vendor/product.",
                f"Upgrade {technology} to the latest stable release as a precaution.",
                "Add HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
            ],
            "code": {
                "Nginx": (
                    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
                    'add_header X-Frame-Options "SAMEORIGIN" always;\n'
                    'add_header X-Content-Type-Options "nosniff" always;\n'
                    "add_header Content-Security-Policy \"default-src 'self'\" always;"
                ),
            },
        }

    for flag in normalised:
        if flag in REMEDIATIONS and flag not in _SKIP_FLAGS:
            return REMEDIATIONS[flag]

    if "missing_security_headers" in normalised:
        return REMEDIATIONS["missing_security_headers"]

    return {
        "title":       "Review and Harden Configuration",
        "priority":    "LOW — review within 30 days",
        "description": "No specific CVE was matched, but the asset has exposure signals worth reviewing.",
        "steps": [
            "Review exposure flags and apply principle of least privilege.",
            "Implement network-level access controls where applicable.",
        ],
        "code": {},
    }


# ══════════════════════════════════════════════════════════════════════════════
#  COVER PAGE  — Premium gradient branding + optional logo
# ══════════════════════════════════════════════════════════════════════════════

def build_cover(styles: dict, meta: dict) -> list:
    story      = []
    label      = meta.get("report_label", "PENETRATION TESTING REPORT")
    client     = meta.get("client_name",  "Client Organisation")
    domain     = meta.get("domain",       "target.com")
    date_str   = meta.get("date",         datetime.now().strftime("%B %d, %Y"))
    assessor   = meta.get("assessor",     "Security Team")
    logo_path  = meta.get("logo_path",    None)

    # ── Draw cover as a matplotlib figure (gives us gradient + logo) ──────
    fig = plt.figure(figsize=(A4[0] / 72, A4[1] / 72), facecolor="#0D1117")
    ax  = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")

    # Background gradient: dark top, slightly lighter bottom
    grad = np.linspace(0, 1, 256).reshape(256, 1)
    ax.imshow(grad, extent=[0, 1, 0, 1], aspect="auto",
              cmap=plt.cm.colors.LinearSegmentedColormap.from_list(
                  "cov", ["#0D1117", "#161B22"]),
              origin="lower", zorder=0)

    # Accent bar — left edge
    ax.axvline(x=0.018, color="#E84C3D", linewidth=14, zorder=2)

    # Subtle grid lines (premium feel)
    for y in np.arange(0.05, 1.0, 0.07):
        ax.axhline(y=y, color="white", linewidth=0.15, alpha=0.05, zorder=1)

    # Logo (optional)
    if logo_path and os.path.isfile(logo_path):
        try:
            from PIL import Image as PILImage
            pil_img  = PILImage.open(logo_path).convert("RGBA")
            logo_arr = np.array(pil_img) / 255.0
            # place top-right
            ax.imshow(logo_arr, extent=[0.72, 0.94, 0.85, 0.96],
                      aspect="auto", zorder=5, origin="upper")
        except Exception:
            pass  # logo load failure is non-fatal

    # Report type label
    ax.text(0.07, 0.88, label,
            color="#E84C3D", fontsize=10, fontweight="bold",
            transform=ax.transAxes, va="center")

    # Client name (big)
    ax.text(0.07, 0.72, client,
            color="white", fontsize=28, fontweight="bold",
            transform=ax.transAxes, va="center",
            wrap=True)

    # Divider line
    ax.axhline(y=0.64, xmin=0.07, xmax=0.93, color="#E84C3D",
               linewidth=1.5, alpha=0.8, zorder=3)

    # Sub-info
    ax.text(0.07, 0.58, f"Target Domain: {domain}",
            color="#A0AEC0", fontsize=12, transform=ax.transAxes, va="center")

    # Meta row at bottom
    meta_y = 0.14
    for i, (key, val) in enumerate([
        ("Assessment Date", date_str),
        ("Prepared By",     assessor),
        ("Classification",  "CONFIDENTIAL"),
        ("Report Version",  REPORT_VERSION),
    ]):
        x = 0.07 + i * 0.23
        ax.text(x, meta_y + 0.035, key, color="#718096", fontsize=7,
                fontweight="bold", transform=ax.transAxes)
        clr = "#E84C3D" if key == "Classification" else "white"
        ax.text(x, meta_y, val, color=clr, fontsize=9,
                fontweight="bold", transform=ax.transAxes)

    # Disclaimer strip at very bottom
    ax.add_patch(plt.Rectangle([0, 0], 1, 0.07,
                                facecolor="#161B22", zorder=4,
                                transform=ax.transAxes))
    disc = (
        "IMPORTANT — AUTHORISED USE ONLY. This report is prepared exclusively for "
        f"{client} and contains confidential security information. "
        "Distribution, reproduction, or use by unauthorised parties is strictly prohibited."
    )
    ax.text(0.5, 0.035, disc, color="#718096", fontsize=6.5,
            ha="center", va="center", transform=ax.transAxes,
            wrap=True, style="italic")

    # Convert to ReportLab Image at full page size
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor="#0D1117", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    cover_img = Image(buf, width=PAGE_W, height=PAGE_H)

    # This flows inside a dedicated zero-margin "Cover" page template
    # (see generate_report) so the image fills the page exactly —
    # no margin-cancelling hacks needed.
    story.append(cover_img)
    story.append(NextPageTemplate("Later"))
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  TABLE OF CONTENTS  — clickable entries + bookmarks
# ══════════════════════════════════════════════════════════════════════════════

TOC_SECTIONS = [
    ("1.", "Executive Summary",               "sec_exec_summary"),
    ("2.", "Assessment Scope & Methodology",  "sec_methodology"),
    ("3.", "Risk Overview",                   "sec_risk_overview"),
    ("4.", "Technical Findings",              "sec_technical_findings"),
    ("5.", "Exposed Asset Inventory",         "sec_asset_inventory"),
    ("6.", "Remediation Roadmap",             "sec_remediation_roadmap"),
    ("7.", "Appendix — Full CVE Table",       "sec_appendix"),
]


def build_toc(styles: dict) -> list:
    story = []
    story += section_divider(styles, "Table of Contents", bookmark_key="sec_toc")
    story.append(Spacer(1, 0.4 * cm))

    for num, title, key in TOC_SECTIONS:
        row    = Table(
            [[Paragraph(f"<b>{num}</b>",    styles["toc_entry"]),
              Paragraph(
                  f'<a href="#{key}" color="#1A6EBD">{title}</a>',
                  styles["toc_entry"]),
              Paragraph("", styles["toc_page"]),
              ]],
            colWidths=[1.0 * cm, INNER_W - 2.2 * cm, 1.2 * cm],
        )
        row.setStyle(TableStyle([
            ("LINEBELOW",     (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ]))
        story.append(row)

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def build_executive_summary(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "1. Executive Summary", bookmark_key="sec_exec_summary")

    m1     = data.get("module1", {})
    m3     = data.get("module3", {})
    leaks  = data.get("leaks",   {})

    domain         = m1.get("domain", "target.com")
    total_subs     = m1.get("total_subdomains", 0)
    alive_subs     = m1.get("alive_subdomains", 0)
    cloud_assets   = len(m1.get("cloud_assets", []))
    cred_leaks     = len(m1.get("leaked_credentials", []))
    kev_matches    = m3.get("kev_matches", 0)
    leak_list      = leaks.get("findings", [])
    total_leak_crit= leaks.get("critical_count", 0)

    live           = count_by_severity(merge_all_findings(m3, leaks))
    critical_count = live["CRITICAL"]
    high_count     = live["HIGH"]
    medium_count   = live["MEDIUM"]
    low_count      = live["LOW"]
    total_findings = sum(live.values())

    verdict = _risk_verdict(live, kev_matches)
    verdict_desc_map = {
        "CRITICAL":    "Critical vulnerabilities exist that require immediate remediation. Active exploitation is a realistic and imminent threat.",
        "HIGH":        "Multiple high-severity vulnerabilities present significant risk and must be addressed urgently.",
        "MEDIUM-HIGH": "High-severity findings require prioritised attention. No critical issues were identified.",
        "MEDIUM":      "Medium-severity findings represent meaningful risk if left unaddressed.",
    }
    verdict_desc = verdict_desc_map.get(verdict, "")

    # Risk verdict banner
    v_color = LEVEL_COLORS.get(verdict.split("-")[0], C_MEDIUM)
    vb = Table([[
        Paragraph(f"Overall Risk Rating: <b>{verdict}</b>",
                  ParagraphStyle("vb", fontSize=14, fontName="Helvetica-Bold",
                                 textColor=C_WHITE, leading=18)),
    ]], colWidths=[INNER_W])
    vb.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), v_color),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(vb)
    story.append(Spacer(1, 0.4 * cm))

    # KPI rows
    story.append(kpi_row([
        (critical_count, "Critical Findings",  "",          C_CRITICAL),
        (high_count,     "High Findings",      "",          C_HIGH),
        (kev_matches,    "Actively Exploited", "CISA KEV",  C_CRITICAL),
        (cred_leaks + len(leak_list), "Credential Leaks", "", C_HIGH),
    ]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(kpi_row([
        (total_findings, "Total Findings",  "",                        C_BLUE),
        (alive_subs,     "Alive Subdomains",f"of {total_subs} found",  C_BLUE),
        (cloud_assets,   "Cloud Assets",    "",                        C_GRAY_MID),
        (len(leak_list), "File Leaks",      "",                        C_HIGH),
    ]))
    story.append(Spacer(1, 0.5 * cm))

    # Narrative
    narrative = (
        f"A comprehensive security assessment of <b>{domain}</b> was conducted to evaluate the "
        f"external attack surface. The engagement discovered <b>{total_subs} subdomains</b>, of which "
        f"<b>{alive_subs}</b> were alive and responsive. "
    )
    if cloud_assets:
        narrative += f"<b>{cloud_assets} cloud asset(s)</b> were enumerated across major providers. "
    if cred_leaks:
        narrative += f"<b>{cred_leaks} potential credential leak(s)</b> were identified in public GitHub repositories. "
    if leak_list:
        narrative += (
            f"Directory fuzzing uncovered <b>{len(leak_list)} exposed file(s)</b>"
            + (f", including <b>{total_leak_crit} critical</b> file(s) such as .env or .git directories"
               if total_leak_crit else "")
            + ". "
        )
    if kev_matches:
        narrative += (
            f"<b>{kev_matches} finding(s) are confirmed in the CISA Known Exploited Vulnerabilities "
            "(KEV) catalog</b>, meaning they are being actively weaponised by threat actors right now. "
        )
    narrative += verdict_desc

    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # Priority actions
    story.append(Paragraph("<b>Priority Actions</b>", styles["section_h2"]))
    recos = []
    if kev_matches:
        recos.append(f"<b>[IMMEDIATE]</b> Patch {kev_matches} CVE(s) in the CISA KEV list — actively exploited in the wild.")
    if cred_leaks or total_leak_crit:
        recos.append("<b>[IMMEDIATE]</b> Rotate all credentials found in GitHub or exposed configuration files.")
    if critical_count:
        recos.append("<b>[24 hrs]</b> Remediate all CRITICAL findings before any other development work proceeds.")
    if high_count:
        recos.append(f"<b>[1 week]</b> Address {high_count} HIGH findings within the next sprint.")
    if medium_count:
        recos.append(f"<b>[1 month]</b> Schedule remediation of {medium_count} MEDIUM findings.")
    recos.append("<b>[Ongoing]</b> Implement continuous monitoring (Module 2) to detect new attack surfaces.")
    for r in recos:
        story.append(Paragraph(r, styles["bullet"]))

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — SCOPE & METHODOLOGY
# ══════════════════════════════════════════════════════════════════════════════

def build_methodology(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "2. Assessment Scope & Methodology", bookmark_key="sec_methodology")
    m1   = data.get("module1", {})
    meta = data.get("meta",    {})

    story.append(Paragraph("<b>Scope</b>", styles["section_h2"]))
    story.append(kv_table([
        ("Target Domain",   m1.get("domain", "N/A")),
        ("Assessment Type", "Black-box External Penetration Test"),
        ("Test Date",       meta.get("date", datetime.now().strftime("%B %d, %Y"))),
        ("Duration",        f"{m1.get('scan_duration_seconds','N/A')}s (automated) + manual review"),
        ("Assessor",        meta.get("assessor", "Security Team")),
        ("Classification",  "CONFIDENTIAL"),
    ]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("<b>Tools &amp; Data Sources</b>", styles["section_h2"]))
    story.append(kv_table([
        ("Subdomain Discovery",   "Certificate transparency logs (crt.sh), AlienVault OTX, URLScan.io, DNS bruteforce"),
        ("Technology Fingerprint","Wappalyzer-style header & response analysis"),
        ("Port Scanning",         "Async TCP connect scan — top ports"),
        ("Cloud Enumeration",     "DNS permutation & public bucket probing (S3, Azure Blob, GCP)"),
        ("Credential Scanning",   "GitHub dork search for tokens, API keys, connection strings"),
        ("Leak Detection",        "Wordlist-based HTTP path fuzzing with content-signature validation"),
        ("CVE Matching",          "NIST NVD API v2.0 with version-range filtering, OSV.dev, Vulners.com"),
        ("Active Exploit Check",  "CISA Known Exploited Vulnerabilities (KEV) catalog"),
        ("Risk Scoring",          "Composite 0-100 score: CVSS + KEV status + exposure context + asset criticality"),
    ]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("<b>Methodology Summary</b>", styles["section_h2"]))
    story.append(Paragraph(
        "The assessment follows a four-phase methodology aligned with PTES and OWASP Testing Guide. "
        "<b>Phase 1 — Reconnaissance:</b> Passive and active asset discovery to enumerate the full "
        "external attack surface without direct exploitation. "
        "<b>Phase 2 — Enumeration:</b> Technology fingerprinting, port scanning, and cloud asset "
        "enumeration to build a detailed picture of exposed services. "
        "<b>Phase 3 — Vulnerability Identification:</b> Automated CVE matching against detected versions, "
        "credential leak detection, and exposed file discovery with content-validated evidence. "
        "<b>Phase 4 — Risk Scoring:</b> Each finding is scored 0-100 using a composite model that "
        "weights CVSS severity, active exploitation status, asset criticality, and exposure context.",
        styles["body"],
    ))
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — RISK OVERVIEW  (donut + bars + heatmap + attack surface)
# ══════════════════════════════════════════════════════════════════════════════

def build_risk_overview(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "3. Risk Overview", bookmark_key="sec_risk_overview")

    m3       = data.get("module3", {})
    m1       = data.get("module1", {})
    leaks_d  = data.get("leaks",   {})
    findings = merge_all_findings(m3, leaks_d)
    counts   = count_by_severity(findings)

    if findings:
        # Donut + bar side by side
        donut = chart_severity_donut(counts)
        bar   = chart_risk_bars(findings)
        row   = Table([[donut, bar]],
                      colWidths=[INNER_W * 0.36, INNER_W * 0.64])
        row.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(row)
        story.append(Spacer(1, 0.4 * cm))

        # Tech distribution
        tech_chart = chart_tech_distribution(findings)
        if tech_chart:
            story.append(tech_chart)
            story.append(Spacer(1, 0.4 * cm))

    # ── Risk Heatmap ──────────────────────────────────────────────────────
    heatmap = chart_risk_heatmap(findings)
    if heatmap:
        story.append(Spacer(1, 0.3 * cm))
        story.append(heatmap)
        story.append(Spacer(1, 0.4 * cm))

    # ── Attack Surface Diagram ────────────────────────────────────────────
    subdomains = m1.get("subdomains", [])
    domain     = m1.get("domain", "target.com")
    asd        = chart_attack_surface(domain, subdomains, findings)
    if asd:
        story.append(Spacer(1, 0.3 * cm))
        story.append(asd)
        story.append(Spacer(1, 0.4 * cm))

    # Finding count table
    story.append(Paragraph("<b>Finding Count by Severity</b>", styles["section_h2"]))
    hdr_s  = ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold",
                             textColor=C_WHITE,     leading=12)
    cell_s = ParagraphStyle("tc", fontSize=9, fontName="Helvetica",
                             textColor=C_GRAY_DARK, leading=12)
    sla    = {
        "CRITICAL": "Immediate (< 24 hours)",
        "HIGH":     "Urgent (< 1 week)",
        "MEDIUM":   "Planned (< 30 days)",
        "LOW":      "Scheduled (< 90 days)",
        "INFO":     "Informational",
    }
    impact = {
        "CRITICAL": "System compromise, data breach, full loss of confidentiality",
        "HIGH":     "Significant service disruption or unauthorised data access",
        "MEDIUM":   "Limited data exposure or potential privilege escalation",
        "LOW":      "Minor information disclosure, defence-in-depth weakening",
        "INFO":     "Informational observation, no direct security impact",
    }
    tbl_data = [[Paragraph(h, hdr_s) for h in
                 ["Severity", "Count", "SLA Target", "Business Impact"]]]
    row_bgs  = {
        "CRITICAL": C_CRITICAL_BG,
        "HIGH":     C_HIGH_BG,
        "MEDIUM":   C_MEDIUM_BG,
        "LOW":      C_LOW_BG,
        "INFO":     C_INFO_BG,
    }
    bg_cmds = []
    for row_i, level in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], 1):
        tbl_data.append([
            Paragraph(f"<b>{level}</b>", cell_s),
            Paragraph(str(counts[level]),  cell_s),
            Paragraph(sla[level],          cell_s),
            Paragraph(impact[level],       cell_s),
        ])
        bg_cmds.append(("BACKGROUND", (0, row_i), (-1, row_i), row_bgs[level]))

    sev_tbl = Table(tbl_data,
                    colWidths=[INNER_W * 0.16, INNER_W * 0.10,
                               INNER_W * 0.30, INNER_W * 0.44])
    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_GRAY_LITE),
    ] + bg_cmds
    sev_tbl.setStyle(TableStyle(style_cmds))
    story.append(sev_tbl)
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — TECHNICAL FINDINGS  (premium evidence cards)
# ══════════════════════════════════════════════════════════════════════════════

def build_technical_findings(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "4. Technical Findings", bookmark_key="sec_technical_findings")

    m3       = data.get("module3", {})
    leaks_d  = data.get("leaks",   {})
    findings = merge_all_findings(m3, leaks_d)

    if not findings:
        story.append(Paragraph("No findings to report.", styles["body"]))
        story.append(PageBreak())
        return story

    seen_levels = set()
    _GROUP_TITLES = {
        "CRITICAL": "Critical Findings", "HIGH": "High Findings",
        "MEDIUM": "Medium Findings", "LOW": "Low Findings", "INFO": "Informational Findings",
    }

    for idx, finding in enumerate(findings, 1):
        level      = (finding.get("risk_level") or "INFO").upper().strip()
        color      = LEVEL_COLORS.get(level, C_INFO)
        bg_color   = LEVEL_BG.get(level, C_INFO_BG)
        subdomain  = finding.get("subdomain", "Unknown")
        technology = finding.get("technology", "N/A")
        version    = finding.get("version") or ""
        score      = _sanitise_score(finding.get("risk_score", 0))
        cves       = finding.get("matched_cves", [])
        in_kev     = finding.get("in_kev", False)
        exp_notes  = (finding.get("exposure_notes") or
                      finding.get("breakdown", {}).get("exposure_notes", ""))
        exposure_flags = [f.strip().replace(" ", "_")
                          for f in exp_notes.split(",") if f.strip()]
        remediation    = get_remediation(exposure_flags, technology, cves)

        # First time we see this severity level (findings are pre-sorted by
        # score desc, so same-severity findings are grouped together) —
        # drop a sub-bookmark so the PDF outline can jump straight to
        # "Critical Findings", "High Findings", etc.
        if level not in seen_levels:
            seen_levels.add(level)
            story.append(sub_bookmark(f"findings_{level.lower()}",
                                      _GROUP_TITLES.get(level, level), level=1))

        # Title text
        if finding.get("_from_leak"):
            title_text = (f"Finding #{idx:02d} — Exposed File: "
                          f"{finding.get('_leak_path','')} on {subdomain}")
        else:
            title_text = f"Finding #{idx:02d} — {technology} {version} on {subdomain}"

        # ── Header bar with severity badge + score ────────────────────────
        icon = LEVEL_ICON.get(level, "[-]")
        header_tbl = Table([[
            Paragraph(title_text, styles["finding_title"]),
            Paragraph(f"<b>{icon} {level}</b>",
                      ParagraphStyle("hbadge", fontSize=9, fontName="Helvetica-Bold",
                                     textColor=C_WHITE, leading=12, alignment=TA_CENTER)),
            Paragraph(f"<b>{score}/100</b>",
                      ParagraphStyle("sc", fontSize=11, fontName="Helvetica-Bold",
                                     textColor=C_WHITE, leading=14, alignment=TA_RIGHT)),
        ]], colWidths=[INNER_W * 0.68, INNER_W * 0.17, INNER_W * 0.15])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), color),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))

        # ── Detail table ──────────────────────────────────────────────────
        detail_rows = [
            ("Affected Asset",   subdomain),
            ("Technology",       f"{technology} {version}".strip()),
            ("Risk Level",       level),
            ("Risk Score",       f"{score} / 100"),
            ("Exposure Context", exp_notes or "None detected"),
        ]
        if in_kev:
            detail_rows.append(("CISA KEV",
                                 "ACTIVELY EXPLOITED IN THE WILD — patch immediately"))
        if finding.get("_leak_url"):
            detail_rows.append(("Evidence URL", finding["_leak_url"]))

        # Wrap detail table in a light background card
        detail_inner = kv_table(detail_rows)
        detail_card  = Table([[detail_inner]], colWidths=[INNER_W])
        detail_card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg_color),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        # ── CVE table ─────────────────────────────────────────────────────
        cve_elements = []
        if cves:
            cve_elements.append(Paragraph("<b>Matched CVEs</b>", styles["section_h3"]))
            hdr_ps  = ParagraphStyle("ch", fontSize=8, fontName="Helvetica-Bold",
                                      textColor=C_WHITE, leading=10)
            cell_ps = ParagraphStyle("cv", fontSize=7.5, fontName="Helvetica",
                                      textColor=C_GRAY_DARK, leading=10)
            link_ps = ParagraphStyle("cl", fontSize=7.5, fontName="Helvetica",
                                      textColor=C_BLUE,  leading=10)
            cve_data = [[Paragraph(h, hdr_ps) for h in
                         ["CVE ID", "CVSS", "Sources", "Summary"]]]
            for cve in cves[:8]:
                cvss_val = _sanitise_score(cve.get("cvss", 0))
                cvss_col = (C_CRITICAL if cvss_val >= 9 else C_HIGH if cvss_val >= 7
                            else C_MEDIUM if cvss_val >= 4 else C_LOW)
                kev_mark = " [KEV]" if cve.get("kev") else ""
                cve_data.append([
                    Paragraph(
                        f'<a href="{cve.get("url","#")}">'
                        f'<b>{cve.get("cve_id","?")}</b></a>{kev_mark}',
                        link_ps),
                    Paragraph(
                        f'<font color="#{cvss_col.hexval()[2:]}" size="8"><b>{cvss_val}</b></font>',
                        cell_ps),
                    Paragraph(", ".join(cve.get("sources", ["NVD"])), cell_ps),
                    Paragraph((cve.get("summary") or "")[:120], cell_ps),
                ])
            cw = INNER_W
            cve_tbl = Table(cve_data,
                             colWidths=[cw*0.20, cw*0.08, cw*0.14, cw*0.58],
                             repeatRows=1)
            cve_tbl.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1, 0), C_GRAY_DARK),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GRAY_VLIT]),
                ("VALIGN",         (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",     (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
                ("LEFTPADDING",    (0, 0), (-1, -1), 6),
                ("GRID",           (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
            ]))
            cve_elements.append(cve_tbl)

        # ── Remediation block ─────────────────────────────────────────────
        rem_elements = [
            Spacer(1, 0.2 * cm),
            Paragraph("<b>Remediation</b>", styles["section_h3"]),
            Paragraph(remediation["description"], styles["body"]),
            Paragraph(f"<b>Priority:</b> {remediation['priority']}", styles["body"]),
        ]
        for i, step in enumerate(remediation["steps"], 1):
            rem_elements.append(Paragraph(f"{i}. {step}", styles["body"]))
        for platform, cmd in (remediation.get("code") or {}).items():
            rem_elements.append(Paragraph(f"<i>{platform}:</i>", styles["body_small"]))
            rem_elements.append(Paragraph(cmd.replace("\n", "<br/>"), styles["mono"]))

        block = KeepTogether([
            header_tbl,
            detail_card,
        ] + cve_elements + rem_elements + [
            HRFlowable(width="100%", thickness=0.5, color=C_GRAY_LITE, spaceAfter=8),
            Spacer(1, 0.3 * cm),
        ])
        story.append(block)
        if idx % 3 == 0:
            story.append(PageBreak())

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — EXPOSED ASSET INVENTORY
# ══════════════════════════════════════════════════════════════════════════════

def build_asset_inventory(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "5. Exposed Asset Inventory", bookmark_key="sec_asset_inventory")

    m1           = data.get("module1", {})
    subdomains   = m1.get("subdomains", [])
    cloud_assets = m1.get("cloud_assets", [])
    leaked_creds = m1.get("leaked_credentials", [])
    alive        = [s for s in subdomains if s.get("is_alive")]

    story.append(Paragraph(
        f"<b>Alive Subdomains</b> ({len(alive)} of {len(subdomains)} discovered)",
        styles["section_h2"],
    ))

    if alive:
        hdr_s  = ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold",
                                 textColor=C_WHITE, leading=10)
        cell_s = ParagraphStyle("tc", fontSize=8, fontName="Helvetica",
                                 textColor=C_GRAY_DARK, leading=10)
        inv_data = [[Paragraph(h, hdr_s)
                     for h in ["Subdomain", "Status", "Open Ports", "Technologies"]]]
        for sub in sorted(alive, key=lambda x: (x.get("https_status")
                                                or x.get("http_status") or 999)):
            status = sub.get("https_status") or sub.get("http_status") or "?"
            ports  = ", ".join(str(p) for p in (sub.get("open_ports") or [])[:6])
            techs  = ", ".join((sub.get("technologies") or [])[:4])
            inv_data.append([
                Paragraph(sub.get("subdomain", "?"), cell_s),
                Paragraph(str(status), cell_s),
                Paragraph(ports or "—", cell_s),
                Paragraph(techs or "—", cell_s),
            ])
        inv_tbl = Table(inv_data,
                        colWidths=[INNER_W*0.38, INNER_W*0.09,
                                   INNER_W*0.17, INNER_W*0.36],
                        repeatRows=1)
        inv_tbl.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GRAY_VLIT]),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("GRID",           (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
        ]))
        story.append(inv_tbl)

    # Cloud assets
    if cloud_assets:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            f"<b>Cloud Assets</b> ({len(cloud_assets)} found)", styles["section_h2"]))
        for asset in cloud_assets:
            pub   = "[PUBLIC]" if asset.get("is_public") else "[Private]"
            color = "#C0392B" if asset.get("is_public") else "#718096"
            story.append(Paragraph(
                f'<font color="{color}"><b>{pub}</b></font>  '
                f'<b>{asset.get("provider","?")}/{asset.get("asset_type","?")}</b>  '
                f'— {asset.get("url","?")}',
                styles["body"],
            ))

    # Credential leaks
    if leaked_creds:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            f"<b>GitHub Credential Leaks</b> ({len(leaked_creds)} found)",
            styles["section_h2"]))
        for leak in leaked_creds[:20]:
            story.append(Paragraph(
                f"[{leak.get('credential_type','?')}]  "
                f"{leak.get('repo_url','?')}<br/>"
                f"File: {leak.get('file_path','?')}",
                styles["body"]))
            story.append(HRFlowable(width="100%", thickness=0.3, color=C_GRAY_LITE))

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — REMEDIATION ROADMAP
# ══════════════════════════════════════════════════════════════════════════════

def build_remediation_roadmap(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "6. Remediation Roadmap", bookmark_key="sec_remediation_roadmap")

    m3       = data.get("module3", {})
    leaks_d  = data.get("leaks",   {})
    findings = merge_all_findings(m3, leaks_d)

    lanes = {"IMMEDIATE": [], "1 WEEK": [], "1 MONTH": [], "90 DAYS": []}
    for f in sorted(findings, key=lambda x: _sanitise_score(x.get("risk_score", 0)),
                    reverse=True):
        lvl = (f.get("risk_level") or "INFO").upper()
        if   lvl == "CRITICAL": lanes["IMMEDIATE"].append(f)
        elif lvl == "HIGH":     lanes["1 WEEK"].append(f)
        elif lvl == "MEDIUM":   lanes["1 MONTH"].append(f)
        else:                   lanes["90 DAYS"].append(f)

    lane_colors  = {
        "IMMEDIATE": C_CRITICAL,
        "1 WEEK":    C_HIGH,
        "1 MONTH":   C_MEDIUM,
        "90 DAYS":   C_LOW,
    }
    lane_bg = {
        "IMMEDIATE": C_CRITICAL_BG,
        "1 WEEK":    C_HIGH_BG,
        "1 MONTH":   C_MEDIUM_BG,
        "90 DAYS":   C_LOW_BG,
    }

    for lane, lane_findings in lanes.items():
        if not lane_findings:
            continue

        lane_hdr = Table([[
            Paragraph(f"[!] {lane}",
                      ParagraphStyle("lh", fontSize=10, fontName="Helvetica-Bold",
                                     textColor=C_WHITE, leading=13)),
            Paragraph(f"{len(lane_findings)} item(s)",
                      ParagraphStyle("lc", fontSize=9, fontName="Helvetica",
                                     textColor=C_WHITE, leading=13, alignment=TA_RIGHT)),
        ]], colWidths=[INNER_W * 0.85, INNER_W * 0.15])
        lane_hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), lane_colors[lane]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(Spacer(1, 0.3 * cm))
        story.append(lane_hdr)

        bg = lane_bg[lane]
        for f in lane_findings[:10]:
            exp_notes = f.get("exposure_notes", "") or ""
            exp_flags = [e.strip().replace(" ", "_")
                         for e in exp_notes.split(",") if e.strip()]
            tech      = f.get("technology", "N/A")
            rem       = get_remediation(exp_flags, tech, f.get("matched_cves", []))

            card_data = [[
                Paragraph(
                    f"<b>{f.get('subdomain','?')}</b>  —  "
                    f"{tech} {f.get('version') or ''}  "
                    f"(score {_sanitise_score(f.get('risk_score',0)):.0f})",
                    styles["section_h3"]),
            ], [
                Paragraph(rem["description"], styles["body"]),
            ]]
            for i, step in enumerate(rem["steps"], 1):
                card_data.append([Paragraph(f"  {i}. {step}", styles["body"])])

            card = Table(card_data, colWidths=[INNER_W])
            card.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW",     (0, -1), (-1, -1), 0.5, C_GRAY_LITE),
            ]))
            story.append(card)

    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — APPENDIX: FULL CVE TABLE
# ══════════════════════════════════════════════════════════════════════════════

def build_appendix(styles: dict, data: dict) -> list:
    story = []
    story += section_divider(styles, "7. Appendix — Full CVE Table", bookmark_key="sec_appendix")

    m3       = data.get("module3", {})
    findings = m3.get("findings", [])

    all_cves: dict = {}
    for f in findings:
        for cve in f.get("matched_cves", []):
            cid = cve.get("cve_id", "")
            if cid and cid not in all_cves:
                all_cves[cid] = {**cve, "_subdomain": f.get("subdomain", "?")}

    if not all_cves:
        story.append(Paragraph("No CVEs were matched in this scan.", styles["body"]))
        return story

    sorted_cves = sorted(all_cves.values(),
                         key=lambda x: _sanitise_score(x.get("cvss", 0)),
                         reverse=True)

    hdr_s  = ParagraphStyle("th", fontSize=7.5, fontName="Helvetica-Bold",
                              textColor=C_WHITE, leading=10)
    cell_s = ParagraphStyle("tc", fontSize=7.5, fontName="Helvetica",
                              textColor=C_GRAY_DARK, leading=10)
    link_s = ParagraphStyle("lk", fontSize=7.5, fontName="Helvetica",
                              textColor=C_BLUE, leading=10)

    tbl_data = [[Paragraph(h, hdr_s)
                 for h in ["CVE ID", "CVSS", "KEV", "Sources",
                            "Affected Asset", "Summary"]]]
    for cve in sorted_cves:
        cvss_val = _sanitise_score(cve.get("cvss", 0))
        tbl_data.append([
            Paragraph(f'<a href="{cve.get("url","#")}">'
                      f'{cve.get("cve_id","?")}</a>', link_s),
            Paragraph(f"{cvss_val:.1f}", cell_s),
            Paragraph("[KEV]" if cve.get("kev") else "—", cell_s),
            Paragraph(", ".join(cve.get("sources", ["NVD"])), cell_s),
            Paragraph(cve.get("_subdomain", "?")[:30], cell_s),
            Paragraph((cve.get("summary") or "")[:100], cell_s),
        ])

    cw = INNER_W
    app_tbl = Table(tbl_data,
                    colWidths=[cw*0.19, cw*0.07, cw*0.06,
                               cw*0.12, cw*0.22, cw*0.34],
                    repeatRows=1)
    app_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GRAY_VLIT]),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("GRID",           (0, 0), (-1, -1), 0.3, C_GRAY_LITE),
    ]))
    story.append(app_tbl)
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(data: dict, output_path: str) -> str:
    styles = build_styles()
    meta   = data.get("meta",    {})
    domain = data.get("module1", {}).get("domain", "target.com")
    client = meta.get("client_name", "Client")

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        title=f"Security Assessment Report — {domain}",
        author=meta.get("assessor", "Security Team"),
        subject="Penetration Testing Report",
        creator=f"Asset Discovery Engine — Module 4 {REPORT_VERSION}",
    )

    # "Cover" — zero-margin, full-bleed frame; the cover art fills the whole page.
    cover_frame = Frame(0, 0, PAGE_W, PAGE_H,
                        leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0, id="cover_frame")

    # "Later" — the normal margined frame used for every page after the cover.
    normal_frame = Frame(MARGIN, 2.0 * cm, INNER_W,
                         PAGE_H - 1.6 * cm - 2.0 * cm, id="normal_frame")

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame]),
        PageTemplate(id="Later", frames=[normal_frame]),
    ])

    story  = []
    story += build_cover(styles, meta)          # ends with NextPageTemplate("Later") + PageBreak
    story += build_toc(styles)
    story += build_executive_summary(styles, data)
    story += build_methodology(styles, data)
    story += build_risk_overview(styles, data)
    story += build_technical_findings(styles, data)
    story += build_asset_inventory(styles, data)
    story += build_remediation_roadmap(styles, data)
    story += build_appendix(styles, data)

    canvas_factory = make_canvas_factory(
        client_name=client,
        domain=domain,
        assessor=meta.get("assessor", "Security Team"),
        report_version=REPORT_VERSION,
    )
    doc.build(story, canvasmaker=canvas_factory)
    return output_path


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT LOADERS
# ══════════════════════════════════════════════════════════════════════════════

def load_json(path: Optional[str], label: str) -> dict:
    if not path:
        return {}
    if not os.path.isfile(path):
        print(f"  WARNING: {label} not found at {path} — section will be empty.")
        return {}
    with open(path) as f:
        return json.load(f)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
║  MODULE 4 — Professional PDF Report Generator  {REPORT_VERSION:<17}║
║  Premium Edition: Dashboard • Heatmap • Attack Surface • Webhooks║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Module 4 — Generate a premium PDF pentest report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full report:
  python3 report_generator_v2.py \\
      --module1  reports/example.com_latest.json \\
      --module3  module3_reports/example.com_risk_report.json \\
      --leaks    module2_5_reports/example.com_leaks.json \\
      --client   "Acme Corp" --assessor "Hawk Security Ltd" \\
      --logo     /path/to/logo.png \\
      --confirm

  # With webhooks enabled (edit WEBHOOKS list at top of file first):
  python3 report_generator_v2.py --module1 ... --confirm
  # Telegram / Discord / Slack / Teams / Google Chat / Mattermost /
  # generic HTTP (any platform) fire automatically after the PDF is saved.

  # Test your webhook config without generating a report:
  python3 report_generator_v2.py --test-webhooks
        """,
    )
    parser.add_argument("--module1",    default=None)
    parser.add_argument("--module3",    default=None)
    parser.add_argument("--leaks",      default=None)
    parser.add_argument("--client",     default="Client Organisation")
    parser.add_argument("--assessor",   default="Security Team")
    parser.add_argument("--label",      default="PENETRATION TESTING REPORT")
    parser.add_argument("--logo",       default=None,
                        help="Path to PNG/JPG logo for cover page (optional)")
    parser.add_argument("--output-dir", default="module4_reports")
    parser.add_argument("--version",    default=REPORT_VERSION,
                        help="Report version string shown in header")
    parser.add_argument("--confirm",    action="store_true")
    parser.add_argument("--test-webhooks", action="store_true",
                        help="Send a dummy notification to every enabled "
                             "webhook slot and exit (no PDF generated).")
    args = parser.parse_args()

    if args.test_webhooks:
        test_webhooks()
        return

    if not args.confirm:
        print("ERROR: Add --confirm to certify you are authorized to generate this report.")
        sys.exit(1)
    if not args.module1 and not args.module3:
        print("ERROR: Provide at least --module1 or --module3 JSON report.")
        sys.exit(1)

    m1_data = load_json(args.module1, "Module 1 report")
    m3_data = load_json(args.module3, "Module 3 report")
    lk_data = load_json(args.leaks,   "Module 2.5 leaks")

    domain   = m1_data.get("domain") or m3_data.get("domain") or "unknown"
    date_str = datetime.now().strftime("%B %d, %Y")
    ts       = int(time.time())

    data = {
        "meta": {
            "client_name":   args.client,
            "assessor":      args.assessor,
            "domain":        domain,
            "date":          date_str,
            "report_label":  args.label,
            "logo_path":     args.logo,
            "report_version":args.version,
        },
        "module1": m1_data,
        "module3": m3_data,
        "leaks":   lk_data,
    }

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(args.output_dir,
                            f"{domain}_pentest_report_{ts}.pdf")

    print(f"  Client      : {args.client}")
    print(f"  Domain      : {domain}")
    print(f"  Assessor    : {args.assessor}")
    print(f"  Logo        : {args.logo or 'none'}")
    print(f"  Output      : {out_path}")
    print(f"  Report ver  : {args.version}")
    print("\n  Generating PDF…")

    t0 = time.time()
    generate_report(data, out_path)
    elapsed = time.time() - t0

    print(f"  ✓ Report saved: {out_path}  ({elapsed:.1f}s)")

    # ── Webhooks ──────────────────────────────────────────────────────────
    live_counts  = count_by_severity(merge_all_findings(m3_data, lk_data))
    verdict      = _risk_verdict(live_counts, m3_data.get("kev_matches", 0))
    fire_webhooks(out_path, data, live_counts, verdict)

    print(f"\n  Pages: cover • TOC • exec summary • methodology • risk overview")
    print(f"         (incl. heatmap + attack surface) • findings • assets")
    print(f"         • remediation roadmap • CVE appendix\n")


if __name__ == "__main__":
    main()
