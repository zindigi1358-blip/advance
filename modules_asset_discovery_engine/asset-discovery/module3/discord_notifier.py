"""
Module 3 — Discord Multi-Webhook Notifier
=============================================
Broadcasts risk alerts to ALL configured Discord webhooks (up to 5+,
config.DISCORD_WEBHOOKS list has no hard cap). Same embed pattern used
in the honeypot monitor project — reused here for consistency.
"""
import requests
import config

RISK_COLORS = {
    "CRITICAL": 10038562,   # dark red
    "HIGH":     15158332,   # red
    "MEDIUM":   16776960,   # yellow
    "LOW":      3066993,    # green
    "INFO":     9807270,    # gray
}

RISK_LEVEL_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _meets_threshold(level: str) -> bool:
    try:
        return RISK_LEVEL_ORDER.index(level) >= RISK_LEVEL_ORDER.index(config.DISCORD_ALERT_MIN_LEVEL)
    except ValueError:
        return False


def _active_webhooks() -> list:
    """Returns only the non-empty configured webhook URLs."""
    return [w.strip() for w in config.DISCORD_WEBHOOKS if w and w.strip()]


def _send_embed(embed: dict):
    """Sends one embed to every configured webhook. Never raises —
    a failed webhook (bad URL, deleted channel) shouldn't crash the scan."""
    webhooks = _active_webhooks()
    if not webhooks:
        return

    payload = {"embeds": [embed]}
    for url in webhooks:
        try:
            requests.post(url, json=payload, timeout=6)
        except Exception as e:
            print(f"⚠️ Discord webhook failed ({url[:40]}...): {e}")


def build_summary_embed(summary: dict) -> dict:
    color = RISK_COLORS["CRITICAL"] if summary["critical_count"] > 0 else RISK_COLORS["HIGH"]
    return {
        "title": f"🛡️ Risk Scan Complete — {summary['domain']}",
        "color": color,
        "fields": [
            {"name": "🔴 Critical", "value": str(summary["critical_count"]), "inline": True},
            {"name": "🟠 High",     "value": str(summary["high_count"]),     "inline": True},
            {"name": "🟡 Medium",   "value": str(summary["medium_count"]),   "inline": True},
            {"name": "🟢 Low",      "value": str(summary["low_count"]),      "inline": True},
            {"name": "☠️ Actively Exploited (KEV)", "value": str(summary["kev_matches"]), "inline": True},
            {"name": "📊 Total Findings", "value": str(summary["total_findings"]), "inline": True},
        ],
        "footer": {"text": "Module 3 — Risk Scoring & CVE Matching Engine"},
    }


def build_finding_embed(finding: dict) -> dict:
    cves_text = "\n".join(
        f"• {c['cve_id']} (CVSS {c['cvss']}) — {c.get('source', 'NVD')}"
        for c in finding["matched_cves"][:5]
    ) or "No specific CVE — flagged on exposure context alone"

    fields = [
        {"name": "🎯 Subdomain",  "value": finding["subdomain"], "inline": True},
        {"name": "⚙️ Technology", "value": f"{finding['technology']} {finding['version'] or ''}", "inline": True},
        {"name": "📈 Risk Score", "value": f"{finding['risk_score']}/100", "inline": True},
        {"name": "🔍 Matched CVEs", "value": cves_text[:1000], "inline": False},
    ]
    if finding.get("exposure_notes"):
        fields.append({"name": "⚠️ Exposure Context", "value": finding["exposure_notes"][:500], "inline": False})
    if finding.get("in_kev"):
        fields.append({"name": "☠️ CISA KEV", "value": "**ACTIVELY EXPLOITED IN THE WILD** — patch immediately", "inline": False})

    return {
        "title": f"[{finding['risk_level']}] Vulnerability Finding",
        "color": RISK_COLORS.get(finding["risk_level"], RISK_COLORS["INFO"]),
        "fields": fields,
        "footer": {"text": "Module 3 — Risk Scoring & CVE Matching Engine"},
    }


def send_alert(summary: dict):
    """
    Main entry point — call this after a scan completes.
    Sends: 1 summary embed + 1 embed per finding that meets DISCORD_ALERT_MIN_LEVEL.
    """
    if not _active_webhooks():
        return  # no webhooks configured — nothing to do, not an error

    _send_embed(build_summary_embed(summary))

    alertable = [f for f in summary["findings"] if _meets_threshold(f["risk_level"])]
    for finding in alertable:
        _send_embed(build_finding_embed(finding))
