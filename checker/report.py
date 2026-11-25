"""Builds the alert email as a professional HTML report.

Email clients (Outlook especially) only render simple HTML reliably, so the layout uses
tables and inline styles only: no external CSS, web fonts, images or scripts.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from zoneinfo import ZoneInfo

REPORT_TZ = ZoneInfo("Africa/Johannesburg")
TITLE = "Software Update &amp; Vulnerability Report"

# Colours
NAVY = "#14233c"
INK = "#1f2937"
MUTED = "#6b7280"
LINE = "#e5e7eb"
BG = "#f3f4f6"
RED = "#b91c1c"
RED_BG = "#fef2f2"
AMBER = "#b45309"
AMBER_BG = "#fffbeb"
BLUE = "#1d4ed8"
BLUE_BG = "#eff6ff"
GREEN = "#047857"

FONT = "Segoe UI, Helvetica, Arial, sans-serif"

VENDOR_RULES = [
    (r"azure|microsoft|windows|sql server|exchange|entra|intune|defender|sentinel|teams|m365|office", "Microsoft"),
    (r"quest", "Quest"),
    (r"one identity", "One Identity"),
    (r"kemp|loadmaster|flowmon|progress", "Progress Kemp"),
    (r"fortinet|forti", "Fortinet"),
    (r"bloodhound|specterops", "SpecterOps"),
    (r"netwrix|pingcastle", "Netwrix"),
    (r"veeam", "Veeam"),
    (r"crowdstrike", "CrowdStrike"),
    (r"proofpoint", "Proofpoint"),
    (r"yubico", "Yubico"),
    (r"commvault", "Commvault"),
]

# Order vendors appear in the report; anything else follows alphabetically.
VENDOR_ORDER = ["Microsoft", "Quest", "One Identity", "Progress Kemp"]


def vendor_of(src: dict, it: dict) -> str:
    if it.get("vendor"):
        return it["vendor"]
    if src.get("vendor"):
        return src["vendor"]
    name = src.get("name", "").lower()
    for pat, vendor in VENDOR_RULES:
        if re.search(pat, name):
            return vendor
    return src.get("name", "Other").split(" ")[0]


def product_of(src: dict, it: dict) -> str:
    if it.get("product"):
        return it["product"]
    return re.sub(r"\s*\(.*?\)", "", src.get("name", ""))


def _e(s) -> str:
    return html.escape(str(s or ""))


def _badge(text: str, fg: str, bg: str) -> str:
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;'
            f'font-weight:600;color:{fg};background:{bg};border:1px solid {fg}33;white-space:nowrap">{_e(text)}</span>')


def _severity_badge(it: dict, section: str) -> str:
    sev = (it.get("severity") or "").upper()
    if it.get("exploited"):
        return _badge("Actively exploited", RED, RED_BG)
    if sev.startswith("CRITICAL"):
        return _badge(it.get("severity_label") or "Critical", RED, RED_BG)
    if sev.startswith("HIGH"):
        return _badge(it.get("severity_label") or "High", AMBER, AMBER_BG)
    if sev.startswith("MEDIUM"):
        return _badge(it.get("severity_label") or "Medium", "#92400e", "#fefce8")
    if sev.startswith("LOW"):
        return _badge(it.get("severity_label") or "Low", MUTED, BG)
    if section == "security":
        return _badge("Advisory", AMBER, AMBER_BG)
    status = it.get("status", "").lower()
    if "retire" in status:
        return _badge("Retirement", "#7c2d12", "#fff7ed")
    if "preview" in status:
        return _badge("Preview", "#6d28d9", "#f5f3ff")
    if "launch" in status or "available" in status:
        return _badge("Generally available", GREEN, "#ecfdf5")
    return _badge("Update", BLUE, BLUE_BG)


def _fmt_date(s: str) -> str:
    if not s:
        return ""
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s.strip(), fmt).strftime("%d %b %Y")
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%d %b %Y")
    except ValueError:
        return s[:16]


def _tile(label: str, value: int, colour: str, bg: str) -> str:
    return (f'<td width="33%" style="padding:0 6px" valign="top">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:{bg};border:1px solid {LINE};border-top:4px solid {colour};border-radius:6px">'
            f'<tr><td style="padding:14px 16px;font-family:{FONT}">'
            f'<div style="font-size:28px;font-weight:700;color:{colour};line-height:1">{value}</div>'
            f'<div style="font-size:12px;color:{MUTED};margin-top:6px;text-transform:uppercase;letter-spacing:.5px">{label}</div>'
            f'</td></tr></table></td>')


def _section(title: str, intro: str, rows: list[tuple[dict, dict]], colour: str, kind: str) -> str:
    if not rows:
        return ""
    groups: dict[str, list[tuple[dict, dict]]] = {}
    for s, i in rows:
        groups.setdefault(vendor_of(s, i), []).append((s, i))
    order = sorted(groups, key=lambda v: (VENDOR_ORDER.index(v) if v in VENDOR_ORDER else 99, v.lower()))

    out = [f'<tr><td style="padding:28px 32px 4px;font-family:{FONT}">'
           f'<div style="font-size:18px;font-weight:700;color:{INK};border-left:4px solid {colour};padding-left:10px">'
           f'{title} <span style="color:{MUTED};font-weight:400">({len(rows)})</span></div>'
           f'<div style="font-size:13px;color:{MUTED};margin:6px 0 0 14px">{intro}</div></td></tr>']
    for vendor in order:
        items = groups[vendor]
        out.append(f'<tr><td style="padding:14px 32px 0;font-family:{FONT}">'
                   f'<div style="font-size:13px;font-weight:700;color:{NAVY};text-transform:uppercase;letter-spacing:.6px;'
                   f'padding-bottom:6px;border-bottom:2px solid {NAVY}">{_e(vendor)} '
                   f'<span style="color:{MUTED};font-weight:400">· {len(items)}</span></div>'
                   f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">')
        for s, i in items:
            m = re.match(r"\s*\[([^\]]+)\]\s*(.*)", i["title"])
            if m:
                i = {**i, "status": m.group(1), "title": m.group(2)}
            title_html = (f'<a href="{_e(i["link"])}" style="color:{INK};text-decoration:none;font-weight:600">{_e(i["title"])}</a>'
                          if i.get("link") else f'<span style="font-weight:600">{_e(i["title"])}</span>')
            summary = _e(i.get("summary", "")).replace("\n", "<br>")
            action = (f'<div style="margin-top:6px;font-size:12px;color:{RED}"><b>Required action:</b> {_e(i["action"])}</div>'
                      if i.get("action") else "")
            link = (f'<div style="margin-top:8px"><a href="{_e(i["link"])}" style="font-size:12px;color:{BLUE};'
                    f'text-decoration:none;font-weight:600">{"View advisory" if kind != "update" else "Release notes"} &rarr;</a></div>'
                    if i.get("link") else "")
            out.append(
                f'<tr><td style="padding:12px 0;border-bottom:1px solid {LINE};font-family:{FONT}" valign="top">'
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
                f'<td valign="top" style="font-family:{FONT}">'
                f'<div style="font-size:11px;color:{MUTED};text-transform:uppercase;letter-spacing:.4px">{_e(product_of(s, i))}</div>'
                f'<div style="font-size:14px;color:{INK};margin-top:2px">{title_html}</div>'
                f'<div style="font-size:13px;color:#4b5563;margin-top:4px;line-height:1.45">{summary}</div>'
                f'{action}{link}</td>'
                f'<td valign="top" align="right" width="150" style="font-family:{FONT};padding-left:12px">'
                f'{_severity_badge(i, kind)}'
                f'<div style="font-size:11px;color:{MUTED};margin-top:6px">{_e(_fmt_date(i.get("date", "")))}</div>'
                f'</td></tr></table></td></tr>')
        out.append('</table></td></tr>')
    return "".join(out)


def build_report(new: list[tuple[dict, dict]], broken: list[tuple[str, dict, str]],
                 sources_checked: int, now: dt.datetime, sample: bool = False) -> tuple[str, str, str]:
    urgent = [(s, i) for s, i in new if i["urgent"]]
    security = [(s, i) for s, i in new if not i["urgent"] and s["category"] == "security"]
    updates = [(s, i) for s, i in new if not i["urgent"] and s["category"] != "security"]

    local = now.astimezone(REPORT_TZ)
    stamp = local.strftime("%A %d %B %Y, %H:%M") + " (SAST)"

    parts = []
    if urgent:
        parts.append(f"{len(urgent)} urgent")
    if security:
        parts.append(f"{len(security)} security")
    if updates:
        parts.append(f"{len(updates)} update{'s' if len(updates) != 1 else ''}")
    prefix = "[SAMPLE] " if sample else ("[URGENT] " if urgent else "")
    subject = f"{prefix}Software Update & Vulnerability Report: " + (", ".join(parts) if parts else "source health")

    # Headline sentence
    if urgent:
        headline = (f'<b style="color:{RED}">{len(urgent)} item{"s" if len(urgent) != 1 else ""} need'
                    f'{"" if len(urgent) != 1 else "s"} urgent attention.</b> Review the urgent section first.')
    elif security:
        headline = "No urgent issues. New security advisories are listed below for review."
    else:
        headline = "No urgent or security issues. New product updates are listed below."

    sample_banner = (f'<tr><td style="background:{AMBER_BG};border-bottom:1px solid {LINE};padding:10px 32px;'
                     f'font-family:{FONT};font-size:12px;color:{AMBER}"><b>Sample report.</b> Built from the latest '
                     f'real items in each source to preview the layout. Live reports contain only items that are new since the previous check.</td></tr>'
                     if sample else "")

    health = ""
    if broken:
        health = (f'<tr><td style="padding:24px 32px 0;font-family:{FONT}">'
                  f'<div style="background:{BG};border:1px solid {LINE};border-radius:6px;padding:12px 16px">'
                  f'<div style="font-size:13px;font-weight:700;color:{INK}">Sources that need attention</div>'
                  f'<div style="font-size:12px;color:{MUTED};margin-top:2px">These sources could not be checked on three consecutive runs.</div>'
                  '<ul style="margin:8px 0 0 18px;padding:0;font-size:12px;color:#4b5563">'
                  + "".join(f"<li>{_e(s['name'])}: {_e(err)}</li>" for _, s, err in broken) +
                  '</ul></div></td></tr>')

    body_html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{TITLE}</title></head>
<body style="margin:0;padding:0;background:{BG}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{BG}"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="760" cellpadding="0" cellspacing="0" style="max-width:760px;width:100%;background:#ffffff;border:1px solid {LINE};border-radius:8px;overflow:hidden">
  <tr><td style="background:{NAVY};padding:24px 32px;font-family:{FONT}">
    <div style="font-size:11px;color:#9fb3d1;text-transform:uppercase;letter-spacing:1.2px">Security &amp; Platform Intelligence</div>
    <div style="font-size:22px;font-weight:700;color:#ffffff;margin-top:4px">{TITLE}</div>
    <div style="font-size:13px;color:#c7d2e3;margin-top:6px">{stamp}</div>
  </td></tr>
  {sample_banner}
  <tr><td style="padding:24px 26px 4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      {_tile("Urgent", len(urgent), RED, "#ffffff")}
      {_tile("Security advisories", len(security), AMBER, "#ffffff")}
      {_tile("Product updates", len(updates), BLUE, "#ffffff")}
    </tr></table>
  </td></tr>
  <tr><td style="padding:16px 32px 0;font-family:{FONT};font-size:14px;color:{INK};line-height:1.5">{headline}</td></tr>
  {_section("Urgent: actively exploited or critical", "Known to be exploited in the wild (CISA KEV) or rated CVSS 9.0 and above. Patch or mitigate as a priority.", urgent, RED, "security")}
  {_section("Security advisories", "New vulnerabilities and vendor advisories for the products we track.", security, AMBER, "security")}
  {_section("Product updates and release notes", "New versions, features, retirements and service changes.", updates, BLUE, "update")}
  {health}
  <tr><td style="padding:28px 32px 24px;font-family:{FONT}">
    <div style="border-top:1px solid {LINE};padding-top:14px;font-size:11px;color:#9ca3af;line-height:1.6">
      {sources_checked} sources checked hourly, including CISA Known Exploited Vulnerabilities, the US National Vulnerability Database,
      the Microsoft Security Update Guide, Azure Updates, the Microsoft 365 Roadmap and vendor release and advisory pages.
      You receive this report only when something new is found.
    </div>
  </td></tr>
</table>
</td></tr></table>
</body></html>'''

    # Plain-text version for clients that don't show HTML
    lines = [TITLE.replace("&amp;", "&"), stamp, ""]
    lines.append(f"Urgent: {len(urgent)}   Security advisories: {len(security)}   Product updates: {len(updates)}")
    for title, rows in (("URGENT", urgent), ("SECURITY ADVISORIES", security), ("PRODUCT UPDATES", updates)):
        if not rows:
            continue
        lines += ["", f"== {title} ({len(rows)}) =="]
        for s, i in sorted(rows, key=lambda r: vendor_of(*r)):
            lines.append(f"- [{vendor_of(s, i)}] {i['title']}")
            if i.get("link"):
                lines.append(f"  {i['link']}")
    if broken:
        lines += ["", "== Sources that need attention =="] + [f"- {s['name']}: {err}" for _, s, err in broken]
    return subject, body_html, "\n".join(lines)
