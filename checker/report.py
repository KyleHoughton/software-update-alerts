"""Builds the alert email as a Symbiosys-branded HTML report.

Email clients (Outlook especially) only render simple HTML reliably, so the layout uses
tables and inline styles only. The logo is attached inline and referenced as cid:LOGO_CID.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from pathlib import Path
from zoneinfo import ZoneInfo

REPORT_TZ = ZoneInfo("Africa/Johannesburg")
TITLE = "Symbiosys Software Updates &amp; Vulnerability Report"
LOGO_FILE = Path(__file__).resolve().parent.parent / "assets" / "logo-email.png"
LOGO_CID = "symbiosys-logo"

# Symbiosys brand colours (from symbiosys.it)
NAVY = "#071320"
NAVY_2 = "#0F2F63"
ORANGE = "#FE9026"
CREAM = "#F4F2EA"
INK = "#1c2430"
MUTED = "#5f6b7a"
LINE = "#e3e6ea"
ZEBRA = "#fafbfc"

# Severity colours
RED, RED_BG = "#b42318", "#fef3f2"
AMBER, AMBER_BG = "#b54708", "#fffaeb"
YELLOW, YELLOW_BG = "#8a6a00", "#fefbe8"
BLUE, BLUE_BG = "#0F2F63", "#eef4ff"
GREEN, GREEN_BG = "#067647", "#ecfdf3"
PURPLE, PURPLE_BG = "#5925dc", "#f4f3ff"
GREY, GREY_BG = "#475467", "#f2f4f7"

FONT = "'Segoe UI', Calibri, Helvetica, Arial, sans-serif"

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
    (r"cisa", "Other vendors"),
]
VENDOR_ORDER = ["Microsoft", "Quest", "One Identity", "Progress Kemp"]


# --------------------------------------------------------------------------- helpers

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


def _clip(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def _fmt_date(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s, fmt).strftime("%d %b %Y")
        except ValueError:
            pass
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%d %b %Y")
    except ValueError:
        return s[:16]


def _badge(text: str, fg: str, bg: str) -> str:
    return (f'<span style="display:inline-block;padding:3px 9px;border-radius:3px;font-size:10px;font-weight:700;'
            f'letter-spacing:.4px;text-transform:uppercase;color:{fg};background:{bg};border:1px solid {fg}40;'
            f'white-space:nowrap;font-family:{FONT}">{_e(text)}</span>')


def _status(it: dict, kind: str) -> tuple[str, str, str]:
    """Return (label, fg, bg) for the item's severity or status."""
    sev = (it.get("severity") or "").upper()
    if it.get("exploited"):
        return "Exploited", RED, RED_BG
    if sev.startswith("CRITICAL"):
        return it.get("severity_label") or "Critical", RED, RED_BG
    if sev.startswith("HIGH"):
        return it.get("severity_label") or "High", AMBER, AMBER_BG
    if sev.startswith("MEDIUM"):
        return it.get("severity_label") or "Medium", YELLOW, YELLOW_BG
    if sev.startswith("LOW"):
        return it.get("severity_label") or "Low", GREY, GREY_BG
    if kind == "security":
        return "Advisory", AMBER, AMBER_BG
    st = (it.get("status") or "").lower()
    if "retire" in st:
        return "Retirement", "#93370d", "#fff6ed"
    if "preview" in st:
        return "Preview", PURPLE, PURPLE_BG
    if "launch" in st or "available" in st:
        return "Available", GREEN, GREEN_BG
    if "progress" in st or "development" in st or "rolling" in st:
        return "Rolling out", BLUE, BLUE_BG
    return "Update", BLUE, BLUE_BG


def _normalise(it: dict) -> dict:
    """Pull '[Launched]'-style prefixes out of titles into a status field."""
    m = re.match(r"\s*\[([^\]]+)\]\s*(.*)", it.get("title", ""))
    if m:
        it = {**it, "status": m.group(1), "title": m.group(2)}
    return it


# --------------------------------------------------------------------------- building blocks

def _kpi(label: str, value: int, colour: str, note: str) -> str:
    return (f'<td width="25%" valign="top" style="padding:0 5px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border:1px solid {LINE};border-top:3px solid {colour};background:#ffffff">'
            f'<tr><td style="padding:12px 14px;font-family:{FONT}">'
            f'<div style="font-size:26px;font-weight:700;color:{colour};line-height:1.1">{value}</div>'
            f'<div style="font-size:11px;font-weight:700;color:{INK};text-transform:uppercase;letter-spacing:.6px;margin-top:4px">{label}</div>'
            f'<div style="font-size:11px;color:{MUTED};margin-top:2px">{note}</div>'
            f'</td></tr></table></td>')


def _section_heading(number: int, title: str, intro: str, colour: str, count: int) -> str:
    return (f'<tr><td style="padding:30px 36px 10px;font-family:{FONT}">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
            f'<td style="font-family:{FONT}">'
            f'<div style="font-size:11px;font-weight:700;color:{colour};letter-spacing:1.2px;text-transform:uppercase">Section {number}</div>'
            f'<div style="font-size:18px;font-weight:700;color:{NAVY};margin-top:2px">{title} '
            f'<span style="font-weight:400;color:{MUTED}">({count})</span></div>'
            f'<div style="font-size:12px;color:{MUTED};margin-top:4px">{intro}</div></td></tr>'
            f'<tr><td style="padding-top:10px"><div style="height:2px;background:{colour};width:48px;font-size:0;line-height:0">&nbsp;</div></td></tr>'
            f'</table></td></tr>')


def _table(rows: list[tuple[dict, dict]], kind: str, detail_chars: int) -> str:
    groups: dict[str, list[tuple[dict, dict]]] = {}
    for s, i in rows:
        groups.setdefault(vendor_of(s, i), []).append((s, _normalise(i)))
    order = sorted(groups, key=lambda v: (VENDOR_ORDER.index(v) if v in VENDOR_ORDER else 99, v.lower()))

    th = (f'style="padding:8px 10px;font-family:{FONT};font-size:10px;font-weight:700;color:#ffffff;'
          f'text-transform:uppercase;letter-spacing:.6px;text-align:left;background:{NAVY_2}"')
    out = [f'<tr><td style="padding:0 36px">'
           f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid {LINE}">'
           f'<tr><th {th} width="22%">Product</th><th {th}>Details</th>'
           f'<th {th} width="15%">{"Severity" if kind == "security" else "Status"}</th><th {th} width="13%">Date</th></tr>']
    for vendor in order:
        items = groups[vendor]
        out.append(f'<tr><td colspan="4" style="padding:7px 10px;background:{CREAM};border-top:1px solid {LINE};'
                   f'font-family:{FONT};font-size:12px;font-weight:700;color:{NAVY}">'
                   f'<span style="color:{ORANGE}">&#9632;</span>&nbsp; {_e(vendor)} '
                   f'<span style="font-weight:400;color:{MUTED}">&middot; {len(items)} item{"s" if len(items) != 1 else ""}</span></td></tr>')
        for n, (s, i) in enumerate(items):
            bg = ZEBRA if n % 2 else "#ffffff"
            label, fg, sbg = _status(i, kind)
            title = (f'<a href="{_e(i["link"])}" style="color:{NAVY_2};text-decoration:none;font-weight:600">{_e(i["title"])}</a>'
                     if i.get("link") else f'<span style="font-weight:600">{_e(i["title"])}</span>')
            detail = _clip(i.get("summary", "").replace("•", " "), detail_chars)
            detail_html = f'<div style="margin-top:3px;color:{MUTED};font-size:12px;line-height:1.45">{_e(detail)}</div>' if detail else ""
            action = (f'<div style="margin-top:5px;font-size:12px;color:{RED};line-height:1.45"><b>Action:</b> {_e(i["action"])}</div>'
                      if i.get("action") else "")
            td = f'style="padding:9px 10px;border-top:1px solid {LINE};background:{bg};font-family:{FONT};vertical-align:top'
            out.append(
                f'<tr><td {td};font-size:12px;color:{INK};font-weight:600">{_e(product_of(s, i))}</td>'
                f'<td {td};font-size:13px;color:{INK};line-height:1.4">{title}{detail_html}{action}</td>'
                f'<td {td}">{_badge(label, fg, sbg)}</td>'
                f'<td {td};font-size:12px;color:{MUTED};white-space:nowrap">{_e(_fmt_date(i.get("date", "")))}</td></tr>')
    out.append('</table></td></tr>')
    return "".join(out)


# --------------------------------------------------------------------------- report

def build_report(new: list[tuple[dict, dict]], broken: list[tuple[str, dict, str]],
                 sources_checked: int, now: dt.datetime, sample: bool = False,
                 logo_src: str = f"cid:{LOGO_CID}") -> tuple[str, str, str]:
    urgent = [(s, i) for s, i in new if i["urgent"]]
    security = [(s, i) for s, i in new if not i["urgent"] and s["category"] == "security"]
    updates = [(s, i) for s, i in new if not i["urgent"] and s["category"] != "security"]
    vendors = sorted({vendor_of(s, i) for s, i in new})

    local = now.astimezone(REPORT_TZ)
    date_long = local.strftime("%A, %d %B %Y")
    time_str = local.strftime("%H:%M") + " SAST"
    ref = "SYM-SUVR-" + local.strftime("%Y%m%d-%H%M")

    parts = []
    if urgent:
        parts.append(f"{len(urgent)} urgent")
    if security:
        parts.append(f"{len(security)} security")
    if updates:
        parts.append(f"{len(updates)} update{'s' if len(updates) != 1 else ''}")
    prefix = "[SAMPLE] " if sample else ("[URGENT] " if urgent else "")
    subject = (f"{prefix}Symbiosys Software Updates & Vulnerability Report | {local.strftime('%d %b %Y %H:%M')} | "
               + (", ".join(parts) if parts else "source health"))

    # Executive summary
    if urgent:
        status_txt, status_fg, status_bg = "Action required", RED, RED_BG
        summary = (f"{len(urgent)} vulnerabilit{'ies' if len(urgent) != 1 else 'y'} known to be actively exploited or rated critical "
                   f"{'were' if len(urgent) != 1 else 'was'} identified and should be assessed and remediated as a priority.")
    elif security:
        status_txt, status_fg, status_bg = "Review advised", AMBER, AMBER_BG
        summary = "No actively exploited or critical issues were identified. New security advisories are listed for review."
    else:
        status_txt, status_fg, status_bg = "Informational", GREEN, GREEN_BG
        summary = "No new security issues were identified. New product releases and service changes are listed below."
    summary += (f" This report covers {len(new)} new item{'s' if len(new) != 1 else ''} across "
                f"{len(vendors)} vendor{'s' if len(vendors) != 1 else ''}.")

    highlights = ""
    top = (urgent + security)[:3]
    if top:
        lis = "".join(
            f'<tr><td valign="top" style="padding:3px 8px 3px 0;color:{ORANGE};font-size:12px">&#9656;</td>'
            f'<td style="padding:3px 0;font-family:{FONT};font-size:12px;color:{INK};line-height:1.45">'
            f'<b>{_e(vendor_of(s, i))}</b> &middot; {_e(_clip(_normalise(i)["title"], 110))}</td></tr>'
            for s, i in top)
        highlights = (f'<div style="font-size:11px;font-weight:700;color:{NAVY};text-transform:uppercase;letter-spacing:.6px;margin-top:14px">Key items</div>'
                      f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:4px">{lis}</table>')

    sample_banner = (f'<tr><td style="background:{CREAM};border-bottom:1px solid {LINE};padding:9px 36px;'
                     f'font-family:{FONT};font-size:11px;color:{MUTED}"><b style="color:{ORANGE}">SAMPLE REPORT</b> &nbsp;'
                     f'Built from the latest items in each source to preview the format. Live reports list only items new since the previous check.</td></tr>'
                     if sample else "")

    sections, n = [], 0
    if urgent:
        n += 1
        sections.append(_section_heading(n, "Urgent: actively exploited or critical",
                                         "Listed in the CISA Known Exploited Vulnerabilities catalogue or rated CVSS 9.0 and above. Prioritise patching or mitigation.",
                                         RED, len(urgent)))
        sections.append(_table(urgent, "security", 260))
    if security:
        n += 1
        sections.append(_section_heading(n, "Security advisories",
                                         "New vulnerabilities (CVE) and vendor security advisories affecting tracked products.",
                                         AMBER, len(security)))
        sections.append(_table(security, "security", 200))
    if updates:
        n += 1
        sections.append(_section_heading(n, "Product updates &amp; release notes",
                                         "New versions, features, previews, retirements and service changes.",
                                         NAVY_2, len(updates)))
        sections.append(_table(updates, "update", 170))

    health = ""
    if broken:
        health = (f'<tr><td style="padding:26px 36px 0;font-family:{FONT}">'
                  f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {LINE};border-left:3px solid {GREY}">'
                  f'<tr><td style="padding:12px 16px;font-family:{FONT}">'
                  f'<div style="font-size:12px;font-weight:700;color:{INK}">Source monitoring notice</div>'
                  f'<div style="font-size:12px;color:{MUTED};margin-top:2px">The following sources could not be checked on three consecutive runs:</div>'
                  '<ul style="margin:6px 0 0 18px;padding:0;font-size:12px;color:#475467">'
                  + "".join(f"<li>{_e(s['name'])}: {_e(err)}</li>" for _, s, err in broken) +
                  '</ul></td></tr></table></td></tr>')

    body_html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting"><title>{TITLE}</title></head>
<body style="margin:0;padding:0;background:#eceef1">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eceef1"><tr><td align="center" style="padding:24px 10px">
<table role="presentation" width="800" cellpadding="0" cellspacing="0" style="max-width:800px;width:100%;background:#ffffff;border:1px solid #d9dde3">

  <!-- Header -->
  <tr><td style="background:{NAVY};padding:26px 36px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="middle" style="font-family:{FONT}">
        <div style="font-size:10px;font-weight:700;color:{ORANGE};letter-spacing:1.6px;text-transform:uppercase">Security Intelligence &middot; Hourly Brief</div>
        <div style="font-size:21px;font-weight:700;color:#ffffff;margin-top:6px;line-height:1.25">Symbiosys Software Updates<br>&amp; Vulnerability Report</div>
      </td>
      <td valign="middle" align="right" width="200" style="padding-left:16px">
        <img src="{logo_src}" width="180" alt="Symbiosys" style="display:block;width:180px;height:auto;border:0;outline:none">
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="background:{ORANGE};height:4px;font-size:0;line-height:0">&nbsp;</td></tr>

  <!-- Meta bar -->
  <tr><td style="background:{CREAM};padding:10px 36px;border-bottom:1px solid {LINE}">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:{FONT};font-size:11px;color:{MUTED}"><b style="color:{INK}">Report date:</b> {date_long} &nbsp;|&nbsp; <b style="color:{INK}">Time:</b> {time_str}</td>
      <td align="right" style="font-family:{FONT};font-size:11px;color:{MUTED}"><b style="color:{INK}">Ref:</b> {ref}</td>
    </tr></table>
  </td></tr>
  {sample_banner}

  <!-- Executive summary -->
  <tr><td style="padding:26px 36px 6px;font-family:{FONT}">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:{FONT}"><div style="font-size:16px;font-weight:700;color:{NAVY}">Executive summary</div></td>
      <td align="right">{_badge(status_txt, status_fg, status_bg)}</td>
    </tr></table>
    <div style="font-size:13px;color:{INK};line-height:1.55;margin-top:8px">{summary}</div>
    {highlights}
  </td></tr>
  <tr><td style="padding:14px 31px 4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      {_kpi("Urgent", len(urgent), RED, "Exploited or critical")}
      {_kpi("Security", len(security), AMBER, "Advisories and CVEs")}
      {_kpi("Updates", len(updates), NAVY_2, "Releases and changes")}
      {_kpi("Vendors", len(vendors), ORANGE, "With new items")}
    </tr></table>
  </td></tr>

  {"".join(sections)}
  {health}

  <!-- Footer -->
  <tr><td style="padding:30px 36px 0"><div style="height:1px;background:{LINE};font-size:0;line-height:0">&nbsp;</div></td></tr>
  <tr><td style="padding:14px 36px 26px;font-family:{FONT}">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top" style="font-family:{FONT};font-size:11px;color:{MUTED};line-height:1.6">
        <b style="color:{INK}">About this report.</b> {sources_checked} sources are monitored every hour, including the CISA Known Exploited
        Vulnerabilities catalogue, the US National Vulnerability Database, the Microsoft Security Update Guide, Azure Updates,
        the Microsoft 365 Roadmap, and vendor release and advisory pages. A report is issued only when new items are found.<br>
        Severity ratings are taken from the source (CVSS). Always confirm applicability against vendor guidance before acting.
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="background:{NAVY};padding:12px 36px;font-family:{FONT};font-size:10px;color:#9aa7b8;letter-spacing:.4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:{FONT};font-size:10px;color:#9aa7b8">&copy; {local.year} Symbiosys &middot; Identity-led security for Microsoft-centric organisations</td>
      <td align="right" style="font-family:{FONT};font-size:10px;color:{ORANGE};font-weight:700;letter-spacing:1px">INTERNAL USE</td>
    </tr></table>
  </td></tr>
</table>
</td></tr></table>
</body></html>'''

    # Plain-text version
    lines = [TITLE.replace("&amp;", "&"), f"{date_long}, {time_str}   Ref: {ref}", "", "EXECUTIVE SUMMARY", summary, "",
             f"Urgent: {len(urgent)} | Security: {len(security)} | Updates: {len(updates)} | Vendors: {len(vendors)}"]
    for title, rows in (("URGENT", urgent), ("SECURITY ADVISORIES", security), ("PRODUCT UPDATES & RELEASE NOTES", updates)):
        if not rows:
            continue
        lines += ["", f"== {title} ({len(rows)}) =="]
        for s, i in sorted(rows, key=lambda r: vendor_of(*r)):
            i = _normalise(i)
            lines.append(f"- [{vendor_of(s, i)}] {product_of(s, i)}: {i['title']}")
            if i.get("link"):
                lines.append(f"  {i['link']}")
    if broken:
        lines += ["", "== SOURCE MONITORING NOTICE =="] + [f"- {s['name']}: {err}" for _, s, err in broken]
    return subject, body_html, "\n".join(lines)
