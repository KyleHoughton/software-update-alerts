"""Builds the alert email as a Symbiosys-branded HTML report.

Follows the Symbiosys Presentation Guide 2026:
  * Palette: Deep Navy #071320, Warm Off-White #F4F2EA, Symbiosys Blue #0B6EDC,
    Orange #FE9026, Silver #ACB1B6 (option A). Exception agreed with Kyle: severity tags
    use traffic-light red, yellow and green.
  * Fonts: Franklin Gothic Demi Cond (headlines, capitals), Aptos Narrow (text).
  * Content on off-white (no blue sidebar, per the "no bar" option); navy text on off-white, off-white or
    orange text on navy; never orange text on off-white or white text on orange.
  * Section number in orange with a short orange bar, label in spaced capitals,
    headline in condensed bold capitals, footer in small spaced capitals.
  * Glass icons only, all the same size; cards as white panels with a soft shadow.

Email clients (Outlook especially) only render simple HTML reliably, so the layout uses
tables and inline styles. Images are attached inline and referenced by cid.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from pathlib import Path
from zoneinfo import ZoneInfo

REPORT_TZ = ZoneInfo("Africa/Johannesburg")
TITLE = "Symbiosys Software Updates &amp; Vulnerabilities Report"
ASSETS = Path(__file__).resolve().parent.parent / "assets"

# Images sent inline with the email: cid -> file
INLINE_IMAGES = {
    "symbiosys-logo": ASSETS / "logo-email.png",
    "icon-warning": ASSETS / "icons" / "warning.png",
    "icon-cyber": ASSETS / "icons" / "cyber.png",
    "icon-update": ASSETS / "icons" / "clouddeploy.png",
    "icon-globe": ASSETS / "icons" / "globe.png",
}
# Kept for backwards compatibility with main.py
LOGO_CID = "symbiosys-logo"
LOGO_FILE = INLINE_IMAGES[LOGO_CID]

# Brand palette
NAVY = "#071320"       # Deep Navy
OFFWHITE = "#F4F2EA"   # Warm Off-White
BLUE = "#0B6EDC"       # Symbiosys Blue
ORANGE = "#FE9026"     # Orange
SILVER = "#ACB1B6"     # Silver (option A accent)
WHITE = "#FFFFFF"
# Traffic-light severity colours: red = critical, yellow = warning, green = OK.
# An agreed exception to the brand palette, used only for severity and status tags.
SEV_RED = "#D92D20"
SEV_YELLOW = "#FDB022"
SEV_GREEN = "#079455"
# Tints used for lines and secondary text (derived from navy, not new colours)
TEXT_2 = "#3d4654"
LINE = "#dedad0"
TABLE_HEAD = "#e6e2d6"

HEAD_FONT = "'Franklin Gothic Demi Cond','Franklin Gothic Medium Cond','Franklin Gothic Demi','Arial Narrow',Arial,sans-serif"
TEXT_FONT = "'Aptos Narrow','Aptos','Segoe UI',Arial,sans-serif"

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
    if src.get("product"):
        return src["product"]
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


def _normalise(it: dict) -> dict:
    """Move '[Launched]'-style prefixes into a status, and 'Product: title' into a product."""
    m = re.match(r"\s*\[([^\]]+)\]\s*(.*)", it.get("title", ""))
    if m:
        it = {**it, "status": m.group(1), "title": m.group(2)}
    if not it.get("product"):
        m = re.match(r"\s*([A-Z][\w .&/-]{2,40}?):\s+(.+)", it.get("title", ""))
        if m and not it["title"].startswith("CVE-"):
            prefix = m.group(1)
            if re.search(r"available|preview|retire|development|rolling|launched|update", prefix, re.I):
                it = {**it, "status": it.get("status") or prefix, "title": m.group(2)}
            else:
                it = {**it, "product": prefix, "title": m.group(2)}
    return it


def _tag(text: str, style: str) -> str:
    """Status tag. Styles follow the guide's approved pairings only."""
    styles = {
        "orange": f"background:{ORANGE};color:{NAVY};border:1px solid {ORANGE}",        # navy on orange
        "navy": f"background:{NAVY};color:{OFFWHITE};border:1px solid {NAVY}",           # off-white on navy
        "blue": f"background:{BLUE};color:{WHITE};border:1px solid {BLUE}",              # white on blue
        "outline": f"background:{WHITE};color:{NAVY};border:1px solid {NAVY}",           # navy on white
        "silver": f"background:{SILVER};color:{NAVY};border:1px solid {SILVER}",         # navy on silver
        # Traffic-light severity (agreed exception to the brand palette)
        "red": f"background:{SEV_RED};color:{WHITE};border:1px solid {SEV_RED}",
        "yellow": f"background:{SEV_YELLOW};color:{NAVY};border:1px solid {SEV_YELLOW}",
        "green": f"background:{SEV_GREEN};color:{WHITE};border:1px solid {SEV_GREEN}",
    }[style]
    return (f'<span style="display:inline-block;padding:3px 8px;border-radius:3px;{styles};'
            f'font-family:{TEXT_FONT};font-size:10px;font-weight:700;letter-spacing:1px;'
            f'text-transform:uppercase;white-space:nowrap">{_e(text)}</span>')


def _status_tag(it: dict, kind: str) -> str:
    sev = (it.get("severity") or "").upper()
    if it.get("exploited"):
        return _tag("Exploited", "red")
    if sev.startswith("CRITICAL"):
        return _tag(it.get("severity_label") or "Critical", "red")
    if sev.startswith("HIGH"):
        return _tag(it.get("severity_label") or "High", "yellow")
    if sev.startswith("MEDIUM"):
        return _tag(it.get("severity_label") or "Medium", "yellow")
    if sev.startswith("LOW"):
        return _tag(it.get("severity_label") or "Low", "green")
    if kind == "security":
        return _tag("Advisory", "yellow")
    st = (it.get("status") or "").lower()
    if "retire" in st:
        return _tag("Retirement", "navy")
    if "preview" in st:
        return _tag("Preview", "silver")
    if "launch" in st or "available" in st:
        return _tag("Available", "green")
    return _tag("Update", "green")


# --------------------------------------------------------------------------- building blocks

def _label(text: str, colour: str = NAVY) -> str:
    return (f'<div style="font-family:{TEXT_FONT};font-size:11px;letter-spacing:4px;text-transform:uppercase;'
            f'color:{colour}">{text}</div>')


def _section_number(n: int) -> str:
    return (f'<div style="font-family:{HEAD_FONT};font-size:20px;font-weight:700;color:{ORANGE};line-height:1">{n:02d}</div>'
            f'<div style="width:26px;height:3px;background:{ORANGE};margin:4px 0 10px;font-size:0;line-height:0">&nbsp;</div>')


def _kpi(icon_cid: str, value: int, label: str, img) -> str:
    return (f'<td width="25%" valign="top" style="padding:0 6px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:{WHITE};border:1px solid {WHITE};border-radius:8px;box-shadow:0 3px 12px rgba(7,19,32,.12)">'
            f'<tr><td style="padding:14px 12px" valign="middle" width="44">'
            f'<img src="{img(icon_cid)}" width="40" height="40" alt="" style="display:block;width:40px;height:40px;border:0"></td>'
            f'<td style="padding:14px 12px 14px 2px" valign="middle">'
            f'<div style="font-family:{HEAD_FONT};font-size:30px;font-weight:700;color:{NAVY};line-height:1">{value}</div>'
            f'<div style="font-family:{TEXT_FONT};font-size:10px;letter-spacing:2px;text-transform:uppercase;color:{NAVY};margin-top:5px">{label}</div>'
            f'</td></tr></table></td>')


def _section(n: int, label: str, headline: str, intro: str, icon_cid: str, img,
             rows: list[tuple[dict, dict]], kind: str, detail_chars: int) -> str:
    groups: dict[str, list[tuple[dict, dict]]] = {}
    for s, i in rows:
        groups.setdefault(vendor_of(s, i), []).append((s, _normalise(i)))
    order = sorted(groups, key=lambda v: (VENDOR_ORDER.index(v) if v in VENDOR_ORDER else 99, v.lower()))

    head = (f'<tr><td style="padding:34px 40px 14px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
            f'<td valign="bottom">{_section_number(n)}{_label(label)}'
            f'<div style="font-family:{HEAD_FONT};font-size:26px;font-weight:700;color:{NAVY};text-transform:uppercase;'
            f'line-height:1.1;margin-top:6px">{headline}</div>'
            f'<div style="font-family:{TEXT_FONT};font-size:14px;color:{TEXT_2};margin-top:6px;line-height:1.45">{intro}</div></td>'
            f'<td valign="bottom" align="right" width="64"><img src="{img(icon_cid)}" width="56" height="56" alt="" '
            f'style="display:block;width:56px;height:56px;border:0"></td></tr></table></td></tr>')

    th = (f'style="padding:9px 12px;font-family:{TEXT_FONT};font-size:11px;font-weight:700;color:{NAVY};'
          f'text-transform:uppercase;letter-spacing:1px;text-align:left;background:{TABLE_HEAD};border-bottom:1px solid {LINE}"')
    out = [head,
           f'<tr><td style="padding:0 40px">'
           f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
           f'style="border-collapse:collapse;background:{WHITE};border:1px solid {LINE}">'
           f'<tr><th {th} width="21%">Product</th><th {th}>Details</th>'
           f'<th {th} width="16%">{"Severity" if kind == "security" else "Status"}</th><th {th} width="12%">Date</th></tr>']
    for vendor in order:
        items = groups[vendor]
        out.append(f'<tr><td colspan="4" style="padding:8px 12px;background:{NAVY};font-family:{TEXT_FONT};'
                   f'font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:{OFFWHITE}">'
                   f'<span style="color:{ORANGE}">&#9632;</span>&nbsp; {_e(vendor)}'
                   f'<span style="font-weight:400;color:{SILVER}"> &nbsp;&middot;&nbsp; {len(items)} item{"s" if len(items) != 1 else ""}</span></td></tr>')
        for s, i in items:
            title = (f'<a href="{_e(i["link"])}" style="color:{NAVY};text-decoration:none;font-weight:700">{_e(i["title"])}</a>'
                     if i.get("link") else f'<span style="font-weight:700">{_e(i["title"])}</span>')
            detail = _clip(i.get("summary", "").replace("•", " "), detail_chars)
            detail_html = (f'<div style="margin-top:3px;color:{TEXT_2};font-size:13px;line-height:1.45">{_e(detail)}</div>'
                           if detail else "")
            action = (f'<div style="margin-top:6px;padding:6px 8px;background:{OFFWHITE};border-left:3px solid {ORANGE};'
                      f'font-size:12px;color:{NAVY};line-height:1.45"><b>Required action:</b> {_e(i["action"])}</div>'
                      if i.get("action") else "")
            link = (f'<div style="margin-top:6px"><a href="{_e(i["link"])}" style="font-size:12px;font-weight:700;color:{BLUE};'
                    f'text-decoration:none">{"View advisory" if kind == "security" else "Release notes"} &rsaquo;</a></div>'
                    if i.get("link") else "")
            td = (f'style="padding:11px 12px;border-bottom:1px solid {LINE};font-family:{TEXT_FONT};vertical-align:top;'
                  f'color:{NAVY}')
            out.append(
                f'<tr><td {td};font-size:13px;font-weight:700">{_e(product_of(s, i))}</td>'
                f'<td {td};font-size:14px;line-height:1.4">{title}{detail_html}{action}{link}</td>'
                f'<td {td}">{_status_tag(i, kind)}</td>'
                f'<td {td};font-size:12px;color:{TEXT_2};white-space:nowrap">{_e(_fmt_date(i.get("date", "")))}</td></tr>')
    out.append('</table></td></tr>')
    return "".join(out)


# --------------------------------------------------------------------------- report

def build_report(new: list[tuple[dict, dict]], broken: list[tuple[str, dict, str]],
                 sources_checked: int, now: dt.datetime, sample: bool = False,
                 logo_src: str | None = None, image_src=None) -> tuple[str, str, str]:
    """image_src(cid) -> URL for that image. Defaults to cid: references for email."""
    img = image_src or (lambda cid: f"cid:{cid}")
    if logo_src:  # backwards compatibility
        base = img
        img = lambda cid: logo_src if cid == LOGO_CID else base(cid)  # noqa: E731

    urgent = [(s, i) for s, i in new if i["urgent"]]
    security = [(s, i) for s, i in new if not i["urgent"] and s["category"] == "security"]
    updates = [(s, i) for s, i in new if not i["urgent"] and s["category"] != "security"]
    vendors = sorted({vendor_of(s, i) for s, i in new})

    local = now.astimezone(REPORT_TZ)
    date_long = local.strftime("%A %d %B %Y").upper()
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
    subject = (f"{prefix}Symbiosys Software Updates & Vulnerabilities Report | {local.strftime('%d %b %Y %H:%M')} | "
               + (", ".join(parts) if parts else "source health"))

    # Executive summary
    if urgent:
        status = _tag("Action required", "red")
        summary = (f"{len(urgent)} vulnerabilit{'ies' if len(urgent) != 1 else 'y'} known to be actively exploited or rated "
                   f"critical {'were' if len(urgent) != 1 else 'was'} identified. Assess exposure and patch or mitigate as a priority.")
    elif security:
        status = _tag("Review advised", "yellow")
        summary = "No actively exploited or critical issues were identified. New security advisories are listed for review."
    else:
        status = _tag("All OK", "green")
        summary = "No new security issues were identified. New product releases and service changes are listed below."
    summary += (f" This report covers {len(new)} new item{'s' if len(new) != 1 else ''} across "
                f"{len(vendors)} vendor{'s' if len(vendors) != 1 else ''}.")

    highlights = ""
    top = (urgent + security)[:3]
    if top:
        lis = "".join(
            f'<tr><td valign="top" style="padding:4px 10px 4px 0;font-family:{HEAD_FONT};font-size:14px;color:{BLUE};font-weight:700">{k:02d}</td>'
            f'<td style="padding:4px 0;font-family:{TEXT_FONT};font-size:14px;color:{NAVY};line-height:1.4">'
            f'<b>{_e(vendor_of(s, i))}</b> &middot; {_e(_clip(_normalise(i)["title"], 110))}</td></tr>'
            for k, (s, i) in enumerate(top, 1))
        highlights = (f'<div style="margin-top:16px">{_label("Key items")}</div>'
                      f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:6px">{lis}</table>')

    sample_banner = (f'<tr><td style="padding:12px 40px 0">'
                     f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                     f'style="background:{NAVY};border-radius:4px"><tr><td style="padding:9px 14px;font-family:{TEXT_FONT};'
                     f'font-size:12px;color:{OFFWHITE}"><b style="color:{ORANGE};letter-spacing:2px">SAMPLE</b> &nbsp; '
                     f'Built from the latest items in each source to preview the format. Live reports list only items new since the previous check.'
                     f'</td></tr></table></td></tr>' if sample else "")

    sections, n = [], 1  # 01 is the summary
    if urgent:
        n += 1
        sections.append(_section(n, "Urgent attention", "Exploited &amp; <span style=\"color:" + BLUE + "\">critical</span>",
                                 "Listed in the CISA Known Exploited Vulnerabilities catalogue or rated CVSS 9.0 and above. Prioritise patching or mitigation.",
                                 "icon-warning", img, urgent, "security", 260))
    if security:
        n += 1
        sections.append(_section(n, "Security advisories", "New <span style=\"color:" + BLUE + "\">vulnerabilities</span>",
                                 "New CVEs and vendor security advisories affecting the products we track.",
                                 "icon-cyber", img, security, "security", 200))
    if updates:
        n += 1
        sections.append(_section(n, "Product updates", "Releases &amp; <span style=\"color:" + BLUE + "\">changes</span>",
                                 "New versions, features, previews, retirements and service changes.",
                                 "icon-update", img, updates, "update", 170))

    health = ""
    if broken:
        health = (f'<tr><td style="padding:28px 40px 0">'
                  f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                  f'style="background:{WHITE};border:1px solid {LINE};border-left:3px solid {SILVER};border-radius:4px">'
                  f'<tr><td style="padding:12px 16px;font-family:{TEXT_FONT}">'
                  f'{_label("Source monitoring")}'
                  f'<div style="font-size:13px;color:{NAVY};margin-top:6px">These sources could not be checked on three consecutive runs:</div>'
                  f'<ul style="margin:6px 0 0 18px;padding:0;font-size:13px;color:{TEXT_2}">'
                  + "".join(f"<li>{_e(s['name'])}: {_e(err)}</li>" for _, s, err in broken) +
                  '</ul></td></tr></table></td></tr>')

    body_html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting"><title>{TITLE}</title></head>
<body style="margin:0;padding:0;background:#dcd9d0">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#dcd9d0"><tr><td align="center" style="padding:24px 10px">
<table role="presentation" width="820" cellpadding="0" cellspacing="0" style="max-width:820px;width:100%;background:{OFFWHITE}">

  <!-- Cover header: Deep Navy, white logo top right -->
  <tr><td style="background:{NAVY};padding:30px 40px 34px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top">{_label("Security intelligence &middot; Hourly brief", SILVER)}</td>
      <td valign="top" align="right" width="190"><img src="{img(LOGO_CID)}" width="170" alt="Symbiosys" style="display:block;width:170px;height:auto;border:0"></td>
    </tr>
    <tr><td colspan="2" style="padding-top:18px">
      <div style="font-family:{HEAD_FONT};font-size:34px;font-weight:700;color:{OFFWHITE};text-transform:uppercase;line-height:1.05">
        Software updates &amp;<br><span style="color:{ORANGE}">vulnerabilities</span> report</div>
      <div style="font-family:{TEXT_FONT};font-size:14px;color:{OFFWHITE};margin-top:10px">New releases, advisories and exploited vulnerabilities across the platforms Symbiosys supports.</div>
    </td></tr></table>
  </td></tr>
  <tr><td style="background:{NAVY};padding:0 40px 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #1d2a3d"><tr>
      <td style="padding-top:12px;font-family:{TEXT_FONT};font-size:10px;letter-spacing:3px;color:{SILVER}">{date_long} &nbsp;&middot;&nbsp; {time_str}</td>
      <td align="right" style="padding-top:12px;font-family:{TEXT_FONT};font-size:10px;letter-spacing:3px;color:{ORANGE}">{ref}</td>
    </tr></table>
  </td></tr>
  {sample_banner}

  <!-- 01 Executive summary -->
  <tr><td style="padding:30px 40px 6px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="bottom">{_section_number(1)}{_label("Executive summary")}
        <div style="font-family:{HEAD_FONT};font-size:26px;font-weight:700;color:{NAVY};text-transform:uppercase;line-height:1.1;margin-top:6px">This hour <span style="color:{BLUE}">at a glance</span></div></td>
      <td valign="bottom" align="right">{status}</td>
    </tr></table>
    <div style="font-family:{TEXT_FONT};font-size:15px;color:{NAVY};line-height:1.5;margin-top:10px">{summary}</div>
    {highlights}
  </td></tr>
  <tr><td style="padding:18px 34px 4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      {_kpi("icon-warning", len(urgent), "Urgent", img)}
      {_kpi("icon-cyber", len(security), "Security", img)}
      {_kpi("icon-update", len(updates), "Updates", img)}
      {_kpi("icon-globe", len(vendors), "Vendors", img)}
    </tr></table>
  </td></tr>

  {"".join(sections)}
  {health}

  <!-- About -->
  <tr><td style="padding:34px 40px 0">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {LINE}"><tr>
      <td style="padding-top:14px;font-family:{TEXT_FONT};font-size:12px;color:{TEXT_2};line-height:1.6">
        <b style="color:{NAVY}">About this report.</b> {sources_checked} sources are monitored every hour, including the CISA Known Exploited
        Vulnerabilities catalogue, the US National Vulnerability Database, the Microsoft Security Update Guide, Azure Updates,
        the Microsoft 365 Roadmap and vendor release and advisory pages. A report is issued only when new items are found.
        Severity ratings come from the source (CVSS); confirm applicability against vendor guidance before acting.
      </td></tr></table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="padding:22px 40px 26px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:{TEXT_FONT};font-size:10px;letter-spacing:3px;text-transform:uppercase;color:{NAVY}">Software updates &amp; vulnerabilities report {local.year}</td>
      <td align="right" style="font-family:{TEXT_FONT};font-size:10px;letter-spacing:3px;text-transform:uppercase;color:{NAVY}">Internal use</td>
    </tr></table>
  </td></tr>
</table>
</td></tr></table>
</body></html>'''

    # Plain-text version
    lines = [TITLE.replace("&amp;", "&"), f"{date_long}, {time_str}   Ref: {ref}", "", "EXECUTIVE SUMMARY", summary, "",
             f"Urgent: {len(urgent)} | Security: {len(security)} | Updates: {len(updates)} | Vendors: {len(vendors)}"]
    for title, rows in (("URGENT: EXPLOITED & CRITICAL", urgent), ("SECURITY ADVISORIES", security),
                        ("PRODUCT UPDATES", updates)):
        if not rows:
            continue
        lines += ["", f"== {title} ({len(rows)}) =="]
        for s, i in sorted(rows, key=lambda r: vendor_of(*r)):
            i = _normalise(i)
            lines.append(f"- [{vendor_of(s, i)}] {product_of(s, i)}: {i['title']}")
            if i.get("link"):
                lines.append(f"  {i['link']}")
    if broken:
        lines += ["", "== SOURCE MONITORING =="] + [f"- {s['name']}: {err}" for _, s, err in broken]
    return subject, body_html, "\n".join(lines)
