"""Monthly Windows Server and SQL Server patch report.

Runs in two modes:
  patch     the day after Patch Tuesday (second Wednesday of the month). Lists this
            month's Windows Server updates, their known issues and SQL Server updates.
            Saves a snapshot in state/monthly/ so the follow-up can show what changed.
  followup  the 1st of the month. The same report for the month just ended, with
            anything new or changed since the Patch Tuesday report marked.

Sources (all public, no sign-in):
  * Windows Server release information (KB, build, date for every update)
  * Windows release health known-issues pages, one per Windows Server version
  * Microsoft Security Update Guide CVRF API (CVEs fixed, severity, exploited)
  * SQL Server "Latest updates and version history" and each update's KB article

Environment:
  REPORT_MODE    auto (default; decides from today's date), patch or followup
  REPORT_MONTH   YYYY-MM to report on (optional; defaults from the mode)
  PREVIEW_ONLY   "true" builds monthly-report.html without emailing
  plus the same email settings as the hourly checker (MAIL_FROM, MAIL_TO, GRAPH_* or SMTP_*).
"""

from __future__ import annotations

import base64
import calendar
import datetime as dt
import html
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from main import get, send_email  # noqa: E402  (reuses the hourly checker's fetch and email code)
import report as R  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SNAP_DIR = ROOT / "state" / "monthly"
LEARN = "https://learn.microsoft.com/en-us"
RELEASE_INFO = f"{LEARN}/windows/release-health/windows-server-release-info"
SQL_LATEST = f"{LEARN}/troubleshoot/sql/releases/download-and-install-latest-updates"
MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_GUIDE = "https://msrc.microsoft.com/update-guide"

# Windows Server versions in the report, with their release health page.
WINDOWS = {
    "Windows Server 2025": f"{LEARN}/windows/release-health/status-windows-server-2025",
    "Windows Server 2022": f"{LEARN}/windows/release-health/status-windows-server-2022",
    "Windows Server 2019": f"{LEARN}/windows/release-health/status-windows-10-1809-and-windows-server-2019",
    "Windows Server 2016": f"{LEARN}/windows/release-health/status-windows-10-1607-and-windows-server-2016",
}
SQL_VERSIONS = ["SQL Server 2025", "SQL Server 2022", "SQL Server 2019", "SQL Server 2017", "SQL Server 2016"]
TITLE = "Symbiosys Windows Server &amp; SQL Server Monthly Patch Report"

now = dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- small helpers

def text(s: str) -> str:
    s = re.sub(r"<br\s*/?>", " ", s or "")
    s = re.sub(r"</?(a|b|strong|em|i|span|code)\b[^>]*>", "", s)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def kb_of(s: str) -> str:
    m = re.search(r"KB\s?(\d{6,7})", s or "") or re.search(r"/help/(\d{6,7})", s or "")
    return m.group(1) if m else ""


def kb_link(kb: str) -> str:
    return f"https://support.microsoft.com/help/{kb}"


def catalog_link(kb: str) -> str:
    return f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB{kb}"


def patch_tuesday(year: int, month: int) -> dt.date:
    first = dt.date(year, month, 1)
    return first + dt.timedelta(days=(1 - first.weekday()) % 7 + 7)


def month_name(ym: str) -> str:
    y, m = map(int, ym.split("-"))
    return f"{calendar.month_name[m]} {y}"


# --------------------------------------------------------------------------- Windows Server

def windows_updates(ym: str) -> dict[str, list[dict]]:
    """Every update released in month ym, per Windows Server version."""
    h = get(RELEASE_INFO).text
    out: dict[str, list[dict]] = {}
    for m in re.finditer(r'id="historyTable_\d+">(.*?)</table>', h, re.S):
        head = re.findall(r"<strong>(Windows Server \d{4}) \(OS build (\d+)\)</strong>", h[max(0, m.start() - 400):m.start()])
        if not head:
            continue
        name = head[-1][0]
        if name not in WINDOWS or name in out:
            continue
        rows = []
        for r in re.findall(r"<tr>(.*?)</tr>", m.group(1), re.S):
            cells = re.findall(r"<td>(.*?)</td>", r, re.S)
            if len(cells) < 5:
                continue
            utype, date, build, kb = text(cells[1]), text(cells[2]), text(cells[3]), kb_of(cells[4])
            if not date.startswith(ym) or not kb:
                continue
            kind = ("Security update" if utype.endswith(" B") else "Out-of-band" if "OOB" in utype
                    else "Preview (non-security)" if utype.endswith(" D") else utype)
            rows.append({"kb": kb, "type": kind, "code": utype, "date": date, "build": build,
                         "notes": kb_link(kb), "download": catalog_link(kb)})
        out[name] = sorted(rows, key=lambda r: r["date"])
    missing = [v for v in WINDOWS if v not in out]
    if missing:
        print(f"[WARN] no update table found for {', '.join(missing)}")
    return out


def known_issues(ym: str) -> list[dict]:
    """Known issues from release health, merged across versions. Keeps open issues and
    issues resolved or updated during month ym."""
    issues: dict[str, dict] = {}
    for version, url in WINDOWS.items():
        try:
            h = get(url).text
        except Exception as e:  # noqa: BLE001
            print(f"[WARN] release health for {version}: {e}")
            continue
        top = h.split('id="issue-details"')[0]
        for row in re.findall(r"<tr><td><div id=\"\d+msg\"></div>(.*?)</tr>", top, re.S):
            cells = re.findall(r"<td[^>]*>(.*?)</td>", "<td>" + row, re.S)
            if len(cells) < 4:
                continue
            m = re.search(r'href="#(\d+)msgdesc"[^>]*><b>(.*?)</b></a><br>(.*)', cells[0], re.S)
            if not m:
                continue
            iid, title, blurb = m.group(1), text(m.group(2)), text(m.group(3))
            status = text(cells[2])
            fixed_kb = kb_of(cells[2])
            status_word = status.split(" ")[0] if status else ""
            updated = text(cells[3])
            orig_kb = kb_of(cells[1])
            orig_date = (re.findall(r"\d{4}-\d{2}-\d{2}", text(cells[1])) or [""])[-1]
            it = issues.setdefault(iid, {
                "id": iid, "title": title, "summary": blurb, "status": status_word, "fixed_kb": fixed_kb,
                "updated": updated, "link": f"{url}#{iid}msgdesc", "versions": [], "workaround": "",
                "detail": ""})
            it["versions"].append({"version": version, "kb": orig_kb, "date": orig_date})
            if updated > it["updated"]:
                it["updated"] = updated
            if not it["detail"]:
                d = re.search(rf'<div id="{iid}msgdesc"></div>(.*?)Back to top', h, re.S)
                if d:
                    paras = [text(p) for p in re.findall(r'<p class="font-size-sm">(.*?)</p>', d.group(1), re.S)]
                    it["detail"] = next((p for p in paras if not p.startswith(("Workaround", "Resolution", "Next steps",
                                                                                  "Affected platforms"))), "")
                    w = next((p for p in paras if p.startswith(("Workaround", "Resolution", "Next steps"))), "")
                    it["workaround"] = w
    keep = []
    for it in issues.values():
        if it["status"].lower() == "resolved" and not it["updated"].startswith(ym):
            continue  # resolved before this month
        keep.append(it)
    order = {"confirmed": 0, "investigating": 0, "mitigated": 1, "resolved": 2}
    keep.sort(key=lambda i: (order.get(i["status"].lower(), 1), i["updated"]), reverse=False)
    return keep


def msrc_month(ym: str) -> dict | None:
    y, m = map(int, ym.split("-"))
    doc_id = f"{y}-{calendar.month_abbr[m]}"
    try:
        r = get(f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}", headers={"Accept": "application/json"})
        return r.json()
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] Security Update Guide for {doc_id}: {e}")
        return None


def cve_stats(cvrf: dict | None, product_pattern: str, kbs: set[str] | None = None) -> dict:
    """CVEs in the month's security release that affect products matching product_pattern.
    With kbs, only CVEs fixed by one of those KBs are counted."""
    empty = {"total": 0, "critical": 0, "exploited": 0, "disclosed": 0, "list": []}
    if not cvrf:
        return empty
    pat = re.compile(product_pattern)
    pids = {p["ProductID"] for p in cvrf["ProductTree"]["FullProductName"] if pat.search(p["Value"])}
    out = dict(empty, list=[])
    for v in cvrf.get("Vulnerability", []):
        rems = [r for r in v.get("Remediations", []) if r.get("Type") == 2 and pids & set(r.get("ProductID", []))]
        if not rems:
            continue
        if kbs is not None and not any((r.get("Description") or {}).get("Value") in kbs for r in rems):
            continue
        sev = {t["Description"]["Value"] for t in v.get("Threats", [])
               if t.get("Type") == 3 and pids & set(t.get("ProductID", []))}
        expl = any(t.get("Type") == 1 and "Exploited:Yes" in t["Description"]["Value"] for t in v.get("Threats", []))
        disc = any(t.get("Type") == 1 and "Publicly Disclosed:Yes" in t["Description"]["Value"] for t in v.get("Threats", []))
        score = max([s.get("BaseScore", 0) for s in v.get("CVSSScoreSets", []) if pids & set(s.get("ProductID", []))] or [0])
        out["total"] += 1
        out["critical"] += "Critical" in sev
        out["exploited"] += expl
        out["disclosed"] += disc
        if expl or "Critical" in sev or disc:
            out["list"].append({"cve": v["CVE"], "title": (v.get("Title") or {}).get("Value", ""), "score": score,
                                "critical": "Critical" in sev, "exploited": expl, "disclosed": disc})
    out["list"].sort(key=lambda c: (not c["exploited"], not c["disclosed"], not c["critical"], -c["score"]))
    return out


# --------------------------------------------------------------------------- SQL Server

def _kb_article_links(page: str, base: str) -> dict[str, str]:
    """KB number -> article URL, from the links on a SQL Server release page."""
    from urllib.parse import urljoin
    out = {}
    for href in re.findall(r'href="([^"#]+)"', page):
        m = re.search(r"/kb(\d{6,7})-[^/]*$", "/" + href)
        if m and "build-versions" not in href:
            out.setdefault(m.group(1), urljoin(base, href))
    return out


def sql_updates(ym: str) -> list[dict]:
    """Latest GDR and CU for each supported SQL Server version, marking what came out in month ym."""
    from urllib.parse import urljoin
    resp = get(SQL_LATEST)
    h = resp.text
    articles = _kb_article_links(h, resp.url)
    build_pages = {m.group(1): urljoin(resp.url, m.group(0)[6:-1])
                   for m in re.finditer(r'href="sql-server-(\d{4})/kb\d+-build-versions"', h)}
    i = h.find("Latest updates available for currently supported versions")
    table = h[i:h.find("</table>", i)]
    target = month_name(ym)
    out = []
    for row in re.findall(r"<tr>(.*?)</tr>", table, re.S):
        cells = re.findall(r"<td>(.*?)</td>", row, re.S)
        if len(cells) < 4:
            continue
        version = text(re.sub(r"<br.*", "", cells[0], flags=re.S))
        if version not in SQL_VERSIONS:
            continue
        rels = []
        for col, kind in ((cells[2], "GDR"), (cells[3], "CU")):
            for a, label, build, when in re.findall(
                    r'<a href="([^"]+)"[^>]*>(.*?)</a>\s*<br/?>\s*\(([\d.]+)\s*-\s*([A-Za-z]+ \d{4})\)', col, re.S):
                kb = kb_of(a)
                label = text(label)
                rels.append({"kb": kb, "label": label, "build": build, "month": when,
                             "kind": "CU + security" if "GDR" in label and "CU" in label else kind,
                             "new": when == target, "notes": articles.get(kb, ""),
                             "download": catalog_link(kb), "issues": []})
        # Keep what is current: anything from the last two years, and never old service-pack branches.
        cutoff = now.year - 2
        keep = [r for r in rels if r["new"] or (int(r["month"][-4:]) >= cutoff and not re.search(r"\b(SP1|SP2|RTM)\b", r["label"]))]
        if not any(r["kind"] != "GDR" for r in keep):
            keep += [r for r in rels if r["kind"] != "GDR" and not re.search(r"\b(SP1|SP2|RTM)\b", r["label"])][:1]
        out.append({"version": version, "releases": keep})
    for v in out:
        if any(not r["notes"] for r in v["releases"]) and build_pages.get(v["version"][-4:]):
            try:
                bp = get(build_pages[v["version"][-4:]])
                articles.update({k: u for k, u in _kb_article_links(bp.text, bp.url).items() if k not in articles})
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] {v['version']} build versions page: {e}")
        for r in v["releases"]:
            r["notes"] = r["notes"] or articles.get(r["kb"]) or f"https://support.microsoft.com/help/{r['kb']}"
            if r["new"] and r["kind"] != "GDR":
                r["issues"] = sql_known_issues(r["notes"])
    return out


def sql_known_issues(url: str) -> list[str]:
    """The 'Known issues in this update' section of a SQL Server CU article."""
    try:
        h = get(url).text
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] SQL KB article {url}: {e}")
        return []
    m = re.search(r'<h2[^>]*>\s*Known issues in this update\s*</h2>(.*?)<h2', h, re.S | re.I)
    if not m:
        return []
    body = m.group(1)
    heads = [text(x) for x in re.findall(r"<h3[^>]*>(.*?)</h3>", body, re.S)]
    if heads:
        return heads[:6]
    paras = [text(p) for p in re.findall(r"<p>(.*?)</p>", body, re.S)]
    paras = [p for p in paras if p]
    if paras and re.search(r"no known issues|there are no", paras[0], re.I):
        return []
    return [R._clip(p, 220) for p in paras[:2]]


# --------------------------------------------------------------------------- snapshot (for the follow-up)

def snapshot(data: dict) -> dict:
    return {
        "windows": sorted(u["kb"] for rows in data["windows"].values() for u in rows),
        "issues": {i["id"]: {"status": i["status"], "updated": i["updated"]} for i in data["issues"]},
        "sql": sorted(r["kb"] for v in data["sql"] for r in v["releases"] if r["new"]),
        "taken": now.isoformat(),
    }


def mark_changes(data: dict, snap: dict | None) -> int:
    """Flag items new or changed since the Patch Tuesday snapshot. Returns the number of changes."""
    if not snap:
        return 0
    n = 0
    for rows in data["windows"].values():
        for u in rows:
            if u["kb"] not in snap["windows"]:
                u["change"] = "New"
                n += 1
    for i in data["issues"]:
        old = snap["issues"].get(i["id"])
        if not old:
            i["change"] = "New"
            n += 1
        elif old["status"] != i["status"] or old["updated"] != i["updated"]:
            i["change"] = "Updated" if old["status"] == i["status"] else f"Was {old['status'].lower()}"
            n += 1
    for v in data["sql"]:
        for r in v["releases"]:
            if r["new"] and r["kb"] not in snap["sql"]:
                r["change"] = "New"
                n += 1
    return n


# --------------------------------------------------------------------------- report

def _issue_tag(status: str) -> str:
    s = status.lower()
    if s == "resolved":
        return R._tag("Resolved", "green")
    if s == "mitigated":
        return R._tag("Mitigated", "yellow")
    return R._tag(status or "Open", "red" if s == "confirmed" else "yellow")


def _change(x: dict) -> str:
    return (f' &nbsp;<span style="display:inline-block;padding:2px 6px;border-radius:3px;background:{R.ORANGE};'
            f'color:{R.NAVY};font-family:{R.TEXT_FONT};font-size:9px;font-weight:700;letter-spacing:1px;'
            f'text-transform:uppercase">{R._e(x["change"])}</span>' if x.get("change") else "")


def _head(n: int, label: str, headline: str, intro: str, icon: str, img) -> str:
    return (f'<tr><td style="padding:34px 40px 14px">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
            f'<td valign="bottom">{R._section_number(n)}{R._label(label)}'
            f'<div style="font-family:{R.HEAD_FONT};font-size:26px;font-weight:700;color:{R.NAVY};text-transform:uppercase;'
            f'line-height:1.1;margin-top:6px">{headline}</div>'
            f'<div style="font-family:{R.TEXT_FONT};font-size:14px;color:{R.TEXT_2};margin-top:6px;line-height:1.45">{intro}</div></td>'
            f'<td valign="bottom" align="right" width="64"><img src="{img(icon)}" width="56" height="56" alt="" '
            f'style="display:block;width:56px;height:56px;border:0"></td></tr></table></td></tr>')


TH = (f'style="padding:9px 12px;font-family:{R.TEXT_FONT};font-size:11px;font-weight:700;color:{R.NAVY};'
      f'text-transform:uppercase;letter-spacing:1px;text-align:left;background:{R.TABLE_HEAD};border-bottom:1px solid {R.LINE}"')
TD = f'style="padding:11px 12px;border-bottom:1px solid {R.LINE};font-family:{R.TEXT_FONT};vertical-align:top;color:{R.NAVY}'
TABLE = (f'<tr><td style="padding:0 40px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
         f'style="border-collapse:collapse;background:{R.WHITE};border:1px solid {R.LINE}">')


def _group(name: str, extra: str = "") -> str:
    return (f'<tr><td colspan="4" style="padding:8px 12px;background:{R.NAVY};font-family:{R.TEXT_FONT};'
            f'font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:{R.OFFWHITE}">'
            f'<span style="color:{R.ORANGE}">&#9632;</span>&nbsp; {R._e(name)}'
            f'<span style="font-weight:400;color:{R.SILVER}">{extra}</span></td></tr>')


def _links(*pairs) -> str:
    return ('<div style="margin-top:6px">' + " &nbsp;&middot;&nbsp; ".join(
        f'<a href="{R._e(u)}" style="font-size:12px;font-weight:700;color:{R.BLUE};text-decoration:none">{t} &rsaquo;</a>'
        for t, u in pairs if u) + "</div>")


def _empty(msg: str) -> str:
    return (f'<tr><td colspan="4" style="padding:14px 12px;font-family:{R.TEXT_FONT};font-size:13px;color:{R.TEXT_2}">'
            f'{msg}</td></tr>')


def build(data: dict, ym: str, mode: str, changes: int, snap: dict | None, sample: bool,
          image_src=None) -> tuple[str, str, str]:
    img = image_src or (lambda cid: f"cid:{cid}")
    local = now.astimezone(R.REPORT_TZ)
    month = month_name(ym)
    win, issues, sql, cves = data["windows"], data["issues"], data["sql"], data["cves"]
    n_win = sum(len(v) for v in win.values())
    sql_new = [(v["version"], r) for v in sql for r in v["releases"] if r["new"]]
    open_issues = [i for i in issues if i["status"].lower() != "resolved"]
    exploited = [c for c in cves["list"] if c["exploited"]]
    followup = mode == "followup"
    ref = f"SYM-WSSQL-{ym.replace('-', '')}-{'F' if followup else 'P'}"

    # Summary
    if exploited:
        status = R._tag("Action required", "red")
        lead = (f"{len(exploited)} vulnerabilit{'ies' if len(exploited) != 1 else 'y'} fixed this month "
                f"{'are' if len(exploited) != 1 else 'is'} being actively exploited. Deploy the {month} updates as a priority.")
    elif open_issues:
        status = R._tag("Review advised", "yellow")
        lead = (f"No actively exploited vulnerabilities affect Windows Server or SQL Server this month, but "
                f"{len(open_issues)} known issue{'s are' if len(open_issues) != 1 else ' is'} still open. Review them before deploying.")
    else:
        status = R._tag("All OK", "green")
        lead = "No actively exploited vulnerabilities or open known issues affect Windows Server or SQL Server this month."
    lead += (f" Microsoft released {n_win} Windows Server update{'s' if n_win != 1 else ''} and "
             f"{len(sql_new)} SQL Server update{'s' if len(sql_new) != 1 else ''} in {month}, fixing "
             f"{cves['total']} CVE{'s' if cves['total'] != 1 else ''} ({cves['critical']} critical).")
    if followup:
        since = R._fmt_date(snap["taken"][:10]) if snap else ""
        lead = ((f"Month-end follow-up. {changes} item{'s have' if changes != 1 else ' has'} been added or changed since the "
                 f"Patch Tuesday report on {since} and {'are' if changes != 1 else 'is'} marked below. ") if snap else
                "Month-end follow-up. ") + lead

    sample_banner = (f'<tr><td style="padding:12px 40px 0"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                     f'style="background:{R.NAVY};border-radius:4px"><tr><td style="padding:9px 14px;font-family:{R.TEXT_FONT};'
                     f'font-size:12px;color:{R.OFFWHITE}"><b style="color:{R.ORANGE};letter-spacing:2px">PREVIEW</b> &nbsp; '
                     f'Built from live Microsoft data to preview the format. Not sent by email.</td></tr></table></td></tr>'
                     if sample else "")

    # 02 Windows Server updates
    wrows = [TABLE, f'<tr><th {TH} width="24%">Update</th><th {TH}>Details</th><th {TH} width="18%">CVEs fixed</th>'
                    f'<th {TH} width="12%">Released</th></tr>']
    for version in WINDOWS:
        rows = win.get(version, [])
        wrows.append(_group(version, f" &nbsp;&middot;&nbsp; {len(rows)} update{'s' if len(rows) != 1 else ''}"))
        if not rows:
            wrows.append(_empty("No update released this month."))
        for u in rows:
            st = u.get("cves") or {}
            cv = (f'<div style="font-family:{R.HEAD_FONT};font-size:20px;font-weight:700;line-height:1">{st["total"]}</div>'
                  + (f'<div style="margin-top:4px">{R._tag(str(st["critical"]) + " critical", "red")}</div>' if st.get("critical") else "")
                  + (f'<div style="margin-top:4px">{R._tag(str(st["exploited"]) + " exploited", "red")}</div>' if st.get("exploited") else "")
                  if st.get("total") else f'<span style="font-size:12px;color:{R.TEXT_2}">None (non-security)</span>')
            wrows.append(
                f'<tr><td {TD};font-size:14px"><b>KB{u["kb"]}</b>{_change(u)}'
                f'<div style="font-size:12px;color:{R.TEXT_2};margin-top:3px">OS build {R._e(u["build"])}</div></td>'
                f'<td {TD};font-size:13px;line-height:1.45"><b>{R._e(u["type"])}</b>'
                f'<span style="color:{R.TEXT_2}"> &nbsp;({R._e(u["code"])})</span>'
                f'{_links(("Release notes", u["notes"]), ("Download", u["download"]))}</td>'
                f'<td {TD}">{cv}</td>'
                f'<td {TD};font-size:12px;color:{R.TEXT_2};white-space:nowrap">{R._fmt_date(u["date"])}</td></tr>')
    wrows.append("</table></td></tr>")

    # 03 Known issues
    irows = [TABLE, f'<tr><th {TH}>Issue</th><th {TH} width="24%">Affects</th><th {TH} width="14%">Status</th>'
                    f'<th {TH} width="12%">Updated</th></tr>']
    if not issues:
        irows.append(_empty("Microsoft lists no open known issues for Windows Server, and none were resolved this month."))
    for i in issues:
        detail = R._clip(i["detail"] or i["summary"], 320)
        wk = (f'<div style="margin-top:6px;padding:6px 8px;background:{R.OFFWHITE};border-left:3px solid {R.ORANGE};'
              f'font-size:12px;color:{R.NAVY};line-height:1.45">{R._e(R._clip(i["workaround"], 260))}</div>'
              if i["workaround"] and i["status"].lower() != "resolved" else "")
        fixed = (f'<div style="font-size:11px;color:{R.TEXT_2};margin-top:4px">Fixed in KB{i["fixed_kb"]}</div>'
                 if i["fixed_kb"] else "")
        affects = "".join(
            f'<div style="margin-bottom:3px"><b>{R._e(v["version"].replace("Windows Server ", "WS "))}</b>'
            f'<span style="color:{R.TEXT_2}"> since KB{v["kb"]}</span></div>' if v["kb"] else
            f'<div style="margin-bottom:3px"><b>{R._e(v["version"].replace("Windows Server ", "WS "))}</b></div>'
            for v in i["versions"])
        irows.append(
            f'<tr><td {TD};font-size:14px;line-height:1.4"><a href="{R._e(i["link"])}" style="color:{R.NAVY};'
            f'text-decoration:none;font-weight:700">{R._e(i["title"])}</a>{_change(i)}'
            f'<div style="margin-top:3px;color:{R.TEXT_2};font-size:13px;line-height:1.45">{R._e(detail)}</div>{wk}'
            f'{_links(("Full details", i["link"]))}</td>'
            f'<td {TD};font-size:12px;line-height:1.4">{affects}</td>'
            f'<td {TD}">{_issue_tag(i["status"])}{fixed}</td>'
            f'<td {TD};font-size:12px;color:{R.TEXT_2};white-space:nowrap">{R._e(R._fmt_date(i["updated"][:10]))}</td></tr>')
    irows.append("</table></td></tr>")

    # 04 SQL Server
    srows = [TABLE, f'<tr><th {TH} width="24%">Update</th><th {TH}>Details</th><th {TH} width="18%">Status</th>'
                    f'<th {TH} width="12%">Released</th></tr>']
    for v in sql:
        new_n = sum(r["new"] for r in v["releases"])
        srows.append(_group(v["version"], f" &nbsp;&middot;&nbsp; {new_n} new this month" if new_n else " &nbsp;&middot;&nbsp; no new update"))
        for r in v["releases"]:
            kind = {"GDR": "Security update (GDR)", "CU": "Cumulative update",
                    "CU + security": "Cumulative update with security fixes"}[r["kind"]]
            known = ""
            if r["issues"]:
                known = (f'<div style="margin-top:6px;padding:6px 8px;background:{R.OFFWHITE};border-left:3px solid {R.ORANGE};'
                         f'font-size:12px;color:{R.NAVY};line-height:1.45"><b>Known issues:</b> '
                         + "; ".join(R._e(x) for x in r["issues"]) + "</div>")
            tag = R._tag("New this month", "blue") if r["new"] else R._tag("Current", "silver")
            srows.append(
                f'<tr><td {TD};font-size:14px"><b>{R._e(r["label"])}</b>{_change(r)}'
                f'<div style="font-size:12px;color:{R.TEXT_2};margin-top:3px">KB{r["kb"]} &middot; build {R._e(r["build"])}</div></td>'
                f'<td {TD};font-size:13px;line-height:1.45"><b>{kind}</b>{known}'
                f'{_links(("Release notes", r["notes"]), ("Download", r["download"]))}</td>'
                f'<td {TD}">{tag}</td>'
                f'<td {TD};font-size:12px;color:{R.TEXT_2};white-space:nowrap">{R._e(r["month"])}</td></tr>')
    srows.append("</table></td></tr>")

    # 05 Notable vulnerabilities
    vrows = [TABLE, f'<tr><th {TH} width="20%">CVE</th><th {TH}>Vulnerability</th><th {TH} width="18%">Severity</th>'
                    f'<th {TH} width="12%">CVSS</th></tr>']
    notable = cves["list"][:15]
    if not notable:
        vrows.append(_empty("No critical, publicly disclosed or exploited vulnerabilities this month."))
    for c in notable:
        tag = (R._tag("Exploited", "red") if c["exploited"] else R._tag("Critical", "red") if c["critical"]
               else R._tag("Disclosed", "yellow"))
        vrows.append(
            f'<tr><td {TD};font-size:13px;font-weight:700"><a href="{MSRC_GUIDE}/vulnerability/{c["cve"]}" '
            f'style="color:{R.NAVY};text-decoration:none">{c["cve"]}</a></td>'
            f'<td {TD};font-size:13px">{R._e(c["title"])}</td><td {TD}">{tag}</td>'
            f'<td {TD};font-size:13px">{c["score"] or ""}</td></tr>')
    more = len(cves["list"]) - len(notable)
    if more > 0:
        vrows.append(_empty(f'…and {more} more critical vulnerabilities. <a href="{MSRC_GUIDE}" style="color:{R.BLUE};'
                            f'font-weight:700;text-decoration:none">Security Update Guide &rsaquo;</a>'))
    vrows.append("</table></td></tr>")

    B = R.BLUE
    sections = (
        _head(2, "Windows Server", f"{month.split()[0]} <span style=\"color:{B}\">updates</span>",
              "Every update Microsoft released this month for each supported version, with the number of security fixes it contains.",
              "icon-update", img) + "".join(wrows)
        + _head(3, "Windows release health", f"Known <span style=\"color:{B}\">issues</span>",
                "Open issues reported by Microsoft, plus issues resolved this month. Check these before you deploy.",
                "icon-warning", img) + "".join(irows)
        + _head(4, "SQL Server", f"SQL Server <span style=\"color:{B}\">updates</span>",
                "The latest security update (GDR) and cumulative update for each supported version. Updates released this month are marked.",
                "icon-globe", img) + "".join(srows)
        + _head(5, "Security Update Guide", f"Notable <span style=\"color:{B}\">vulnerabilities</span>",
                "Exploited, publicly disclosed and critical vulnerabilities fixed this month in Windows Server or SQL Server.",
                "icon-cyber", img) + "".join(vrows))

    subject = (("[PREVIEW] " if sample else "[URGENT] " if exploited else "")
               + f"Symbiosys Windows Server & SQL Server Patch Report | {month}"
               + (" | Month-end follow-up" if followup else "")
               + f" | {n_win} Windows, {len(sql_new)} SQL, {len(open_issues)} open issue{'s' if len(open_issues) != 1 else ''}")

    body = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting"><title>{TITLE}</title></head>
<body style="margin:0;padding:0;background:#dcd9d0">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#dcd9d0"><tr><td align="center" style="padding:24px 10px">
<table role="presentation" width="820" cellpadding="0" cellspacing="0" style="max-width:820px;width:100%;background:{R.OFFWHITE}">
  <tr><td style="background:{R.NAVY};padding:30px 40px 34px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top">{R._label("Patch intelligence &middot; " + ("Month-end follow-up" if followup else "Monthly brief"), R.SILVER)}</td>
      <td valign="top" align="right" width="190"><img src="{img(R.LOGO_CID)}" width="170" alt="Symbiosys" style="display:block;width:170px;height:auto;border:0"></td>
    </tr>
    <tr><td colspan="2" style="padding-top:18px">
      <div style="font-family:{R.HEAD_FONT};font-size:34px;font-weight:700;color:{R.OFFWHITE};text-transform:uppercase;line-height:1.05">
        Windows Server &amp; <span style="color:{R.ORANGE}">SQL Server</span><br>patch report</div>
      <div style="font-family:{R.TEXT_FONT};font-size:14px;color:{R.OFFWHITE};margin-top:10px">{month}: updates, known issues and download links for the Microsoft server platforms Symbiosys supports.</div>
    </td></tr></table>
  </td></tr>
  <tr><td style="background:{R.NAVY};padding:0 40px 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #1d2a3d"><tr>
      <td style="padding-top:12px;font-family:{R.TEXT_FONT};font-size:10px;letter-spacing:3px;color:{R.SILVER}">{month.upper()} &nbsp;&middot;&nbsp; ISSUED {local.strftime("%d %b %Y %H:%M").upper()} SAST</td>
      <td align="right" style="padding-top:12px;font-family:{R.TEXT_FONT};font-size:10px;letter-spacing:3px;color:{R.ORANGE}">{ref}</td>
    </tr></table>
  </td></tr>
  {sample_banner}
  <tr><td style="padding:30px 40px 6px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="bottom">{R._section_number(1)}{R._label("Executive summary")}
        <div style="font-family:{R.HEAD_FONT};font-size:26px;font-weight:700;color:{R.NAVY};text-transform:uppercase;line-height:1.1;margin-top:6px">This month <span style="color:{R.BLUE}">at a glance</span></div></td>
      <td valign="bottom" align="right">{status}</td>
    </tr></table>
    <div style="font-family:{R.TEXT_FONT};font-size:15px;color:{R.NAVY};line-height:1.5;margin-top:10px">{R._e(lead)}</div>
  </td></tr>
  <tr><td style="padding:18px 34px 4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      {R._kpi("icon-update", n_win, "Windows updates", img)}
      {R._kpi("icon-globe", len(sql_new), "SQL updates", img)}
      {R._kpi("icon-warning", len(open_issues), "Open issues", img)}
      {R._kpi("icon-cyber", cves["critical"], "Critical CVEs", img)}
    </tr></table>
  </td></tr>
  {sections}
  <tr><td style="padding:34px 40px 0">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid {R.LINE}"><tr>
      <td style="padding-top:14px;font-family:{R.TEXT_FONT};font-size:12px;color:{R.TEXT_2};line-height:1.6">
        <b style="color:{R.NAVY}">About this report.</b> Issued the day after Microsoft's Patch Tuesday, with a follow-up on the
        1st of the next month. Sources: Windows Server release information, Windows release health, the Microsoft Security
        Update Guide and the SQL Server update history. Confirm applicability against Microsoft guidance before deploying.
      </td></tr></table>
  </td></tr>
  <tr><td style="padding:22px 40px 26px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-family:{R.TEXT_FONT};font-size:10px;letter-spacing:3px;text-transform:uppercase;color:{R.NAVY}">Windows Server &amp; SQL Server patch report {local.year}</td>
      <td align="right" style="font-family:{R.TEXT_FONT};font-size:10px;letter-spacing:3px;text-transform:uppercase;color:{R.NAVY}">Internal use</td>
    </tr></table>
  </td></tr>
</table></td></tr></table>
</body></html>'''

    lines = [TITLE.replace("&amp;", "&"), f"{month}   Ref: {ref}", "", lead, ""]
    for version in WINDOWS:
        lines.append(f"== {version} ==")
        for u in win.get(version, []):
            lines.append(f"- KB{u['kb']} {u['type']} ({u['date']}), build {u['build']}: {u['notes']}")
    lines += ["", "== Known issues =="] + [f"- [{i['status']}] {i['title']}: {i['link']}" for i in issues]
    lines += ["", "== SQL Server =="] + [f"- {v} {r['label']} KB{r['kb']} ({r['month']}): {r['notes']}" for v, r in sql_new]
    return subject, body, "\n".join(lines)


# --------------------------------------------------------------------------- main

def decide_mode() -> tuple[str | None, str]:
    mode = (os.environ.get("REPORT_MODE") or "auto").strip().lower()
    today = now.astimezone(R.REPORT_TZ).date()
    if mode == "auto":
        if today.day == 1:
            mode = "followup"
        elif today == patch_tuesday(today.year, today.month) + dt.timedelta(days=1):
            mode = "patch"
        else:
            return None, ""
    ym = (os.environ.get("REPORT_MONTH") or "").strip()
    if not ym:
        if mode == "followup":
            prev = today.replace(day=1) - dt.timedelta(days=1)
            ym = prev.strftime("%Y-%m")
        else:
            ym = today.strftime("%Y-%m")
    return mode, ym


def main() -> int:
    mode, ym = decide_mode()
    if not mode:
        print("Not a report day (the day after Patch Tuesday or the 1st). Nothing to do.")
        return 0
    preview = os.environ.get("PREVIEW_ONLY") == "true"
    print(f"Mode: {mode}, month: {ym}, preview only: {preview}")

    win = windows_updates(ym)
    cvrf = msrc_month(ym)
    for version, rows in win.items():
        for u in rows:
            u["cves"] = cve_stats(cvrf, rf"^{re.escape(version)}\b", {u["kb"]})
    cves = cve_stats(cvrf, r"^Windows Server (2016|2019|2022|2025)\b|^Microsoft SQL Server (2016|2017|2019|2022|2025)\b")
    data = {"windows": win, "issues": known_issues(ym), "sql": sql_updates(ym), "cves": cves}

    snap_file = SNAP_DIR / f"{ym}.json"
    snap = json.loads(snap_file.read_text(encoding="utf-8")) if snap_file.exists() else None
    changes = mark_changes(data, snap) if mode == "followup" else 0

    subject, body_html, body_text = build(data, ym, mode, changes, snap, sample=preview)

    pv = body_html
    for cid, path in R.INLINE_IMAGES.items():
        if path.exists():
            pv = pv.replace(f"cid:{cid}", "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode())
    (ROOT / "monthly-report.html").write_text(pv, encoding="utf-8")
    print(f"Subject: {subject}")
    if preview:
        print("Preview only: saved monthly-report.html, no email sent.")
        return 0

    send_email(subject, body_html, body_text)
    if mode == "patch":
        SNAP_DIR.mkdir(parents=True, exist_ok=True)
        snap_file.write_text(json.dumps(snapshot(data), indent=1, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
