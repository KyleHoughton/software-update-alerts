"""Hourly software update and vulnerability checker.

Reads sources.yaml, checks every source, compares with state/seen.json and emails
the group when anything new appears. The first time a source is seen it is only
recorded (no email), so the group isn't flooded with old items.

Environment variables (set as GitHub secrets):
  MAIL_FROM, MAIL_TO (comma separated), and either
  GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET (Microsoft 365, works with a shared mailbox) or
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
  NVD_API_KEY (optional, raises the NVD rate limit)
If SMTP settings are missing, the email is written to the GitHub job summary instead.
"""

from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import html
import json
import os
import re
import smtplib
import sys
import time
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "state" / "seen.json"
PAGES_DIR = ROOT / "state" / "pages"
MAX_IDS_PER_SOURCE = 1000
FAIL_REPORT_AFTER = 3  # consecutive failures before a source is reported as broken

UA = "Mozilla/5.0 (compatible; software-update-alerts/1.0; +https://github.com)"
session = requests.Session()
session.headers.update({"User-Agent": UA, "Accept": "*/*"})

now = dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- helpers

def get(url: str, **kw) -> requests.Response:
    last = None
    for attempt in range(3):
        try:
            r = session.get(url, timeout=45, **kw)
            if r.status_code in (429, 503) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:  # noqa: PERF203
            last = e
            time.sleep(3 * (attempt + 1))
    raise last  # type: ignore[misc]


def item(id_: str, title: str, link: str = "", summary: str = "", date: str = "",
         urgent: bool = False) -> dict:
    return {"id": id_, "title": title.strip(), "link": link, "summary": summary,
            "date": date, "urgent": urgent}


def strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def short(s: str, n: int = 400) -> str:
    s = strip_tags(s)
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


# --------------------------------------------------------------------------- fetchers

def fix_entities(text: str) -> str:
    """Some vendor feeds use HTML entities such as &nbsp; that strict XML parsers reject."""
    from html.entities import name2codepoint
    xml_ok = {"amp", "lt", "gt", "quot", "apos"}

    def repl(m):
        name = m.group(1)
        if name in xml_ok or name not in name2codepoint:
            return m.group(0)
        return f"&#{name2codepoint[name]};"
    text = re.sub(r"&([A-Za-z][A-Za-z0-9]*);", repl, text)
    return re.sub(r"^\s*<\?xml[^>]*\?>", "", text)  # encoding already handled by requests

def fetch_rss(src: dict) -> list[dict]:
    r = get(src["url"])
    try:
        root = ET.fromstring(fix_entities(r.text))
    except ET.ParseError as e:
        head = re.sub(r"\s+", " ", r.text[:300])
        raise ValueError(f"not a valid feed ({e}); got {r.headers.get('content-type')} from {r.url}: {head}") from None
    out = []
    excl = [re.compile(p, re.I) for p in src.get("exclude_titles", [])]
    incl = [re.compile(p, re.I) for p in src.get("include_titles", [])]
    atom = "{http://www.w3.org/2005/Atom}"
    entries = root.findall(".//item") or root.findall(f".//{atom}entry")
    for e in entries:
        def t(tag):
            el = e.find(tag)
            if el is None:
                el = e.find(atom + tag)
            return (el.text or "") if el is not None else ""
        title = t("title")
        if any(p.search(title) for p in excl):
            continue
        if incl and not any(p.search(title) for p in incl):
            continue
        link = t("link")
        if not link:
            le = e.find(atom + "link")
            link = le.get("href", "") if le is not None else ""
        guid = t("guid") or t("id") or link or title
        summary = t("description") or t("summary") or t("content")
        date = t("pubDate") or t("updated") or t("published")
        out.append(item(guid, title, link, short(summary), date))
    if not entries and not src.get("allow_empty"):
        raise ValueError("feed returned no items (may not be an RSS/Atom feed)")
    return out


def fetch_github_release(src: dict) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = get(f"https://api.github.com/repos/{src['repo']}/releases?per_page=10", headers=headers)
    out = []
    for rel in r.json():
        if rel.get("draft"):
            continue
        name = rel.get("name") or rel.get("tag_name")
        out.append(item(str(rel["id"]), f"{src['name']} {name}", rel.get("html_url", ""),
                        short(rel.get("body") or "", 600), rel.get("published_at", "")))
    return out


def fetch_cisa_kev(src: dict) -> list[dict]:
    data = get(src["url"]).json()
    out = []
    for v in data.get("vulnerabilities", []):
        title = f"{v['cveID']}: {v.get('vendorProject', '')} {v.get('product', '')} – {v.get('vulnerabilityName', '')}"
        summary = (f"{v.get('shortDescription', '')} Required action: {v.get('requiredAction', '')} "
                   f"Ransomware use: {v.get('knownRansomwareCampaignUse', 'Unknown')}.")
        out.append(item(v["cveID"], title, f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                        short(summary, 600), v.get("dateAdded", ""), urgent=True))
    return out


def fetch_nvd(src: dict, vendors: list[dict], last_run: str | None) -> list[dict]:
    start = (dt.datetime.fromisoformat(last_run) if last_run else now - dt.timedelta(days=2)) - dt.timedelta(hours=2)
    start = max(start, now - dt.timedelta(days=100))  # NVD allows max 120-day window
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    matchers = []
    for v in vendors:
        kw = [re.compile(r"(?<![\w-])" + re.escape(k) + r"(?![\w-])", re.I) for k in v.get("keywords", [])]
        matchers.append((v["name"], [c.lower() for c in v.get("cpe", [])], kw))
    out = []
    while True:
        data = get(src["url"], params=params, headers=headers).json()
        for wrap in data.get("vulnerabilities", []):
            c = wrap["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            cpes = " ".join(m.get("criteria", "") for cfg in c.get("configurations", [])
                            for n in cfg.get("nodes", []) for m in n.get("cpeMatch", [])).lower()
            hit = None
            for name, cpe_ids, kws in matchers:
                if any(f":{cid}:" in cpes for cid in cpe_ids) or any(k.search(desc) for k in kws):
                    hit = name
                    break
            if not hit:
                continue
            score, sev = cvss(c)
            urgent = score is not None and score >= float(src.get("urgent_cvss", 9.0))
            label = f" (CVSS {score} {sev})" if score is not None else " (not yet scored)"
            out.append(item(c["id"], f"{c['id']}: {hit}{label}",
                            f"https://nvd.nist.gov/vuln/detail/{c['id']}", short(desc, 600),
                            c.get("published", ""), urgent=urgent))
        total = data.get("totalResults", 0)
        params["startIndex"] += data.get("resultsPerPage", 0) or 2000
        if params["startIndex"] >= total:
            break
        time.sleep(6 if not headers else 1)
    return out


def cvss(c: dict):
    m = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity") or m[key][0].get("baseSeverity", "")
    return None, ""


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer", "header", "form"}

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.lines: list[str] = []
        self.buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.depth += 1
        elif tag in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "br", "td", "section", "article"}:
            self.flush()

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.depth:
            self.depth -= 1
        elif tag in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "td", "section", "article"}:
            self.flush()

    def handle_data(self, data):
        if not self.depth:
            self.buf.append(data)

    def flush(self):
        line = re.sub(r"\s+", " ", "".join(self.buf)).strip()
        if line:
            self.lines.append(line)
        self.buf = []


def page_lines(url: str) -> list[str]:
    p = _Text()
    p.feed(get(url).text)
    p.flush()
    seen, out = set(), []
    for line in p.lines:
        if len(line) < 15 or line in seen:  # drop menu fragments and duplicates
            continue
        seen.add(line)
        out.append(line)
    return out


def fetch_page_watch(sid: str, src: dict, first: bool) -> list[dict]:
    lines = page_lines(src["url"])
    if sum(len(x) for x in lines) < 200:
        raise ValueError("page has almost no readable text (probably needs JavaScript or blocks bots)")
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    f = PAGES_DIR / f"{sid}.txt"
    old = f.read_text(encoding="utf-8").splitlines() if f.exists() else []
    f.write_text("\n".join(lines), encoding="utf-8")
    if first or not old:
        return []
    old_set = set(old)
    added = [x for x in lines if x not in old_set]
    if src.get("only_lines"):
        keep = re.compile(src["only_lines"], re.I)
        added = [x for x in added if keep.search(x)]
    if not added:
        return []
    digest = hashlib.sha1("\n".join(added).encode()).hexdigest()[:12]
    preview = "\n".join(f"• {short(x, 220)}" for x in added[:8])
    more = f"\n…and {len(added) - 8} more new lines" if len(added) > 8 else ""
    return [item(f"{sid}:{digest}", f"{src['name']}: page updated ({len(added)} new lines)",
                 src["url"], preview + more, now.strftime("%Y-%m-%d"))]


# --------------------------------------------------------------------------- email

def build_email(new: list[tuple[dict, dict]], broken: list[tuple[str, dict, str]]) -> tuple[str, str, str]:
    urgent = [(s, i) for s, i in new if i["urgent"]]
    security = [(s, i) for s, i in new if not i["urgent"] and s["category"] == "security"]
    updates = [(s, i) for s, i in new if not i["urgent"] and s["category"] != "security"]

    parts = []
    if urgent:
        parts.append(f"{len(urgent)} URGENT")
    if security:
        parts.append(f"{len(security)} security")
    if updates:
        parts.append(f"{len(updates)} update{'s' if len(updates) != 1 else ''}")
    subject = "[Update alerts] " + (", ".join(parts) if parts else "source health")

    def section(title, rows, colour):
        if not rows:
            return "", ""
        h = [f'<h2 style="color:{colour};font-family:Segoe UI,Arial;font-size:18px;margin:24px 0 8px">{title} ({len(rows)})</h2>']
        t = [f"\n== {title} ({len(rows)}) =="]
        rows = sorted(rows, key=lambda r: r[0]["name"])
        for s, i in rows:
            link = f'<a href="{html.escape(i["link"])}">{html.escape(i["title"])}</a>' if i["link"] else html.escape(i["title"])
            summ = html.escape(i["summary"]).replace("\n", "<br>")
            h.append(
                '<div style="border-left:3px solid %s;padding:6px 12px;margin:8px 0;font-family:Segoe UI,Arial;font-size:14px">'
                '<div style="color:#666;font-size:12px">%s%s</div><div style="font-weight:600">%s</div>'
                '<div style="color:#333;margin-top:4px">%s</div></div>'
                % (colour, html.escape(s["name"]), (" · " + html.escape(i["date"])) if i["date"] else "", link, summ))
            t.append(f"- [{s['name']}] {i['title']}\n  {i['link']}\n  {i['summary']}")
        return "\n".join(h), "\n".join(t)

    html_parts, text_parts = [], []
    for title, rows, colour in (("Urgent: actively exploited or critical", urgent, "#c62828"),
                                ("Security advisories", security, "#ef6c00"),
                                ("Product updates and release notes", updates, "#1565c0")):
        h, t = section(title, rows, colour)
        html_parts.append(h)
        text_parts.append(t)

    if broken:
        html_parts.append('<h2 style="color:#555;font-family:Segoe UI,Arial;font-size:16px;margin:24px 0 8px">Sources that need attention</h2><ul style="font-family:Segoe UI,Arial;font-size:13px;color:#555">'
                          + "".join(f"<li>{html.escape(s['name'])}: {html.escape(err)}</li>" for _, s, err in broken) + "</ul>")
        text_parts.append("\n== Sources that need attention ==\n" + "\n".join(f"- {s['name']}: {err}" for _, s, err in broken))

    stamp = now.strftime("%Y-%m-%d %H:%M UTC")
    body_html = ('<div style="max-width:760px">' + "".join(html_parts) +
                 f'<p style="color:#999;font-size:12px;font-family:Segoe UI,Arial;margin-top:24px">Checked {stamp}. Sent automatically by software-update-alerts.</p></div>')
    body_text = "\n".join(text_parts) + f"\n\nChecked {stamp}."
    return subject, body_html, body_text


def send_graph(subject: str, body_html: str, to: list[str]) -> None:
    """Send through Microsoft Graph as MAIL_FROM (works for shared mailboxes, no mailbox password)."""
    tenant = os.environ["GRAPH_TENANT_ID"]
    data = {"client_id": os.environ["GRAPH_CLIENT_ID"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials"}
    if os.environ.get("GRAPH_CLIENT_SECRET"):
        data["client_secret"] = os.environ["GRAPH_CLIENT_SECRET"]
    else:
        # No secret: sign in with GitHub's own identity token (Entra federated credential).
        req_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        if not req_url:
            raise RuntimeError("No GRAPH_CLIENT_SECRET and no GitHub identity token (needs 'id-token: write').")
        gh = requests.get(req_url + "&audience=api://AzureADTokenExchange",
                          headers={"Authorization": f"bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"},
                          timeout=30)
        gh.raise_for_status()
        data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        data["client_assertion"] = gh.json()["value"]
    token = requests.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=data, timeout=30)
    if token.status_code != 200:
        raise RuntimeError(f"Graph sign-in failed: {token.status_code} {token.text[:300]}")
    sender = os.environ["MAIL_FROM"]
    r = requests.post(
        f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json={"message": {"subject": subject,
                          "body": {"contentType": "HTML", "content": body_html},
                          "toRecipients": [{"emailAddress": {"address": a}} for a in to]},
              "saveToSentItems": True},
        timeout=60)
    if r.status_code != 202:
        raise RuntimeError(f"Graph sendMail failed: {r.status_code} {r.text[:300]}")
    print(f"Email sent via Microsoft Graph from {sender} to {len(to)} recipient(s): {subject}")


def send_email(subject: str, body_html: str, body_text: str) -> None:
    host = os.environ.get("SMTP_HOST")
    to = [a.strip() for a in os.environ.get("MAIL_TO", "").split(",") if a.strip()]
    if os.environ.get("GRAPH_CLIENT_ID") and to:
        send_graph(subject, body_html, to)
        return
    if not host or not to:
        print("SMTP settings not configured; writing email to the job summary instead.")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"## {subject}\n\n(email not sent: SMTP secrets not set)\n\n{body_html}\n")
        else:
            print(subject)
            print(body_text)
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("MAIL_FROM") or os.environ["SMTP_USER"]
    msg["To"] = ", ".join(to)
    msg.set_content(body_text)
    msg.add_alternative(body_html, subtype="html")
    port = int(os.environ.get("SMTP_PORT") or 587)
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=60)
    else:
        server = smtplib.SMTP(host, port, timeout=60)
        server.starttls()
    with server:
        if os.environ.get("SMTP_USER"):
            server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        server.send_message(msg)
    print(f"Email sent to {len(to)} recipient(s): {subject}")


# --------------------------------------------------------------------------- main

def main() -> int:
    cfg = yaml.safe_load((ROOT / "sources.yaml").read_text(encoding="utf-8"))
    sources: dict[str, dict] = {}
    sources.update(cfg.get("vulnerabilities") or {})
    sources.update(cfg.get("updates") or {})
    vendors = cfg.get("vendors") or []

    only = os.environ.get("ONLY_SOURCES")  # comma separated ids, for testing
    if only:
        keep = {x.strip() for x in only.split(",")}
        sources = {k: v for k, v in sources.items() if k in keep}

    state = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    state.setdefault("sources", {})
    test_email = os.environ.get("SEND_TEST_EMAIL") == "true"

    new: list[tuple[dict, dict]] = []
    broken: list[tuple[str, dict, str]] = []

    for sid, src in sources.items():
        st = state["sources"].setdefault(sid, {"seen": [], "fails": 0})
        first = not st.get("initialised")
        try:
            t = src["type"]
            if t == "rss":
                items = fetch_rss(src)
            elif t == "github_release":
                items = fetch_github_release(src)
            elif t == "cisa_kev":
                items = fetch_cisa_kev(src)
            elif t == "nvd":
                items = fetch_nvd(src, vendors, st.get("last_ok"))
            elif t == "page_watch":
                items = fetch_page_watch(sid, src, first)
            else:
                raise ValueError(f"unknown type {t}")
        except Exception as e:  # noqa: BLE001
            st["fails"] = st.get("fails", 0) + 1
            err = f"{type(e).__name__}: {str(e)[:200]}"
            st["last_error"] = err
            print(f"[FAIL] {sid}: {err}")
            if st["fails"] == FAIL_REPORT_AFTER or (test_email and st["fails"] >= 1):
                broken.append((sid, src, err))
            continue

        seen = set(st["seen"])
        fresh = [i for i in items if i["id"] not in seen]
        if not first:
            new.extend((src, i) for i in fresh)
        if st.get("fails", 0) >= FAIL_REPORT_AFTER:
            print(f"[RECOVERED] {sid}")
        st["fails"] = 0
        st.pop("last_error", None)
        # Keep every id still in the feed, plus a tail of older ones in case items come back.
        current = [i["id"] for i in items]
        cur_set = set(current)
        older = [x for x in st["seen"] if x not in cur_set][-MAX_IDS_PER_SOURCE:]
        st["seen"] = older + current
        st["initialised"] = True
        st["last_ok"] = now.isoformat()
        print(f"[OK] {sid}: {len(items)} items, {len(fresh)} new{' (baseline, no alert)' if first else ''}")

    state["last_run"] = now.isoformat()
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")

    # The same CVE can come from several sources (CISA, NVD, Microsoft). Show it once, urgent first.
    new.sort(key=lambda si: not si[1]["urgent"])
    dedup, ids = [], set()
    for s, i in new:
        cve = re.match(r"CVE-\d{4}-\d+", i["title"]) or re.match(r"CVE-\d{4}-\d+", i["id"])
        key = cve.group(0) if cve else (s["name"], i["id"])
        if key not in ids:
            ids.add(key)
            dedup.append((s, i))
    new = dedup

    if new or broken or test_email:
        subject, body_html, body_text = build_email(new, broken)
        if test_email and not new and not broken:
            subject = "[Update alerts] Test email: setup works"
            body_html = "<p>This is a test email from software-update-alerts. Alerts will arrive here when new updates or vulnerabilities are found.</p>"
            body_text = "This is a test email from software-update-alerts."
        send_email(subject, body_html, body_text)
    else:
        print("Nothing new. No email sent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
