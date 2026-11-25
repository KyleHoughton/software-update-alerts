# Software update alerts

Checks every hour for new software releases, release notes and security vulnerabilities, and emails a group when something new appears. It runs free on GitHub Actions.

## What it watches

Everything is listed in [`sources.yaml`](sources.yaml):

- **Vulnerabilities:** CISA's actively exploited list (all software, always marked urgent), new CVEs from the US National Vulnerability Database for the vendors listed under `vendors:`, the Microsoft Security Update Guide and Fortinet PSIRT.
- **Microsoft:** Azure Updates, the Microsoft 365 Roadmap (Teams, Entra, Defender, Intune, Purview, Copilot), Azure Status, and the release pages for Windows Server, SQL Server, Exchange, Entra, Intune, Defender and Sentinel.
- **Quest and One Identity:** per-product support feeds (releases, patches and product notices).
- **Other vendors:** GitHub releases, release-note pages and security advisory pages.

## How it behaves

- On its first run a source is only recorded, so the group doesn't get thousands of old items.
- After that, one email goes out per hour **only if something is new**. It has three sections: Urgent (actively exploited, or CVSS 9.0 or higher), Security advisories, and Product updates.
- If a source fails three runs in a row, the next email lists it under "Sources that need attention".
- What has already been seen is saved in `state/`, and the job commits it back after each run.

## Setup (one time)

### Option A: Microsoft 365 shared mailbox (recommended, no mailbox password)

1. Entra admin center → **App registrations → New registration**, name it "Update alerts".
2. **API permissions → Add → Microsoft Graph → Application permissions → Mail.Send**, then **Grant admin consent**.
3. **Certificates & secrets → Federated credentials → Add credential**:
   - Scenario: **GitHub Actions deploying Azure resources**
   - Organization: `KyleHoughton`, Repository: `software-update-alerts`
   - Entity type: **Branch**, Branch: `main`
   - Name: `github-main`
   
   No client secret is needed, and nothing expires. (A client secret also works if you prefer: add it as `GRAPH_CLIENT_SECRET`.)
4. Recommended: limit the app to the shared mailbox only. In Exchange Online PowerShell:
   ```powershell
   Connect-ExchangeOnline
   New-DistributionGroup -Name "UpdateAlertsSenders" -Type Security -Members alerts@yourdomain.com
   New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId UpdateAlertsSenders -AccessRight RestrictAccess -Description "Update alerts can only send as this mailbox"
   Test-ApplicationAccessPolicy -AppId <client id> -Identity alerts@yourdomain.com
   ```
5. Add these repository secrets:

| Secret | Value |
|---|---|
| `GRAPH_TENANT_ID` | Directory (tenant) ID from the app's Overview page |
| `GRAPH_CLIENT_ID` | Application (client) ID from the app's Overview page |
| `MAIL_FROM` | the shared mailbox address |
| `MAIL_TO` | the group address (several can be separated by commas) |

### Option B: SMTP (Gmail or a normal mailbox)

In the repository go to **Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret | Gmail example | Microsoft 365 example |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | `smtp.office365.com` |
| `SMTP_PORT` | `587` | `587` |
| `SMTP_USER` | the Gmail address | the mailbox address |
| `SMTP_PASSWORD` | a Gmail **app password** (Google Account → Security → 2-Step Verification → App passwords) | the mailbox password (SMTP AUTH must be enabled for the mailbox) |
| `MAIL_FROM` | usually the same as `SMTP_USER` | usually the same as `SMTP_USER` |
| `MAIL_TO` | the group address (several addresses can be separated by commas) | same |
| `NVD_API_KEY` | optional, free from https://nvd.nist.gov/developers/request-an-api-key | same |

Then go to **Actions → Hourly update check → Run workflow**, tick **Send a test email**, and run it.

Until the email secrets are set, results are written to the run's summary page instead of being emailed.

## Monthly Windows Server & SQL Server report

A second, separate report ([`checker/monthly.py`](checker/monthly.py), workflow **Monthly Windows Server & SQL report**). It uses the same mailbox, secrets and Symbiosys look as the hourly alerts, and doesn't change the hourly job.

**When it is sent** (08:00 South African time):

- **The Wednesday after Patch Tuesday:** that month's updates for Windows Server 2025, 2022, 2019 and 2016 (KB, build, release notes and download links, and how many CVEs each fixes), the known issues Microsoft lists on Windows release health, the latest SQL Server 2025, 2022, 2019, 2017 and 2016 updates (with each new cumulative update's known issues), and the month's exploited or critical vulnerabilities.
- **The 1st of the next month:** a follow-up for the month just ended. Anything added or changed since the Patch Tuesday report (out-of-band updates, preview updates, new SQL updates, new or updated known issues) is marked **New** or **Updated**.

**Recipients:** `MAIL_TO`, or add a `MAIL_TO_MONTHLY` secret to send this report to a different list.

**Preview without emailing:** Actions → **Monthly Windows Server & SQL report** → Run workflow. "Build the preview only" is ticked by default. The report is attached to the run as **monthly-report** (download, unzip, open in a browser). Untick it to send the email now. You can also pick the follow-up mode and a past month (YYYY-MM).

Sources: [Windows Server release information](https://learn.microsoft.com/windows/release-health/windows-server-release-info), Windows release health known-issues pages, the Microsoft Security Update Guide API, and [SQL Server latest updates](https://learn.microsoft.com/troubleshoot/sql/releases/download-and-install-latest-updates).

## Adding or removing software

Edit `sources.yaml`. Copy an existing entry, give it a unique id, and set its `type`, `category` and `url`. To catch vulnerabilities for a new vendor, add it under `vendors:`.
