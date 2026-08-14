# OutlookDraftCanary

**First draft. Not a product.** A small lab fixture so an analyst can ask: would we log this if it happened? Can we write a SIEM rule that will detect it?

It creates **one labeled Outlook draft** that is never sent, then tells you **what to search for in your SIEM**. It does not connect to Elastic, Sentinel, Splunk, or any other SIEM. You hunt.

Ingest is often late. An empty search in the first few minutes is usually delay, not a failed test. Wait 15–30 minutes before you call it a miss.

Authorized use only. Lab mailbox you control.

## What a run does

1. You sign in as a lab mailbox.
2. The script creates one draft. The subject is the canary (`LAB-DRAFT-...`). It is never sent.
3. It prints **HUNT NOW** with the canary so you can start searching.
4. It prints a **GO CHECK YOUR SIEM** card: canary, mailbox, time, message id, and field-level filters.
5. It deletes the draft unless you pass `-SkipCleanup`.

Default run does not wait on Microsoft audit and does not query any SIEM.

## What a run prints

```
HUNT NOW: LAB-DRAFT-20260814-A1B2

GO CHECK YOUR SIEM
This script does not query Elastic, Sentinel, Splunk, or any other SIEM.
First: can you find this event (would we log it)?
Then: can we write a SIEM rule that will detect it?
Ingest is often delayed. Wait 15-30 minutes before you call it a miss.

CANARY  : LAB-DRAFT-20260814-A1B2
MAILBOX : lab@contoso.com
WHEN    : 2026-08-14T...Z
MSG ID  : <draft id>
```

Filter on, in order: exact canary, mailbox, time window (WHEN through 30+ minutes later UTC), message id. The card also lists optional extra fields (API path, mailbox Create/Update on Drafts) and paste-ready searches for a generic box, Elastic, Sentinel, Splunk, and Purview.

## How to run it

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Set-Location C:\path\to\OutlookDraftCanary
Set-ExecutionPolicy -Scope Process Bypass
.\Test-OutlookDraftCanary.ps1
```

```powershell
.\Test-OutlookDraftCanary.ps1 -WhatIf
.\Test-OutlookDraftCanary.ps1 -SkipCleanup
.\Test-OutlookDraftCanary.ps1 -CheckMicrosoftAudit
.\Test-OutlookDraftCanary.ps1 -CheckMicrosoftAudit -WaitMinutes 15
```

You do not need SIEM credentials or a specific vendor.

## What this does not do

- Send mail
- Query or score a SIEM
- Steal tokens or persist
- Prove you would catch a real implant

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- A lab Microsoft 365 mailbox
- `Microsoft.Graph.Authentication` (used only to create and delete the draft)
- First-run consent for that lab user: `Mail.ReadWrite`, `User.Read`

Optional `-CheckMicrosoftAudit`: after the hunt card, the script can ask Microsoft 365 whether *it* recorded the draft. That is a source-log check, not a SIEM check. It needs extra audit rights (`AuditLogsQuery-Exchange.Read.All`, or Exchange Online plus an audit role). Off by default so the test finishes quickly.

## Later

This first draft will change. Later work stays as small fixtures, not a platform. See `PRINCIPLES.md`.

## Author

[@cyb3rw01f](https://github.com/cyb3rw01f)
