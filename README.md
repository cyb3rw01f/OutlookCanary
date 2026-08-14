# OutlookDraftLab

**First draft.** This is the first public cut of a small analyst fixture. It works, it is intentionally narrow, and it will change. Plans for improvements are later — do not treat this README as a finished product spec.

A PowerShell control test. It creates **one Outlook draft through Microsoft Graph**, then tells you **what to search for in your SIEM**.

It does not log into Elastic, Sentinel, Splunk, or any other SIEM. You hunt. Ingest is often late. An empty search in the first few minutes is usually delay, not a failed test.

Authorized use only. Lab mailbox you control. The script never sends mail.

## What a run prints

```
GO CHECK YOUR SIEM
Ingest is often delayed. Wait 15-30 minutes before you call it a miss.

CANARY  : LAB-DRAFT-20260814-A1B2
MAILBOX : lab@contoso.com
WHEN    : 2026-08-14T...Z
MSG ID  : <graph message id>
```

Then search the canary in whatever console you use.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- A lab Microsoft 365 mailbox
- `Microsoft.Graph.Authentication`

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Set-Location C:\path\to\OutlookDraftLab
Set-ExecutionPolicy -Scope Process Bypass
.\Test-OutlookDraftGraph.ps1
```

First run: consent `Mail.ReadWrite` and `User.Read` for that lab user.

You do not need SIEM credentials, API keys, or a specific vendor.

Optional: `-CheckMicrosoftAudit` polls Microsoft unified audit only (not your SIEM). That needs `AuditLogsQuery-Exchange.Read.All` or Exchange Online plus an audit role.

```powershell
.\Test-OutlookDraftGraph.ps1 -WhatIf
.\Test-OutlookDraftGraph.ps1 -SkipCleanup
.\Test-OutlookDraftGraph.ps1 -CheckMicrosoftAudit
```

## What to filter on

Best first: the **exact canary**. Also: mailbox UPN, time window (WHEN UTC through WHEN + 30 minutes or more), `POST` `/messages`, mailbox audit `Create`/`Update` on Drafts, message id.

Same canary in any product search box. Do not treat a blank result at T+2 minutes as “not logged.”

## What this does not do

- Send mail
- Query or score a SIEM
- Steal tokens or persist
- Prove you would catch a real implant

It only generates a labeled Graph draft and tells you how to find it.

## Later

Not in this first draft. Expected later, still as small fixtures, not a platform:

- Hunt-card wording from real analyst runs
- Optional Microsoft audit check polish
- More **separate** one-action fixtures (same canary style, different door)

See `PRINCIPLES.md`.

## Author

[@cyb3rw01f](https://github.com/cyb3rw01f)
