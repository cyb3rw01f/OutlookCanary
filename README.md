# OutlookDraftLab

**First draft. Not a product.** A small lab fixture so an analyst can ask: would we log this if it happened? Can we write a SIEM rule that will detect it?

It creates **one labeled Outlook draft** that is never sent, then tells you **what to search for**. It does not log into Elastic, Sentinel, Splunk, or any other SIEM. You hunt.

Ingest is often late. An empty search in the first few minutes is usually delay, not a failed test. Wait 15–30 minutes before you call it a miss.

Authorized use only. Lab mailbox you control.

## What a run prints

```
GO CHECK YOUR SIEM
Ingest is often delayed. Wait 15-30 minutes before you call it a miss.

CANARY  : LAB-DRAFT-20260814-A1B2
MAILBOX : lab@contoso.com
WHEN    : 2026-08-14T...Z
MSG ID  : <draft id>
```

Then: can you find this event? If yes, can you write a SIEM rule that would fire on it?

## How to run it

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Set-Location C:\path\to\OutlookDraftLab
Set-ExecutionPolicy -Scope Process Bypass
.\Test-OutlookDraftGraph.ps1
```

Sign in as the lab mailbox when prompted. The script creates one draft (subject = canary), prints the hunt card, and deletes the draft unless you pass `-SkipCleanup`.

```powershell
.\Test-OutlookDraftGraph.ps1 -WhatIf
.\Test-OutlookDraftGraph.ps1 -SkipCleanup
```

You do not need SIEM credentials or a specific vendor.

## What to filter on

Best first: the **exact canary**. Then:

| Field | What to use |
| --- | --- |
| Canary | `LAB-DRAFT-...` from the run |
| Mailbox | the lab UPN printed in the run |
| Time (UTC) | WHEN through WHEN + 30 minutes or more |
| Message id | MSG ID from the run |

Same canary in any search box. Do not treat a blank result at T+2 minutes as “not logged.”

## What this does not do

- Send mail
- Query or score a SIEM
- Steal tokens or persist
- Prove you would catch a real implant

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- A lab Microsoft 365 mailbox
- The `Microsoft.Graph.Authentication` module (the script uses it only to create and delete the draft)
- First-run consent for that lab user to create mail (`Mail.ReadWrite`, `User.Read`)

Optional: `-CheckMicrosoftAudit` asks Microsoft 365 whether *it* recorded the draft. That is a source-log check, not a SIEM check, and needs extra audit rights.

## Later

This first draft will change. Later work stays as small fixtures, not a platform. See `PRINCIPLES.md`.

## Author

[@cyb3rw01f](https://github.com/cyb3rw01f)
