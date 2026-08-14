# OutlookCanary

**First draft. Not a product.** One unsent Outlook draft through Graph. Then you hunt your own logs: would we have logged this, and can we write a rule that would fire?

It does not talk to Elastic, Sentinel, Splunk, or anything else. You search.

## Why bother

After a breach, quiet theft often does not look like ransomware or some random C2 domain. FINALDRAFT, SIESTAGRAPH, the Graph/OneDrive jobs, OilBooster — they write to Outlook through Microsoft’s own API. Drafts, calendars, OneDrive. Mail never goes out, so the gateway and DLP never see it. Traffic is `graph.microsoft.com`. If you cannot find a draft you planted on purpose, you will not find the same thing when it is hostile.

The mailbox event is realistic. These campaigns go after people who live in Outlook, not admins. Once they have a token they do not need local admin. The way this script creates the draft is not realistic. Nobody in accounting opens PowerShell and consents to Graph. Stolen token from the attacker’s box, malware with its own app id, or a bad OAuth grant. Use a lab copy of a normal mailbox. If you write a rule on “Microsoft Graph PowerShell” you will catch the lab and miss the real one. Hunt the canary, the mailbox, the time, and `POST …/messages`. Not the process name.

Unlike [GraphMeCanary](https://github.com/cyb3rw01f/GraphMeCanary), this canary *is* in the mailbox. The subject is `LAB-DRAFT-…`. Keyword search is the right first move here.

Finding this draft in mailbox audit does **not** mean you can see Graph reads. That is a different log. Run GraphMeCanary with the same user if you want that answer.

Lab mailbox only. Not a VIP. Not a mailbox you care about.

## Requirements

**To run it**

- Windows PowerShell 5.1 or PowerShell 7
- A lab Microsoft 365 mailbox that can sign in interactively
- Path to `login.microsoftonline.com` and `graph.microsoft.com`
- `Microsoft.Graph.Authentication` — used to create and delete the draft
- First time, that user consents to `Mail.ReadWrite` and `User.Read`

You do not need a SIEM login. You do not need an audit role for the default run.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

**To actually see it**

The draft subject is a real mailbox field. Unified audit and mailbox audit can record Create/Update on Drafts if those are on. That is enough to answer “would we log a Graph-created unsent item?”

Graph activity (`POST` + `/messages`) is a second plane. Entra P1 or P2, category `MicrosoftGraphActivityLogs` on, and that feed in the box you search. A hit in mailbox audit and a miss in Graph activity is still a useful result: you see the write as mail, not as Graph.

Wait 15–30 minutes. Empty in the first couple of minutes is almost always ingest.

`-CheckMicrosoftAudit` is optional and off by default. It asks Microsoft whether *it* recorded the draft. That is not a SIEM check. It needs `AuditLogsQuery-Exchange.Read.All`, or Exchange Online plus an audit role. Do not wait on that flag for the SIEM answer.

## How to run the test

```powershell
Set-Location C:\path\to\OutlookCanary
Set-ExecutionPolicy -Scope Process Bypass
.\Test-OutlookCanary.ps1 -WhatIf
.\Test-OutlookCanary.ps1
```

Sign in as the lab mailbox. Accept `Mail.ReadWrite` and `User.Read` if it asks. The script creates one draft, prints the hunt card, and deletes the draft unless you pass `-SkipCleanup`.

```powershell
.\Test-OutlookCanary.ps1 -SkipCleanup
.\Test-OutlookCanary.ps1 -CheckMicrosoftAudit
.\Test-OutlookCanary.ps1 -CheckMicrosoftAudit -WaitMinutes 15
```

Copy `CANARY`, `MAILBOX`, `WHEN`, and `MSG ID` off the card. The canary looks like `LAB-DRAFT-20260814-A1B2`. That string *is* the draft subject. Start there.

Give it 15–30 minutes, longer if your pipeline is slow. Hunt, in order:

- exact canary
- that mailbox
- `WHEN` through a half hour later UTC
- message id
- mailbox Create or Update, folder Drafts
- Graph activity: `POST`, URI contains `/messages`, status 201

If the canary shows up, you would have logged a Graph-created unsent draft. If it does not, mailbox audit or your ingest is blind to that write. If you only found it because the client said Microsoft Graph PowerShell, a token used from another host will walk by you.

Leave `-SkipCleanup` on if you want to click the draft in Outlook while you hunt. Default run deletes it so the lab mailbox stays clean.

## What a run does

1. You sign in as the lab mailbox.
2. One draft. Subject is the canary. Never sent.
3. Prints **HUNT NOW** and the card.
4. Deletes the draft unless `-SkipCleanup`.

Default run does not query Microsoft audit and does not query a SIEM.

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

## What this does not do

- Send mail
- Query or score a SIEM
- Steal tokens or persist
- Prove you would catch an implant
- Prove you can see Graph reads (that is [GraphMeCanary](https://github.com/cyb3rw01f/GraphMeCanary))

See `PRINCIPLES.md`.

[@cyb3rw01f](https://github.com/cyb3rw01f)
