#Requires -Version 5.1
<#
.SYNOPSIS
Create one labeled Outlook draft through Microsoft Graph, then tell
you what to search for in whatever SIEM you use.

.DESCRIPTION
Authorized control test only. Malicious use is prohibited.

Signs in as a lab mailbox and creates a single draft that is never sent.
It does not connect to Elastic, Sentinel, Splunk, or any other SIEM.
After the draft is created it prints a canary and filter list. Go check
your own console. SIEM ingest is often delayed; a miss in the first
minutes is not a fail.

Optionally (-CheckMicrosoftAudit) it also polls Microsoft unified audit.
That is a source-log check, not a SIEM check.

.PARAMETER CheckMicrosoftAudit
Also search Microsoft 365 unified audit for the canary. Requires extra
Graph or Exchange audit rights. Off by default so the test finishes
quickly and you can hunt the SIEM yourself.

.PARAMETER WaitMinutes
How long to poll Microsoft unified audit when -CheckMicrosoftAudit is
set. Default 10. Does not apply to your SIEM.

.PARAMETER SkipCleanup
Leave the draft in the mailbox after the run.

.EXAMPLE
.\Test-OutlookDraftGraph.ps1

.EXAMPLE
.\Test-OutlookDraftGraph.ps1 -CheckMicrosoftAudit -WaitMinutes 15

.NOTES
Author @cyb3rw01f
Requires Microsoft.Graph.Authentication.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$CheckMicrosoftAudit,

    [ValidateRange(1, 30)]
    [int]$WaitMinutes = 10,

    [switch]$SkipCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GraphMailScopes = @('Mail.ReadWrite', 'User.Read')
$script:GraphAuditScopes = @('Mail.ReadWrite', 'User.Read', 'AuditLogsQuery-Exchange.Read.All')

function Write-LabBanner {
    Write-Host
    Write-Host '============================================================' -ForegroundColor Magenta
    Write-Host ' OutlookDraftLab' -ForegroundColor Magenta
    Write-Host ' Authorized control test — Graph draft, never sent' -ForegroundColor Green
    Write-Host ' @cyberw01f' -ForegroundColor Green
    Write-Host '============================================================' -ForegroundColor Magenta
    Write-Host
}

function Test-LabGraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}

function Connect-LabGraph {
    param(
        [string[]]$Scopes
    )

    $connect = @{ Scopes = $Scopes }
    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($cmd.Parameters.ContainsKey('NoWelcome')) {
        $connect.NoWelcome = $true
    }

    Connect-MgGraph @connect
}

function Invoke-LabGraph {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [object]$Body
    )

    $request = @{
        Method = $Method
        Uri    = $Uri
    }
    if ($null -ne $Body) {
        $request.Body = ($Body | ConvertTo-Json -Depth 8 -Compress)
        $request.Headers = @{ 'Content-Type' = 'application/json' }
    }

    Invoke-MgGraphRequest @request
}

function New-LabCanary {
    $stamp = Get-Date -Format 'yyyyMMdd'
    $rand = -join ((1..4) | ForEach-Object { '{0:X}' -f (Get-Random -Maximum 16) })
    return "LAB-DRAFT-$stamp-$rand"
}

function Get-LabMailbox {
    $me = Invoke-LabGraph -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName'
    if (-not $me.userPrincipalName) {
        throw 'Could not read the signed-in mailbox (GET /me).'
    }
    return $me
}

function New-LabDraft {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Canary,

        [Parameter(Mandatory = $true)]
        [string]$Mailbox
    )

    $body = @{
        subject = $Canary
        body    = @{
            contentType = 'Text'
            content     = @"
Authorized control test. This is not a real message. Do not send.

Canary: $Canary
Mailbox: $Mailbox
Created: $([DateTime]::UtcNow.ToString('o'))
Method: Microsoft Graph POST /me/messages (draft)

Hunt this canary in your SIEM. Ingest is often delayed.
"@
        }
    }

    return Invoke-LabGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/me/messages' -Body $body
}

function Remove-LabDraft {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MessageId
    )

    $encodedId = [Uri]::EscapeDataString($MessageId)
    Invoke-LabGraph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/me/messages/$encodedId"
}

function Test-LabRecordHit {
    param(
        [object]$Record,
        [string]$Canary
    )

    if ($null -eq $Record) {
        return $false
    }

    $blob = ($Record | ConvertTo-Json -Depth 12 -Compress)
    return ($blob -like "*$Canary*")
}

function Search-LabAuditGraph {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Canary,

        [Parameter(Mandatory = $true)]
        [string]$Upn,

        [Parameter(Mandatory = $true)]
        [datetime]$StartUtc
    )

    $queryBody = @{
        displayName              = $Canary
        filterStartDateTime      = $StartUtc.ToString('o')
        filterEndDateTime        = [DateTime]::UtcNow.AddMinutes(5).ToString('o')
        keywordFilter            = $Canary
        userPrincipalNameFilters = @($Upn)
    }

    $created = Invoke-LabGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/auditLog/queries' -Body $queryBody
    if (-not $created.id) {
        throw 'Audit query did not return an id.'
    }

    $deadline = (Get-Date).AddMinutes(3)
    $status = $null
    do {
        Start-Sleep -Seconds 8
        $status = Invoke-LabGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries/$($created.id)"
        Write-Verbose "Graph audit query $($created.id) status=$($status.status)"
    } while ($status.status -in @('notStarted', 'running') -and (Get-Date) -lt $deadline)

    if ($status.status -ne 'succeeded') {
        throw "Graph audit query ended with status '$($status.status)'."
    }

    $page = Invoke-LabGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries/$($created.id)/records"
    $records = @()
    if ($page.value) {
        $records = @($page.value)
    }

    foreach ($record in $records) {
        if (Test-LabRecordHit -Record $record -Canary $Canary) {
            return $record
        }
    }

    return $null
}

function Search-LabAuditExchange {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Canary,

        [Parameter(Mandatory = $true)]
        [string]$Upn,

        [Parameter(Mandatory = $true)]
        [datetime]$StartUtc
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        return $null
    }

    if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.State -eq 'Opened' })) {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $exo = Get-Command Connect-ExchangeOnline
        if ($exo.Parameters.ContainsKey('ShowBanner')) {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        else {
            Connect-ExchangeOnline
        }
    }

    $rows = Search-UnifiedAuditLog -StartDate $StartUtc.ToLocalTime() -EndDate (Get-Date).AddMinutes(5) -UserIds $Upn -Operations Create, Update -ResultSize 200
    if (-not $rows) {
        return $null
    }

    foreach ($row in @($rows)) {
        $data = $row.AuditData
        if ($data -is [string] -and $data.Length -gt 0) {
            try { $data = $data | ConvertFrom-Json } catch { }
        }
        $pack = [pscustomobject]@{
            Operation    = $row.Operations
            CreationTime = $row.CreationDate
            UserIds      = $row.UserIds
            AuditData    = $data
        }
        if (Test-LabRecordHit -Record $pack -Canary $Canary) {
            return $pack
        }
    }

    return $null
}

function Find-LabAuditRecord {
    param(
        [string]$Canary,
        [string]$Upn,
        [datetime]$StartUtc,
        [int]$WaitMinutes
    )

    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $graphTried = $false
    $graphFailed = $false
    $firstWait = $true

    while ((Get-Date) -lt $deadline) {
        if ($firstWait) {
            Write-Host 'Waiting 60s for Microsoft audit ingest...'
            Start-Sleep -Seconds 60
            $firstWait = $false
        }

        if (-not $graphFailed) {
            try {
                $graphTried = $true
                $hit = Search-LabAuditGraph -Canary $Canary -Upn $Upn -StartUtc $StartUtc
                if ($hit) {
                    return [pscustomobject]@{ Source = 'Graph auditLog/queries'; Record = $hit; Error = $null }
                }
            }
            catch {
                $graphFailed = $true
                Write-Warning "Graph audit search failed: $($_.Exception.Message)"
                Write-Host 'Trying Exchange Online Search-UnifiedAuditLog if that module is installed...'
            }
        }

        if ($graphFailed) {
            try {
                $hit = Search-LabAuditExchange -Canary $Canary -Upn $Upn -StartUtc $StartUtc
                if ($hit) {
                    return [pscustomobject]@{ Source = 'Search-UnifiedAuditLog'; Record = $hit; Error = $null }
                }
            }
            catch {
                Write-Warning "Exchange audit search failed: $($_.Exception.Message)"
                return [pscustomobject]@{ Source = 'none'; Record = $null; Error = $_.Exception.Message }
            }
        }

        $left = [int]($deadline - (Get-Date)).TotalSeconds
        if ($left -le 0) {
            break
        }
        $sleep = [Math]::Min(30, $left)
        Write-Host "No Microsoft audit hit yet. Retrying in ${sleep}s ($left s left)..."
        Start-Sleep -Seconds $sleep
    }

    if (-not $graphTried) {
        return [pscustomobject]@{ Source = 'none'; Record = $null; Error = $null }
    }
    return [pscustomobject]@{ Source = 'checked'; Record = $null; Error = $null }
}

function Write-LabSiemCard {
    param(
        [string]$Canary,
        [string]$Mailbox,
        [string]$MessageId,
        [string]$CreatedUtc,
        [string]$Logged,
        [string]$LogDetail
    )

    $windowStart = $CreatedUtc
    $windowHint = "from $CreatedUtc through 30+ minutes later (UTC; wait longer if your pipeline is slow)"

    Write-Host
    Write-Host '------------------------------------------------------------'
    Write-Host 'GO CHECK YOUR SIEM'
    Write-Host 'This script does not query Elastic, Sentinel, Splunk, or any other SIEM.'
    Write-Host 'First: can you find this event (would we log it)?'
    Write-Host 'Then: can we write a SIEM rule that will detect it?'
    Write-Host 'Ingest is often delayed. Wait 15-30 minutes before you call it a miss.'
    Write-Host 'A search that is empty at T+2 minutes usually means lag, not failure.'
    Write-Host
    Write-Host "FIXTURE : Outlook draft via Microsoft Graph (never sent)"
    Write-Host "CANARY  : $Canary"
    Write-Host "MAILBOX : $Mailbox"
    Write-Host "WHEN    : $CreatedUtc"
    Write-Host "MSG ID  : $MessageId"
    Write-Host "M365 LOG: $Logged"
    if ($LogDetail) {
        Write-Host "DETAIL  : $LogDetail"
    }
    Write-Host
    Write-Host 'Filter on (best first):'
    Write-Host "  1. Exact canary     $Canary"
    Write-Host "  2. Mailbox          $Mailbox"
    Write-Host "  3. Time window UTC  $windowHint"
    Write-Host '  4. API              POST /me/messages   or   POST .../users/.../messages'
    Write-Host '  5. Mailbox audit    Operation = Create or Update, folder Drafts'
    Write-Host "  6. Message id       $MessageId"
    Write-Host
    Write-Host 'Paste-ready searches (same canary, any product):'
    Write-Host "  Any search box      `"$Canary`""
    Write-Host "  Elastic Discover    `"$Canary`""
    Write-Host "  Elastic alerts      `"$Canary`"   data view .alerts-security.alerts-*"
    Write-Host "  Sentinel            search `"$Canary`""
    Write-Host "  Splunk              `"$Canary`" earliest=-2h"
    Write-Host "  Purview audit       keyword $Canary   operations Create, Update"
    Write-Host
    Write-Host 'Graph activity logs (if you stream them to the SIEM):'
    Write-Host '  RequestMethod = POST'
    Write-Host '  RequestUri contains /messages'
    Write-Host '  ResponseStatusCode = 201'
    Write-Host "  TimeGenerated around $windowStart"
    Write-Host '------------------------------------------------------------'
    Write-Host
}

Write-LabBanner

if (-not $PSCmdlet.ShouldProcess('lab mailbox', 'Create one Outlook draft via Microsoft Graph')) {
    Write-Host 'What if: would sign in, create one labeled draft, print SIEM filters, then delete the draft.'
    Write-Host 'What if: would not query any SIEM. Ingest delay is expected; hunt after 15-30 minutes.'
    return
}

Test-LabGraphModule

$draft = $null
try {
    $auditEnabled = [bool]$CheckMicrosoftAudit
    if ($auditEnabled) {
        try {
            Connect-LabGraph -Scopes $script:GraphAuditScopes
        }
        catch {
            Write-Warning "Could not consent audit scope. Connecting with mail only. $($_.Exception.Message)"
            Connect-LabGraph -Scopes $script:GraphMailScopes
            $auditEnabled = $false
        }
    }
    else {
        Connect-LabGraph -Scopes $script:GraphMailScopes
    }

    $box = Get-LabMailbox
    $canary = New-LabCanary
    $startUtc = [DateTime]::UtcNow.AddMinutes(-2)
    Write-Host "Mailbox : $($box.userPrincipalName)"
    Write-Host "Canary  : $canary"
    Write-Host 'Creating draft via POST /me/messages ...'

    $draft = New-LabDraft -Canary $canary -Mailbox $box.userPrincipalName
    if (-not $draft.id) {
        throw 'Graph did not return a draft id.'
    }
    $createdUtc = [DateTime]::UtcNow.ToString('o')
    Write-Host "Draft id: $($draft.id)"

    $logged = 'not checked (source audit off; that is normal)'
    $detail = 'Use -CheckMicrosoftAudit if you also want a Microsoft unified-audit yes/no.'

    Write-Host "HUNT NOW: $canary"
    Write-Host "Mailbox : $($box.userPrincipalName)  When: $createdUtc"
    Write-Host 'Full filter card prints at the end. SIEM ingest still lags.'

    if ($auditEnabled) {
        Write-Host "Optional: searching Microsoft unified audit for up to $WaitMinutes minute(s)..."
        Write-Host 'You can hunt the SIEM now. Do not wait on this for the SIEM answer.'
        $found = Find-LabAuditRecord -Canary $canary -Upn $box.userPrincipalName -StartUtc $startUtc -WaitMinutes $WaitMinutes
        if ($found.Record) {
            $logged = 'YES'
            $detail = $found.Source
        }
        elseif ($found.Source -eq 'none') {
            $logged = 'NOT CHECKED'
            $detail = 'No Microsoft audit API available.'
            if ($found.Error) {
                $detail = $found.Error
            }
        }
        else {
            $logged = 'NO'
            $detail = "No matching Create/Update in $WaitMinutes minute(s) on the Microsoft side."
        }
    }

    Write-LabSiemCard -Canary $canary -Mailbox $box.userPrincipalName -MessageId $draft.id -CreatedUtc $createdUtc -Logged $logged -LogDetail $detail
}
finally {
    if ($draft -and $draft.id -and -not $SkipCleanup) {
        try {
            Remove-LabDraft -MessageId $draft.id
            Write-Host 'Cleanup : draft deleted.'
        }
        catch {
            Write-Warning "Could not delete draft $($draft.id): $($_.Exception.Message)"
        }
    }
    elseif ($SkipCleanup -and $draft -and $draft.id) {
        Write-Host 'Cleanup : skipped. Remove the draft from Outlook yourself.'
    }
}
