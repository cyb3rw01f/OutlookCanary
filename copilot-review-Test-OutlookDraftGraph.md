# Copilot CLI review of Test-OutlookDraftGraph.ps1

Read-only. Copilot did not modify files. Session resume: `copilot --resume=9275fa64-ae7d-4837-8792-1c30f8102946`

## Summary

The script is reasonably well-structured for a lab/test tool: `SupportsShouldProcess`, strict mode, and a try/finally cleanup path are good practices. The main functional issues are a missing URL-encoding on the message ID used in the DELETE request, and a user-facing status message that reports stale "not checked" audit status even when `-CheckMicrosoftAudit` was used. A couple of minor UX/robustness nits round out the review.

## Issues

### Issue 1 -- Severity: bug
- File: Test-OutlookDraftGraph.ps1:161
- Description: `Remove-LabDraft` builds the DELETE URI without URL-encoding `$MessageId`. Graph message IDs often contain `+`, `/`, and `=`, which can make DELETE 404 and leave the draft in the mailbox.
- Suggestion: `.../me/messages/$([Uri]::EscapeDataString($MessageId))`

### Issue 2 -- Severity: suggestion
- File: Test-OutlookDraftGraph.ps1:442-445
- Description: The SIEM card is printed before `-CheckMicrosoftAudit` runs, so it always shows "M365 LOG: not checked" even when a YES/NO is computed later.
- Suggestion: Print the card after the audit block, or reprint it with the final result.

### Issue 3 -- Severity: suggestion
- File: Test-OutlookDraftGraph.ps1:354-355
- Description: `$windowHint` is single-quoted, so the card literally says "WHEN (UTC)" instead of the real timestamp.
- Suggestion: Interpolate `$CreatedUtc`.

### Issue 4 -- Severity: nit
- File: Test-OutlookDraftGraph.ps1:265
- Description: Empty `catch` on `ConvertFrom-Json` hides bad `AuditData`.
- Suggestion: `Write-Verbose` in the catch.

No security-critical issues (credential handling, injection). Interactive Graph/Exchange sign-in; no persisted secrets.
