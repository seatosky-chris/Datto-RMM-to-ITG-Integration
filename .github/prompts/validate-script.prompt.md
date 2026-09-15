---
name: "validate-script"
description: "Validate a PowerShell integration script for syntax errors, safety guardrails, IT Glue API conventions, and best practices."
argument-hint: "[script-path or empty for active file]"
agent: "agent"
---

Perform a comprehensive validation and safety review of the specified PowerShell script (or the currently active script in the workspace).

### Input
- Target Script: `${input:script-path:ITG_to_DattoRMM_Integration.ps1}`

### Validation Checklist

1. **Syntax & AST Parsing**:
   - Verify all braces, parentheses, and hashtable syntax blocks are properly balanced.
   - Ensure all cmdlets and functions are called with valid parameter signatures.
   - Check for any unexpected tokens or syntax issues.

2. **Security & Secrets**:
   - Verify no hardcoded API keys, bearer tokens, or credentials exist.
   - Confirm configuration and credentials are dot-sourced from `Config.ps1` (`. "$PSScriptRoot\Config.ps1"`).
   - Ensure TLS 1.2+ security protocol check is present before making API calls.

3. **Safety Guardrails & Concurrency**:
   - Confirm single-instance enforcement via `Test-IfAlreadyRunning`.
   - Verify batch safety limits (e.g. kill switches blocking mass creation/deletion if count $> 100$).
   - Ensure protected device types (`$DeviceTypes_PreventDeletion`) are respected before archival.

4. **IT Glue & Datto RMM API Conventions**:
   - Verify all IT Glue collection queries handle pagination (`links.next` loops with 1-2s throttle delays).
   - Ensure error responses (`if (!$result -or $result.Error)`) are checked after API invocations.
   - Check that structured logging uses `Write-PSFMessage` (with levels `Verbose`, `Warning`, `Error`).

5. **Code Quality & Best Practices**:
   - Identify aliases (e.g. `where` -> `Where-Object`, `select` -> `Select-Object`).
   - Identify unapproved PowerShell verbs or unhandled exceptions in `try/catch` blocks.

### Output Format

Produce a summary table in the following structure:

| Check Category | Status | Details & Findings |
|---|---|---|
| **Syntax & Parsing** | PASS / FAIL | ... |
| **Security & Secrets** | PASS / FAIL | ... |
| **Safety Guardrails** | PASS / WARN / FAIL | ... |
| **API Pagination & Throttling** | PASS / WARN / FAIL | ... |
| **Logging & Error Handling** | PASS / WARN / FAIL | ... |

If any warnings or failures are detected, provide specific code snippets demonstrating how to remediate the issue.
