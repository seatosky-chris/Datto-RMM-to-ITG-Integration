# IT Glue & Datto RMM Integration - AI Agent Guidelines

This repository contains PowerShell automation scripts that synchronize device, monitor, and manufacturer/model asset data between **Datto RMM** and **IT Glue**.

For project background and manual setup steps, refer to [README.md](./README.md) and [Config.ps1.template](./Config.ps1.template).

---

## 1. Environment & Dependencies

- **Runtime**: PowerShell 5.1+ / PowerShell 7+ on Windows (uses WMI/CIM for process checks).
- **Required PowerShell Modules**:
  - `DattoRMM` — API wrapper for Datto RMM.
  - `ITGlueAPI` — API wrapper for IT Glue REST API.
  - `PSFramework` — Structured logging (`Write-PSFMessage`, `Set-PSFLoggingProvider`).
- **Configuration**:
  - `Config.ps1` (gitignored, copied from `Config.ps1.template`) contains API keys (`$ITGAPIKey`, `$DattoAPIKey`), configuration status/type IDs, and safety blacklists.
  - Always dot-source using relative path: `. "$PSScriptRoot\Config.ps1"`.

---

## 2. Core Scripts & Architecture

| Script | Purpose |
|--------|---------|
| `ITG_to_DattoRMM_Integration.ps1` | Primary device sync: matches RMM devices to ITG configs, tracks changes via CSV delta in `DeviceTracking/`, handles additions/deletions/archival, and runs full weekly audits. |
| `DattoRMM_to_ITG_Monitors_Integration.ps1` | Parses monitor info from Datto RMM UDF, creates/updates Monitor configurations in IT Glue, calculates warranty/EOL, and links related workstations. |
| `ITG_Manufacturer_and_Model_Cleanup.ps1` | Normalizes and cleans up manufacturer and model names across IT Glue assets. |
| `Config.ps1.template` | Baseline configuration template with types, mappings, and API structures. |

---

## 3. Development Conventions & Patterns

### Logging & Error Handling
- Use `PSFramework` for logging: `Write-PSFMessage -Level Verbose|Warning|Error -Message "..."`.
- Rotate logs into `$PSScriptRoot\Logs\` using `Set-PSFLoggingProvider`.
- Check for API errors after IT Glue and Datto RMM calls (`if (!$result -or $result.Error) { ... }`).

### IT Glue API Handling
- **Pagination**: IT Glue endpoints return paginated responses. Always handle `links.next` with `page_size 1000` loops and 1–2 second sleep intervals between pages to prevent rate limiting.
- **Asset Identification**: RMM device UIDs are stored in the ITG `installed-by` field (`"RMM: " + $RMMDevice.uid`) for unambiguous matching.
- **Fuzzy Matching**: When `installed-by` is empty, fallback matching follows: Exact Name/Hostname -> Description -> Serial Number -> Levenshtein distance (`Measure-StringDistance`).

### Safety & Guardrails
- **Kill Switches**: Preserve safety checks that prevent bulk additions or deletions (e.g., aborting if adding/deleting > 100 devices in one run) to protect against API failure regressions.
- **Single Instance**: Scripts enforce single-instance execution via `Test-IfAlreadyRunning` checking running `powershell.exe` command lines.
- **TLS Protocol**: Enforce TLS 1.2+ (`[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)`).
- **Pending Audit Retries**: New devices sync immediately; devices missing Serial Number or Model are stored in `DeviceTracking/PendingDeviceAudits.json` and retried until populated or until meeting online/offline timeouts.

---

## 4. Testing & Running

- **Dry-run / Step-through**: `ITG_to_DattoRMM_Integration.ps1` supports `-FullCheck` and `-StepThroughUpdates` parameters for manual review.
- **Run in PowerShell**:
  ```powershell
  pwsh -File .\ITG_to_DattoRMM_Integration.ps1 -StepThroughUpdates $true
  ```
- **Syntax validation**:
  ```powershell
  Get-Command -Syntax -ErrorAction Stop .\ITG_to_DattoRMM_Integration.ps1
  ```
