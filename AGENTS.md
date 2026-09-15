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
- **Centralized Asset Updates (`Update-ITGDevice`)**: Never submit ad-hoc field subsets directly to `Set-ITGlueConfigurations`. Always route configuration updates through `Update-ITGDevice` to guarantee full attribute parity (hostname, primary IP, operating system, OS notes, serial, model, manufacturer, MAC, asset tag, warranty expiry, and unarchival).

### Lifecycle & Deduplication
- **Pending Audit Queue & Deduplication**: When newly created workstations/servers lack serial number or model data, register them in `DeviceTracking/PendingDeviceAudits.json`. On subsequent runs, once audit data populates:
  1. Call `Get-RelatedITGDevices` to check for pre-existing matching configurations, excluding the temporary created asset (`$_.id -ne $PendingItem.itg_id`).
  2. If a pre-existing asset matches, unarchive and update that asset with `Update-ITGDevice`, then delete the temporary duplicate configuration using `Remove-ITGlueConfigurations`.
  3. If no pre-existing match exists, perform a full update on the created asset via `Update-ITGDevice`.
- **Queue Scope Boundaries**: `PendingDeviceAudits.json` strictly tracks agent-managed workstations and servers (`Desktop`, `Laptop`, `Server`, `ESXi Host`). SNMP and network devices (`$RMMDevice.snmpEnabled`) must bypass the pending retry queue and rely on their dedicated SNMP discovery delay controls (`$RMM_Devices_RecentlyAuditedSNMP`).
- **Function Declaration Order**: In all scripts, declare functions in a strict bottom-up dependency order. Utility and transformation functions (`Get-ITGOperatingSystem`, `Get-ITGManufacturerAndModel`, `Update-ITGDevice`, `Get-PendingDevices`, `Add-PendingDevice`) must precede composite lifecycle functions (`Process-PendingDevices`, `New-ITGDevice`, `Archive-ITGDevice`).

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
