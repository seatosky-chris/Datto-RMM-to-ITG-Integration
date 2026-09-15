---
name: itg-sync-helper
description: 'Helper workflows and best practices for developing, debugging, and testing IT Glue and Datto RMM sync integrations. USE WHEN: modifying sync logic, adding new asset types, implementing IT Glue API pagination, troubleshooting device matching, or adding safety guardrails.'
argument-hint: '[sync-task or function to implement/debug]'
user-invocable: true
---

# IT Glue & Datto RMM Sync Helper

Guide for developing, refactoring, and troubleshooting PowerShell synchronization scripts between Datto RMM and IT Glue.

## Core Workflows

### 1. IT Glue API Safe Pagination Pattern
When querying IT Glue collections that may exceed 1000 items (Configurations, Models, Manufacturers, Organizations), always implement page loop with retry backoff:

```powershell
$Collection = Get-ITGlueConfigurations -page_size "1000" -organization_id $OrgID
$page = 1
while ($Collection.links.next) {
    $page++
    $NextPage = Get-ITGlueConfigurations -page_size "1000" -page_number $page -organization_id $OrgID
    if (!$NextPage -or $NextPage.Error) {
        # Retry once after 2-second sleep on error
        Start-Sleep -Seconds 2
        $NextPage = Get-ITGlueConfigurations -page_size "1000" -page_number $page -organization_id $OrgID
        if (!$NextPage -or $NextPage.Error) {
            Write-PSFMessage -Level Error -Message "Failed to fetch page $page: $($NextPage.Error)"
            break
        }
    }
    $Collection.data += $NextPage.data
    $Collection.links = $NextPage.links
    Start-Sleep -Seconds 1
}
```

### 2. Device Matching Hierarchy
Follow the established multi-tier matching cascade to prevent duplicate configuration entries in IT Glue:

1. **RMM UID (`installed-by` field)**: Match exact `"RMM: " + $RMMDevice.uid`.
2. **Exact Hostname / Name**: Compare `$_.attributes.name` against `$RMMDevice.hostname`.
3. **Description**: Compare `$_.attributes.name` against `$RMMDevice.description`.
4. **Serial Number**: Verify serial is not in `$IgnoreSerials` / wildcard blacklist (`123456789*`), then match `$_.attributes.'serial-number'`.
5. **Fuzzy String Distance**: For ties or unmatched items, compute distance via `Measure-StringDistance` and `Measure-PartsEquality`.

### 3. Adding New Device Types / Mappings
To support a new device type:
1. Update `Config.ps1.template` under `$ITG_ConfigTypeIDs` mapping RMM category/type to IT Glue configuration type ID.
2. In `New-ITGDevice`, ensure category overrides (e.g. firewall/switch regex categorization) correctly set `$RMMDevice.deviceType`.
3. Map network interfaces to `relationships.configuration_interfaces.data` payload.

### 4. Safety Guardrails Checklist
Before executing or deploying modifications:
- [ ] **Kill Switch**: Ensure additions and deletions verify count `< 100` before committing changes to IT Glue.
- [ ] **Single Instance**: Ensure `Test-IfAlreadyRunning` is called at script startup.
- [ ] **Protected Types**: Verify `$DeviceTypes_PreventDeletion` is respected before flagging an asset for archival.
- [ ] **Logging**: Use `Write-PSFMessage` (Verbose/Warning/Error) rather than bare `Write-Host` for background tasks.
- [ ] **TLS Enforcement**: Retain TLS 1.2+ protocol check at the entry point.

### 5. Dry-Run & Step-Through Testing
Test changes safely without unattended mass modifications:

```powershell
# Run with manual confirmation prompt per update
pwsh -File .\ITG_to_DattoRMM_Integration.ps1 -FullCheck $true -StepThroughUpdates $true
```
