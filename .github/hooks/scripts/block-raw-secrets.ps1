# Hook companion script: blocks tool executions that attempt to write raw API keys or secrets into codebase files.
param()

$rawInput = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($rawInput)) {
    exit 0
}

try {
    $data = $rawInput | ConvertFrom-Json
} catch {
    exit 0
}

$toolName = $data.toolName
$toolInput = $data.toolInput

if ($toolName -in @("create_file", "replace_string_in_file", "insert_edit_into_file")) {
    $filePath = $toolInput.filePath
    $content = ""
    if ($toolInput.content) { $content = $toolInput.content }
    if ($toolInput.newString) { $content = $toolInput.newString }
    if ($toolInput.code) { $content = $toolInput.code }

    # Exclude Config.ps1 and Config.ps1.template
    if ($filePath -notlike "*Config.ps1" -and $filePath -notlike "*Config.ps1.template") {
        # Patterns matching sensitive keys and secrets
        $secretPatterns = @(
            '(?i)(ITGAPIKey|DattoAPIKey|APIKey|SecretKey|Password|Token)\s*=\s*["''][a-zA-Z0-9_\-\.]{12,}["'']',
            '(?i)Add-ITGlueAPIKey\s+["''][a-zA-Z0-9_\-\.]{12,}["'']',
            '(?i)Set-DrmmApiParameters.*?-SecretKey\s+["''][a-zA-Z0-9_\-\.]{8,}["'']'
        )

        foreach ($pattern in $secretPatterns) {
            if ($content -match $pattern) {
                $response = @{
                    hookSpecificOutput = @{
                        hookEventName = "PreToolUse"
                        permissionDecision = "deny"
                        permissionDecisionReason = "Blocked attempt to hardcode API credentials/secrets into script files. Store sensitive keys and configurations in Config.ps1 instead."
                    }
                } | ConvertTo-Json -Depth 5 -Compress
                [Console]::Out.WriteLine($response)
                exit 0
            }
        }
    }
}

# Allow tool invocation by default
$response = @{
    hookSpecificOutput = @{
        hookEventName = "PreToolUse"
        permissionDecision = "allow"
    }
} | ConvertTo-Json -Depth 5 -Compress
[Console]::Out.WriteLine($response)
exit 0
