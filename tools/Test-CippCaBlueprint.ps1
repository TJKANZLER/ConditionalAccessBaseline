[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$policyRoot = Join-Path $RepositoryRoot 'Config\ConditionalAccess'
$groupRoot = Join-Path $RepositoryRoot 'Config\Groups'
$migrationPath = Join-Path $RepositoryRoot 'Config\MigrationTable.json'

$errors = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$policies = @()

foreach ($file in Get-ChildItem -LiteralPath $policyRoot -Filter '*.json') {
    try {
        $policy = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -Depth 50
        $policies += $policy
    }
    catch {
        $errors.Add("Invalid policy JSON: $($file.Name): $($_.Exception.Message)")
        continue
    }

    if (-not $policy.displayName -or -not $policy.conditions -or (-not $policy.grantControls -and -not $policy.sessionControls)) {
        $errors.Add("Policy is missing a required field: $($file.Name)")
    }
    if ($policy.'@odata.type' -notlike '*conditionalAccessPolicy*') {
        $errors.Add("CIPP cannot identify this as a Conditional Access template: $($file.Name)")
    }
    if ($policy.state -notin @('enabledForReportingButNotEnforced', 'disabled')) {
        $errors.Add("Unsafe initial state in $($file.Name): $($policy.state)")
    }
    if ($policy.grantControls.builtInControls -contains 'approvedApplication') {
        $errors.Add("Retired approvedApplication control found in $($file.Name)")
    }
    if (($policy.conditions.userRiskLevels.Count -gt 0) -and ($policy.conditions.signInRiskLevels.Count -gt 0)) {
        $errors.Add("User and sign-in risk are combined in $($file.Name)")
    }
}

$duplicateNames = $policies | Group-Object displayName | Where-Object Count -gt 1
foreach ($duplicate in $duplicateNames) {
    $errors.Add("Duplicate policy display name: $($duplicate.Name)")
}

if ($policies.Count -ne 36) {
    $errors.Add("Expected 36 Conditional Access policies but found $($policies.Count)")
}

$reportOnlyCount = @($policies | Where-Object state -eq 'enabledForReportingButNotEnforced').Count
$disabledCount = @($policies | Where-Object state -eq 'disabled').Count
if ($reportOnlyCount -ne 19 -or $disabledCount -ne 17) {
    $errors.Add("Expected 19 Report-only and 17 Disabled policies; found $reportOnlyCount and $disabledCount")
}

$migration = Get-Content -LiteralPath $migrationPath -Raw | ConvertFrom-Json -Depth 20
$migrationIds = @($migration.Objects.Id)
$groups = @()
$groupIds = foreach ($file in Get-ChildItem -LiteralPath $groupRoot -Filter '*.json') {
    try {
        $group = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $groups += $group
        if (-not $group.id -or -not $group.displayName -or -not $group.mailNickname) {
            $errors.Add("CIPP group template is missing id, displayName, or mailNickname: $($file.Name)")
        }
        $group.id
    }
    catch {
        $errors.Add("Invalid group JSON: $($file.Name): $($_.Exception.Message)")
    }
}

foreach ($property in 'id', 'displayName', 'mailNickname') {
    foreach ($duplicate in $groups | Group-Object $property | Where-Object Count -gt 1) {
        $errors.Add("Duplicate group $property value: $($duplicate.Name)")
    }
}

$allowedJsonPaths = @(
    (Get-ChildItem -LiteralPath $policyRoot -Filter '*.json').FullName
    (Get-ChildItem -LiteralPath $groupRoot -Filter '*.json').FullName
    $migrationPath
)
foreach ($jsonFile in Get-ChildItem -LiteralPath $RepositoryRoot -Filter '*.json' -Recurse) {
    if ($jsonFile.FullName -notin $allowedJsonPaths) {
        $errors.Add("Non-template JSON may appear in CIPP's repository importer: $($jsonFile.FullName)")
    }
}

foreach ($groupId in $groupIds) {
    if ($groupId -notin $migrationIds) {
        $errors.Add("Group ID is missing from MigrationTable.json: $groupId")
    }
}

if ($groupIds.Count -ne 14) {
    $errors.Add("Expected 14 supporting groups but found $($groupIds.Count)")
}

$knownGroupIds = @($groupIds)
foreach ($policy in $policies) {
    foreach ($groupId in @($policy.conditions.users.includeGroups) + @($policy.conditions.users.excludeGroups)) {
        if ($groupId -and $groupId -notin $knownGroupIds) {
            $errors.Add("Unmapped group ID $groupId in $($policy.displayName)")
        }
    }
}

$mfaInternal = $policies | Where-Object displayName -eq 'MSP-CA002-Global-Require-MFA'
if ($mfaInternal.conditions.users.excludeGuestsOrExternalUsers -eq $null) {
    $errors.Add('Internal MFA policy does not exclude guest/external identities; guest policy overlap would result.')
}

$guestMfa = $policies | Where-Object displayName -eq 'MSP-CA200-Guests-Require-MFA'
$guestTypes = [string]$guestMfa.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes
if ($guestTypes -match 'serviceProvider') {
    $errors.Add('Guest MFA includes serviceProvider identities and can interfere with CIPP/GDAP.')
}

$mustRemainDisabledPatterns = @(
    'MSP-CA007-*',
    'MSP-CA008-*',
    'MSP-CA102-*',
    'MSP-CA103-*',
    'MSP-CA104-*',
    'MSP-CA304-*',
    'MSP-CA305-*',
    'MSP-CA306-*',
    'MSP-CA308-*',
    'MSP-CA309-*',
    'MSP-CA402-*',
    'MSP-CA501-*',
    'MSP-CA7*'
)
foreach ($pattern in $mustRemainDisabledPatterns) {
    foreach ($policy in $policies | Where-Object displayName -Like $pattern) {
        if ($policy.state -ne 'disabled') {
            $errors.Add("Dependency-heavy or preview policy must begin Disabled: $($policy.displayName)")
        }
    }
}

$tokenPolicies = @($policies | Where-Object displayName -Like '*TokenProtection*')
foreach ($policy in $tokenPolicies) {
    if ($policy.conditions.applications.includeApplications -contains 'Office365') {
        $errors.Add("Token protection must not target the Office365 app bundle: $($policy.displayName)")
    }
    if ($policy.conditions.clientAppTypes -contains 'browser') {
        $errors.Add("Token protection must not target browser clients: $($policy.displayName)")
    }
    if (-not $policy.sessionControls.secureSignInSession.isEnabled) {
        $errors.Add("Token protection session control is missing: $($policy.displayName)")
    }
}

$riskRemediation = $policies | Where-Object displayName -eq 'MSP-CA401-Risk-User-High-Require-Remediation'
if (($riskRemediation.grantControls.builtInControls -notcontains 'riskRemediation') -or
    $riskRemediation.grantControls.operator -ne 'AND' -or
    -not $riskRemediation.grantControls.authenticationStrength -or
    $riskRemediation.conditions.userRiskLevels -notcontains 'high' -or
    $riskRemediation.conditions.signInRiskLevels.Count -gt 0 -or
    $riskRemediation.conditions.applications.includeApplications -notcontains 'All' -or
    $riskRemediation.conditions.applications.excludeApplications.Count -gt 0) {
    $errors.Add('High user-risk remediation policy does not meet Microsoft Graph control constraints.')
}

$workloadPolicies = @($policies | Where-Object displayName -Like 'MSP-CA5*')
foreach ($policy in $workloadPolicies) {
    if ($policy.conditions.clientApplications.includeServicePrincipals -notcontains 'ServicePrincipalsInMyTenant') {
        $errors.Add("Workload policy is missing the portable all-service-principals selector: $($policy.displayName)")
    }
}

$agentPolicies = @($policies | Where-Object displayName -Like 'MSP-CA7*')
if ($agentPolicies.Count -ne 5) {
    $errors.Add("Expected five Agent Preview policies but found $($agentPolicies.Count)")
}

foreach ($policy in $policies) {
    foreach ($property in 'insiderRiskLevels', 'agentIdRiskLevels') {
        if ($policy.conditions.PSObject.Properties.Name -contains $property -and
            [string]::IsNullOrWhiteSpace([string]$policy.conditions.$property)) {
            $errors.Add("Empty optional Graph enum property $property in $($policy.displayName)")
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

$warnings | ForEach-Object { Write-Warning $_ }
Write-Output "PASS: $($policies.Count) policies ($reportOnlyCount Report-only, $disabledCount Disabled), $($groupIds.Count) groups, safe CIPP layout, valid dependencies, no duplicate names, and no retired approved-client-app controls."
