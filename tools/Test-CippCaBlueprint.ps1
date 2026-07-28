[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$policyRoot = Join-Path $RepositoryRoot 'Config\ConditionalAccess'
$groupRoot = Join-Path $RepositoryRoot 'Config\Groups'
$migrationPath = Join-Path $RepositoryRoot 'Config\MigrationTable.json'
$packagePath = Join-Path $RepositoryRoot 'Config\PolicyPackages.psd1'

$errors = [System.Collections.Generic.List[string]]::new()
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
    if ($policy.state -ne 'enabledForReportingButNotEnforced') {
        $errors.Add("Every deployable template must start Report-only: $($file.Name) is $($policy.state)")
    }
    if ($policy.grantControls.builtInControls -contains 'approvedApplication') {
        $errors.Add("Retired approvedApplication control found in $($file.Name)")
    }
    foreach ($previewProperty in 'agents', 'agentContext', 'agentIdRiskLevels') {
        if ($policy.conditions.PSObject.Properties.Name -contains $previewProperty) {
            $errors.Add("Preview condition $previewProperty found in production template $($file.Name)")
        }
    }
}

foreach ($duplicate in $policies | Group-Object displayName | Where-Object Count -gt 1) {
    $errors.Add("Duplicate policy display name: $($duplicate.Name)")
}

if ($policies.Count -ne 30) {
    $errors.Add("Expected 30 Conditional Access policies but found $($policies.Count)")
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
foreach ($migrationId in $migrationIds) {
    if ($migrationId -notin $groupIds) {
        $errors.Add("MigrationTable.json contains a retired group ID: $migrationId")
    }
}

if ($groupIds.Count -ne 15) {
    $errors.Add("Expected 15 supporting groups but found $($groupIds.Count)")
}

foreach ($policy in $policies) {
    foreach ($groupId in @($policy.conditions.users.includeGroups) + @($policy.conditions.users.excludeGroups)) {
        if ($groupId -and $groupId -notin $groupIds) {
            $errors.Add("Unmapped group ID $groupId in $($policy.displayName)")
        }
    }
}

$directorySyncRole = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
foreach ($policy in $policies | Where-Object { $_.conditions.users.includeUsers -contains 'All' }) {
    if ($directorySyncRole -notin @($policy.conditions.users.excludeRoles)) {
        $errors.Add("$($policy.displayName) targets all users without excluding Directory Synchronization Accounts.")
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
if ($guestMfa.grantControls.builtInControls -notcontains 'mfa' -or $guestMfa.grantControls.authenticationStrength) {
    $errors.Add('Guest MFA must use the MFA grant so email OTP, SAML/WS-Fed, and Google-federated guests remain supported.')
}

$expectedAdminRoles = @(
    '62e90394-69f5-4237-9190-012177145e10'
    '194ae4cb-b126-40b2-bd5b-6091b380977d'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
    '29232cdf-9323-42fd-ade2-1d097af3e4de'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe'
    'fe930be7-5e62-47db-91af-98c3a49a38b1'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
    '158c047a-c907-4556-b7ef-446551a6b5f7'
    '966707d0-3269-4727-9be2-8c3a10f19b9d'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
    'e8611ab8-c189-46e8-94e1-60213ab1f814'
)
foreach ($policyName in 'MSP-CA100-Admins-Require-PhishingResistantMFA', 'MSP-CA101-Admins-Session-Hardening', 'MSP-CA102-Admins-Require-CompliantDevice', 'MSP-CA103-Admins-Block-Outside-TrustedLocations') {
    $adminPolicy = $policies | Where-Object displayName -eq $policyName
    $actualRoles = @($adminPolicy.conditions.users.includeRoles)
    if ($actualRoles.Count -ne $expectedAdminRoles.Count -or
        @($expectedAdminRoles | Where-Object { $_ -notin $actualRoles }).Count -gt 0) {
        $errors.Add("$policyName does not target the current Microsoft-recommended administrator role set.")
    }
}

$deviceCodePolicy = $policies | Where-Object displayName -eq 'MSP-CA005-Global-Block-DeviceCodeFlow'
$deviceRegistrationServiceAppId = '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'
if ($deviceRegistrationServiceAppId -notin @($deviceCodePolicy.conditions.applications.excludeApplications)) {
    $errors.Add('Device-code blocking does not exclude Microsoft Entra Device Registration Service.')
}

$deviceComplianceGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-DeviceCompliance').id
$deviceComplianceOwners = @(
    'MSP-CA102-Admins-Require-CompliantDevice'
    'MSP-CA302-Windows-Require-CompliantDevice'
    'MSP-CA303-macOS-Require-CompliantDevice'
    'MSP-CA304-Managed-iOS-Require-CompliantDevice'
    'MSP-CA305-Managed-Android-Require-CompliantDevice'
    'MSP-CA306-Linux-Require-CompliantDevice'
)
foreach ($policy in $policies) {
    if ($deviceComplianceGroupId -in @($policy.conditions.users.excludeGroups) -and $policy.displayName -notin $deviceComplianceOwners) {
        $errors.Add("$($policy.displayName) reuses the device-compliance exception outside its intended scope.")
    }
}

$tokenPolicy = $policies | Where-Object displayName -eq 'MSP-CA307-Windows-Require-TokenProtection'
$supportedTokenResources = @(
    '00000002-0000-0ff1-ce00-000000000000'
    '00000003-0000-0ff1-ce00-000000000000'
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'
)
foreach ($resource in $supportedTokenResources) {
    if ($resource -notin @($tokenPolicy.conditions.applications.includeApplications)) {
        $errors.Add("Windows token protection is missing supported resource $resource.")
    }
}
if ($tokenPolicy.conditions.applications.includeApplications -contains 'Office365' -or
    $tokenPolicy.conditions.clientAppTypes -contains 'browser' -or
    -not $tokenPolicy.sessionControls.secureSignInSession.isEnabled) {
    $errors.Add('Windows token-protection scope is unsafe or incomplete.')
}

$riskRemediation = $policies | Where-Object displayName -eq 'MSP-CA401-Risk-User-High-Require-Remediation'
if ($riskRemediation.conditions.userRiskLevels -notcontains 'high' -or
    $riskRemediation.grantControls.builtInControls -notcontains 'riskRemediation' -or
    $riskRemediation.conditions.PSObject.Properties.Name -contains 'signInRiskLevels') {
    $errors.Add('High user-risk policy must use a separate high-risk remediation control.')
}

foreach ($workloadPolicy in $policies | Where-Object displayName -Like 'MSP-CA5*') {
    if ($workloadPolicy.conditions.clientApplications.includeServicePrincipals -notcontains 'ServicePrincipalsInMyTenant') {
        $errors.Add("Workload policy lacks the portable tenant-owned service-principal selector: $($workloadPolicy.displayName)")
    }
}

if (-not (Test-Path -LiteralPath $packagePath)) {
    $errors.Add('Config\PolicyPackages.psd1 is missing.')
}
else {
    $packageManifest = Import-PowerShellDataFile -LiteralPath $packagePath
    $packages = @($packageManifest.Packages)
    if ($packages.Count -ne 9) {
        $errors.Add("Expected nine activation packages but found $($packages.Count).")
    }
    $expectedPackageNames = @(
        'SHOOTHILL-CA-01-Identity-Foundation-P1'
        'SHOOTHILL-CA-02-Privileged-Access-P1-Intune'
        'SHOOTHILL-CA-03-External-Collaboration-P1'
        'SHOOTHILL-CA-04-Endpoint-and-App-Protection-Intune'
        'SHOOTHILL-CA-05-Trusted-Location-Guardrails-P1'
        'SHOOTHILL-CA-06-Closed-Network-Perimeter-P1'
        'SHOOTHILL-CA-07-Identity-Protection-P2'
        'SHOOTHILL-CA-08-Workload-Identity-Premium'
        'SHOOTHILL-CA-09-Defender-and-Purview-Advanced'
    )
    foreach ($expectedName in $expectedPackageNames) {
        if ($expectedName -notin @($packages.Name)) {
            $errors.Add("Required activation package is missing or renamed: $expectedName")
        }
    }

    foreach ($package in $packages) {
        if (-not $package.Name -or -not $package.Purpose -or -not $package.ReadinessGate -or @($package.Policies).Count -eq 0) {
            $errors.Add('Each package needs a descriptive name, purpose, readiness gate, and at least one policy.')
        }
    }

    $packagedPolicies = @($packages | ForEach-Object { @($_.Policies) })
    foreach ($duplicate in $packagedPolicies | Group-Object | Where-Object Count -gt 1) {
        $errors.Add("Policy is assigned to more than one package: $($duplicate.Name)")
    }
    foreach ($policy in $policies) {
        if ($policy.displayName -notin $packagedPolicies) {
            $errors.Add("Policy is not assigned to a package: $($policy.displayName)")
        }
    }
    foreach ($policyName in $packagedPolicies) {
        if ($policyName -notin @($policies.displayName)) {
            $errors.Add("Package contains a missing or retired policy: $policyName")
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output "PASS: 30 production policies (all Report-only), 15 groups, nine complete capability packages, safe CIPP layout, and validated Microsoft dependencies."
