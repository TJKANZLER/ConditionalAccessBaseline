[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$policyRoot = Join-Path $RepositoryRoot 'Config\ConditionalAccess'
$groupRoot = Join-Path $RepositoryRoot 'Config\Groups'
$migrationPath = Join-Path $RepositoryRoot 'Config\MigrationTable.json'
$packagePath = Join-Path $RepositoryRoot 'Config\PolicyPackages.psd1'
$extensionPath = Join-Path $RepositoryRoot 'Config\PolicyExtensions.psd1'

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
    $expectedFileName = '{0}.json' -f ($policy.displayName -replace '[\\/:*?"<>|]', '-')
    if ($file.Name -cne $expectedFileName) {
        $errors.Add("Policy filename does not match its display name: $($file.Name) should be $expectedFileName")
    }
    if ($policy.displayName -notmatch '^MSP-CA(?<PolicyNumber>\d{3})-') {
        $errors.Add("Policy does not use the MSP-CA### numbering convention: $($policy.displayName)")
    }
    $expectedTopLevelOrder = @('@odata.type', 'displayName', 'state', 'conditions', 'grantControls', 'sessionControls')
    $actualTopLevelOrder = @($policy.PSObject.Properties.Name)
    if ((($actualTopLevelOrder | Select-Object -First $expectedTopLevelOrder.Count) -join '|') -cne ($expectedTopLevelOrder -join '|')) {
        $errors.Add("Policy top-level JSON key ordering is inconsistent: $($file.Name)")
    }
    $expectedConditionOrder = @('clientAppTypes', 'platforms', 'locations', 'devices', 'authenticationFlows', 'applications', 'users')
    $actualConditionOrder = @($policy.conditions.PSObject.Properties.Name)
    if ((($actualConditionOrder | Select-Object -First $expectedConditionOrder.Count) -join '|') -cne ($expectedConditionOrder -join '|')) {
        $errors.Add("Policy condition JSON key ordering is inconsistent: $($file.Name)")
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
foreach ($duplicate in $policies | ForEach-Object {
    if ($_.displayName -match '^MSP-CA(?<PolicyNumber>\d{3})-') {
        $Matches.PolicyNumber
    }
} | Group-Object | Where-Object Count -gt 1) {
    $errors.Add("Duplicate policy number: CA$($duplicate.Name)")
}

if ($policies.Count -ne 32) {
    $errors.Add("Expected 32 Conditional Access policies but found $($policies.Count)")
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

if ($groupIds.Count -ne 17) {
    $errors.Add("Expected 17 supporting groups but found $($groupIds.Count)")
}

foreach ($policy in $policies) {
    foreach ($groupId in @($policy.conditions.users.includeGroups) + @($policy.conditions.users.excludeGroups)) {
        if ($groupId -and $groupId -notin $groupIds) {
            $errors.Add("Unmapped group ID $groupId in $($policy.displayName)")
        }
    }

    $declaredLocationIds = @($policy.LocationInfo.id)
    foreach ($locationId in @($policy.conditions.locations.includeLocations) + @($policy.conditions.locations.excludeLocations)) {
        if ($locationId -and $locationId -notin @('All', 'AllTrusted') -and $locationId -notin $declaredLocationIds) {
            $errors.Add("Unresolved named-location reference $locationId in $($policy.displayName)")
        }
    }
    foreach ($location in @($policy.LocationInfo)) {
        if ($null -eq $location) {
            continue
        }
        if (-not $location.id -or -not $location.displayName) {
            $errors.Add("LocationInfo requires a stable id and displayName in $($policy.displayName)")
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

$authTransferPolicy = $policies | Where-Object displayName -eq 'MSP-CA006-Global-Block-AuthenticationTransfer'
$authTransferExclusionId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-AuthenticationTransfer').id
if ($authTransferPolicy.conditions.authenticationFlows.transferMethods -ne 'authenticationTransfer' -or
    $authTransferPolicy.grantControls.builtInControls -notcontains 'block' -or
    $authTransferExclusionId -notin @($authTransferPolicy.conditions.users.excludeGroups)) {
    $errors.Add('Authentication-transfer blocking is missing, incorrectly scoped, or lacks its dedicated exception group.')
}

$internalSessionPolicy = $policies | Where-Object displayName -eq 'MSP-CA010-Global-InternalUser-Session-Hardening'
if ($internalSessionPolicy.conditions.users.includeUsers -notcontains 'All' -or
    $internalSessionPolicy.conditions.users.excludeGroups -notcontains ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-All-EmergencyAccess').id -or
    $internalSessionPolicy.conditions.users.excludeGuestsOrExternalUsers -eq $null -or
    $internalSessionPolicy.sessionControls.signInFrequency.value -ne 24 -or
    $internalSessionPolicy.sessionControls.signInFrequency.type -ne 'hours' -or
    $internalSessionPolicy.sessionControls.signInFrequency.frequencyInterval -ne 'timeBased' -or
    -not $internalSessionPolicy.sessionControls.signInFrequency.isEnabled -or
    $internalSessionPolicy.sessionControls.persistentBrowser.mode -ne 'never' -or
    -not $internalSessionPolicy.sessionControls.persistentBrowser.isEnabled) {
    $errors.Add('CA010 must apply 24-hour sign-in frequency and never-persistent browser sessions to internal users.')
}

$countryPolicy = $policies | Where-Object displayName -eq 'MSP-CA011-Global-Block-Outside-AllowedCountries'
$countryExceptionId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-CountryRestriction').id
$countryLocationId = '20000000-0000-4000-8000-000000000001'
$countryLocationName = 'SHOOTHILL-CA-Allowed-Countries-Operator-Defined'
if ($countryPolicy.conditions.users.includeUsers -notcontains 'All' -or
    $countryPolicy.conditions.users.excludeGroups -notcontains $countryExceptionId -or
    $countryPolicy.conditions.locations.includeLocations -notcontains 'All' -or
    $countryPolicy.conditions.locations.excludeLocations -notcontains $countryLocationId -or
    $countryPolicy.conditions.locations.excludeLocations -contains 'AllTrusted' -or
    $countryPolicy.grantControls.builtInControls -notcontains 'block' -or
    @($countryPolicy.LocationInfo).Count -ne 1 -or
    $countryPolicy.LocationInfo[0].id -ne $countryLocationId -or
    $countryPolicy.LocationInfo[0].displayName -ne $countryLocationName) {
    $errors.Add('CA011 must block internal users outside its dedicated operator-defined allowed-country location.')
}

$extensionMamIds = @()
if (-not (Test-Path -LiteralPath $extensionPath)) {
    $errors.Add('Config\PolicyExtensions.psd1 is missing.')
}
else {
    try {
        $extensionConfig = Import-PowerShellDataFile -LiteralPath $extensionPath
        if ($extensionConfig.SchemaVersion -ne '1.0') {
            $errors.Add("Unsupported PolicyExtensions.psd1 SchemaVersion: $($extensionConfig.SchemaVersion)")
        }
        $extensionMamIds = @($extensionConfig.AdditionalMamApplicationIds)
        foreach ($applicationId in $extensionMamIds) {
            $parsedApplicationId = [guid]::Empty
            if (-not [guid]::TryParse([string]$applicationId, [ref]$parsedApplicationId)) {
                $errors.Add("AdditionalMamApplicationIds contains a non-GUID value: $applicationId")
            }
        }
        foreach ($duplicate in $extensionMamIds | Group-Object | Where-Object Count -gt 1) {
            $errors.Add("Duplicate AdditionalMamApplicationIds value: $($duplicate.Name)")
        }
    }
    catch {
        $errors.Add("Invalid policy extension configuration: $($_.Exception.Message)")
    }
}

$mobileAppProtection = $policies | Where-Object displayName -eq 'MSP-CA300-Mobile-Require-AppProtection'
$expectedMamApplications = @('Office365') + @($extensionMamIds)
$actualMamApplications = @($mobileAppProtection.conditions.applications.includeApplications)
if ($actualMamApplications.Count -ne $expectedMamApplications.Count -or
    @($expectedMamApplications | Where-Object { $_ -notin $actualMamApplications }).Count -gt 0 -or
    $mobileAppProtection.grantControls.builtInControls -notcontains 'compliantApplication') {
    $errors.Add('CA300 application scope does not match Office 365 plus the declared third-party MAM extension IDs.')
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
    if ($packageManifest.SchemaVersion -ne '5.0') {
        $errors.Add("Unsupported PolicyPackages.psd1 SchemaVersion: $($packageManifest.SchemaVersion)")
    }
    $packages = @($packageManifest.Packages)
    if ($packages.Count -ne 6) {
        $errors.Add("Expected six activation packages but found $($packages.Count).")
    }
    $expectedPackageNames = @(
        'SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1'
        'SHOOTHILL-CA-02-Privileged-Endpoint-and-App-Protection'
        'SHOOTHILL-CA-03-Identity-Protection-P2'
        'SHOOTHILL-CA-04-Workload-Identity-Premium'
        'SHOOTHILL-CA-05-Defender-and-Purview-Advanced'
        'SHOOTHILL-CA-06-Optional-Country-Restriction'
    )
    foreach ($expectedName in $expectedPackageNames) {
        if ($expectedName -notin @($packages.Name)) {
            $errors.Add("Required activation package is missing or renamed: $expectedName")
        }
    }

    $corePackage = $packages | Where-Object Name -eq 'SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1'
    foreach ($requiredCorePolicy in @(
        'MSP-CA006-Global-Block-AuthenticationTransfer'
        'MSP-CA009-Registration-Block-Outside-TrustedLocations'
        'MSP-CA010-Global-InternalUser-Session-Hardening'
        'MSP-CA103-Admins-Block-Outside-TrustedLocations'
        'MSP-CA600-MFAExceptionAccounts-Block-Outside-TrustedLocations'
    )) {
        if ($requiredCorePolicy -notin @($corePackage.Policies)) {
            $errors.Add("Core package is missing foundational policy: $requiredCorePolicy")
        }
    }

    $standardPackages = @($packages | Where-Object PromotionTrack -eq 'Standard')
    $optionalPackage = $packages | Where-Object Name -eq 'SHOOTHILL-CA-06-Optional-Country-Restriction'
    if ($standardPackages.Count -ne 5 -or
        $optionalPackage.PromotionTrack -ne 'ExplicitAdoption' -or
        @($optionalPackage.Policies).Count -ne 1 -or
        $optionalPackage.Policies -notcontains 'MSP-CA011-Global-Block-Outside-AllowedCountries' -or
        @($standardPackages.Policies) -contains 'MSP-CA011-Global-Block-Outside-AllowedCountries') {
        $errors.Add('CA011 must exist only in the explicit-adoption optional country-restriction package.')
    }

    foreach ($package in $packages) {
        if (-not $package.Name -or -not $package.PromotionTrack -or -not $package.Purpose -or -not $package.ReadinessGate -or @($package.Policies).Count -eq 0) {
            $errors.Add('Each package needs a descriptive name, promotion track, purpose, readiness gate, and at least one policy.')
        }
        if ($package.PromotionTrack -notin @('Standard', 'ExplicitAdoption')) {
            $errors.Add("Unsupported package promotion track '$($package.PromotionTrack)' in $($package.Name)")
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

Write-Output "PASS: 32 production policies (all Report-only), 17 groups, five standard packages plus one explicit-adoption optional package, safe CIPP layout, and validated Microsoft dependencies."
