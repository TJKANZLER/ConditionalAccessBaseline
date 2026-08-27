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

if ($policies.Count -ne 35) {
    $errors.Add("Expected 35 Conditional Access policies but found $($policies.Count)")
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

if ($groupIds.Count -ne 20) {
    $errors.Add("Expected 20 supporting groups but found $($groupIds.Count)")
}
if (@($groups.displayName) -contains 'MSP-CA-Exclude-LocationPolicies') {
    $errors.Add('Retired shared location exception group is still present.')
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
    $privilegedUsersGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Include-PrivilegedUsers').id
    if ($actualRoles.Count -ne $expectedAdminRoles.Count -or
        @($expectedAdminRoles | Where-Object { $_ -notin $actualRoles }).Count -gt 0) {
        $errors.Add("$policyName does not target the current Microsoft-recommended administrator role set.")
    }
    if ($privilegedUsersGroupId -notin @($adminPolicy.conditions.users.includeGroups)) {
        $errors.Add("$policyName does not include the explicit privileged-user extension group.")
    }
}

$highValueUsersGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Include-HighValueUsers').id
$highValueMfaPolicy = $policies | Where-Object displayName -eq 'MSP-CA110-HighValueUsers-Require-PhishingResistantMFA'
$highValueBrowserPolicy = $policies | Where-Object displayName -eq 'MSP-CA111-HighValueUsers-Browser-Require-CompliantDevice'
foreach ($highValuePolicy in @($highValueMfaPolicy, $highValueBrowserPolicy)) {
    if ($null -eq $highValuePolicy -or
        @($highValuePolicy.conditions.users.includeGroups).Count -ne 1 -or
        $highValuePolicy.conditions.users.includeGroups -notcontains $highValueUsersGroupId -or
        @($highValuePolicy.conditions.users.excludeGroups).Count -ne 1 -or
        $highValuePolicy.conditions.users.excludeGroups -notcontains ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-All-EmergencyAccess').id) {
        $errors.Add('CA110 and CA111 must target only the declared high-value-user group and exclude emergency access.')
    }
}
if ($highValueMfaPolicy.conditions.applications.includeApplications -notcontains 'All' -or
    $highValueMfaPolicy.conditions.clientAppTypes -notcontains 'all' -or
    $highValueMfaPolicy.grantControls.operator -ne 'AND' -or
    $highValueMfaPolicy.grantControls.authenticationStrength.id -ne '00000000-0000-0000-0000-000000000004') {
    $errors.Add('CA110 must require phishing-resistant MFA for high-value users across all resources and clients.')
}
if ($highValueBrowserPolicy.conditions.applications.includeApplications -notcontains 'All' -or
    $highValueBrowserPolicy.conditions.clientAppTypes -notcontains 'browser' -or
    $highValueBrowserPolicy.grantControls.builtInControls -notcontains 'compliantDevice') {
    $errors.Add('CA111 must require a compliant device for all high-value-user browser access.')
}

$adminCompliancePolicy = $policies | Where-Object displayName -eq 'MSP-CA102-Admins-Require-CompliantDevice'
$expectedAdminCompliancePlatforms = @('windows', 'macOS', 'iOS', 'android', 'linux')
$actualAdminCompliancePlatforms = @($adminCompliancePolicy.conditions.platforms.includePlatforms)
if ($actualAdminCompliancePlatforms.Count -ne $expectedAdminCompliancePlatforms.Count -or
    @($expectedAdminCompliancePlatforms | Where-Object { $_ -notin $actualAdminCompliancePlatforms }).Count -gt 0 -or
    $adminCompliancePolicy.grantControls.builtInControls -notcontains 'compliantDevice') {
    $errors.Add('CA102 must require device compliance across every supported administrator platform.')
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

$trustedSessionPolicy = $policies | Where-Object displayName -eq 'MSP-CA010-InternalUsers-TrustedLocation-Session-Hardening'
$untrustedSessionPolicy = $policies | Where-Object displayName -eq 'MSP-CA012-InternalUsers-UntrustedLocation-Session-Hardening'
$emergencyGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-All-EmergencyAccess').id
$mfaExceptionGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-MFA-Temporary').id
foreach ($sessionPolicy in @($trustedSessionPolicy, $untrustedSessionPolicy)) {
    if ($null -eq $sessionPolicy -or
        $sessionPolicy.conditions.users.includeUsers -notcontains 'All' -or
        @($sessionPolicy.conditions.users.excludeGroups).Count -ne 2 -or
        $sessionPolicy.conditions.users.excludeGroups -notcontains $emergencyGroupId -or
        $sessionPolicy.conditions.users.excludeGroups -notcontains $mfaExceptionGroupId -or
        $sessionPolicy.conditions.users.excludeGuestsOrExternalUsers -eq $null -or
        $sessionPolicy.sessionControls.signInFrequency.authenticationType -ne 'primaryAndSecondaryAuthentication' -or
        $sessionPolicy.sessionControls.signInFrequency.frequencyInterval -ne 'timeBased' -or
        -not $sessionPolicy.sessionControls.signInFrequency.isEnabled -or
        $sessionPolicy.sessionControls.persistentBrowser.mode -ne 'never' -or
        -not $sessionPolicy.sessionControls.persistentBrowser.isEnabled) {
        $errors.Add('CA010 and CA012 must apply the expected session controls and exclusions to internal users.')
    }
}
if ($trustedSessionPolicy.conditions.locations.includeLocations -notcontains 'AllTrusted' -or
    @($trustedSessionPolicy.conditions.locations.excludeLocations).Count -ne 0 -or
    $trustedSessionPolicy.sessionControls.signInFrequency.value -ne 14 -or
    $trustedSessionPolicy.sessionControls.signInFrequency.type -ne 'days') {
    $errors.Add('CA010 must apply a 14-day sign-in frequency at trusted locations.')
}
if ($untrustedSessionPolicy.conditions.locations.includeLocations -notcontains 'All' -or
    $untrustedSessionPolicy.conditions.locations.excludeLocations -notcontains 'AllTrusted' -or
    $untrustedSessionPolicy.sessionControls.signInFrequency.value -ne 24 -or
    $untrustedSessionPolicy.sessionControls.signInFrequency.type -ne 'hours') {
    $errors.Add('CA012 must apply a 24-hour sign-in frequency outside trusted locations.')
}

$countryPolicy = $policies | Where-Object displayName -eq 'MSP-CA011-Global-Block-Outside-AllowedCountries'
$countryExceptionId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-CountryRestriction').id
$countryLocationId = '20000000-0000-4000-8000-000000000001'
$countryLocationName = 'SHOOTHILL-CA-Allowed-Countries-Operator-Defined'
if ($countryPolicy.conditions.users.includeUsers -notcontains 'All' -or
    @($countryPolicy.conditions.users.excludeGroups).Count -ne 3 -or
    $countryPolicy.conditions.users.excludeGroups -notcontains $emergencyGroupId -or
    $countryPolicy.conditions.users.excludeGroups -notcontains $mfaExceptionGroupId -or
    $countryPolicy.conditions.users.excludeGroups -notcontains $countryExceptionId -or
    $countryPolicy.conditions.users.excludeGuestsOrExternalUsers -eq $null -or
    $countryPolicy.conditions.locations.includeLocations -notcontains 'All' -or
    $countryPolicy.conditions.locations.excludeLocations -notcontains $countryLocationId -or
    $countryPolicy.conditions.locations.excludeLocations -contains 'AllTrusted' -or
    $countryPolicy.grantControls.builtInControls -notcontains 'block' -or
    @($countryPolicy.LocationInfo).Count -ne 1 -or
    $countryPolicy.LocationInfo[0].id -ne $countryLocationId -or
    $countryPolicy.LocationInfo[0].displayName -ne $countryLocationName) {
    $errors.Add('CA011 must block internal users outside its dedicated operator-defined allowed-country location.')
}

$extensionMamResourceIds = @()
$extensionTokenResourceIds = @()
if (-not (Test-Path -LiteralPath $extensionPath)) {
    $errors.Add('Config\PolicyExtensions.psd1 is missing.')
}
else {
    try {
        $extensionConfig = Import-PowerShellDataFile -LiteralPath $extensionPath
        if ($extensionConfig.SchemaVersion -ne '3.0') {
            $errors.Add("Unsupported PolicyExtensions.psd1 SchemaVersion: $($extensionConfig.SchemaVersion)")
        }
        if (-not $extensionConfig.ContainsKey('AdditionalMamProtectedResources')) {
            $errors.Add('PolicyExtensions.psd1 must declare AdditionalMamProtectedResources.')
        }
        if (-not $extensionConfig.ContainsKey('AdditionalWindowsTokenProtectionResources')) {
            $errors.Add('PolicyExtensions.psd1 must declare AdditionalWindowsTokenProtectionResources.')
        }
        if ($extensionConfig.ContainsKey('AdditionalMamApplicationIds')) {
            $errors.Add('Retired AdditionalMamApplicationIds setting found; use AdditionalMamProtectedResources.')
        }
        $extensionMamResources = @($extensionConfig.AdditionalMamProtectedResources)
        foreach ($resource in $extensionMamResources) {
            if (-not $resource.ApplicationId -or -not $resource.DisplayName) {
                $errors.Add('Every AdditionalMamProtectedResources entry requires ApplicationId and DisplayName.')
                continue
            }
            $parsedApplicationId = [guid]::Empty
            if (-not [guid]::TryParse([string]$resource.ApplicationId, [ref]$parsedApplicationId)) {
                $errors.Add("AdditionalMamProtectedResources contains a non-GUID ApplicationId: $($resource.ApplicationId)")
            }
            $extensionMamResourceIds += [string]$resource.ApplicationId
        }
        foreach ($duplicate in $extensionMamResourceIds | Group-Object | Where-Object Count -gt 1) {
            $errors.Add("Duplicate AdditionalMamProtectedResources ApplicationId: $($duplicate.Name)")
        }
        $supportedOptionalTokenResources = @{
            '9cdead84-a844-4324-93f2-b2e6bb768d07' = 'Azure Virtual Desktop'
            '0af06dc6-e4b5-4f28-818e-e78e62d137a5' = 'Windows 365'
            '270efc09-cd0d-444b-a71f-39af4910ec45' = 'Windows Cloud Login'
        }
        foreach ($resource in @($extensionConfig.AdditionalWindowsTokenProtectionResources)) {
            $applicationId = [string]$resource.ApplicationId
            if (-not $resource.ApplicationId -or -not $resource.DisplayName -or
                -not $supportedOptionalTokenResources.ContainsKey($applicationId) -or
                [string]$resource.DisplayName -ne $supportedOptionalTokenResources[$applicationId]) {
                $errors.Add("Invalid optional Windows token-protection resource: $applicationId")
                continue
            }
            $extensionTokenResourceIds += $applicationId
        }
        foreach ($duplicate in $extensionTokenResourceIds | Group-Object | Where-Object Count -gt 1) {
            $errors.Add("Duplicate AdditionalWindowsTokenProtectionResources ApplicationId: $($duplicate.Name)")
        }
    }
    catch {
        $errors.Add("Invalid policy extension configuration: $($_.Exception.Message)")
    }
}

$mobileAppProtection = $policies | Where-Object displayName -eq 'MSP-CA300-Mobile-Require-AppProtection'
$expectedMamApplications = @('Office365') + @($extensionMamResourceIds)
$actualMamApplications = @($mobileAppProtection.conditions.applications.includeApplications)
if ($actualMamApplications.Count -ne $expectedMamApplications.Count -or
    @($expectedMamApplications | Where-Object { $_ -notin $actualMamApplications }).Count -gt 0 -or
    $mobileAppProtection.grantControls.builtInControls -notcontains 'compliantApplication') {
    $errors.Add('CA300 target-resource scope does not match Office 365 plus the declared protected resource IDs.')
}

$insiderRiskPolicy = $policies | Where-Object displayName -eq 'MSP-CA402-InsiderRisk-Elevated-Block'
if (@($insiderRiskPolicy.conditions.users.excludeGroups).Count -ne 3 -or
    $insiderRiskPolicy.conditions.users.excludeGroups -notcontains $emergencyGroupId -or
    $insiderRiskPolicy.conditions.users.excludeGroups -notcontains $mfaExceptionGroupId -or
    $insiderRiskPolicy.conditions.users.excludeGroups -notcontains ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-InsiderRisk').id) {
    $errors.Add('CA402 must exclude temporary user-based service accounts from user-scoped insider-risk enforcement.')
}

$registrationLocationGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-RegistrationLocation').id
$adminLocationGroupId = ($groups | Where-Object displayName -eq 'MSP-CA-Exclude-AdminLocation').id
$registrationLocationPolicy = $policies | Where-Object displayName -eq 'MSP-CA009-Registration-Block-Outside-TrustedLocations'
$adminLocationPolicy = $policies | Where-Object displayName -eq 'MSP-CA103-Admins-Block-Outside-TrustedLocations'
$mfaExceptionLocationPolicy = $policies | Where-Object displayName -eq 'MSP-CA600-MFAExceptionAccounts-Block-Outside-TrustedLocations'
if ($registrationLocationGroupId -notin @($registrationLocationPolicy.conditions.users.excludeGroups) -or
    $registrationLocationGroupId -in @($adminLocationPolicy.conditions.users.excludeGroups) -or
    $registrationLocationGroupId -in @($mfaExceptionLocationPolicy.conditions.users.excludeGroups)) {
    $errors.Add('The CA009 registration-location exception must be dedicated to CA009.')
}
if ($adminLocationGroupId -notin @($adminLocationPolicy.conditions.users.excludeGroups) -or
    $adminLocationGroupId -in @($registrationLocationPolicy.conditions.users.excludeGroups) -or
    $adminLocationGroupId -in @($mfaExceptionLocationPolicy.conditions.users.excludeGroups)) {
    $errors.Add('The CA103 administrator-location exception must be dedicated to CA103.')
}
foreach ($policy in $policies) {
    if ($registrationLocationGroupId -in @($policy.conditions.users.excludeGroups) -and
        $policy.displayName -ne 'MSP-CA009-Registration-Block-Outside-TrustedLocations') {
        $errors.Add("$($policy.displayName) reuses the CA009 registration-location exception.")
    }
    if ($adminLocationGroupId -in @($policy.conditions.users.excludeGroups) -and
        $policy.displayName -ne 'MSP-CA103-Admins-Block-Outside-TrustedLocations') {
        $errors.Add("$($policy.displayName) reuses the CA103 administrator-location exception.")
    }
}
if (@($mfaExceptionLocationPolicy.conditions.users.excludeGroups).Count -ne 1 -or
    $mfaExceptionLocationPolicy.conditions.users.excludeGroups -notcontains $emergencyGroupId -or
    $mfaExceptionLocationPolicy.conditions.users.includeGroups -notcontains $mfaExceptionGroupId) {
    $errors.Add('CA600 must constrain MFA-exception accounts without a bypass group other than emergency access.')
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
$requiredTokenResources = @(
    '00000002-0000-0ff1-ce00-000000000000'
    '00000003-0000-0ff1-ce00-000000000000'
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'
)
$expectedTokenResources = @($requiredTokenResources) + @($extensionTokenResourceIds)
foreach ($resource in $expectedTokenResources) {
    if ($resource -notin @($tokenPolicy.conditions.applications.includeApplications)) {
        $errors.Add("Windows token protection is missing supported resource $resource.")
    }
}
if (@($tokenPolicy.conditions.applications.includeApplications).Count -ne $expectedTokenResources.Count -or
    @($tokenPolicy.conditions.applications.includeApplications | Where-Object { $_ -notin $expectedTokenResources }).Count -gt 0 -or
    $tokenPolicy.conditions.applications.includeApplications -contains 'Office365' -or
    $tokenPolicy.conditions.clientAppTypes -contains 'browser' -or
    -not $tokenPolicy.sessionControls.secureSignInSession.isEnabled) {
    $errors.Add('Windows token-protection scope is unsafe or incomplete.')
}

$riskRemediation = $policies | Where-Object displayName -eq 'MSP-CA401-Risk-User-High-Require-Remediation'
if ($riskRemediation.conditions.userRiskLevels -notcontains 'high' -or
    @($riskRemediation.grantControls.builtInControls).Count -ne 1 -or
    $riskRemediation.grantControls.builtInControls -notcontains 'riskRemediation' -or
    $riskRemediation.grantControls.operator -ne 'AND' -or
    $riskRemediation.grantControls.authenticationStrength.id -ne '00000000-0000-0000-0000-000000000002' -or
    $riskRemediation.conditions.applications.includeApplications -notcontains 'All' -or
    @($riskRemediation.conditions.applications.excludeApplications).Count -ne 0 -or
    $null -ne $riskRemediation.conditions.platforms -or
    $null -ne $riskRemediation.conditions.locations -or
    $null -ne $riskRemediation.conditions.devices -or
    $null -ne $riskRemediation.conditions.authenticationFlows -or
    $riskRemediation.sessionControls.signInFrequency.frequencyInterval -ne 'everyTime' -or
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
    if ($packageManifest.SchemaVersion -ne '5.1') {
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
        'MSP-CA010-InternalUsers-TrustedLocation-Session-Hardening'
        'MSP-CA012-InternalUsers-UntrustedLocation-Session-Hardening'
        'MSP-CA103-Admins-Block-Outside-TrustedLocations'
        'MSP-CA600-MFAExceptionAccounts-Block-Outside-TrustedLocations'
    )) {
        if ($requiredCorePolicy -notin @($corePackage.Policies)) {
            $errors.Add("Core package is missing foundational policy: $requiredCorePolicy")
        }
    }

    $protectionPackage = $packages | Where-Object Name -eq 'SHOOTHILL-CA-02-Privileged-Endpoint-and-App-Protection'
    foreach ($requiredProtectionPolicy in @(
        'MSP-CA110-HighValueUsers-Require-PhishingResistantMFA'
        'MSP-CA111-HighValueUsers-Browser-Require-CompliantDevice'
    )) {
        if ($requiredProtectionPolicy -notin @($protectionPackage.Policies)) {
            $errors.Add("Protection package is missing high-value-user policy: $requiredProtectionPolicy")
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

Write-Output "PASS: 35 production policies (all Report-only), 20 groups, five standard packages plus one explicit-adoption optional package, safe CIPP layout, and validated Microsoft dependencies."
