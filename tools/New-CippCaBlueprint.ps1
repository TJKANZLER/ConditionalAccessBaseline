[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$configRoot = Join-Path $RepositoryRoot 'Config'
$policyRoot = Join-Path $configRoot 'ConditionalAccess'
$groupRoot = Join-Path $configRoot 'Groups'
foreach ($path in @($configRoot, $policyRoot, $groupRoot)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

$ids = [ordered]@{
    ExcludeAll              = '10000000-0000-4000-8000-000000000001'
    ExcludeMfa              = '10000000-0000-4000-8000-000000000002'
    ExcludeDeviceCode       = '10000000-0000-4000-8000-000000000003'
    ExcludeAuthTransfer     = '10000000-0000-4000-8000-000000000004'
    ExcludeRegistration     = '10000000-0000-4000-8000-000000000005'
    ExcludeCompliance       = '10000000-0000-4000-8000-000000000006'
    ExcludeAppProtection    = '10000000-0000-4000-8000-000000000007'
    AllowGuestAdminPortals  = '10000000-0000-4000-8000-000000000008'
    ExcludeRisk             = '10000000-0000-4000-8000-000000000009'
    ExcludeLocation         = '10000000-0000-4000-8000-000000000010'
    ExcludeTokenProtection  = '10000000-0000-4000-8000-000000000011'
    ExcludeCAE              = '10000000-0000-4000-8000-000000000012'
    ExcludeCloudAppSecurity = '10000000-0000-4000-8000-000000000013'
    ExcludeInsiderRisk      = '10000000-0000-4000-8000-000000000014'
    ExcludeUnknownPlatforms = '10000000-0000-4000-8000-000000000015'
    ExcludeUnmanagedBrowser = '10000000-0000-4000-8000-000000000016'
}

$groupNames = [ordered]@{
    ExcludeAll             = 'MSP-CA-Exclude-All-EmergencyAccess'
    ExcludeMfa             = 'MSP-CA-Exclude-MFA-Temporary'
    ExcludeDeviceCode      = 'MSP-CA-Exclude-DeviceCodeFlow'
    ExcludeAuthTransfer    = 'MSP-CA-Exclude-AuthenticationTransfer'
    ExcludeRegistration    = 'MSP-CA-Exclude-Registration'
    ExcludeCompliance      = 'MSP-CA-Exclude-DeviceCompliance'
    ExcludeAppProtection   = 'MSP-CA-Exclude-AppProtection'
    AllowGuestAdminPortals = 'MSP-CA-Allow-GuestAdminPortals'
    ExcludeRisk            = 'MSP-CA-Exclude-RiskPolicies'
    ExcludeLocation        = 'MSP-CA-Exclude-LocationPolicies'
    ExcludeTokenProtection = 'MSP-CA-Exclude-TokenProtection'
    ExcludeCAE             = 'MSP-CA-Exclude-StrictCAE'
    ExcludeCloudAppSecurity = 'MSP-CA-Exclude-DefenderAppControl'
    ExcludeInsiderRisk     = 'MSP-CA-Exclude-InsiderRisk'
    ExcludeUnknownPlatforms = 'MSP-CA-Exclude-UnknownPlatforms'
    ExcludeUnmanagedBrowser = 'MSP-CA-Exclude-UnmanagedBrowser'
}

$groupDescriptions = [ordered]@{
    ExcludeAll             = 'Emergency access accounts only. Membership must be monitored and alerted.'
    ExcludeMfa             = 'Temporary exception for user-based service accounts pending migration. Keep empty by default.'
    ExcludeDeviceCode      = 'Approved identities that have a documented requirement for OAuth device code flow.'
    ExcludeAuthTransfer    = 'Approved identities that require authentication transfer. Keep empty unless tested.'
    ExcludeRegistration    = 'Temporary exception for device or security-information registration workflows.'
    ExcludeCompliance      = 'Temporary device compliance exception, shared by every compliant-device requirement (CA102, CA302-306, CA310). Keep empty by default.'
    ExcludeAppProtection   = 'Temporary Intune App Protection exception. Keep empty by default.'
    AllowGuestAdminPortals = 'Explicitly approved B2B guest administrators allowed to reach Microsoft admin portals.'
    ExcludeRisk            = 'Emergency risk-policy exceptions. Keep empty by default.'
    ExcludeLocation        = 'Temporary exception from trusted-location restrictions. Keep empty by default.'
    ExcludeTokenProtection = 'Temporary exception for token-protection compatibility issues. Keep empty by default.'
    ExcludeCAE             = 'Temporary exception from strict-location Continuous Access Evaluation. Keep empty by default.'
    ExcludeCloudAppSecurity = 'Temporary exception from Defender for Cloud Apps session controls. Keep empty by default.'
    ExcludeInsiderRisk     = 'Approved exception from Purview insider-risk enforcement. Keep empty by default.'
    ExcludeUnknownPlatforms = 'Temporary exception from the unknown-platform block (CA007) only. Keep empty by default.'
    ExcludeUnmanagedBrowser = 'Temporary exception from the unmanaged-browser download restriction (CA301) only. Keep empty by default.'
}

$mfaStrength = [ordered]@{
    id                    = '00000000-0000-0000-0000-000000000002'
    displayName           = 'Multifactor authentication'
    policyType            = 'builtIn'
    requirementsSatisfied = 'mfa'
}

$phishingResistantStrength = [ordered]@{
    id                    = '00000000-0000-0000-0000-000000000004'
    displayName           = 'Phishing-resistant MFA'
    policyType            = 'builtIn'
    requirementsSatisfied = 'mfa'
}

# Microsoft-recommended privileged roles plus additional high-impact roles used by the
# maintained j0eyv framework. Role template IDs are stable across tenants.
$adminRoleTemplateIds = @(
    '62e90394-69f5-4237-9190-012177145e10',
    '194ae4cb-b126-40b2-bd5b-6091b380977d',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
    '29232cdf-9323-42fd-ade2-1d097af3e4de',
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe',
    'fe930be7-5e62-47db-91af-98c3a49a38b1',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
    '158c047a-c907-4556-b7ef-446551a6b5f7',
    '966707d0-3269-4727-9be2-8c3a10f19b9d',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
    'e8611ab8-c189-46e8-94e1-60213ab1f814',
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451',
    '3a2c62db-5318-420d-8d74-23affee5d9d5',
    'db506228-d27e-4b7d-95e5-295956d6615f',
    '6b942400-691f-4bf0-9d12-d8a254a2baf5',
    'd2562ede-74db-457e-a7b6-544e236ebb61',
    'e93e3737-fa85-474a-aee4-7d3fb86510f3',
    'b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb',
    '1707125e-0aa2-4d4d-8655-a7c786c76a25',
    '69091246-20e8-4a56-aa4d-066075b2a7a8',
    '11451d60-acb2-45eb-a7d6-43d0f0125c13'
)

function New-AllExternalUsersObject {
    [ordered]@{
        '@odata.type'            = '#microsoft.graph.conditionalAccessGuestsOrExternalUsers'
        guestOrExternalUserTypes = 'internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser'
        externalTenants          = [ordered]@{
            '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
            membershipKind = 'all'
        }
    }
}

function New-ServiceProviderUsersObject {
    [ordered]@{
        '@odata.type'            = '#microsoft.graph.conditionalAccessGuestsOrExternalUsers'
        guestOrExternalUserTypes = 'serviceProvider'
        externalTenants          = [ordered]@{
            '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'
            membershipKind = 'all'
        }
    }
}

function New-UserScope {
    param(
        [ValidateSet('AllHuman', 'Internal', 'Guests', 'Admins')]
        [string]$Scope,
        [string[]]$ExcludeGroups = @()
    )

    $users = [ordered]@{
        includeUsers                 = @()
        excludeUsers                 = @()
        includeGroups                = @()
        excludeGroups                = @($ExcludeGroups)
        includeRoles                 = @()
        excludeRoles                 = @()
        includeGuestsOrExternalUsers = $null
        excludeGuestsOrExternalUsers = $null
    }

    switch ($Scope) {
        'AllHuman' {
            $users.includeUsers = @('All')
            $users.excludeGuestsOrExternalUsers = New-ServiceProviderUsersObject
        }
        'Internal' {
            $users.includeUsers = @('All')
            $users.excludeGuestsOrExternalUsers = New-AllExternalUsersObject
        }
        'Guests' {
            $users.includeGuestsOrExternalUsers = New-AllExternalUsersObject
        }
        'Admins' {
            $users.includeRoles = @($adminRoleTemplateIds)
            $users.excludeGuestsOrExternalUsers = New-ServiceProviderUsersObject
        }
    }

    $users
}

function New-ApplicationsScope {
    param(
        [string[]]$IncludeApplications = @('All'),
        [string[]]$ExcludeApplications = @(),
        [string[]]$IncludeUserActions = @(),
        [string[]]$IncludeAuthenticationContexts = @()
    )

    [ordered]@{
        includeApplications                         = @($IncludeApplications)
        excludeApplications                         = @($ExcludeApplications)
        includeUserActions                          = @($IncludeUserActions)
        includeAuthenticationContextClassReferences = @($IncludeAuthenticationContexts)
        applicationFilter                           = $null
    }
}

function New-Conditions {
    param(
        $Users = $null,
        $Applications = (New-ApplicationsScope),
        [string[]]$ClientAppTypes = @('all'),
        $Platforms = $null,
        $Devices = $null,
        $Locations = $null,
        $AuthenticationFlows = $null,
        [string[]]$SignInRiskLevels = @(),
        [string[]]$UserRiskLevels = @(),
        [string[]]$ServicePrincipalRiskLevels = @(),
        $InsiderRiskLevels = $null,
        $ClientApplications = $null,
        $Agents = $null,
        $AgentContext = $null,
        $AgentIdRiskLevels = $null
    )

    $conditions = [ordered]@{
        userRiskLevels      = @($UserRiskLevels)
        signInRiskLevels    = @($SignInRiskLevels)
        servicePrincipalRiskLevels = @($ServicePrincipalRiskLevels)
        clientAppTypes      = @($ClientAppTypes)
        platforms           = $Platforms
        locations           = $Locations
        devices             = $Devices
        authenticationFlows = $AuthenticationFlows
        applications        = $Applications
        users               = $Users
        clientApplications  = $ClientApplications
        agents              = $Agents
        agentContext        = $AgentContext
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$InsiderRiskLevels)) {
        $conditions.insiderRiskLevels = $InsiderRiskLevels
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$AgentIdRiskLevels)) {
        $conditions.agentIdRiskLevels = $AgentIdRiskLevels
    }
    $conditions
}

function New-Grant {
    param(
        [string[]]$BuiltInControls = @(),
        [ValidateSet('AND', 'OR')]
        [string]$Operator = 'OR',
        $AuthenticationStrength = $null
    )

    [ordered]@{
        operator                    = $Operator
        builtInControls             = @($BuiltInControls)
        customAuthenticationFactors = @()
        termsOfUse                  = @()
        authenticationStrength      = $AuthenticationStrength
    }
}

function New-Policy {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)]$Conditions,
        $GrantControls = $null,
        $SessionControls = $null,
        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string]$State = 'enabledForReportingButNotEnforced'
    )

    [ordered]@{
        '@odata.type'   = '#microsoft.graph.conditionalAccessPolicy'
        displayName     = $DisplayName
        state           = $State
        conditions      = $Conditions
        grantControls   = $GrantControls
        sessionControls = $SessionControls
    }
}

$allGroup = $ids.ExcludeAll
$policies = @()
$intuneExclusions = @(
    '0000000a-0000-0000-c000-000000000000',
    'd4ebce55-015a-49b5-a083-c84d1797ae8c'
)
$tokenProtectionResources = @(
    '00000002-0000-0ff1-ce00-000000000000',
    '00000003-0000-0ff1-ce00-000000000000'
)

$policies += New-Policy -DisplayName 'MSP-CA001-Global-Block-LegacyAuthentication' `
    -Conditions (New-Conditions -Users (New-UserScope AllHuman -ExcludeGroups @($allGroup)) `
        -ClientAppTypes @('exchangeActiveSync', 'other')) `
    -GrantControls (New-Grant -BuiltInControls @('block'))

$policies += New-Policy -DisplayName 'MSP-CA002-Global-Require-MFA' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeMfa))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $mfaStrength)

$policies += New-Policy -DisplayName 'MSP-CA003-Global-Protect-SecurityInfoRegistration' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeRegistration)) `
        -Applications (New-ApplicationsScope -IncludeApplications @() -IncludeUserActions @('urn:user:registersecurityinfo'))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $mfaStrength)

$policies += New-Policy -DisplayName 'MSP-CA004-Global-Protect-DeviceRegistration' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeRegistration)) `
        -Applications (New-ApplicationsScope -IncludeApplications @() -IncludeUserActions @('urn:user:registerdevice'))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $mfaStrength)

$policies += New-Policy -DisplayName 'MSP-CA005-Global-Block-DeviceCodeFlow' `
    -Conditions (New-Conditions -Users (New-UserScope AllHuman -ExcludeGroups @($allGroup, $ids.ExcludeDeviceCode)) `
        -AuthenticationFlows ([ordered]@{ transferMethods = 'deviceCodeFlow' })) `
    -GrantControls (New-Grant -BuiltInControls @('block'))

$policies += New-Policy -DisplayName 'MSP-CA006-Global-Block-AuthenticationTransfer' `
    -Conditions (New-Conditions -Users (New-UserScope AllHuman -ExcludeGroups @($allGroup, $ids.ExcludeAuthTransfer)) `
        -AuthenticationFlows ([ordered]@{ transferMethods = 'authenticationTransfer' })) `
    -GrantControls (New-Grant -BuiltInControls @('block'))

$policies += New-Policy -DisplayName 'MSP-CA007-Global-Block-UnknownPlatforms' `
    -Conditions (New-Conditions -Users (New-UserScope AllHuman -ExcludeGroups @($allGroup, $ids.ExcludeUnknownPlatforms)) `
        -Platforms ([ordered]@{
            includePlatforms = @('all')
            excludePlatforms = @('android', 'iOS', 'windows', 'macOS', 'linux')
        })) `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA008-Global-Block-Outside-TrustedLocations' `
    -Conditions (New-Conditions -Users (New-UserScope AllHuman -ExcludeGroups @($allGroup, $ids.ExcludeLocation)) `
        -Locations ([ordered]@{ includeLocations = @('All'); excludeLocations = @('AllTrusted') })) `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA100-Admins-Require-PhishingResistantMFA' `
    -Conditions (New-Conditions -Users (New-UserScope Admins -ExcludeGroups @($allGroup))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $phishingResistantStrength)

$policies += New-Policy -DisplayName 'MSP-CA101-Admins-Session-Hardening' `
    -Conditions (New-Conditions -Users (New-UserScope Admins -ExcludeGroups @($allGroup))) `
    -SessionControls ([ordered]@{
        signInFrequency = [ordered]@{
            value = 12; type = 'hours'; authenticationType = 'primaryAndSecondaryAuthentication';
            frequencyInterval = 'timeBased'; isEnabled = $true
        }
        persistentBrowser = [ordered]@{ mode = 'never'; isEnabled = $true }
    })

$policies += New-Policy -DisplayName 'MSP-CA102-Admins-Require-CompliantDevice' `
    -Conditions (New-Conditions -Users (New-UserScope Admins -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -Platforms ([ordered]@{ includePlatforms = @('windows', 'macOS'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA103-Admins-StrictLocation-CAE' `
    -Conditions (New-Conditions -Users (New-UserScope Admins -ExcludeGroups @($allGroup, $ids.ExcludeCAE))) `
    -SessionControls ([ordered]@{
        continuousAccessEvaluation = [ordered]@{ mode = 'strictLocation' }
    }) `
    -State disabled

$sensitiveActionPolicy = New-Policy -DisplayName 'MSP-CA104-Admins-SensitiveActions-Reauthenticate' `
    -Conditions (New-Conditions -Users (New-UserScope Admins -ExcludeGroups @($allGroup)) `
        -Applications (New-ApplicationsScope -IncludeApplications @() -IncludeAuthenticationContexts @('c1'))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $phishingResistantStrength) `
    -SessionControls ([ordered]@{ signInFrequency = [ordered]@{
        value = $null; type = $null; authenticationType = 'primaryAndSecondaryAuthentication';
        frequencyInterval = 'everyTime'; isEnabled = $true
    } }) `
    -State disabled
$sensitiveActionPolicy['AuthContextInfo'] = @([ordered]@{
    id = 'c1'
    displayName = 'MSP Sensitive Action'
    description = 'Step-up authentication context for PIM activation and sensitive application operations.'
    isAvailable = $true
})
$policies += $sensitiveActionPolicy

$policies += New-Policy -DisplayName 'MSP-CA200-Guests-Require-MFA' `
    -Conditions (New-Conditions -Users (New-UserScope Guests -ExcludeGroups @($allGroup))) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $mfaStrength)

$policies += New-Policy -DisplayName 'MSP-CA201-Guests-Session-Hardening' `
    -Conditions (New-Conditions -Users (New-UserScope Guests -ExcludeGroups @($allGroup))) `
    -SessionControls ([ordered]@{
        signInFrequency = [ordered]@{
            value = 12; type = 'hours'; authenticationType = 'primaryAndSecondaryAuthentication';
            frequencyInterval = 'timeBased'; isEnabled = $true
        }
        persistentBrowser = [ordered]@{ mode = 'never'; isEnabled = $true }
    })

$policies += New-Policy -DisplayName 'MSP-CA202-Guests-Block-AdminPortals' `
    -Conditions (New-Conditions -Users (New-UserScope Guests -ExcludeGroups @($allGroup, $ids.AllowGuestAdminPortals)) `
        -Applications (New-ApplicationsScope -IncludeApplications @('MicrosoftAdminPortals'))) `
    -GrantControls (New-Grant -BuiltInControls @('block'))

$policies += New-Policy -DisplayName 'MSP-CA300-Mobile-Require-AppProtection' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeAppProtection)) `
        -Applications (New-ApplicationsScope -IncludeApplications @('Office365')) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('android', 'iOS'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantApplication'))

$policies += New-Policy -DisplayName 'MSP-CA301-UnmanagedBrowser-Restrict-Downloads' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeUnmanagedBrowser)) `
        -Applications (New-ApplicationsScope -IncludeApplications @(
            '00000002-0000-0ff1-ce00-000000000000',
            '00000003-0000-0ff1-ce00-000000000000'
        )) `
        -ClientAppTypes @('browser') `
        -Devices ([ordered]@{
            deviceFilter = [ordered]@{ mode = 'include'; rule = 'device.isCompliant -ne True' }
        })) `
    -SessionControls ([ordered]@{
        applicationEnforcedRestrictions = [ordered]@{ isEnabled = $true }
    })

$policies += New-Policy -DisplayName 'MSP-CA302-Windows-Require-CompliantDevice' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('windows'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice'))

$policies += New-Policy -DisplayName 'MSP-CA310-Windows-Require-CompliantOrHybridJoined-Alternative' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('windows'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice', 'domainJoinedDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA303-macOS-Require-CompliantDevice' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('macOS'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice'))

$policies += New-Policy -DisplayName 'MSP-CA304-iOS-Require-CompliantDevice-Alternative' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('iOS'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA305-Android-Require-CompliantDevice-Alternative' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('android'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA306-Linux-Require-CompliantDevice' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCompliance)) `
        -Applications (New-ApplicationsScope -ExcludeApplications $intuneExclusions) `
        -Platforms ([ordered]@{ includePlatforms = @('linux'); excludePlatforms = @() })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA307-Windows-Require-TokenProtection' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeTokenProtection)) `
        -Applications (New-ApplicationsScope -IncludeApplications $tokenProtectionResources) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('windows'); excludePlatforms = @() })) `
    -SessionControls ([ordered]@{
        secureSignInSession = [ordered]@{ '@odata.type' = '#microsoft.graph.secureSignInSessionControl'; isEnabled = $true }
    })

$policies += New-Policy -DisplayName 'MSP-CA308-Apple-Require-TokenProtection-Preview' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeTokenProtection)) `
        -Applications (New-ApplicationsScope -IncludeApplications $tokenProtectionResources) `
        -ClientAppTypes @('mobileAppsAndDesktopClients') `
        -Platforms ([ordered]@{ includePlatforms = @('iOS', 'macOS'); excludePlatforms = @() })) `
    -SessionControls ([ordered]@{
        secureSignInSession = [ordered]@{ '@odata.type' = '#microsoft.graph.secureSignInSessionControl'; isEnabled = $true }
    }) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA309-M365-Browser-DefenderAppControl' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeCloudAppSecurity)) `
        -Applications (New-ApplicationsScope -IncludeApplications @('Office365')) `
        -ClientAppTypes @('browser')) `
    -SessionControls ([ordered]@{
        cloudAppSecurity = [ordered]@{ cloudAppSecurityType = 'monitorOnly'; isEnabled = $true }
    }) `
    -State disabled

$everyTime = [ordered]@{
    value = $null
    type = $null
    authenticationType = 'primaryAndSecondaryAuthentication'
    frequencyInterval = 'everyTime'
    isEnabled = $true
}

$policies += New-Policy -DisplayName 'MSP-CA400-Risk-SignIn-MediumHigh-Require-MFA' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeRisk, $ids.ExcludeMfa)) `
        -SignInRiskLevels @('medium', 'high')) `
    -GrantControls (New-Grant -Operator AND -AuthenticationStrength $mfaStrength) `
    -SessionControls ([ordered]@{ signInFrequency = $everyTime })

$policies += New-Policy -DisplayName 'MSP-CA401-Risk-User-High-Require-Remediation' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeRisk, $ids.ExcludeMfa)) `
        -UserRiskLevels @('high')) `
    -GrantControls (New-Grant -BuiltInControls @('riskRemediation')) `
    -SessionControls ([ordered]@{ signInFrequency = $everyTime })

$policies += New-Policy -DisplayName 'MSP-CA402-InsiderRisk-Elevated-Block' `
    -Conditions (New-Conditions -Users (New-UserScope Internal -ExcludeGroups @($allGroup, $ids.ExcludeInsiderRisk)) `
        -InsiderRiskLevels 'elevated') `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$allWorkloadIdentities = [ordered]@{
    includeServicePrincipals = @('ServicePrincipalsInMyTenant')
    excludeServicePrincipals = @()
}

$policies += New-Policy -DisplayName 'MSP-CA500-Workloads-HighRisk-Block' `
    -Conditions (New-Conditions -Applications (New-ApplicationsScope) `
        -ClientApplications $allWorkloadIdentities `
        -ServicePrincipalRiskLevels @('high')) `
    -GrantControls (New-Grant -BuiltInControls @('block'))

$policies += New-Policy -DisplayName 'MSP-CA501-Workloads-Block-Outside-TrustedLocations' `
    -Conditions (New-Conditions -Applications (New-ApplicationsScope) `
        -ClientApplications $allWorkloadIdentities `
        -Locations ([ordered]@{ includeLocations = @('All'); excludeLocations = @('AllTrusted') })) `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$noneUsers = [ordered]@{
    includeUsers = @('None')
    excludeUsers = @()
    includeGroups = @()
    excludeGroups = @()
    includeRoles = @()
    excludeRoles = @()
    includeGuestsOrExternalUsers = $null
    excludeGuestsOrExternalUsers = $null
}
$allAgentIdentities = [ordered]@{
    includeServicePrincipals = @()
    includeAgentIdServicePrincipals = @('All')
    excludeServicePrincipals = @()
}
$allAgentUsers = [ordered]@{
    includeAgentUsers = @('All')
    excludeAgentUsers = @()
    agentFilter = $null
}

$policies += New-Policy -DisplayName 'MSP-CA700-Agents-HighRiskIdentities-Block-Preview' `
    -Conditions (New-Conditions -Users $noneUsers `
        -ClientApplications $allAgentIdentities `
        -AgentIdRiskLevels 'high') `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA701-Agents-Block-AllAgentResources-Preview' `
    -Conditions (New-Conditions -Users $noneUsers `
        -Applications (New-ApplicationsScope -IncludeApplications @('AllAgentIdResources')) `
        -ClientApplications $allAgentIdentities) `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA702-AgentUsers-Require-CompliantDevice-Preview' `
    -Conditions (New-Conditions -Users $noneUsers `
        -Agents $allAgentUsers `
        -AgentContext ([ordered]@{
            includeAgentContexts = @('agentUserSessionsInitiatedFromEndpoints')
            excludeAgentContexts = @()
        })) `
    -GrantControls (New-Grant -BuiltInControls @('compliantDevice')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA703-AgentUsers-RiskyAgents-Block-Preview' `
    -Conditions (New-Conditions -Users $noneUsers `
        -Agents $allAgentUsers `
        -AgentIdRiskLevels 'medium,high') `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

$policies += New-Policy -DisplayName 'MSP-CA704-AgentUsers-Block-Outside-TrustedLocations-Preview' `
    -Conditions (New-Conditions -Users $noneUsers `
        -Applications (New-ApplicationsScope -IncludeApplications @('AllAgentIdResources')) `
        -Agents $allAgentUsers `
        -Locations ([ordered]@{ includeLocations = @('All'); excludeLocations = @('AllTrusted') })) `
    -GrantControls (New-Grant -BuiltInControls @('block')) `
    -State disabled

foreach ($policy in $policies) {
    $fileName = '{0}.json' -f ($policy.displayName -replace '[\\/:*?"<>|]', '-')
    $policy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $policyRoot $fileName) -Encoding utf8
}

foreach ($key in $ids.Keys) {
    $group = [ordered]@{
        id             = $ids[$key]
        organizationId = '%OrganizationId%'
        description    = $groupDescriptions[$key]
        displayName    = $groupNames[$key]
        groupTypes     = @()
        mail           = $null
        mailEnabled    = $false
        mailNickname   = ('mspca-{0}' -f $key.ToLowerInvariant())
        securityEnabled = $true
        visibility     = $null
    }
    $group | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $groupRoot "$($groupNames[$key]).json") -Encoding utf8
}

$migrationObjects = foreach ($key in $ids.Keys) {
    [ordered]@{
        DisplayName = $groupNames[$key]
        Id          = $ids[$key]
        Type        = 'Group'
    }
}

$migrationTable = [ordered]@{
    TenantId    = '11111111-1111-4111-8111-111111111111'
    Objects     = @($migrationObjects)
    Organization = 'MSP CIPP Conditional Access Blueprint'
}
$migrationTable | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $configRoot 'MigrationTable.json') -Encoding utf8

Write-Output "Generated $($policies.Count) Conditional Access policies and $($ids.Count) supporting groups in $RepositoryRoot"
