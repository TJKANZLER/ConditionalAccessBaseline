@{
    SchemaVersion = '4.1'
    Packages = @(
        @{
            Name = 'SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1'
            Purpose = 'Universal identity, registration, authentication-flow, guest, and trusted-location controls for every managed Entra ID P1 tenant.'
            ReadinessGate = 'Emergency access, MFA registration, TAP onboarding, legacy-auth/device-code/authentication-transfer inventory, representative B2B collaboration, and every admin/registration/service-account egress are complete.'
            Policies = @(
                'MSP-CA001-Global-Block-LegacyAuthentication'
                'MSP-CA002-Global-Require-MFA'
                'MSP-CA003-Global-Protect-SecurityInfoRegistration'
                'MSP-CA004-Global-Protect-DeviceRegistration'
                'MSP-CA005-Global-Block-DeviceCodeFlow'
                'MSP-CA006-Global-Block-AuthenticationTransfer'
                'MSP-CA200-Guests-Require-MFA'
                'MSP-CA201-Guests-Session-Hardening'
                'MSP-CA202-Guests-Block-AdminPortals'
                'MSP-CA009-Registration-Block-Outside-TrustedLocations'
                'MSP-CA103-Admins-Block-Outside-TrustedLocations'
                'MSP-CA600-MFAExceptionAccounts-Block-Outside-TrustedLocations'
            )
        }
        @{
            Name = 'SHOOTHILL-CA-02-Privileged-Endpoint-and-App-Protection'
            Purpose = 'Administrator, supported-platform, Intune MAM/compliance, unmanaged-browser, and Windows token controls.'
            ReadinessGate = 'Admins have phishing-resistant methods and compliant workstations; every targeted Intune platform, MAM flow, managed-mobile assignment, and supported client is verified.'
            Policies = @(
                'MSP-CA100-Admins-Require-PhishingResistantMFA'
                'MSP-CA101-Admins-Session-Hardening'
                'MSP-CA102-Admins-Require-CompliantDevice'
                'MSP-CA007-Global-Block-UnknownOrUnsupportedPlatforms'
                'MSP-CA300-Mobile-Require-AppProtection'
                'MSP-CA301-UnmanagedBrowser-Restrict-Downloads'
                'MSP-CA302-Windows-Require-CompliantDevice'
                'MSP-CA303-macOS-Require-CompliantDevice'
                'MSP-CA304-Managed-iOS-Require-CompliantDevice'
                'MSP-CA305-Managed-Android-Require-CompliantDevice'
                'MSP-CA306-Linux-Require-CompliantDevice'
                'MSP-CA307-Windows-Require-TokenProtection'
            )
        }
        @{
            Name = 'SHOOTHILL-CA-03-Identity-Protection-P2'
            Purpose = 'Automated sign-in and user-risk remediation using Entra ID Protection.'
            ReadinessGate = 'Every in-scope user has Entra ID P2 or Entra Suite, SSPR writeback works where required, and the risk help-desk process is tested.'
            Policies = @(
                'MSP-CA400-Risk-SignIn-MediumHigh-Require-MFA'
                'MSP-CA401-Risk-User-High-Require-Remediation'
            )
        }
        @{
            Name = 'SHOOTHILL-CA-04-Workload-Identity-Premium'
            Purpose = 'Risk and network controls for tenant-owned service principals.'
            ReadinessGate = 'Workload ID Premium is licensed and every service-principal execution location is inventoried.'
            Policies = @(
                'MSP-CA500-Workloads-HighRisk-Block'
                'MSP-CA501-Workloads-Block-Outside-TrustedLocations'
            )
        }
        @{
            Name = 'SHOOTHILL-CA-05-Defender-and-Purview-Advanced'
            Purpose = 'Defender for Cloud Apps session monitoring and Purview Adaptive Protection enforcement.'
            ReadinessGate = 'Defender App Control is integrated; Entra ID P2 and Purview Adaptive Protection are licensed; HR/legal governance and incident handling are approved and tested.'
            Policies = @(
                'MSP-CA309-M365-Browser-Monitor-With-DefenderAppControl'
                'MSP-CA402-InsiderRisk-Elevated-Block'
            )
        }
    )
}
