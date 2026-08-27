# Operator policy guide

All policies begin Report-only. Packages 01–05 are the standard rollout. Package 06 is adopted only by an explicit tenant decision. Promote any adopted package only after its readiness gate in `Config/PolicyPackages.psd1` is satisfied.

## 01 — Core Identity and External Access P1

Deploy to every managed P1 tenant. It blocks legacy authentication, device-code phishing, and authentication transfer; requires internal and guest MFA; protects security-info/device registration; hardens internal and guest sessions; blocks ordinary guests from admin portals; and applies trusted-location guardrails to high-risk identities and workflows.

CA005 excludes Device Registration Service. CA006 uses a separate empty-by-default authentication-transfer exception group. TAP is the supported registration bootstrap. CIPP/GDAP service-provider identities are excluded from guest scope.

CA009 restricts security-info registration, CA103 restricts administrators, and CA600 constrains MFA-exempt user service accounts. CA009 and CA103 use separate, policy-specific location-exception groups. CA600 deliberately has no ordinary location bypass: add legitimate service-account egress to a trusted named location or migrate the account. Every admin, registration, VPN/ZTNA, service-account, and recovery egress must be marked trusted.

CA010 sets internal users to a 14-day sign-in frequency at IP-based trusted locations. CA012 applies a 24-hour frequency outside trusted locations. Both disable persistent browser sessions. The location scopes are mutually exclusive so the 24-hour policy cannot override the trusted-location interval. Treat both values as documented starting points and tune them only after reviewing user experience, network egress, application behavior, and report-only evidence. Temporary user-based service accounts are excluded and remain governed by CA600 while they are migrated to workload identities.

Main risks: unregistered users, legacy scanners/apps, CLI device-code workflows, Outlook/mobile authentication transfer, incomplete trusted-location data, session interruption, guest-admin access, and user-based service accounts.

## 02 — Privileged, Endpoint and App Protection

Targets Microsoft's current 14 recommended administrator roles plus `MSP-CA-Include-PrivilegedUsers`, the explicit extension for custom roles, administrative-unit-scoped roles, and other privileged users. CA100–CA103 give the combined scope phishing-resistant MFA, hardened sessions, trusted-location enforcement, and compliant-device enforcement on Windows, macOS, iOS, Android, and Linux. CA110–CA111 give the separately governed `MSP-CA-Include-HighValueUsers` group phishing-resistant MFA across all resources and compliant-device enforcement for browser access. This is intended for finance, payroll, executives, legal, and other identities whose data or authority makes a stolen session unusually damaging. It also provides the complete Intune access layer:

- unsupported-platform blocking;
- iOS/Android App Protection;
- unmanaged Exchange/SharePoint browser restrictions;
- Windows, macOS, Linux, and managed-mobile compliance;
- Windows token protection for Exchange, SharePoint, and Teams Services, with declared Windows App resource extensions.

Main risks: incomplete privileged/high-value include groups, admin lockout, unenrolled devices, unsupported apps or ChromeOS, stale clients, and missing platform compliance policies. Populate `MSP-CA-Include-PrivilegedUsers` from the tenant's privileged-role inventory, populate `MSP-CA-Include-HighValueUsers` from a documented business-impact review, and populate `MSP-CA-Include-ManagedMobileDeviceCompliance` only for users whose mobile devices are organization-managed.

CA300 remains Office 365-only in the default generated baseline. A MAM-capable third-party client accessing Office 365 is already evaluated by CA300; do not add its mobile client-app ID. To protect a separate resource or API, add an `ApplicationId` and `DisplayName` entry to `AdditionalMamProtectedResources` in `Config/PolicyExtensions.psd1`. Confirm the value identifies the target resource service principal, the client supports Intune App Protection, and a matching App Protection policy is assigned. Regenerate, validate, and review the CA300 diff before deployment. The empty default keeps CA300 unchanged and auditable.

CA307 covers Exchange Online, SharePoint Online, and Teams by default. If the tenant deploys Windows App, declare Azure Virtual Desktop, Windows 365, and Windows Cloud Login under `AdditionalWindowsTokenProtectionResources` in `Config/PolicyExtensions.psd1`, regenerate, and test supported and unsupported registration types before enforcement. Only the three documented optional IDs are accepted by the generator.

## 03 — Identity Protection P2

CA400 requires MFA every time for medium/high sign-in risk. CA401 combines high user-risk remediation with MFA authentication strength using `AND`, as required by the current Microsoft Graph contract. Confirm P2 licensing, SSPR, password writeback for hybrid users, and a tested risk-response process.

## 04 — Workload Identity Premium

CA500 blocks high-risk tenant-owned service principals. CA501 blocks them outside trusted locations. Inventory automation, CI/CD, Azure, third-party hosting, and disaster-recovery egress before enforcement.

## 05 — Defender and Purview Advanced

CA309 routes Microsoft 365 browser sessions through Defender App Control in monitor mode. CA402 blocks elevated Purview insider risk while excluding temporary user-based service accounts. Deploy only after integrations and licensing are live; CA402 also requires HR/legal governance and an incident path.

## 06 — Optional Country Restriction

CA011 blocks ordinary internal users outside the tenant-owned named location `SHOOTHILL-CA-Allowed-Countries-Operator-Defined`. It deliberately does not use `AllTrusted`, because allowed operating countries and trusted network egress are different security decisions.

This package is not part of the standard five-package promotion sequence. Adopt it only when the tenant has an approved geographic access model, creates and maintains the exact named location before package assignment, decides how unknown countries are handled, tests travel and recovery paths, and governs the dedicated `MSP-CA-Exclude-CountryRestriction` group.

Country detection uses the public IP address seen by Entra. Cloud VPN, secure web gateway, and proxy traffic is evaluated at its egress country, not the user's physical position. Test every relevant egress and do not treat this policy as proof of physical presence.

## Exception rule

Every exception needs an owner, approver, affected policy, reason, expiry, remediation action, and review date. Emergency access is not a general exception mechanism.
