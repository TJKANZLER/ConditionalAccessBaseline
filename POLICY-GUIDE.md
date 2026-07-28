# Operator policy guide

All policies begin Report-only. Promote a package only after its readiness gate in `Config/PolicyPackages.psd1` is satisfied.

## 01 — Core Identity and External Access P1

Deploy to every managed P1 tenant. It blocks legacy authentication and device-code phishing, requires internal and guest MFA, protects security-info/device registration, hardens guest sessions, and blocks ordinary guests from admin portals.

CA005 excludes Device Registration Service. TAP is the supported registration bootstrap. CIPP/GDAP service-provider identities are excluded from guest scope.

Main risks: unregistered users, legacy scanners/apps, CLI device-code workflows, guest-admin access, and user-based service accounts.

## 02 — Privileged, Endpoint and App Protection

Targets Microsoft's current 14 recommended administrator roles with phishing-resistant MFA, hardened sessions, and compliant workstations. It also provides the complete Intune access layer:

- unsupported-platform blocking;
- iOS/Android App Protection;
- unmanaged Exchange/SharePoint browser restrictions;
- Windows, macOS, Linux, and managed-mobile compliance;
- Windows token protection for Exchange, SharePoint, and Teams Services.

Main risks: admin lockout, unenrolled devices, unsupported apps or ChromeOS, stale clients, and missing platform compliance policies. Populate `MSP-CA-Include-ManagedMobileDeviceCompliance` only for users whose mobile devices are organization-managed.

## 03 — Trusted Location Guardrails P1

CA009 restricts security-info registration, CA103 restricts administrators, and CA600 constrains MFA-exempt user service accounts. This protects high-risk paths without imposing a closed-network model on ordinary remote users.

Every admin, registration, VPN/ZTNA, service-account, and recovery egress must be marked trusted.

## 04 — Identity Protection P2

CA400 requires MFA every time for medium/high sign-in risk. CA401 requires high user-risk remediation. Confirm P2 licensing, SSPR, password writeback for hybrid users, and a tested risk-response process.

## 05 — Workload Identity Premium

CA500 blocks high-risk tenant-owned service principals. CA501 blocks them outside trusted locations. Inventory automation, CI/CD, Azure, third-party hosting, and disaster-recovery egress before enforcement.

## 06 — Defender and Purview Advanced

CA309 routes Microsoft 365 browser sessions through Defender App Control in monitor mode. CA402 blocks elevated Purview insider risk. Deploy only after integrations and licensing are live; CA402 also requires HR/legal governance and an incident path.

## Exception rule

Every exception needs an owner, approver, affected policy, reason, expiry, remediation action, and review date. Emergency access is not a general exception mechanism.
