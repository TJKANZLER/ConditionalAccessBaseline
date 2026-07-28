# Operator policy guide

All policies begin Report-only. Promote a package only after its readiness gate in `Config/PolicyPackages.psd1` is satisfied.

## 01 — Identity Foundation P1

Deploy to every managed P1 tenant. It blocks legacy authentication and device-code phishing, requires MFA, and protects security-info/device registration. CA005 excludes Device Registration Service. TAP is the supported registration bootstrap.

Main risks: unregistered users, legacy scanners/apps, CLI device-code workflows, and user-based service accounts. Migrate service accounts; any temporary MFA exception is automatically constrained by CA600 when the location package is enabled.

## 02 — Privileged Access P1/Intune

Targets Microsoft's current 14 recommended administrator roles with phishing-resistant MFA, 12-hour reauthentication/no persistent browser, and compliant Windows/macOS workstations.

Main risk: admin lockout. Register resistant methods and validate two cloud-only emergency accounts before enforcement.

## 03 — External Collaboration P1

Requires guest MFA, hardens guest sessions, and blocks ordinary guests from Microsoft admin portals. CIPP/GDAP service-provider identities are excluded. Legitimate guest administrators belong in the explicit allow group.

## 04 — Endpoint and App Protection

- CA007 blocks platforms outside Windows, macOS, Linux, iOS, and Android.
- CA300 requires Intune App Protection for Microsoft 365 mobile apps.
- CA301 limits Exchange/SharePoint downloads from noncompliant browsers.
- CA302/303 require compliant Windows/macOS native clients.
- CA304/305 add full compliance for users in the managed-mobile include group.
- CA306 covers supported Intune Linux devices.
- CA307 binds supported Windows native-client tokens for Exchange, SharePoint, and Teams Services.

Main risks: unenrolled devices, unsupported applications, ChromeOS, stale clients, and missing platform compliance policies. Populate `MSP-CA-Include-ManagedMobileDeviceCompliance` only for users whose mobile devices are organization-managed.

## 05 — Trusted Location Guardrails

CA009 restricts security-info registration, CA103 restricts administrators, and CA600 constrains MFA-exempt user service accounts. This is the normal location package.

Every admin, registration, VPN/ZTNA, service-account, and recovery egress must be marked trusted. Remote ordinary users remain productive.

## 06 — Closed Network Perimeter

CA008 blocks every human sign-in outside `AllTrusted`. Use only for office-only or always-on VPN/ZTNA tenants. It is not part of a normal remote-work deployment and must be enforced as a standalone change.

## 07 — Identity Protection P2

CA400 requires MFA every time for medium/high sign-in risk. CA401 requires high user-risk remediation. Confirm P2 licensing, SSPR, password writeback for hybrid users, and a tested risk-response process.

## 08 — Workload Identity Premium

CA500 blocks high-risk tenant-owned service principals. CA501 blocks them outside trusted locations. Inventory automation, CI/CD, Azure, third-party hosting, and disaster-recovery egress before enforcement.

## 09 — Defender and Purview Advanced

CA309 routes Microsoft 365 browser sessions through Defender App Control in monitor mode. CA402 blocks elevated Purview insider risk. Deploy only after the integrations and licensing are live; CA402 also requires HR/legal governance and an incident path.

## Exception rule

Every exception needs an owner, approver, affected policy, reason, expiry, remediation action, and review date. Emergency access is not a general exception mechanism.
