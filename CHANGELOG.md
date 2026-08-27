# Changelog

## 3.8.0 — 2026-08-27

- Corrected CA012's 24-hour sign-in frequency to the Graph-valid equivalent of one day.
- Added CIPP companion metadata that resolves CA011 to a pre-created country named location without defining or overwriting the tenant's approved countries.
- Added regression checks for both live-deployment failures found during the first Lloyds Standards run.

## 3.7.0 — 2026-08-27

- Moved CA011 country restriction into the standard Core P1 package so every tenant receives it in Report-only by default.
- Removed the separate optional country-restriction package while retaining tenant-owned country lists, travel exceptions, and enforcement readiness gates.
- Corrected the deployment runbook group-template count from 19 to 20.

## 3.6.0 — 2026-08-27

- Corrected CA401 to combine `riskRemediation` with the built-in MFA authentication strength using `AND`, and added regression checks for the current Microsoft Graph requirements.
- Added CA110 and CA111 plus `MSP-CA-Include-HighValueUsers`, giving finance and other high-impact users phishing-resistant MFA across all resources and compliant-device enforcement for browser access.
- Extended CA307 configuration to accept only the documented Azure Virtual Desktop, Windows 365, and Windows Cloud Login resource IDs when Windows App is deployed.
- Made regeneration prune retired `MSP-CA*.json` policy and group artifacts from the dedicated generated directories.
- Expanded the suite to 35 Report-only policies and 20 supporting groups, with updated package readiness and acceptance tests.

## 3.5.0 — 2026-08-27

- Split ordinary internal-user session enforcement into mutually exclusive location scopes: CA010 now applies a 14-day sign-in frequency at trusted locations, while new CA012 retains 24 hours outside trusted locations.
- Kept persistent browser sessions disabled in both policies and retained the emergency-access and temporary MFA-exception exclusions.
- Expanded the suite to 33 Report-only policies and added validation that the trusted and untrusted scopes cannot overlap.

## 3.4.0 — 2026-07-29

- Extended CA102 compliant-device enforcement from Windows/macOS to Windows, macOS, iOS, Android, and Linux.
- Added `MSP-CA-Include-PrivilegedUsers` so custom-role, administrative-unit-scoped, and other explicitly declared privileged identities receive CA100–CA103 alongside Microsoft's 14 recommended built-in roles.
- Replaced the shared `MSP-CA-Exclude-LocationPolicies` group with dedicated CA009 registration and CA103 administrator location exceptions; CA600 now has no ordinary bypass, preserving its compensating control for MFA-exempt user accounts.
- Excluded temporary user-based service accounts from CA010 session hardening, CA011 country restriction, and CA402 insider-risk enforcement while retaining CA600 trusted-egress enforcement.
- Replaced the ambiguous CA300 client-app extension with `AdditionalMamProtectedResources`, requiring a display name and target resource/API service-principal application ID. The default CA300 output remains unchanged.
- Expanded the suite to 19 supporting groups while retaining 32 Report-only policies, five standard packages, and one explicit-adoption package.
- Added validation for dedicated location exceptions, non-bypassable CA600 scope, declared privileged users, every supported admin platform, service-account exclusions, CA300 resource metadata, and exact new schema versions.
- Documented public-egress IP behavior for country restrictions, including cloud VPN, proxy, secure web gateway, and mobile-carrier paths.

## 3.3.0 — 2026-07-28

- Added CA010 to apply a 24-hour sign-in frequency and nonpersistent browser sessions to ordinary internal users; documented the value as a tenant-tunable starting point.
- Added CA011 and `SHOOTHILL-CA-06-Optional-Country-Restriction` as an explicit-adoption path outside the standard five-package rollout.
- Gave CA011 its own travel/exception group and the resolvable `SHOOTHILL-CA-Allowed-Countries-Operator-Defined` placeholder instead of reusing `AllTrusted`.
- Added `Config/PolicyExtensions.psd1` so audited third-party Intune-MAM-enlightened application IDs can extend CA300 while its default Office 365 output remains unchanged.
- Expanded the generated suite to 32 Report-only policies, 17 supporting groups, five standard packages, and one optional package.
- Extended validation for internal session settings, tenant-owned location references, optional-package isolation, CA300 application extensions, complete package membership, and non-overlap.

## 3.2.0 — 2026-07-28

- Merged the three trusted-location guardrails into the Core P1 activation package and reduced the suite from six packages to five without removing location protection.
- Added CA006 to block authentication transfer, now part of Microsoft's advanced-protection rollout guidance, with a dedicated empty-by-default exception group.
- Expanded the generated suite to 30 Report-only policies and 16 supporting groups.
- Added validator coverage for the authentication-transfer policy, its block control, and its dedicated exception mapping.
- Added a peer-baseline comparison and continuous validation workflow.
- Added a package-by-package acceptance test matrix and explicit `AllTrusted` named-location inventory controls.

## 3.1.0 — 2026-07-28

- Consolidated nine narrowly split packages into six operational packages aligned to real deployment and licence boundaries.
- Merged identity foundation with external collaboration, and privileged access with endpoint/app protection.
- Removed the one-policy closed-network perimeter package and CA008; retained safer location guardrails for administrators, registration, and MFA-exempt service accounts.
- Updated package validation and all operator documentation for the 29-policy, six-package suite.

## 3.0.0 — 2026-07-28

- Rebuilt the library as a deterministic, licence-aware production suite: 30 Report-only policies and 15 supporting groups.
- Added nine descriptive, non-overlapping capability packages with machine-validated membership and readiness gates.
- Retained trusted-location enforcement as a separately controlled package rather than an optional/lab template.
- Removed preview controls, P2/Purview/Defender for Cloud Apps/Workload ID Premium policies, inert scaffolding, and mutually exclusive device alternatives.
- Excluded the stable Directory Synchronization Accounts role from all-user scopes.
- Excluded Microsoft Entra Device Registration Service from CA005 so device-code blocking does not break device registration.
- Added Microsoft Teams Services to the supported Windows token-protection resource scope.
- Aligned CA100, CA101, and CA102 to Microsoft's current 14-role administrator protection set instead of carrying unrelated framework-specific roles.
- Restored generally available production coverage for unsupported platforms, managed mobile and Linux compliance, Entra ID Protection risk remediation, workload identities, Defender App Control, and Purview insider risk.
- Added trusted-location guardrails for administrator access, security-info registration, and MFA-exempt user service accounts.
- Changed guest MFA to the interoperable MFA grant instead of authentication strength so email OTP, SAML/WS-Fed, and Google-federated guests remain supported.
- Removed preview-only condition fields from generated production payloads.
- Expanded validation to enforce Report-only state, complete package coverage, role/app exclusions, supported token resources, and absence of preview schema.
- Rewrote deployment, operator, troubleshooting, and source-mapping documentation around repeatable CIPP package rollout.

## 2.1.0 — 2026-07-20

- Gave CA007 (unknown-platform block) and CA301 (unmanaged-browser download restriction) their own dedicated exception groups (`MSP-CA-Exclude-UnknownPlatforms`, `MSP-CA-Exclude-UnmanagedBrowser`) instead of reusing `MSP-CA-Exclude-DeviceCompliance`, so a device-compliance exception can no longer silently bypass an unrelated control.
- Added `MSP-CA-Exclude-MFA-Temporary` to CA400 and CA401's exclusions so legacy service accounts exempted from baseline MFA (CA002) aren't still challenged for MFA by the risk-based policies.
- Simplified CA401's grant control to `riskRemediation` alone, removing a stacked `authenticationStrength` requirement that duplicated what risk remediation already enforces and was unverified against the current Graph schema.
- Added MSP-CA310, a Disabled alternative to CA302 that accepts `compliantDevice` OR `domainJoinedDevice`, covering hybrid-Azure-AD-joined Windows environments that aren't fully on Intune compliance.
- Expanded supporting groups from 14 to 16 and Conditional Access policies from 36 to 37 (19 Report-only, 18 Disabled).
- Extended `Test-CippCaBlueprint.ps1` to assert the new group scoping and the MFA-Temporary/risk-policy relationship so these regressions can't reappear silently.

## 2.0.0 — 2026-07-20

- Expanded the library from 17 to 36 Conditional Access policies.
- Added trusted-location, unknown-platform, administrator device, strict CAE, and sensitive-action modules.
- Added Windows and Apple token-protection templates and Defender for Cloud Apps session control.
- Added optional mobile and Linux compliance policies.
- Added insider-risk and Workload ID policies.
- Added five Disabled Agent 365 Preview policies.
- Expanded supporting groups from 9 to 14.
- Split safe initial posture into 19 Report-only and 17 Disabled policies.

## 1.0.0 — 2026-07-20

- Created a 17-policy, non-overlapping Conditional Access blueprint.
- Added Entra ID P1, Intune, and Entra ID P2 tiers.
- Added CIPP-compatible group templates and migration mappings.
- Used phishing-resistant MFA for privileged roles.
- Used risk remediation for high user risk.
- Replaced approved-client-app requirements with App Protection.
- Defaulted every policy to Report-only.
- Excluded CIPP/GDAP service-provider identities from the guest persona.
- Added a phased CIPP deployment and rollback runbook.
- Added validation for CIPP template identification and repository-safe JSON layout.
