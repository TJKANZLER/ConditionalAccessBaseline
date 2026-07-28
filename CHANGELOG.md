# Changelog

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
