# Shoothill CIPP Conditional Access Baseline

A production-focused Microsoft Entra Conditional Access suite for repeatable deployment through CIPP. It contains **35 policies and 20 supporting groups**. Every policy starts in **Report-only**.

The suite has five standard deployment packages covering the Entra ID P1/Intune foundation, Entra ID Protection P2, Workload ID Premium, Defender for Cloud Apps, and Purview Adaptive Protection. A sixth explicit-adoption package provides optional country restriction without changing the standard remote-user model.

Preview controls, conflicting alternatives, and inert tenant-specific scaffolding are not shipped. Licence- or capability-dependent controls remain available through clearly named packages with enforceable readiness gates.

## Activation packages

Package membership is defined in [Config/PolicyPackages.psd1](Config/PolicyPackages.psd1) and validated by the test suite.

| CIPP package | Track | Policies | Activation gate |
|---|---|---:|---|
| `SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1` | Standard | 14 | MFA, registration, authentication flows, internal/guest sessions, and trusted-location guardrails |
| `SHOOTHILL-CA-02-Privileged-Endpoint-and-App-Protection` | Standard | 14 | Admin/high-value methods and devices, MAM, compliance, platforms, and token clients |
| `SHOOTHILL-CA-03-Identity-Protection-P2` | Standard | 2 | P2 licensing, SSPR, and risk-response operations |
| `SHOOTHILL-CA-04-Workload-Identity-Premium` | Standard | 2 | Workload ID Premium and service-principal location inventory |
| `SHOOTHILL-CA-05-Defender-and-Purview-Advanced` | Standard | 2 | Defender App Control plus Purview/HR/legal governance |
| `SHOOTHILL-CA-06-Optional-Country-Restriction` | Explicit adoption | 1 | Tenant-owned allowed-country location, travel model, and exception governance |

Packages 01–05 form the standard rollout. Package 06 is genuinely optional and is never part of that promotion sequence unless a tenant explicitly adopts country restriction. Every adopted package remains Report-only until its readiness gate is satisfied.

## Safety and portability decisions

- Emergency-access accounts are mapped through `MSP-CA-Exclude-All-EmergencyAccess`. Use two cloud-only accounts, monitor membership, and test them regularly.
- Microsoft Entra Connect identities holding the built-in **Directory Synchronization Accounts** role are excluded from all-user policy scopes.
- CA005 excludes Microsoft Entra Device Registration Service, preventing device-code blocking from breaking device registration.
- CA006 blocks authentication transfer and has its own empty-by-default exception group, separate from device-code exceptions.
- CA010 gives internal users a 14-day sign-in frequency at IP-based trusted locations; CA012 applies 24 hours everywhere else. Both disable persistent browser sessions and exclude temporary user service accounts. Because the scopes are mutually exclusive, the shorter untrusted interval does not override the trusted-location interval.
- CA011 uses the dedicated `SHOOTHILL-CA-Allowed-Countries-Operator-Defined` location, not `AllTrusted`; CIPP must resolve that precreated tenant location before the optional package can deploy. It excludes temporary user service accounts, which remain constrained by CA600.
- CIPP/GDAP `serviceProvider` identities are excluded from human and guest scopes.
- CA100–CA103 target Microsoft's 14 recommended built-in roles plus the empty-by-default `MSP-CA-Include-PrivilegedUsers` group for custom, administrative-unit-scoped, and other privileged identities.
- CA110 requires phishing-resistant MFA and CA111 requires compliant browser devices for the empty-by-default `MSP-CA-Include-HighValueUsers` group. Populate it with finance, payroll, executive, legal, and other high-impact identities only after method and device readiness is proven.
- CA102 requires compliant devices for administrators on Windows, macOS, iOS, Android, and Linux.
- CA307 targets supported Windows native-client resources: Exchange Online, SharePoint Online, and Microsoft Teams Services. `PolicyExtensions.psd1` can add Azure Virtual Desktop, Windows 365, and Windows Cloud Login together where Windows App is deployed. It never targets browsers or the whole Office 365 bundle.
- CA009, CA103, and CA600 use trusted locations for registration, administrators, and MFA-exempt user service accounts without imposing a closed-network model on ordinary remote users.
- CA009 and CA103 have separate location-exception groups. CA600 has no ordinary bypass group, so an MFA exception cannot also escape its compensating location control.
- Intune enrollment applications are excluded from device-compliance grants to avoid an enrollment deadlock.
- CA300 remains scoped to Office 365 by default. `Config/PolicyExtensions.psd1` can append audited protected resource/API service-principal application IDs without changing the baseline default; these are target resources, not mobile client-app IDs.
- Temporary exception groups start empty. Every member needs an owner, reason, expiry, and review date.

## Repository layout

```text
Config/
  ConditionalAccess/   35 CIPP Conditional Access templates
  Groups/              20 portable security-group templates
  MigrationTable.json  stable template-ID mappings
  PolicyExtensions.psd1 validated MAM and Windows App resource extensions
  PolicyPackages.psd1  exact package membership and readiness gates
tools/
  New-CippCaBlueprint.ps1
  Test-CippCaBlueprint.ps1
```

`MigrationTable.json` is metadata and is not a selectable template.

## Import and deploy through CIPP

1. Add `TJKANZLER/ConditionalAccessBaseline` under **Tools → Community Repositories**.
2. Import the 20 templates in `Config/Groups` before the 35 templates in `Config/ConditionalAccess`.
3. Confirm CIPP applies `Config/MigrationTable.json` mappings and that every policy resolves its group references.
4. Keep all imported policies Report-only.
5. In **Available Conditional Access Templates**, assign policies to the six manifest package names. Use packages 01–05 for the standard rollout; assign package 06 only for tenants that explicitly adopt country restriction.
6. In a CIPP Standards template, add **Conditional Access Template**, select a package, choose Report-only, enable **Create Groups**, and disable Security Defaults only as part of the controlled CA rollout.
7. Review report-only sign-ins and complete the package readiness gate before changing policy state.

CIPP package tags are local CIPP metadata; GitHub template JSON cannot safely embed them in the Microsoft Graph policy payload. If the installed CIPP table does not show **Add to package**, use the manifest to select all policies for one package in the multi-select Conditional Access standard. Do not create one catch-all package.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the rollout runbook, [TEST-PLAN.md](TEST-PLAN.md) for repeatable acceptance evidence, [POLICY-MATRIX.md](POLICY-MATRIX.md) for exact coverage, [POLICY-GUIDE.md](POLICY-GUIDE.md) for operator impact, and [BENCHMARK.md](BENCHMARK.md) for the dated peer comparison and remaining gaps.

## Validate or regenerate

PowerShell 7 is recommended:

```powershell
./tools/New-CippCaBlueprint.ps1
./tools/Test-CippCaBlueprint.ps1
```

The validator checks counts, JSON parsing, Report-only state, group and named-location mappings, dedicated exception ownership, service-account scoping, complete and non-overlapping package membership, the standard/explicit-adoption boundary, internal session controls, privileged/high-value-user coverage, all supported admin platforms, CA300 protected-resource extensions, CA401's required remediation/authentication-strength relationship, directory-sync exclusion, Device Registration Service exclusion, authentication-transfer coverage, token-protection scope, preview-field absence, and retired approved-client-app controls.

Review the baseline quarterly and whenever Microsoft changes Conditional Access behavior, licensing, supported token-protection resources, or CIPP's template schema.
