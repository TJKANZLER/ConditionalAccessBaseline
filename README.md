# Shoothill CIPP Conditional Access Baseline

A production-focused Microsoft Entra Conditional Access suite for repeatable deployment through CIPP. It contains **29 policies and 15 supporting groups**. Every policy starts in **Report-only**.

The suite has a complete Entra ID P1/Intune foundation and explicit production packages for Entra ID Protection P2, Workload ID Premium, Defender for Cloud Apps, and Purview Adaptive Protection.

Preview controls, conflicting alternatives, and inert tenant-specific scaffolding are not shipped. Licence- or capability-dependent controls remain available through clearly named packages with enforceable readiness gates.

## Activation packages

Package membership is defined in [Config/PolicyPackages.psd1](Config/PolicyPackages.psd1) and validated by the test suite.

| CIPP package | Policies | Activation gate |
|---|---:|---|
| `SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1` | 8 | MFA, registration, legacy auth, device code, and guest collaboration |
| `SHOOTHILL-CA-02-Privileged-Endpoint-and-App-Protection` | 12 | Admin methods/workstations, MAM, compliance, platforms, and token clients |
| `SHOOTHILL-CA-03-Trusted-Location-Guardrails-P1` | 3 | Trusted egress for admins, registration, and MFA-exempt accounts |
| `SHOOTHILL-CA-04-Identity-Protection-P2` | 2 | P2 licensing, SSPR, and risk-response operations |
| `SHOOTHILL-CA-05-Workload-Identity-Premium` | 2 | Workload ID Premium and service-principal location inventory |
| `SHOOTHILL-CA-06-Defender-and-Purview-Advanced` | 2 | Defender App Control plus Purview/HR/legal governance |

These are activation gates, not “core/optional/lab” labels. A package is promoted from Report-only only when its stated dependency is true for that tenant.

## Safety and portability decisions

- Emergency-access accounts are mapped through `MSP-CA-Exclude-All-EmergencyAccess`. Use two cloud-only accounts, monitor membership, and test them regularly.
- Microsoft Entra Connect identities holding the built-in **Directory Synchronization Accounts** role are excluded from all-user policy scopes.
- CA005 excludes Microsoft Entra Device Registration Service, preventing device-code blocking from breaking device registration.
- CIPP/GDAP `serviceProvider` identities are excluded from human and guest scopes.
- CA307 targets only supported native-client resources: Exchange Online, SharePoint Online, and Microsoft Teams Services. It never targets browsers or the whole Office 365 bundle.
- CA009, CA103, and CA600 use trusted locations for registration, administrators, and MFA-exempt user service accounts without imposing a closed-network model on ordinary remote users.
- Intune enrollment applications are excluded from device-compliance grants to avoid an enrollment deadlock.
- Temporary exception groups start empty. Every member needs an owner, reason, expiry, and review date.

## Repository layout

```text
Config/
  ConditionalAccess/   29 CIPP Conditional Access templates
  Groups/              15 portable security-group templates
  MigrationTable.json  stable template-ID mappings
  PolicyPackages.psd1  exact package membership and readiness gates
tools/
  New-CippCaBlueprint.ps1
  Test-CippCaBlueprint.ps1
```

`MigrationTable.json` is metadata and is not a selectable template.

## Import and deploy through CIPP

1. Add `TJKANZLER/ConditionalAccessBaseline` under **Tools → Community Repositories**.
2. Import `Config/Groups` before `Config/ConditionalAccess`.
3. Confirm CIPP applies `Config/MigrationTable.json` mappings and that every policy resolves its group references.
4. Keep all imported policies Report-only.
5. In **Available Conditional Access Templates**, assign the policies to the six package names in `Config/PolicyPackages.psd1`.
6. In a CIPP Standards template, add **Conditional Access Template**, select a package, choose Report-only, enable **Create Groups**, and disable Security Defaults only as part of the controlled CA rollout.
7. Review report-only sign-ins and complete the package readiness gate before changing policy state.

CIPP package tags are local CIPP metadata; GitHub template JSON cannot safely embed them in the Microsoft Graph policy payload. If the installed CIPP table does not show **Add to package**, use the manifest to select all policies for one package in the multi-select Conditional Access standard. Do not create one catch-all package.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the rollout runbook, [POLICY-MATRIX.md](POLICY-MATRIX.md) for exact coverage, and [POLICY-GUIDE.md](POLICY-GUIDE.md) for operator impact.

## Validate or regenerate

PowerShell 7 is recommended:

```powershell
./tools/New-CippCaBlueprint.ps1
./tools/Test-CippCaBlueprint.ps1
```

The validator checks counts, JSON parsing, Report-only state, group mappings, complete and non-overlapping package membership, directory-sync exclusion, Device Registration Service exclusion, token-protection scope, preview-field absence, and retired approved-client-app controls.

Review the baseline quarterly and whenever Microsoft changes Conditional Access behavior, licensing, supported token-protection resources, or CIPP's template schema.
