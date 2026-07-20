# CIPP Conditional Access Blueprint

A comprehensive, deduplicated Microsoft Entra Conditional Access library for CIPP. It covers human identities, administrators, guests, managed and unmanaged devices, token theft, identity risk, insider risk, workload identities, network restrictions, session controls, authentication flows, and Agent 365 preview scenarios.

The library contains **36 policies and 14 supporting groups**. Completeness does not mean every policy should be enabled: 19 broadly deployable policies start in **Report-only**, while 17 dependency-heavy, alternative, restrictive, or preview policies start **Disabled**.

## Coverage

| Module | Policies | Initial posture |
|---|---:|---|
| Foundation, administrators, and guests | 16 | 11 Report-only; 5 Disabled advanced controls |
| Intune, unmanaged access, and token protection | 10 | 5 Report-only; 5 Disabled alternatives/integrations |
| User and insider risk | 3 | 2 Report-only; insider-risk policy Disabled |
| Workload identities | 2 | High-risk block Report-only; location restriction Disabled |
| Agent identities and agent users | 5 | Disabled because the surface is Preview |
| **Total** | **36** | **19 Report-only; 17 Disabled** |

See [POLICY-MATRIX.md](POLICY-MATRIX.md) for every policy, license tier, dependency, and overlap rule.

## Design principles

- Nothing starts On.
- Internal MFA excludes external identities; dedicated guest policies own guest authentication.
- Administrator phishing-resistant MFA intentionally layers over ordinary MFA.
- Mobile App Protection and mobile device-compliance templates are alternatives; the compliance alternatives remain Disabled.
- Device compliance protects desktop clients while app-enforced restrictions preserve controlled browser access from unmanaged devices.
- Risk policies use current self-remediation guidance instead of blanket user blocking.
- Token protection is limited to supported Exchange Online and SharePoint Online native-client scenarios.
- The retired **Require approved client app** control is never used.
- CIPP/GDAP `serviceProvider` identities are excluded from human and administrator personas and omitted from the guest persona.
- Country lists, selected sensitive applications, and Terms of Use IDs remain tenant data, not guessed universal values.

## Required preparation

1. Create and test at least two cloud-only emergency-access accounts.
2. Import the group templates and add only those accounts to `MSP-CA-Exclude-All-EmergencyAccess`.
3. Alert on every membership change to the emergency-access group.
4. Register users for MFA and administrators for passkeys/FIDO2, Windows Hello for Business, or certificate-based authentication.
5. Establish Temporary Access Pass procedures for passwordless bootstrapping.
6. Configure the CIPP service-provider exception for GDAP deployments.
7. Deploy compatible Intune compliance and App Protection policies before the managed-device tier.
8. Confirm licenses and prerequisites for P2, Purview, Defender for Cloud Apps, Workload ID, Global Secure Access, or Agent 365 modules.

## CIPP import

1. Publish this folder as a GitHub repository.
2. In CIPP, open **Tools → Community Repositories → Find a Repository** and add `owner/repository`.
3. Import the 14 files under `Config/Groups` first.
4. Import the 36 files under `Config/ConditionalAccess` next.
5. Do not select `Config/MigrationTable.json`; CIPP reads it while importing the CA templates.
6. Deploy only the appropriate module through **Tenant → Conditional Access → Policies → Deploy Template**.
7. Retain the template state, display-name replacement, group creation, and CIPP service-provider exception.
8. Follow [DEPLOYMENT.md](DEPLOYMENT.md) before moving any policy to On.

## Tenant-specific items that cannot be universalized

- Allowed or blocked countries and customer IP ranges.
- Approved guest applications and sensitive line-of-business application IDs.
- Terms of Use document IDs.
- Direct workload-identity exceptions for individual service principals.
- Authentication-context integration with PIM and applications.
- Global Secure Access signaling and compliant-network location configuration.
- Legacy user-based service accounts; migrate these to managed identities, workload federation, or service principals.

The library includes safe Disabled scaffolding where Graph supports portable selectors such as `AllTrusted` or `ServicePrincipalsInMyTenant`. It does not invent customer-specific identifiers.

## Validation

Regenerate and validate with PowerShell 7:

```powershell
./tools/New-CippCaBlueprint.ps1
./tools/Test-CippCaBlueprint.ps1
```

Validation checks JSON parsing, unique names, safe initial states, CIPP object identification, repository-safe JSON layout, migration mappings, guest/service-provider separation, risk-policy construction, optional-policy safety, token-protection scope, and retired controls.

## Sources

- [Microsoft Conditional Access deployment planning](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Microsoft Conditional Access policy model](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies)
- [Microsoft risk policy recommendations](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Microsoft token protection](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [Microsoft Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Microsoft Conditional Access for agents](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-target-agent-identities)
- [CIPP Conditional Access Baseline](https://github.com/j0eyv/ConditionalAccessBaseline)
- [ITProMentor SMB baseline](https://github.com/vanvfields/Microsoft-365/blob/master/mggraph-samples/Install-SmbConditionalAccessPolicies.ps1)
- [AlexFilipin Conditional Access as Code](https://github.com/AlexFilipin/ConditionalAccess)
- [Microsoft Zero Trust resources](https://github.com/microsoft/ConditionalAccessforZeroTrustResources)

Review the library at least quarterly and whenever Microsoft changes a Conditional Access control, platform status, licensing requirement, or Graph schema.
