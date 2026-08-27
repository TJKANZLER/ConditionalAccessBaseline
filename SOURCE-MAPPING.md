# Source mapping and design decisions

The suite maps security objectives to explicit production paths by licence and operating capability. It does not concatenate frameworks or retain inert examples.

| Objective | Primary guidance | Baseline decision |
|---|---|---|
| Legacy authentication | Microsoft Conditional Access templates | One all-human block policy |
| Internal MFA | Microsoft Zero Trust and CA planning | One all-resource authentication-strength policy |
| Directory synchronization | Microsoft hybrid-identity CA guidance and built-in roles | Exclude stable Directory Synchronization Accounts role ID from all-user scopes |
| Registration | Microsoft registration and TAP guidance | Separate security-info and device-registration policies with TAP as bootstrap |
| Device-code phishing | Microsoft authentication-flow guidance | Block device-code flow but exclude Entra Device Registration Service |
| Authentication transfer | Microsoft authentication-flow guidance | Block authentication transfer with a dedicated, empty-by-default exception group |
| Internal user sessions | Microsoft Conditional Access session-control and location guidance | Mutually exclusive 14-day trusted-location and 24-hour untrusted-location sign-in frequencies, with nonpersistent browser sessions in both scopes |
| Administrator access | Microsoft phishing-resistant admin policy | Stable recommended roles plus a declared privileged-user group, phishing-resistant MFA, session hardening, trusted egress, and compliant devices on all supported platforms |
| High-value identities | Microsoft authentication-strength and device-compliance guidance | Declared internal finance/high-impact group, phishing-resistant MFA across all resources, and compliant-device enforcement for browsers |
| Guest access | Microsoft guest CA guidance | MFA, session hardening, admin-portal block; exclude CIPP/GDAP service providers |
| Mobile access | Microsoft Intune App Protection and compliance guidance | App Protection for Office 365 by default, an audited target-resource/API extension where separate resources need protection, plus full compliance for the managed-mobile include group |
| Desktop access | Microsoft Intune compliance guidance | Separate Windows, macOS, and Linux compliance policies |
| Unmanaged browser | Microsoft app-enforced restrictions | Restrict Exchange/SharePoint downloads on noncompliant devices |
| Token replay | Microsoft Token Protection guidance | Windows GA; Exchange, SharePoint, and Microsoft Teams Services by default, with validated Azure Virtual Desktop, Windows 365, and Windows Cloud Login extensions where Windows App is deployed |
| Network boundary | Microsoft location-based CA guidance | Separate admin and registration location exceptions, non-bypassable trusted-location compensation for MFA-exempt accounts, and an explicit-adoption country restriction evaluated from public egress IP |
| Identity risk | Microsoft Entra ID Protection and Microsoft Graph grant-control contract | Separate sign-in-risk and user-risk policies in a P2 package; risk remediation is combined with MFA authentication strength using `AND` |
| Workload identities | Microsoft workload Conditional Access | Risk and location controls in a Workload ID Premium package |
| Advanced sessions and risk | Microsoft Defender for Cloud Apps and Purview | Defender monitoring and insider-risk enforcement in an integration-gated package |
| Emergency access | Microsoft emergency-access guidance | Dedicated group excluded from every human policy |

## Deliberately excluded

| Removed area | Reason |
|---|---|
| Strict-location CAE | Preview session control |
| Apple token protection | Preview platform support |
| Agent identity policies | Emerging schema/licensing, not a Business Premium baseline |
| Hybrid-join alternative | Weaker parallel design that made deployment nondeterministic |
| Sensitive-action authentication context | Inert until tenant-specific PIM/application wiring exists |

Tenant-specific resource IDs, country lists, IP ranges, Terms of Use documents, and permanent exceptions are not fabricated. Additional MAM-protected target resources and documented Windows App token-protection resources enter through `Config/PolicyExtensions.psd1`; mobile client-app IDs do not. CA011 resolves the separately maintained `SHOOTHILL-CA-Allowed-Countries-Operator-Defined` tenant location by display name. The underlying values remain tenant configuration with explicit ownership.

## Primary references

- [Plan a Conditional Access deployment](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Conditional Access policy model](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies)
- [Authentication flows and Device Registration Service exclusion](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
- [Block device code and authentication transfer flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)
- [Require phishing-resistant MFA for administrators](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa)
- [Conditional Access authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [Block access by location](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location)
- [Block unknown or unsupported platforms](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported)
- [Require device compliance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance)
- [Configure identity risk policies](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Token Protection deployment guide for Windows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/deployment-guide-token-protection-windows)
- [Microsoft Entra built-in role IDs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Conditional Access grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)
- [Microsoft Graph Conditional Access grant controls](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0)
- [Conditional Access session controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-session)
- [Protected actions in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/protected-actions-overview)
- [CIPP named locations](https://docs.cipp.app/user-documentation/tenant/conditional/list-named-locations/add)
- [CIPP Standards and drift management](https://docs.cipp.app/user-documentation/tenant/standards)
