# Source mapping and design decisions

The suite maps security objectives to explicit production paths by licence and operating capability. It does not concatenate frameworks or retain inert examples.

| Objective | Primary guidance | Baseline decision |
|---|---|---|
| Legacy authentication | Microsoft Conditional Access templates | One all-human block policy |
| Internal MFA | Microsoft Zero Trust and CA planning | One all-resource authentication-strength policy |
| Directory synchronization | Microsoft hybrid-identity CA guidance and built-in roles | Exclude stable Directory Synchronization Accounts role ID from all-user scopes |
| Registration | Microsoft registration and TAP guidance | Separate security-info and device-registration policies with TAP as bootstrap |
| Device-code phishing | Microsoft authentication-flow guidance | Block device-code flow but exclude Entra Device Registration Service |
| Administrator access | Microsoft phishing-resistant admin policy | Stable privileged roles, phishing-resistant MFA, session hardening, compliant devices |
| Guest access | Microsoft guest CA guidance | MFA, session hardening, admin-portal block; exclude CIPP/GDAP service providers |
| Mobile access | Microsoft Intune App Protection and compliance guidance | App Protection for all mobile users plus full compliance for the managed-mobile include group |
| Desktop access | Microsoft Intune compliance guidance | Separate Windows, macOS, and Linux compliance policies |
| Unmanaged browser | Microsoft app-enforced restrictions | Restrict Exchange/SharePoint downloads on noncompliant devices |
| Token replay | Microsoft Token Protection guidance | Windows GA only; Exchange, SharePoint, and Microsoft Teams Services native clients |
| Network boundary | Microsoft location-based CA guidance | Trusted-location guardrails for admins, registration, and MFA-exempt service accounts without a global remote-user block |
| Identity risk | Microsoft Entra ID Protection | Separate sign-in and user-risk remediation policies in a P2 package |
| Workload identities | Microsoft workload Conditional Access | Risk and location controls in a Workload ID Premium package |
| Advanced sessions and risk | Microsoft Defender for Cloud Apps and Purview | Defender monitoring and insider-risk enforcement in an integration-gated package |
| Emergency access | Microsoft emergency-access guidance | Dedicated group excluded from every human policy |

## Deliberately excluded

| Removed area | Reason |
|---|---|
| Authentication transfer block | Preview authentication-flow control |
| Strict-location CAE | Preview session control |
| Apple token protection | Preview platform support |
| Agent identity policies | Emerging schema/licensing, not a Business Premium baseline |
| Hybrid-join alternative | Weaker parallel design that made deployment nondeterministic |
| Sensitive-action authentication context | Inert until tenant-specific PIM/application wiring exists |

Tenant-specific application IDs, country lists, IP ranges, Terms of Use documents, and permanent exceptions are not fabricated. They remain tenant configuration with explicit ownership.

## Primary references

- [Plan a Conditional Access deployment](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Conditional Access policy model](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies)
- [Authentication flows and Device Registration Service exclusion](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
- [Require phishing-resistant MFA for administrators](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa)
- [Block access by location](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location)
- [Block unknown or unsupported platforms](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported)
- [Require device compliance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance)
- [Configure identity risk policies](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
- [Token Protection deployment guide for Windows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/deployment-guide-token-protection-windows)
- [Microsoft Entra built-in role IDs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Conditional Access grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)
