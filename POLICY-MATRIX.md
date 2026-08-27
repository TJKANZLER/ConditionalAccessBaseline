# Conditional Access policy matrix

All 35 policies start Report-only. Packages 01–05 are the standard rollout; package 06 is an explicit-adoption option, not a standard promotion step.

| Package | Policies | Production coverage |
|---:|---|---|
| 01 Core Identity and External Access | CA001–CA006, CA009–CA010, CA012, CA103, CA200–CA202, CA600 | Authentication, registration, authentication-flow, internal/guest session, and trusted-location controls |
| 02 Privileged, Endpoint and App Protection | CA007, CA100–CA102, CA110–CA111, CA300–CA307 | Administrator/high-value identity, platform, MAM, browser, compliance, and token controls |
| 03 Identity Protection P2 | CA400–CA401 | Sign-in risk MFA and high user-risk remediation |
| 04 Workload Identity Premium | CA500–CA501 | Service-principal risk and location controls |
| 05 Defender and Purview | CA309, CA402 | Defender App Control monitoring and insider-risk enforcement |
| 06 Optional Country Restriction | CA011 | Explicit-adoption internal-user block outside a tenant-owned allowed-country location |

## Exact policies

| ID | Policy | Primary prerequisite |
|---|---|---|
| CA001 | Block legacy authentication | Legacy-client remediation |
| CA002 | Require MFA for internal users | MFA registration |
| CA003 | Require MFA for security-info registration | Temporary Access Pass |
| CA004 | Require MFA for device registration | Enrollment testing |
| CA005 | Block device-code flow | CLI and Teams-device inventory |
| CA006 | Block authentication transfer | Outlook/mobile transfer workflow inventory |
| CA007 | Block unknown or unsupported platforms | Supported-platform decision |
| CA009 | Block security-info registration outside trusted locations | Trusted registration paths |
| CA010 | Harden internal-user sessions at trusted locations | IP-based trusted named locations; 14-day sign-in frequency; user service accounts excluded |
| CA011 | Block internal users outside allowed countries | Explicit adoption, operator-owned named location, and user service accounts excluded |
| CA012 | Harden internal-user sessions outside trusted locations | 24-hour sign-in frequency; user service accounts excluded |
| CA100 | Require phishing-resistant MFA for admins | Resistant methods for 14 recommended roles plus declared privileged users |
| CA101 | Harden admin sessions | Separate admin identities |
| CA102 | Require compliant admin devices | Windows, macOS, iOS, Android, and Linux |
| CA103 | Block admin access outside trusted locations | Admin VPN/ZTNA egress |
| CA110 | Require phishing-resistant MFA for high-value users | Governed high-value group and resistant methods |
| CA111 | Require compliant devices for high-value browser access | Intune compliance and supported browsers |
| CA200 | Require guest MFA | Cross-tenant authentication testing |
| CA201 | Harden guest sessions | Guest communications |
| CA202 | Block ordinary guests from admin portals | Guest-admin allow group |
| CA300 | Require mobile App Protection | Office 365 plus audited protected resource/API IDs |
| CA301 | Restrict unmanaged-browser downloads | Exchange/SharePoint restrictions |
| CA302 | Require compliant Windows native clients | Windows compliance |
| CA303 | Require compliant macOS native clients | macOS compliance |
| CA304 | Require compliance for managed iOS users | Managed-mobile include group |
| CA305 | Require compliance for managed Android users | Managed-mobile include group |
| CA306 | Require compliant Linux devices | Supported Intune Linux fleet |
| CA307 | Require Windows token protection | Supported registered native clients; optional Windows App resources declared in extensions |
| CA309 | Monitor M365 browsers through Defender App Control | Defender for Cloud Apps |
| CA400 | Require MFA every time for medium/high sign-in risk | Entra ID P2 |
| CA401 | Require remediation for high user risk | Entra ID P2, SSPR/password writeback |
| CA402 | Block elevated insider risk | Purview Adaptive Protection; user service accounts excluded |
| CA500 | Block high-risk workload identities | Workload ID Premium |
| CA501 | Block workloads outside trusted locations | Workload ID Premium and known egress |
| CA600 | Block MFA-exempt user accounts outside trusted locations | Complete service-account inventory |

## Deliberate exclusions

Strict-location CAE, Apple token protection, browser token protection outside Microsoft's supported preview scenarios, and Agent ID controls remain excluded while preview. The hybrid-join and mobile alternatives were replaced by one declared production model. Sensitive-action authentication context was removed because it is inert until tenant-specific PIM/application wiring exists.
