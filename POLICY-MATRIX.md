# Conditional Access policy matrix

All 30 policies start Report-only. Package prerequisites determine applicability; there are no lab templates or disabled placeholders.

| Package | Policies | Production coverage |
|---:|---|---|
| 01 Identity Foundation P1 | CA001–CA005 | Legacy authentication, all-user MFA, security-info registration, device registration, device-code flow |
| 02 Privileged Access | CA100–CA102 | Phishing-resistant admin MFA, session hardening, compliant admin devices |
| 03 External Collaboration | CA200–CA202 | Guest MFA, guest session hardening, guest admin-portal block |
| 04 Endpoint and App Protection | CA007, CA300–CA307 | Unsupported platforms, mobile MAM, unmanaged browsers, Windows/macOS/iOS/Android/Linux compliance, Windows token protection |
| 05 Trusted Location Guardrails | CA009, CA103, CA600 | Registration, administrator, and MFA-exempt service-account locations |
| 06 Closed Network Perimeter | CA008 | All-human trusted-location boundary |
| 07 Identity Protection P2 | CA400–CA401 | Sign-in risk MFA and high user-risk remediation |
| 08 Workload Identity Premium | CA500–CA501 | Service-principal risk and location controls |
| 09 Defender and Purview | CA309, CA402 | Defender App Control monitoring and insider-risk enforcement |

## Exact policies

| ID | Policy | Primary prerequisite |
|---|---|---|
| CA001 | Block legacy authentication | Legacy-client remediation |
| CA002 | Require MFA for internal users | MFA registration |
| CA003 | Require MFA for security-info registration | Temporary Access Pass |
| CA004 | Require MFA for device registration | Enrollment testing |
| CA005 | Block device-code flow | CLI and Teams-device inventory |
| CA007 | Block unknown or unsupported platforms | Supported-platform decision |
| CA008 | Block all-human access outside trusted locations | Closed-network operating model |
| CA009 | Block security-info registration outside trusted locations | Trusted registration paths |
| CA100 | Require phishing-resistant MFA for admins | Resistant methods for 14 recommended roles |
| CA101 | Harden admin sessions | Separate admin identities |
| CA102 | Require compliant admin devices | Managed privileged workstations |
| CA103 | Block admin access outside trusted locations | Admin VPN/ZTNA egress |
| CA200 | Require guest MFA | Cross-tenant authentication testing |
| CA201 | Harden guest sessions | Guest communications |
| CA202 | Block ordinary guests from admin portals | Guest-admin allow group |
| CA300 | Require mobile App Protection | iOS/Android Intune MAM |
| CA301 | Restrict unmanaged-browser downloads | Exchange/SharePoint restrictions |
| CA302 | Require compliant Windows native clients | Windows compliance |
| CA303 | Require compliant macOS native clients | macOS compliance |
| CA304 | Require compliance for managed iOS users | Managed-mobile include group |
| CA305 | Require compliance for managed Android users | Managed-mobile include group |
| CA306 | Require compliant Linux devices | Supported Intune Linux fleet |
| CA307 | Require Windows token protection | Supported registered native clients |
| CA309 | Monitor M365 browsers through Defender App Control | Defender for Cloud Apps |
| CA400 | Require MFA every time for medium/high sign-in risk | Entra ID P2 |
| CA401 | Require remediation for high user risk | Entra ID P2, SSPR/password writeback |
| CA402 | Block elevated insider risk | Purview Adaptive Protection |
| CA500 | Block high-risk workload identities | Workload ID Premium |
| CA501 | Block workloads outside trusted locations | Workload ID Premium and known egress |
| CA600 | Block MFA-exempt user accounts outside trusted locations | Complete service-account inventory |

## Deliberate exclusions

Authentication transfer blocking, strict-location CAE, Apple token protection, and Agent ID controls remain excluded while preview. The hybrid-join and mobile alternatives were replaced by one declared production model. Sensitive-action authentication context was removed because it is inert until tenant-specific PIM/application wiring exists.
