# Policy matrix

## Foundation, administrators, and guests

| Policy | Purpose | Initial state | Dependency or decision |
|---|---|---|---|
| MSP-CA001 | Block legacy authentication | Report-only | Legacy-usage inventory |
| MSP-CA002 | Require MFA for internal users | Report-only | MFA registration |
| MSP-CA003 | Protect security-info registration | Report-only | Temporary Access Pass process |
| MSP-CA004 | Protect device registration and join | Report-only | Enrollment testing |
| MSP-CA005 | Block device-code flow | Report-only | CLI/device inventory |
| MSP-CA006 | Block authentication transfer | Report-only | Mobile onboarding testing |
| MSP-CA007 | Block unknown device platforms | Disabled | User-agent condition is mutable; approve supported-platform policy first; exception group is `MSP-CA-Exclude-UnknownPlatforms`, not the compliance-exception group |
| MSP-CA008 | Block outside trusted locations | Disabled | Define and verify every trusted egress path |
| MSP-CA100 | Require phishing-resistant MFA for privileged roles | Report-only | Passkeys, WHfB, FIDO2, or CBA |
| MSP-CA101 | Harden administrator sessions | Report-only | Separate administrator identities |
| MSP-CA102 | Require compliant administrator devices | Disabled | Intune-managed privileged workstations |
| MSP-CA103 | Use strict-location CAE for administrators | Disabled | Resilient network design and outage testing |
| MSP-CA104 | Reauthenticate sensitive actions | Disabled | Connect `MSP Sensitive Action` authentication context to PIM/apps |
| MSP-CA200 | Require MFA for guests | Report-only | Cross-tenant trust review |
| MSP-CA201 | Harden guest sessions | Report-only | Guest user-experience review |
| MSP-CA202 | Block ordinary guests from admin portals | Report-only | Approved B2B-admin exception group |

## Intune, sessions, and token protection

| Policy | Purpose | Initial state | Dependency or decision |
|---|---|---|---|
| MSP-CA300 | Require App Protection for Microsoft 365 mobile apps | Report-only | Intune MAM policies |
| MSP-CA301 | Restrict Exchange/SharePoint downloads on unmanaged browsers | Report-only | SharePoint and Exchange configuration; exception group is `MSP-CA-Exclude-UnmanagedBrowser`, not the compliance-exception group |
| MSP-CA302 | Require compliant Windows desktop clients | Report-only | Windows compliance |
| MSP-CA303 | Require compliant macOS desktop clients | Report-only | macOS compliance and Apple SSO configuration |
| MSP-CA304 | Require compliant iOS devices | Disabled | Alternative to CA300, not an automatic companion |
| MSP-CA305 | Require compliant Android devices | Disabled | Alternative to CA300, not an automatic companion |
| MSP-CA306 | Require compliant Linux devices | Disabled | Supported Intune Linux and application inventory |
| MSP-CA307 | Require token protection on Windows native clients | Report-only | Supported Exchange/SharePoint clients and registered devices |
| MSP-CA310 | Require compliant OR hybrid-joined Windows desktop clients | Disabled | Alternative to CA302 for hybrid Azure AD join environments not fully on Intune compliance; not an automatic companion |
| MSP-CA308 | Require token protection on Apple native clients | Disabled | Preview; MDM and Enterprise SSO/Platform SSO |
| MSP-CA309 | Monitor Microsoft 365 browser sessions with Defender App Control | Disabled | Defender for Cloud Apps integration |

## Risk, workloads, and agents

| Policy | Purpose | Initial state | License or dependency |
|---|---|---|---|
| MSP-CA400 | Medium/high sign-in risk requires MFA every time | Report-only | Entra ID P2 or Entra Suite; excludes the same temporary service-account group as CA002 |
| MSP-CA401 | High user risk requires risk remediation | Report-only | Entra ID P2 or Entra Suite; `riskRemediation` alone (no stacked authentication strength); excludes the same temporary service-account group as CA002 |
| MSP-CA402 | Block elevated insider risk | Disabled | Entra ID P2 plus Purview Adaptive Protection |
| MSP-CA500 | Block high-risk workload identities | Report-only | Workload Identities Premium; inspect service-principal logs |
| MSP-CA501 | Block workload identities outside trusted locations | Disabled | Workload Identities Premium and verified trusted locations |
| MSP-CA700 | Block high-risk agent identities | Disabled | Preview and applicable agent-risk licensing |
| MSP-CA701 | Block all agent identities from agent resources | Disabled | Preview deny-by-default option; define permitted agents first |
| MSP-CA702 | Require compliant devices for endpoint-hosted agent users | Disabled | Preview, Intune, and endpoint execution context |
| MSP-CA703 | Block risky agent-user sessions | Disabled | Preview and agent-risk signals |
| MSP-CA704 | Restrict agent users to trusted locations | Disabled | Preview and verified trusted network locations |

## Overlap rules

- CA100 intentionally layers over CA002; phishing-resistant MFA satisfies the ordinary MFA requirement.
- CA304 and CA305 are alternatives to the mobile App Protection approach in CA300. Do not enable both models without intentionally requiring both controls.
- CA310 is an alternative to CA302 for hybrid Azure AD join environments. Do not enable both without intent; CA302 is the default primary and CA310 stays Disabled unless the customer relies on hybrid join instead of, or alongside, Intune compliance.
- CA102 adds a privileged-workstation requirement over CA302/CA303/CA310 and should be enabled only when all administrator platforms are managed.
- CA008 is a global location boundary. If enabled, narrower location policies can become redundant and should be reviewed.
- Agent and workload policies target distinct non-human identity surfaces and do not replace user policies.
- `MSP-CA-Exclude-DeviceCompliance` is shared only by the compliant-device policies (CA102, CA302-306, CA310); CA007 (unknown platforms) and CA301 (unmanaged-browser downloads) use their own dedicated exception groups (`MSP-CA-Exclude-UnknownPlatforms`, `MSP-CA-Exclude-UnmanagedBrowser`) so one exception can't silently bypass an unrelated control.
- `MSP-CA-Exclude-MFA-Temporary` is excluded from CA002, CA400, and CA401 together, so a legacy service account exempted from baseline MFA isn't still challenged for MFA by the risk-based policies it can't complete.
