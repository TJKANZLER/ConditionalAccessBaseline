# Troubleshooting

## CIPP deployment returns “Empty Payload. JSON content expected”

This means CIPP reached its Conditional Access deployment path without a resolved policy JSON body. It is not a Microsoft Graph policy validation error.

1. Stop the rollout and check whether any CA policy was actually created.
2. If Security Defaults was disabled and no replacement policies exist, re-enable it.
3. Open the selected Conditional Access template in CIPP and confirm it has a GUID/RowKey and visible JSON.
4. If a package was selected, confirm it expands to real templates rather than only returning a package label.
5. Retry with one known template in Report-only. If that works, the problem is package expansion, not the policy JSON.
6. Verify the CIPP frontend and API are on compatible releases and inspect **Conditional Access Logs**.

GitHub package membership is documented in `Config/PolicyPackages.psd1`, but CIPP package tags are local metadata. Importing policy JSON alone does not create those tags.

## Policy created but expected groups are missing

- Import `Config/Groups` before `Config/ConditionalAccess`.
- Confirm **Create Groups** is enabled in the CIPP standard.
- Confirm `Config/MigrationTable.json` was detected by the community repository.
- Do not choose “remove all exclusions”; that removes the emergency-access and control-specific safeguards.
- When CIPP asks how to handle users/groups, use display-name replacement only after confirming every target group name is unique.

## Common sign-in failures

| Symptom or code | Likely policy | Check |
|---|---|---|
| AADSTS50076 / AADSTS50079 | CA002, CA003, CA004, CA100, CA200 | Registered methods, TAP bootstrap, and phishing-resistant method availability |
| AADSTS53000 / AADSTS53001 | CA102, CA302–CA306 | Intune enrollment, current compliance state, managed-mobile membership, and platform match |
| AADSTS53003 | Any enforced CA policy | Sign-in log → Conditional Access tab → failed policy and unmet control |
| AADSTS50131 or location-based blocks | CA009, CA103, CA600 | Source IP, trusted flag, VPN/ZTNA egress, and named-location contents |
| Native Microsoft 365 clients fail but browsers work | CA307 | Supported client version, registered device/PRT, and token-protection result |
| Mobile Office app fails | CA300 | App Protection assignment, supported app, broker, and user licensing |
| Browser can view but cannot download | CA301 | Expected behavior on noncompliant devices; verify app-enforced restrictions |
| High-value user cannot use a browser | CA111 | Confirm group membership, supported browser device identification, Intune registration, and current compliance state |
| CLI device login fails | CA005 | Replace device-code authentication or use a documented temporary exception |
| Outlook QR/mobile transfer fails | CA006 | Expected when authentication transfer is blocked; verify whether the workflow has an approved requirement |
| Ordinary users reauthenticate or cannot persist browser sessions | CA010/CA012 | Confirm the request is classified against the expected trusted IP location, then review the 14-day trusted or 24-hour untrusted interval and report-only evidence |
| Ordinary internal user receives a geographic block | CA011 | Confirm the resolved allowed-country location, unknown-country behavior, travel status, and exception membership |
| Custom/AU-scoped privileged user misses admin controls | CA100–CA103 | Confirm membership in `MSP-CA-Include-PrivilegedUsers` and rerun What If after a fresh token is issued |
| Temporary user service account repeatedly reauthenticates | CA010/CA012 | Confirm it is in the governed MFA-temporary group while migration is active; do not use the emergency group |
| MFA prompt appears because of risk | CA400 | Confirm P2 licensing and review the exact sign-in risk detection |
| User is forced through password remediation | CA401 | Review high user-risk evidence, SSPR, and password-writeback health |
| Service principal is blocked | CA500/CA501 | Review workload risk and the automation source IP |

## Triage order

1. Identify the exact sign-in event and failing policy.
2. Confirm user, resource, client type, device platform, device compliance, source IP, and grant result.
3. Use the Conditional Access **What If** tool with the same attributes.
4. Return only the suspect policy to Report-only if access must be restored.
5. Fix the prerequisite or scope; do not solve an unrelated failure by adding a broad exception.

## Location lockout

Use a prevalidated emergency-access account, return the failing location policy to Report-only, and confirm recovery. Then verify every named location used by `AllTrusted` is marked trusted and contains the current public egress addresses. Test trusted and untrusted paths before re-enforcement.

For CA011, do not troubleshoot against `AllTrusted`. Confirm CIPP resolved the placeholder to the exact `SHOOTHILL-CA-Allowed-Countries-Operator-Defined` location, then inspect its country list and `includeUnknownCountriesAndRegions` value. Compare the public IP in the sign-in log with cloud VPN, secure web gateway, proxy, and mobile-carrier egress; Entra does not prove the user's physical position. If the named location does not exist, create it before assigning the Core package; the repository intentionally does not invent it.

The retired `MSP-CA-Exclude-LocationPolicies` group must not be reused. CA009 uses `MSP-CA-Exclude-RegistrationLocation`; CA103 uses `MSP-CA-Exclude-AdminLocation`; CA600 has no ordinary location bypass.

## Device compliance deadlock

The baseline already excludes Microsoft Intune and Microsoft Intune Enrollment resources from CA102 and CA302–CA306. If enrollment still fails, inspect the sign-in audience and resource. Add an application exclusion only when Microsoft documents that enrollment dependency and record it as a baseline change—not as an arbitrary tenant exception.

## Rollback evidence

Keep the failed policy in Report-only, preserve its sign-in results, and record:

- affected users and applications;
- first and last failure;
- failed control;
- root cause;
- temporary mitigation;
- permanent fix and retest evidence.
