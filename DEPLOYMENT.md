# CIPP deployment runbook

The repository contains 30 Report-only Conditional Access templates, 15 group templates, stable migration mappings, and nine capability packages.

## 1. Preflight

- Confirm Microsoft 365 Business Premium or equivalent licensing for every in-scope user.
- Create two cloud-only emergency-access accounts and monitor the emergency-access group.
- Confirm at least one independent Global Administrator session works.
- Verify CIPP/GDAP access and export the tenant's current Conditional Access policies.
- Record whether Security Defaults is enabled. Do not disable it until the CA replacement is ready to deploy.
- Validate Temporary Access Pass onboarding and administrator phishing-resistant methods.
- If Microsoft Entra Connect is present, confirm its account holds the built-in Directory Synchronization Accounts role.

## 2. Import

1. Add `TJKANZLER/ConditionalAccessBaseline` in **Tools → Community Repositories**.
2. Import the 15 files under `Config/Groups`.
3. Import the 30 files under `Config/ConditionalAccess`.
4. Confirm CIPP resolves every template group ID through `Config/MigrationTable.json`.
5. Confirm every imported policy state is Report-only.

Do not import `MigrationTable.json` or `PolicyPackages.psd1` as templates.

When CIPP asks how to handle groups and users, choose **Replace by display name** after confirming the 15 target group names are unique. Do not choose **Remove all exclusions**; that would remove emergency-access and policy-specific safeguards. **Leave as is** is suitable only when the referenced object IDs already belong to that same tenant, which is not the portable community-repository path.

## 3. Build the nine CIPP packages

Use [Config/PolicyPackages.psd1](Config/PolicyPackages.psd1) as the source of truth.

Where **Add to package** is available, multi-select each manifest set and apply its exact package name. Package tags are stored in CIPP, not in the Graph policy JSON.

Where that table action is unavailable, create the Conditional Access standard with the individual templates from one manifest package selected together. This still deploys the set to a tenant in one standard run; it does not require 30 separate deployments.

## 4. Assign in Report-only

For each package:

1. Add **Conditional Access Template** to the tenant or tenant-group Standards template.
2. Select the package, or its complete manifest policy set.
3. Set policy state to Report-only.
4. Enable **Create Groups**.
5. Disable Security Defaults only when package 01 is being deployed successfully in the same controlled change.
6. Run the standard and confirm all expected policies exist in Entra.
7. Re-run the standard to prove the deployment is idempotent.

If CIPP reports `Empty Payload. JSON content expected`, stop. Confirm the selected standard resolves actual Conditional Access template RowKeys rather than only a package label, and verify CIPP frontend/API versions match. Re-enable Security Defaults if no replacement CA policies were created.

## 5. Promotion sequence

| Order | Package | Evidence required before enforcement |
|---:|---|---|
| 1 | Identity Foundation P1 | Legacy authentication, MFA, TAP, registration, and device-code flows pass |
| 2 | Privileged Access P1/Intune | Admin authentication, sessions, and compliant workstations pass |
| 3 | External Collaboration P1 | B2B collaboration and approved guest-admin paths pass |
| 4 | Endpoint and App Protection | Every enabled Intune platform, MAM flow, browser restriction, and token client passes |
| 5 | Trusted Location Guardrails | Admin, registration, and MFA-exempt account egress is complete |
| 6 | Closed Network Perimeter | Only for a formally adopted office-only or always-on secure-access model |
| 7 | Identity Protection P2 | Licensing, SSPR, risk detections, and help-desk remediation pass |
| 8 | Workload Identity Premium | Licensing and all service-principal execution locations are verified |
| 9 | Defender and Purview Advanced | Defender integration and Purview/HR/legal response are operational |

Promote one package at a time. Do not assign packages 6–9 without their named operating model, licence, and service prerequisites.

## 6. Location package controls

CA008 blocks every all-human sign-in outside `AllTrusted`. Before enforcement:

- verify each named location is marked trusted;
- test every office, VPN/ZTNA exit, and recovery path;
- test from a deliberately untrusted network;
- confirm the emergency-access accounts remain excluded;
- identify mobile and travelling-user handling;
- schedule CA008 as a standalone change with a rollback administrator already signed in.

## 7. Exception governance

All exception groups start empty. For every member record:

- owner and approver;
- business reason;
- policy being bypassed;
- start and expiry date;
- migration/remediation action;
- last review date.

Emergency access is not a general exception mechanism.

## 8. Rollback

1. Use the prevalidated emergency-access account.
2. Return only the newly enforced policy or package to Report-only.
3. Revoke affected user sessions only if necessary.
4. Confirm sign-in recovery.
5. Correct the prerequisite or scope before retrying.

Do not delete failed policies during an incident; retaining them in Report-only preserves evidence and makes the fix auditable.
