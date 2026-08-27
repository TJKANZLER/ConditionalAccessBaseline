# CIPP deployment runbook

The repository contains 35 Report-only Conditional Access templates, 20 group templates, stable migration mappings, and five standard capability packages.

## 1. Preflight

- Confirm Microsoft 365 Business Premium or equivalent licensing for every in-scope user.
- Create two cloud-only emergency-access accounts and monitor the emergency-access group.
- Confirm at least one independent Global Administrator session works.
- Verify CIPP/GDAP access and export the tenant's current Conditional Access policies.
- Record whether Security Defaults is enabled. Do not disable it until the CA replacement is ready to deploy.
- Validate Temporary Access Pass onboarding and administrator phishing-resistant methods.
- Inventory custom roles, administrative-unit-scoped roles, and privileged users outside Microsoft's 14 recommended built-in roles; approve membership for `MSP-CA-Include-PrivilegedUsers`.
- Inventory temporary user-based service accounts and every trusted egress while they are migrated to managed identities or service principals.
- If Microsoft Entra Connect is present, confirm its account holds the built-in Directory Synchronization Accounts role.

## 2. Import

1. Add `TJKANZLER/ConditionalAccessBaseline` in **Tools → Community Repositories**.
2. Import the 20 files under `Config/Groups`.
3. Import the 35 files under `Config/ConditionalAccess`.
4. Confirm CIPP resolves every template group ID through `Config/MigrationTable.json`.
5. Confirm every imported policy state is Report-only.

Do not import `MigrationTable.json`, `PolicyExtensions.psd1`, or `PolicyPackages.psd1` as templates.

When CIPP asks how to handle groups and users, choose **Replace by display name** after confirming the 20 target group names are unique. Do not choose **Remove all exclusions**; that would remove emergency-access and policy-specific safeguards. **Leave as is** is suitable only when the referenced object IDs already belong to that same tenant, which is not the portable community-repository path.

Older imports can contain `MSP-CA-Exclude-LocationPolicies`. It is retired because one membership bypassed unrelated controls. Move approved memberships, with fresh review, into either `MSP-CA-Exclude-RegistrationLocation` or `MSP-CA-Exclude-AdminLocation`; never carry the old group forward automatically.

## 3. Build the five CIPP packages

Use [Config/PolicyPackages.psd1](Config/PolicyPackages.psd1) as the source of truth.

Where **Add to package** is available, multi-select each manifest set and apply its exact package name. Package tags are stored in CIPP, not in the Graph policy JSON.

Where that table action is unavailable, create the Conditional Access standard with the individual templates from one manifest package selected together. This still deploys the set to a tenant in one standard run; it does not require 35 separate deployments.

## 4. Assign in Report-only

For each adopted package:

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
| 1 | Core Identity and External Access | MFA, registration, device code, authentication transfer, 14-day trusted and 24-hour untrusted internal sessions, B2B collaboration, trusted egress, and allowed-country tests pass |
| 2 | Privileged, Endpoint and App Protection | Built-in and declared privileged users, all supported admin platforms, MAM resources, browser, compliance, and token-client testing pass |
| 3 | Identity Protection P2 | Licensing, SSPR, risk detections, and help-desk remediation pass |
| 4 | Workload Identity Premium | Licensing and all service-principal execution locations are verified |
| 5 | Defender and Purview Advanced | Defender integration and Purview/HR/legal response are operational |

Promote one standard package at a time. Do not assign packages 3–5 without their named licence and service prerequisites.

## 6. Core trusted-location controls

The Core package protects administrators, security-info registration, and MFA-exempt user service accounts without restricting ordinary remote users. Before enforcement:

- verify each named location is marked trusted;
- test every office, VPN/ZTNA exit, and recovery path;
- test from a deliberately untrusted network;
- confirm the emergency-access accounts remain excluded;
- identify mobile and travelling-user handling;
- inventory every existing Entra named location marked **Trusted**, including its owner, current public CIDRs, purpose, and last review date;
- create or update tenant-specific named locations in **CIPP → Tenant → Conditional Access → Named Locations** and mark only approved IP-based locations as trusted;
- keep a rollback administrator signed in while each location policy is promoted.

The policies use the portable `AllTrusted` selector. A stale or overly broad location marked trusted therefore weakens all three Core location controls. Remove the trusted flag from obsolete entries before enforcement.

CA009 and CA103 have separate exception groups. CA600 has no ordinary location exception because it is the compensating control for accounts temporarily exempted from MFA. Do not place a normal account in multiple exception groups to manufacture a composite bypass.

## 7. Core country-restriction readiness

CA011 is part of `SHOOTHILL-CA-01-Core-Identity-and-External-Access-P1` for every tenant. Leave CA011 Report-only until:

1. Create a country-based named location with the exact display name `SHOOTHILL-CA-Allowed-Countries-Operator-Defined`.
2. Populate every country where the tenant permits ordinary-user sign-in.
3. Inventory cloud VPN, secure web gateway, proxy, mobile carrier, and disaster-recovery egress. Entra evaluates the public egress IP's country, not physical user presence.
4. Make an explicit decision for unknown countries/regions; excluding unknown locations from the allowed set is the safer default.
5. Record ownership, review cadence, travel handling, emergency recovery, and the approval path for `MSP-CA-Exclude-CountryRestriction`.
6. Run the country-restriction test section in `TEST-PLAN.md` while CA011 remains Report-only.
7. Promote only after permitted, denied, travelling-user, proxy/VPN, and exception cases all match the approved model.

CA011 carries only the location's stable placeholder ID and required display name. CIPP resolves it to the pre-existing tenant location. The repository does not create or overwrite the tenant's country list.

## 8. Additional MAM-protected resources

CA300 includes Office 365 as its protected target resource by default. A third-party MAM-capable client accessing Office 365 is already covered. Add an extension only when protecting a separate resource or API:

1. Fork or branch the community repository used for that tenant cohort.
2. Add an `ApplicationId` and descriptive `DisplayName` to `AdditionalMamProtectedResources` in `Config/PolicyExtensions.psd1`.
3. Confirm the ID belongs to the target resource service principal in the tenant, not the mobile client app.
4. Confirm the client genuinely supports Intune App Protection and matching iOS/Android App Protection policies are assigned.
5. Run the generator and validator, then inspect the CA300 JSON diff; only `includeApplications` should change.
6. Import the updated CA300 template and repeat mobile acceptance tests in Report-only.

Do not add application IDs directly to generated JSON; regeneration would correctly remove that untracked edit.

## 9. Exception governance

All exception groups start empty. For every member record:

- owner and approver;
- business reason;
- policy being bypassed;
- start and expiry date;
- migration/remediation action;
- last review date.

Emergency access is not a general exception mechanism.

## 10. Rollback

1. Use the prevalidated emergency-access account.
2. Return only the newly enforced policy or package to Report-only.
3. Revoke affected user sessions only if necessary.
4. Confirm sign-in recovery.
5. Correct the prerequisite or scope before retrying.

Do not delete failed policies during an incident; retaining them in Report-only preserves evidence and makes the fix auditable.

Execute [TEST-PLAN.md](TEST-PLAN.md) for the package before and after promotion.
