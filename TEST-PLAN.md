# Conditional Access acceptance test plan

Run this plan after import, after any policy change, and before promoting each adopted package from Report-only. Packages 01–05 are the standard rollout. Package 06 is tested only after an explicit tenant decision to adopt country restriction. Use dedicated test identities and devices; never use an emergency-access account for normal administration.

Record for every test:

- tenant, date, tester, and package version;
- user or service principal;
- source public IP and named-location result;
- resource application ID, client type, platform, and device state;
- expected policy and result;
- actual sign-in correlation ID and Conditional Access result;
- pass, fail, remediation owner, and retest date.

For What If tests, select a concrete resource application rather than an aggregate such as Office 365 or Microsoft Admin Portals. Confirm the result against a real report-only sign-in; simulation does not replace an actual test.

## Package 01 — Core Identity and External Access P1

| Scenario | Test path | Expected result |
|---|---|---|
| Emergency access | Sign in with each monitored emergency account from a nontrusted network | No Shoothill user policy blocks the account; alerting records the use |
| Internal MFA | Internal user signs in to Exchange Online in a modern client | CA002 reports MFA/authentication-strength requirement |
| Internal session frequency | Internal user with authentication older than 24 hours accesses a concrete resource | CA010 reports reauthentication |
| Internal browser persistence | Internal user closes and reopens a browser after selecting “Stay signed in” | CA010 reports `persistentBrowser: never`; tenant documents any tuning from the 24-hour starting point |
| Temporary user service account session | Account in `MSP-CA-Exclude-MFA-Temporary` repeats its approved automation path | CA010 does not apply; CA600 remains the location compensating control |
| Legacy authentication | Test account attempts an approved legacy-protocol test | CA001 reports block |
| Device code | Test account attempts device-code flow to a nonexcluded resource | CA005 reports block |
| Device registration dependency | Exercise the documented device-registration flow | CA005 does not block Device Registration Service |
| Authentication transfer | Attempt the Outlook desktop-to-mobile authentication-transfer workflow | CA006 reports block |
| Authentication-transfer exception | Add a test identity temporarily to `MSP-CA-Exclude-AuthenticationTransfer` and repeat | CA006 does not apply; remove the test membership immediately |
| Security-info registration, trusted | Register a method using TAP through a trusted office or VPN/ZTNA exit | CA003 requires MFA strength; CA009 does not block |
| Security-info registration, untrusted | Attempt security-info registration from a deliberately nontrusted network | CA009 reports block |
| Device registration | Register or join a test device | CA004 reports MFA requirement without creating an enrollment deadlock |
| Guest MFA | B2B collaboration guest accesses a normal permitted application | CA200 reports MFA while supported external MFA/OTP remains usable |
| Guest session | Guest uses a browser after the configured session interval | CA201 reports the hardened session controls |
| Guest admin portal | Ordinary guest opens a concrete Microsoft admin resource | CA202 reports block |
| Approved guest administrator | Approved test guest is placed in `MSP-CA-Allow-GuestAdminPortals` and repeats | CA202 does not apply; admin protection is tested separately |
| Administrator, trusted | Each targeted role signs in from a trusted egress | CA100 reports phishing-resistant MFA; CA103 does not block |
| Administrator, untrusted | A targeted test administrator signs in from a nontrusted network | CA103 reports block |
| MFA-exempt service account, trusted | Test account in `MSP-CA-Exclude-MFA-Temporary` signs in from its approved egress | CA600 does not block |
| MFA-exempt service account, untrusted | The same account signs in from a nontrusted source | CA600 reports block |
| MFA-exempt service account bypass attempt | Inspect CA600 and exception memberships | CA600 has no ordinary exclusion group and the account cannot combine MFA and location exceptions |
| CIPP/GDAP | Perform a delegated CIPP tenant operation | `serviceProvider` exclusion prevents human/guest policies from interrupting the operation |
| Directory synchronization | Confirm normal Entra Connect synchronization and inspect applicable policies | Built-in Directory Synchronization Accounts role is excluded from all-user scopes |

Core is accepted only when both trusted and deliberately untrusted location tests pass and every tenant location marked **Trusted** has a current owner and valid public CIDR inventory.

## Package 02 — Privileged, Endpoint and App Protection

| Scenario | Test path | Expected result |
|---|---|---|
| Admin method | Targeted administrator uses phishing-resistant and non-phishing-resistant methods | CA100 accepts only the phishing-resistant method |
| Built-in admin device | Targeted administrator uses compliant and noncompliant Windows and macOS devices | CA102 accepts only compliant devices |
| Mobile/Linux admin device | Targeted administrator uses compliant and noncompliant iOS, Android, and Linux devices | CA102 accepts only compliant devices on every supported platform |
| Declared privileged user | User without one of the 14 built-in role assignments is added to `MSP-CA-Include-PrivilegedUsers` | CA100–CA103 apply exactly as they do to a role-targeted administrator |
| Admin session | Targeted administrator uses browser and native clients | CA101 reports the configured sign-in frequency and browser persistence controls |
| Unknown platform | Use an explicitly unsupported platform or a controlled user-agent test | CA007 reports block |
| Mobile App Protection | iOS and Android test users access Microsoft 365 with protected and unprotected apps | CA300 accepts only a supported app with the assigned App Protection policy |
| Additional MAM-protected resource | Add a test resource service-principal ID and display name through `PolicyExtensions.psd1`, regenerate, and use protected/unprotected mobile clients | CA300 includes the target resource ID and accepts only a client with its assigned App Protection policy |
| Unmanaged browser | Noncompliant device accesses Exchange Online and SharePoint Online | CA301 allows restricted web access and blocks downloads through service-side restrictions |
| Desktop compliance | Windows, macOS, and Linux users test compliant and noncompliant devices | CA302, CA303, and CA306 report the correct per-platform result |
| Managed mobile compliance | User in the managed-mobile include group tests compliant and noncompliant iOS/Android devices | CA304 or CA305 reports the correct result |
| Enrollment bootstrap | Enroll a new supported device | Intune and Intune Enrollment exclusions prevent a circular compliance dependency |
| Token protection | Supported Windows native clients access Exchange, SharePoint, and Teams Services | CA307 reports bound-token success on supported clients and exposes unbound clients before enforcement |

## Package 03 — Identity Protection P2

| Scenario | Test path | Expected result |
|---|---|---|
| Medium/high sign-in risk | Use an approved Identity Protection simulation or existing detection | CA400 reports MFA every time |
| High user risk | Use an approved high-risk test identity | CA401 reports risk remediation and the password reset/writeback path succeeds |
| Risk exception | Temporarily add a test identity to the risk-exception group | Both risk policies stop applying; remove membership and record the exception test |

## Package 04 — Workload Identity Premium

| Scenario | Test path | Expected result |
|---|---|---|
| High-risk workload | Use an approved workload-risk test or captured detection | CA500 reports block for a tenant-owned service principal |
| Trusted workload location | Execute a test service principal from every approved automation egress | CA501 does not block |
| Untrusted workload location | Execute the same test from a deliberately nontrusted egress | CA501 reports block |

## Package 05 — Defender and Purview Advanced

| Scenario | Test path | Expected result |
|---|---|---|
| Defender App Control | Internal user opens a Microsoft 365 browser session | CA309 reports routing to Defender App Control and the session appears in Defender |
| Elevated insider risk | Use the approved Purview Adaptive Protection test procedure | CA402 reports block and the HR/legal/security incident path receives the event |
| Service-account insider-risk scope | Inspect a temporary user service account and CA402 What If result | CA402 does not apply to the account while CA600 continues to constrain its egress |

## Package 06 — Optional Country Restriction

Do not run this section during the standard five-package rollout. First create the exact tenant-owned named location `SHOOTHILL-CA-Allowed-Countries-Operator-Defined` and populate its approved countries.

| Scenario | Test path | Expected result |
|---|---|---|
| Package not adopted | Inspect the tenant's standard package assignments | Package 06 and CA011 are absent |
| Allowed country | Internal test user signs in from each approved operating country | CA011 does not block |
| Disallowed country | Internal test user signs in through a controlled egress outside the approved list | CA011 reports block |
| Unknown location | Exercise the tenant's approved unknown-country test path | Result matches the documented `includeUnknownCountriesAndRegions` decision |
| VPN/proxy egress | Sign in through every cloud VPN, secure web gateway, and proxy path | CA011 evaluates the egress IP's country and the result matches the documented network design |
| Travel exception | Add a test user temporarily to `MSP-CA-Exclude-CountryRestriction` and repeat the denied path | CA011 does not apply; membership is removed and the time-bound exception record is retained |
| Emergency recovery | Test both emergency-access accounts from outside the approved list | CA011 does not apply and emergency-use monitoring records the sign-in |

Package 06 is accepted only when the country list has an owner and review date, permitted and denied paths pass, unknown-location behavior is deliberate, and travel/recovery processes are operational.

## Promotion and rollback acceptance

An adopted package can be enforced only when:

1. every applicable row passes in Report-only;
2. exclusions are empty or have an owner, approval, expiry, and remediation action;
3. report-only results have been reviewed for at least the agreed observation period;
4. support communications and rollback ownership are confirmed;
5. both emergency-access accounts were tested independently;
6. the rollback administrator session remains available during enforcement.

After enforcement, repeat the permitted and denied paths. If the actual outcome differs, return only the affected policy to Report-only, preserve the sign-in evidence, correct the dependency, and rerun the failed case.
