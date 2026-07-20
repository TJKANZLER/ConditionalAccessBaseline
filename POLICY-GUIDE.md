# Policy guide — plain English

What each policy actually does to a real user, and what tends to go wrong when you flip it from Report-only/Disabled to On. Read this alongside [POLICY-MATRIX.md](POLICY-MATRIX.md) (scope/dependencies) and [DEPLOYMENT.md](DEPLOYMENT.md) (rollout order) — this doc is the "what will the helpdesk phone ring about" reference.

Every policy below excludes `MSP-CA-Exclude-All-EmergencyAccess`. That's not repeated per entry.

---

## Foundation (CA001–CA008)

### CA001 — Block legacy authentication
**Plain English:** Refuses sign-in from old protocols that can't do MFA at all — POP, IMAP, older Outlook clients, Exchange ActiveSync on ancient phone mail apps. If an app can't prompt for MFA, it's blocked outright, no exceptions.
**Expected issues:** A copier/scanner or an old accounting package sending mail via IMAP/SMTP with a stored password just stops working, silently, until someone notices invoices aren't arriving. Old Android/iOS native mail apps (not Outlook) doing ActiveSync also break.
**Solutions:** Run Report-only for at least 2 weeks first and check the sign-in log's "Client app" column for real legacy-auth usage before enabling. Migrate scanners/apps to modern auth or an app password equivalent (SMTP AUTH client submission with a dedicated account, not IMAP). There's no exception group by design — legacy auth is not something to carve exceptions for; fix the client instead.

### CA002 — Require MFA (internal users)
**Plain English:** Every internal (non-guest) sign-in needs MFA, everywhere, on every app.
**Expected issues:** Anyone not yet registered for MFA gets locked out the moment this goes live. Break/fix and monitoring service accounts that sign in as a "real" user (not an app registration) can't complete MFA and grind to a halt.
**Solutions:** Complete MFA registration for all humans before enforcing (Report-only phase surfaces who hasn't registered). For legacy service accounts, add them to `MSP-CA-Exclude-MFA-Temporary` as a named, tracked exception — while migrating them to a managed identity or app registration, since that group is a "pending migration" bucket, not a permanent fix.

### CA003 — Protect security-info registration
**Plain English:** Requires MFA before someone can add or change their own MFA methods (phone number, authenticator app, etc.).
**Expected issues:** A brand-new user with no MFA methods yet can't register a first method, because registering needs MFA, which they don't have yet — classic bootstrap deadlock.
**Solutions:** Use a Temporary Access Pass (TAP) for new-starter onboarding — TAP satisfies the MFA requirement so the user can register their real method. `MSP-CA-Exclude-Registration` exists for a documented, time-boxed exception if TAP isn't set up yet; don't leave anyone in it permanently.

### CA004 — Protect device registration/join
**Plain English:** Requires MFA before a device can be registered or Azure AD/Entra-joined.
**Expected issues:** Same bootstrap problem as CA003 if a new device is being set up for a user who hasn't got MFA yet, or during Autopilot/OOBE flows that expect a smoother sign-in.
**Solutions:** Same TAP-based bootstrap process as CA003. Test Autopilot/enrollment end-to-end in Report-only before enforcing — some enrollment flows re-prompt for auth mid-process and this is where it'll surface.

### CA005 — Block device-code flow
**Plain English:** Blocks the "go to microsoft.com/devicelogin and enter this code" sign-in flow, which is how a lot of phishing kits and infostealers trick users into authorizing a session, and also how legitimate CLI tools (Azure CLI, `az login`, some Graph PowerShell flows) sign in on devices without a browser.
**Expected issues:** IT admins and any automation using `az login --use-device-code`, older Graph PowerShell auth, or CLI tools on headless/server boxes suddenly can't authenticate.
**Solutions:** Inventory CLI/automation device-code usage before enforcing (Report-only shows this). Move scripts to a service principal with certificate/secret auth instead of device code where possible. For a genuine ongoing need, add the identity to `MSP-CA-Exclude-DeviceCodeFlow` — kept deliberately empty by default, and each addition should be a documented, reviewed decision, not a default.

### CA006 — Block authentication transfer
**Plain English:** Blocks the newer "scan this QR code on your phone to sign in on this PC" flow (auth transfer), another vector abused in phishing.
**Expected issues:** Low — this is a newer feature most orgs aren't relying on yet. Some newer mobile-to-desktop Outlook/Teams onboarding flows use it.
**Solutions:** Test mobile onboarding flows in Report-only first. `MSP-CA-Exclude-AuthenticationTransfer` is the exception group if a specific workflow needs it — keep it empty otherwise.

### CA007 — Block unknown platforms (Disabled)
**Plain English:** Only lets Windows, macOS, iOS, Android, and Linux through; everything else (ChromeOS, unusual embedded browsers, platform spoofing) gets blocked.
**Expected issues:** The "platform" signal comes from the user agent string, which is trivially spoofable — this is a soft control, not a hard security boundary. If a client base has ChromeOS devices (Chromebooks), they'll be blocked outright since ChromeOS isn't one of the five recognized platforms.
**Solutions:** Decide how ChromeOS/other platforms are handled *before* enabling — either accept them going forward as an intentional platform decision, or don't enable this policy for that tenant. Use `MSP-CA-Exclude-UnknownPlatforms` for a documented, narrow exception, not a general safety net.

### CA008 — Block outside trusted locations (Disabled)
**Plain English:** Only allows sign-in from IP ranges/countries you've explicitly marked "trusted" in Entra Named Locations; everything else is blocked.
**Expected issues:** This is the single highest-blast-radius policy in the whole library. If *no* named locations are marked trusted when this goes live, it blocks *everyone, everywhere* — including admins. Remote/hybrid workers, home broadband with dynamic IPs, and mobile data all commonly fall outside a naive office-IP-only trusted list.
**Solutions:** Build and verify the complete trusted-location list first — every office, every legitimate remote-work egress path, and any VPN/ZTNA exit IPs — and test from each one before flipping to On. Never enable this in the same change window as anything else. Keep `MSP-CA-Exclude-LocationPolicies` for a genuine ongoing traveling-user exception, reviewed regularly.

---

## Administrators (CA100–CA104)

### CA100 — Require phishing-resistant MFA for admins
**Plain English:** Anyone holding one of ~24 privileged roles (Global Admin, Security Admin, Exchange Admin, etc.) must use a phishing-resistant method — Windows Hello for Business, a physical FIDO2 key/passkey, or a certificate — not just any MFA. A regular phone-based MFA prompt won't satisfy this.
**Expected issues:** Admins who've only ever registered Microsoft Authenticator push notifications get locked out of their own admin roles the moment this enforces, including possibly locking themselves out of fixing the problem.
**Solutions:** Every admin needs a phishing-resistant method registered *before* this goes to On — budget for FIDO2 keys or WHfB rollout as a real project, not an afterthought. Verify at least one working emergency-access account is fully excluded and tested from a clean browser before enforcing this on anyone else.

### CA101 — Harden admin sessions
**Plain English:** Admins get re-prompted for MFA every 12 hours and their browser never "stays signed in" — closing the browser ends the session.
**Expected issues:** Admins doing long stretches of portal work get logged out mid-task and lose unsaved work in whatever they were doing (e.g., a half-finished CIPP or Entra portal form).
**Solutions:** Mostly a training/expectation issue — tell admins up front this is coming and why. Low technical risk; no real workaround needed beyond re-authenticating.

### CA102 — Require compliant device for admins (Disabled)
**Plain English:** Admin accounts can only be used from an Intune-managed, compliant device — no doing admin work from a personal laptop or an unmanaged machine, even with MFA.
**Expected issues:** Locks out any admin whose "admin machine" isn't actually Intune-enrolled yet, or whose device has drifted out of compliance (missing an update, disk encryption toggled off, etc.) without them realizing.
**Solutions:** Enroll and confirm compliance for every privileged workstation *before* enabling — this should be the last CA policy you turn on for admins, not an early one. `MSP-CA-Exclude-DeviceCompliance` is shared with CA302-306/CA310 as a documented device-compliance exception; don't reach for it as a quick fix without knowing it also affects those.

### CA103 — Strict-location CAE for admins (Disabled)
**Plain English:** Uses Continuous Access Evaluation to re-check an admin's network location in near-real-time — if they move networks mid-session (leave the office Wi-Fi, VPN drops), the session gets cut immediately rather than waiting for the token to expire.
**Expected issues:** Admins working from unstable connections (mobile hotspot, flaky home Wi-Fi, VPN reconnecting) get logged out repeatedly, which reads as "CIPP/Entra is broken" to anyone who doesn't know this is intentional.
**Solutions:** This depends entirely on trusted named locations being accurate and complete (same prerequisite as CA008) — build that first. Test through a realistic network-change scenario (e.g., disconnect/reconnect Wi-Fi) before enforcing. Use `MSP-CA-Exclude-StrictCAE` for admins who travel constantly and would otherwise be logged out all day.

### CA104 — Reauthenticate for sensitive actions (Disabled)
**Plain English:** For a specific set of high-risk actions (defined via the "MSP Sensitive Action" authentication context — e.g., PIM role activation), demands fresh phishing-resistant MFA every single time, no matter how recently the admin last signed in.
**Expected issues:** Does nothing at all until the "MSP Sensitive Action" authentication context is actually wired up to PIM or specific applications in the target tenant — this policy is inert scaffolding out of the box.
**Solutions:** This is a two-step deployment: import the policy (CIPP auto-creates the authentication context on first deploy), *then* separately go into PIM role-activation settings (or the relevant app) and attach that authentication context. Skipping step two means the policy silently does nothing — verify it's actually being evaluated (check the sign-in log for the auth context) before assuming it's protecting anything.

---

## Guests (CA200–CA202)

### CA200 — Require MFA for guests
**Plain English:** Same idea as CA002 but for external/guest users collaborating via Teams or SharePoint.
**Expected issues:** External partners who've never had to do MFA for your tenant before suddenly can't get in, and they may not have any easy path to register a method since they're not "your" user.
**Solutions:** Warn active guest collaborators before enforcing. Most guests already have MFA from their *home* tenant's own policies and this mostly just requires them to complete it when challenged — but for guests from tenants with weak security, this can be a real blocker worth a heads-up email.

### CA201 — Harden guest sessions
**Plain English:** Same as CA101 (12-hour re-auth, no persistent browser) but for guests.
**Expected issues:** Low — guests re-prompted for auth periodically during long collaboration sessions. Mild annoyance at worst.
**Solutions:** None really needed; this is low-risk to enable.

### CA202 — Block ordinary guests from admin portals
**Plain English:** Guests can use Teams/SharePoint normally, but can't reach Entra, M365 admin center, or other Microsoft admin portals unless they're in the explicit allow-list group.
**Expected issues:** Breaks access for any legitimate outsourced/partner admin (e.g., a specialist consultant with a guest account managing one specific service) who isn't yet in the allow group.
**Solutions:** Identify every legitimate external admin *before* enabling and add them to `MSP-CA-Allow-GuestAdminPortals` first. This is a low-risk policy to enable broadly since the failure mode (an unexpected external admin) is exactly the thing worth catching.

---

## Devices and sessions (CA300–CA310)

### CA300 — Require App Protection for mobile Office apps
**Plain English:** On phones/tablets (Android/iOS), Office 365 apps must be wrapped in an Intune App Protection Policy (controls copy/paste, save-to-personal-storage, etc.) — the device itself doesn't need to be enrolled, just the app.
**Expected issues:** Users on personal phones who've never had App Protection applied suddenly can't open email/Teams/OneDrive on mobile until the policy syncs, which can take a little while after first sign-in.
**Solutions:** Deploy the actual Intune App Protection policies *before* this CA policy enforces — CA300 only checks that protection is applied, it doesn't create it. Warn mobile users there may be a short re-provisioning delay the first time.

### CA301 — Restrict downloads from unmanaged browsers
**Plain English:** If someone opens Exchange/SharePoint in a plain browser (not a managed device, not the app), they can view files/email but can't download, print, or sync — read-only access from an unmanaged browser.
**Expected issues:** Users legitimately checking webmail from a home PC or public library machine find they can't download an attachment they need, and it's not obvious why (no error, just a missing/disabled option).
**Solutions:** This is generally the *intended* behavior for unmanaged devices, so mostly a communication issue — tell users why. `MSP-CA-Exclude-UnmanagedBrowser` is its own dedicated exception group (not shared with the compliant-device policies) for a documented case that genuinely needs it.

### CA302 — Require compliant Windows device
**Plain English:** Windows PCs must be Intune-managed and passing compliance checks (encryption, patch level, etc.) to access anything — this is the strongest, most common device control in the library.
**Expected issues:** The biggest single source of lockouts in the whole rollout — any PC not yet enrolled, or enrolled but non-compliant (missing an update, AV out of date, etc.) loses access entirely, including the person trying to fix it.
**Solutions:** Full Intune compliance rollout and verification across every Windows device *before* enabling — this should be one of the last policies you turn on, not one of the first. If the environment relies on hybrid Azure AD join rather than full Intune management, use **CA310** instead (see below) rather than fighting this one.

### CA303 — Require compliant macOS device
**Plain English:** Same as CA302, for Macs.
**Expected issues:** Same lockout risk as CA302, plus Mac-specific gotchas: Platform SSO / Apple SSO extension needs to be configured correctly or users get stuck in an authentication loop.
**Solutions:** Confirm Apple SSO extension deployment and Mac Intune compliance profiles are working *before* enabling, same discipline as CA302.

### CA304 / CA305 — Compliant iOS/Android device (alternatives, Disabled)
**Plain English:** A stricter alternative to CA300 — instead of just wrapping the *app* in protection, this requires the whole *device* to be enrolled and compliant, for iOS/Android respectively.
**Expected issues:** If enabled alongside CA300 without realizing they're alternatives, users need to satisfy *both* app protection *and* full device enrollment — much more friction than intended, and probably not what was meant.
**Solutions:** Pick one model per tenant — App Protection (CA300, default) or full device compliance (CA304/305) — not both. Only enable these if a customer specifically wants full MDM control over personal/mobile devices rather than the lighter MAM approach.

### CA306 — Require compliant Linux device (Disabled)
**Plain English:** Same idea as CA302/303 but for Linux desktops.
**Expected issues:** Intune's Linux support is newer and narrower than Windows/Mac — check exactly which distros/versions are actually supported before assuming this will work for a given fleet.
**Solutions:** Only enable for tenants with a known, small, Intune-supported Linux fleet; verify enrollment works end-to-end first.

### CA307 — Require token protection (Windows)
**Plain English:** For Windows apps talking to Exchange/SharePoint, ties the sign-in token to the specific device, so a stolen token can't be replayed from an attacker's machine — a real defense against the most common token-theft attacks (AiTM phishing kits).
**Expected issues:** Only works with specific, up-to-date native clients (current Outlook/OneDrive builds on registered devices) — older client versions or unregistered devices get blocked from those apps.
**Solutions:** Check client versions and device-registration status in Report-only before enforcing. `MSP-CA-Exclude-TokenProtection` is the escape hatch for a specific compatibility issue while it's investigated.

### CA308 — Require token protection (Apple, Preview, Disabled)
**Plain English:** Same idea as CA307, extended to iOS/macOS — still a Microsoft preview feature.
**Expected issues:** Preview-feature instability; requires MDM plus Enterprise SSO/Platform SSO configured correctly, which is a nontrivial Apple-side deployment on its own.
**Solutions:** Don't enable for a customer unless they've explicitly accepted using a preview feature, and only after Platform SSO is confirmed working.

### CA309 — Monitor M365 browser sessions with Defender App Control (Disabled)
**Plain English:** Routes M365 browser sessions through Defender for Cloud Apps for monitoring — currently configured as observe-only, not blocking anything.
**Expected issues:** Requires the Defender for Cloud Apps integration to actually be set up in the tenant; without it, this policy effectively does nothing.
**Solutions:** Confirm Defender for Cloud Apps licensing and the session-controls integration are live before enabling, even though it's monitor-only and low-risk to turn on.

### CA310 — Compliant OR hybrid-joined Windows device (alternative, Disabled)
**Plain English:** A softer version of CA302 for environments that rely on traditional on-prem AD + hybrid Azure AD join rather than full Intune management — a hybrid-joined PC that isn't Intune-compliant can still get in.
**Expected issues:** If enabled *alongside* CA302, they don't conflict (both use the same `compliantDevice` control, satisfying either is fine) but running CA310 without ever having CA302 gives weaker assurance — a hybrid-joined-but-poorly-maintained PC still gets in.
**Solutions:** Use this instead of CA302, not in addition to it, for tenants that genuinely aren't on full Intune compliance. Treat it as a stopgap, not a permanent replacement — the direction of travel should be toward full Intune compliance and eventually CA302.

---

## Risk-based (CA400–CA402)

### CA400 — Medium/high sign-in risk requires MFA every time
**Plain English:** When Identity Protection flags a specific *sign-in* as risky (impossible travel, anonymous IP, leaked credential match, etc.), that sign-in must complete MFA, every time, regardless of how recently they last authenticated.
**Expected issues:** False positives — a user traveling, or on a new/unusual network, gets an unexpected MFA challenge. Requires Entra ID P2 or Entra Suite licensing to function at all.
**Solutions:** Confirm P2/Entra Suite licensing before relying on this. Mostly self-solving (user just completes MFA) — the real risk is licensing gaps making the policy silently a no-op, so verify Identity Protection is actually generating risk signals in that tenant.

### CA401 — High user risk requires remediation
**Plain English:** When Identity Protection flags the *user* (not just one sign-in) as high risk — likely compromised — it requires them to go through Microsoft's self-service risk remediation (secure password reset), not just an MFA prompt.
**Expected issues:** A user who's actually just triggered a false positive (e.g., a shared/kiosk account, or unusual-but-legitimate travel) gets forced through a full remediation flow, which can be disruptive and confusing without warning.
**Solutions:** Have a documented help-desk process for "user says they got locked out for risk" *before* enabling — most cases are legitimate compromises, but false positives need a fast, known resolution path. `MSP-CA-Exclude-RiskPolicies` is for genuine emergency exceptions only, reviewed immediately.

### CA402 — Block elevated insider risk (Disabled)
**Plain English:** Blocks access entirely for users flagged as elevated insider risk by Purview Adaptive Protection (e.g., signals suggesting data theft ahead of resignation).
**Expected issues:** This is a people/HR-sensitive control, not just a technical one — a wrongly blocked employee is a serious, visible incident, and insider-risk false positives are not rare.
**Solutions:** Needs Purview Adaptive Protection properly tuned and, critically, needs HR/legal sign-off on the process *before* this is anything other than Disabled. Don't enable without a clear escalation path for a blocked user that doesn't route through a confused helpdesk tech.

---

## Workload identities (CA500–CA501)

### CA500 — Block high-risk workload identities
**Plain English:** Blocks service principals/app registrations that Identity Protection flags as high risk (e.g., credentials leaked, unusual sign-in pattern for an app).
**Expected issues:** Requires Workload Identities Premium licensing. A flagged-but-legitimate automation (e.g., a script running from a new but valid location) could get blocked.
**Solutions:** Confirm licensing first. Review flagged service principals before assuming they're compromised — investigate, don't just re-enable blindly.

### CA501 — Block workload identities outside trusted locations (Disabled)
**Plain English:** Same idea as CA008, but for service principals instead of humans — only allows app/service sign-ins from your trusted IP ranges.
**Expected issues:** Same "block everyone if the trusted list is wrong" risk as CA008, applied to automation instead of people — potentially worse, since a blocked automated job might fail silently overnight with nobody watching.
**Solutions:** Same discipline as CA008: complete and verify the trusted-location list, including every legitimate cloud service/CI system's egress IPs, before enabling. Monitor the first few runs closely after enabling.

---

## Agent identities (CA700–CA704, all Preview, Disabled)

These target Microsoft's emerging "Agent 365"/AI agent identity surface. Everything here is genuinely new (Microsoft preview), so treat all of it with extra caution.

### CA700 — Block high-risk agent identities
**Plain English:** Blocks AI agents that Microsoft's risk signals flag as compromised or behaving suspiciously.
**Expected issues:** Preview feature — behavior, licensing, and even the exact risk signals it relies on may still change.
**Solutions:** Don't enable for a customer without their explicit, informed sign-off that they're using a preview capability that could change under them.

### CA701 — Block all agent identities from agent resources
**Plain English:** A deny-by-default stance — no agent can reach agent-specific resources unless explicitly permitted elsewhere.
**Expected issues:** If a customer *is* using agents for something real, this blocks all of it until permitted agents are explicitly defined.
**Solutions:** Only enable after deciding exactly which agents should be allowed and building that allow path first — this is a "lock the door first, then hand out keys" policy, not one to flip on casually.

### CA702 — Require compliant device for endpoint-hosted agent users
**Plain English:** If an agent's actions are initiated from a user's endpoint (device), that device must be compliant — same idea as CA302 but for the agent-on-behalf-of-user scenario.
**Expected issues:** Depends entirely on the endpoint already being Intune-managed and compliant (same prerequisite as CA302) — if that's not true yet, this fails immediately.
**Solutions:** Don't enable ahead of CA302/general device compliance being solid for that tenant.

### CA703 — Block risky agent-user sessions
**Plain English:** Blocks agent sessions where Microsoft's agent-risk signals indicate medium or higher risk.
**Expected issues:** Preview risk signals — false-positive rate and tuning are unknowns this early.
**Solutions:** Watch it closely if enabled; treat any block as worth investigating rather than assumed-correct, given how new this signal is.

### CA704 — Restrict agent users to trusted locations
**Plain English:** Same idea as CA008/CA501 but for agent-initiated sessions — only allowed from your trusted network locations.
**Expected issues:** Same trusted-location-list dependency and same "block everything if the list is wrong" risk as CA008/CA501.
**Solutions:** Same discipline: complete and verify the trusted-location list first, and don't enable in the same window as CA008/CA501 so you can tell which policy caused a problem if one appears.

---

## Cross-cutting issues that show up regardless of which policy you're enabling

- **"It worked five minutes ago"** — Conditional Access changes can take a few minutes to propagate, and browser/app token caching can delay when a user actually feels the effect. Don't assume a policy did nothing just because a test didn't immediately show the expected block.
- **Stacking Report-only policies hides real impact** — a Report-only policy shows what *it* would have done, but doesn't show interaction effects with policies already On. Enable in the phased order in DEPLOYMENT.md, not all at once.
- **Emergency-access accounts must be tested from a clean, private browser session** after *every* new policy goes to On — a cached session can mask a break that would otherwise lock out the one account meant to prevent lockouts.
- **CIPP template re-deployment doesn't touch tenant-side exclusion group membership** — updating a template and redeploying will not add/remove anyone from `MSP-CA-Exclude-*` groups; those are managed directly in the tenant, not through the template.
