# Troubleshooting guide

How to actually diagnose "a user can't sign in" once a policy from this library is involved. Pairs with [POLICY-GUIDE.md](POLICY-GUIDE.md) (what each policy does and its known failure modes) — this doc is the general workflow and where to look; POLICY-GUIDE.md is what to expect once you know which policy is responsible.

---

## The three places you'll live

1. **Entra sign-in logs** (`entra.microsoft.com` → Identity → Monitoring & health → Sign-in logs, or Azure AD Portal → Sign-ins) — the actual record of what happened, per sign-in attempt.
2. **Conditional Access "What If" tool** (Identity → Protection → Conditional Access → What If) — simulates a sign-in for a given user/app/conditions and tells you exactly which policies would apply, without waiting for the user to actually try and fail.
3. **CIPP itself** — Tenant → Administration → Conditional Access (view current deployed state per tenant), Tenant → Standards/Best Practice Analyser, and CIPP's own logbook for what CIPP has changed and when.

Start with #1 for "why did this specific sign-in fail." Use #2 to test a fix before deploying it. Use #3 to confirm what's actually live in that tenant right now — the repo's Report-only/Disabled starting state doesn't tell you what a tenant has actually been promoted to.

---

## Step-by-step: diagnosing a single user's block

1. **Get the specifics from the user**: exact time (to the minute if possible), what app/service they were using (Outlook desktop? Outlook mobile? a browser? which URL?), and the exact error text or screenshot if they got one.
2. **Find the sign-in in the log.** Filter by User Principal Name, narrow the time window, and if it's not an interactive sign-in (a service, a background token refresh, an app), check the **Non-interactive sign-ins** and **Service principal sign-ins** tabs too — most complaints are interactive, but scheduled tasks/scripts show up elsewhere.
3. **Open the event and go to the Conditional Access tab.** Every policy that was evaluated shows one of:
   - **Success** — the policy applied and its requirements were met.
   - **Failure** — the policy applied and blocked the sign-in, or its grant requirement wasn't satisfied. This is almost always the one you want.
   - **Not applied** — the policy's conditions (user/app/platform/location) didn't match this sign-in, so it was irrelevant here.
   - **Not enabled** — the policy is Report-only or Disabled; it's shown for visibility but did not affect the outcome.
4. **Identify the policy in "Failure."** Its name tells you which `MSP-CA###` this is. Go to that policy's row in [POLICY-GUIDE.md](POLICY-GUIDE.md) for what it does and the fix pattern.
5. **Check the failure reason and the `Status` → `Failure reason` field** on the event itself — it's usually a plain-English sentence ("Blocked by Conditional Access", "MFA required, but MFA registration is not present", "Device is not compliant", etc.) that confirms what you already inferred from step 4.
6. **Decide: legitimate block, false positive, or bootstrap problem** (see the decision guide below) before you touch any group membership.

---

## Reading common failure reasons (AADSTS error codes)

Users and helpdesk tickets often quote the raw error code shown on the sign-in screen rather than what you'd see in the log. This maps the common ones to what's actually happening and where to look.

| Code | What it means | Likely policy | What to check |
|---|---|---|---|
| **AADSTS53003** | Blocked by Conditional Access, generic. | Any block policy (CA001, 005, 006, 007, 008, 202, 402, 500, 501, 700, 701, 703, 704) | Open the sign-in log — the CA tab tells you exactly which one, the generic error text on screen won't. |
| **AADSTS50076 / AADSTS50079** | MFA required but not completed / MFA registration required. | CA002, CA100, CA200, CA400, CA401 | Check the user's registered authentication methods (below). If they have none, this is a bootstrap issue (CA003/TAP), not a bug. |
| **AADSTS50158** | External/conditional access security challenge — often device-related or risk-based step-up. | CA400, CA401, CA104 | Check Identity Protection's risk detections for that user/sign-in, or confirm the authentication context (CA104) is actually wired up. |
| **AADSTS53000 / AADSTS53001** | Device is not compliant / not registered/joined. | CA102, CA302, CA303, CA304, CA305, CA306, CA310, CA702 | Check the device's compliance state in Intune (below) — don't assume the policy is wrong before checking the actual device state. |
| **AADSTS50155** | Device authentication failed — often a broken or missing device certificate/token. | CA102, CA302/303/306, CA307 (token protection) | Usually a device-side fix: re-register the device, check WHfB/device cert health, or check the token-protection client compatibility list. |
| **AADSTS50097** | Device confirmation required — the tenant expects a managed/registered device and doesn't see one. | CA102, CA302–CA306, CA310 | User is likely on an unmanaged or unregistered device. Confirm enrollment status rather than assuming a false positive. |
| **AADSTS900023 / "unsupported client"** | Legacy or unsupported client protocol used. | CA001 | This is almost always working as intended — an old client needs replacing, not excepting. |
| **AADSTS50131** | Device is disabled, or a Conditional Access location/network policy blocked it. | CA008, CA501, CA704 | Check whether the sign-in's IP falls inside a Named Location marked Trusted. This is the most common false-positive source in the whole library. |
| **AADSTS500011 / resource not found for tenant** | Not a CA issue — usually a licensing or app-registration problem masquerading as one. | — | Rule this out before chasing a CA policy that isn't actually involved. |

If a code isn't in this table, search it directly — Microsoft documents the full AADSTS error code list, and it changes over time.

---

## Checking the things a CA failure usually turns out to be

### MFA / authentication method registration
Entra → Identity → Users → (user) → Authentication methods. Confirms whether they have zero methods (a CA003/TAP bootstrap issue), only weak methods like SMS (relevant if CA100 or the Enhanced tier's method-restriction controls are live), or a phishing-resistant method registered but not the *default* one they're being prompted with.

### Device compliance
Intune admin center → Devices → All devices → (device) → check **Compliance** and click into it for the specific failing check (encryption, OS version, antivirus, etc.), not just the pass/fail state. A device can be "enrolled" but still non-compliant — those are different problems with different fixes.

### Group / exclusion membership
Entra → Groups → search `MSP-CA-Exclude-*` or `MSP-CA-Allow-*` → Members. This is also where you confirm a fix actually landed — CIPP redeploying a template does **not** touch group membership (see POLICY-GUIDE.md's cross-cutting notes); membership changes happen directly against the group.

### Named Locations / trusted IPs
Entra → Identity → Protection → Conditional Access → Named locations. If CA008/CA501/CA704/CA103 are involved, confirm the failing sign-in's source IP is actually inside a location marked "Mark as trusted location" — a location existing isn't enough, it has to be flagged trusted.

### Risk state (Identity Protection)
Entra → Identity → Protection → Identity Protection → Risky sign-ins / Risky users. Relevant for CA400/CA401 — confirms whether a block was a genuine risk detection (investigate before dismissing) or something to whitelist as a known-safe pattern (e.g., a user who travels between two fixed offices and keeps tripping "atypical travel").

---

## Is it a real bug, a bootstrap problem, or working as intended?

| Symptom | Usually means | Don't do this | Do this instead |
|---|---|---|---|
| Brand-new user/device can't get past MFA at all | Bootstrap deadlock (CA002/CA003/CA004) — they need MFA to register MFA | Add them to a permanent exclusion | Issue a Temporary Access Pass |
| One specific legitimate app/device stopped working after enabling a policy | Working as intended, but the client needs to catch up | Blanket-disable the policy | Fix or replace the client (modern auth, current build, Intune enrollment) |
| Everyone, everywhere, all at once, is blocked right after enabling CA008/CA103/CA501/CA704 | Trusted-location list is empty or wrong | Panic-exclude everyone | Revert that one policy to Report-only immediately, fix the Named Locations, retest before re-enabling |
| A single user intermittently blocked, no clear pattern | Sign-in risk false positive, or genuinely risky | Silently add to an exclusion group | Check Identity Protection's risk detail for that sign-in before deciding either way |
| "It was fine five minutes ago and now it's broken" / "I fixed it and it's still broken" | Propagation or token/browser caching delay | Assume the fix didn't work | Wait a few minutes, then retest from a fresh/private browser session, not the same cached one |

---

## Before you add anyone to an exclusion group

Every `MSP-CA-Exclude-*` group is deliberately narrow-scoped to one control (see POLICY-MATRIX.md's overlap rules and POLICY-GUIDE.md's per-policy notes) — adding someone doesn't just "fix this one thing" if you pick the wrong group, since some groups (like `MSP-CA-Exclude-DeviceCompliance`) are shared across several policies. Before adding anyone:

1. Confirm via the sign-in log which specific policy failed — don't guess from the symptom alone.
2. Confirm the *right* exclusion group for that specific policy (check POLICY-GUIDE.md's table — the group name is called out per policy where relevant).
3. Treat every addition as temporary and tracked — who, why, and a review date — never a silent permanent fix. `MSP-CA-Exclude-All-EmergencyAccess` is the only group meant to be genuinely static.
4. If you can't find the exact right group or aren't sure, revert the *policy* to Report-only rather than widening an exclusion group's membership as a workaround.

---

## Quick sanity checks before assuming CIPP or the policy is broken

- **Wait a few minutes.** Conditional Access changes aren't always instant, and browsers/mobile apps cache tokens.
- **Test from a genuinely fresh session** — a private/incognito window, or a full sign-out and back in, not just a page refresh.
- **Confirm the policy is actually On in that tenant**, not just present in the repo — CIPP → Tenant → Conditional Access shows live state, which can differ from this repo's default Report-only/Disabled starting point once a tenant has been through DEPLOYMENT.md's phased rollout.
- **Check the What If tool** for the exact user/app/platform combination before spending time in the raw logs — it'll often show you the answer in ten seconds.
- **Check whether more than one policy applies.** Conditional Access is additive — a user might be satisfying the policy you're looking at but failing a completely different one further down; the sign-in log's CA tab lists every policy evaluated, not just the one you expected.
