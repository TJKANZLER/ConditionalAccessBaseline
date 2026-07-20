# Deployment runbook

The repository contains 37 Conditional Access templates and 16 group templates. `Config/MigrationTable.json` is support metadata, not a selectable template.

## 1. Prepare

1. Confirm licensing for each chosen module.
2. Create and test two cloud-only emergency-access accounts with different strong authentication methods.
3. Import the groups and populate `MSP-CA-Exclude-All-EmergencyAccess` before deploying policies.
4. Alert on emergency-group changes and test both accounts from a clean browser.
5. Confirm Security Defaults can be disabled when Conditional Access enforcement begins.

## 2. Import

1. Publish this directory as a GitHub repository.
2. Add `owner/repository` under **Tools → Community Repositories**.
3. Import the 16 group JSON files.
4. Import the 37 Conditional Access JSON files.
5. Do not import `MigrationTable.json`; CIPP uses it automatically for dependency conversion.

If bulk row selection is unavailable in the installed CIPP frontend, import the same folders row by row.

## 3. Deploy in controlled phases

Retain every template's initial state. Use display-name replacement, create missing groups, and preserve CIPP's GDAP/service-provider exception.

| Phase | Policies | Gate before moving to On |
|---|---|---|
| 0 | Groups only | Emergency accounts work and membership alerts fire |
| 1 | CA001 | Legacy-auth dependencies are removed or formally migrated |
| 2 | CA002–CA006 | MFA, TAP, enrollment, CLI, and mobile onboarding tests pass |
| 3 | CA100–CA101 | Every administrator has phishing-resistant authentication and a separate admin identity |
| 4 | CA200–CA202 | Representative B2B collaboration and approved guest-admin workflows pass |
| 5 | CA300–CA303 | MAM, compliance, enrollment, desktop apps, and unmanaged browser tests pass |
| 6 | CA307 | Interactive and noninteractive logs show compatible token-protection clients |
| 7 | CA400–CA401 | Risk detections, self-remediation, licensing, and help-desk procedures pass |
| 8 | CA500 | Workload ID license is present and service-principal report-only results are understood |

Do not enable Disabled templates as a batch. Promote each optional template only after satisfying its dependency in the policy matrix.

## Optional decisions

- Choose CA300 App Protection or CA304/CA305 mobile compliance as the normal mobile model.
- Choose CA302 (Intune compliance) or CA310 (compliant OR hybrid-joined) as the normal Windows desktop model; do not run both.
- Enable CA007 only after deciding how ChromeOS and other platforms are handled.
- Enable CA008 or CA501 only after every legitimate public egress address is represented by a trusted named location.
- Integrate CA104's authentication context with PIM or a sensitive application before expecting evaluations.
- Keep CA308 and CA700–CA704 Disabled while their required features remain Preview unless the customer formally accepts preview use.

## Enforcement and rollback

Change one phase at a time. Review Conditional Access failures, Identity Protection events, service-principal logs, help-desk volume, and CIPP drift before continuing.

For rollback, return the affected policy to Report-only first. Do not delete it during an incident; retaining it preserves configuration and evaluation visibility. Use narrow, time-boxed exclusions only for documented business-critical dependencies, and monitor the group until it is empty.
