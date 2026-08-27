# Contributing

Conditional Access changes can lock out users or create a false sense of protection. Every contribution must therefore be generated, reviewable, and safe to import.

## Required workflow

1. Change `tools/New-CippCaBlueprint.ps1` rather than editing generated policy or group JSON by hand.
2. Keep every deployable policy in `enabledForReportingButNotEnforced` state.
3. Add or update semantic assertions in `tools/Test-CippCaBlueprint.ps1` for every security-relevant relationship.
4. Update package readiness gates, `POLICY-MATRIX.md`, `POLICY-GUIDE.md`, `TEST-PLAN.md`, and `CHANGELOG.md` where behavior changes.
5. Run the generator and validator with PowerShell 7:

   ```powershell
   ./tools/New-CippCaBlueprint.ps1
   ./tools/Test-CippCaBlueprint.ps1
   ```

6. Review the generated JSON diff. Do not approve unresolved placeholder IDs, undocumented exceptions, preview-only fields, or an enabled policy.

## Evidence standard

Link security behavior and application IDs to current first-party Microsoft documentation. State licence and service-side prerequisites explicitly. A passing static validator does not replace report-only sign-in evidence, What If testing, emergency-access testing, or the acceptance plan.

Never commit tenant exports, user identifiers, access tokens, incident evidence, IP inventories, credentials, or real emergency-access account details.
