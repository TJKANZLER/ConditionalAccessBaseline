# Conditional Access baseline benchmark

Snapshot date: 2026-07-28.

This repository is designed for repeatable multitenant deployment through CIPP. It is benchmarked against four public projects with overlapping goals:

- [Microsoft Conditional Access for Zero Trust resources](https://github.com/microsoft/ConditionalAccessforZeroTrustResources)
- [AlexFilipin Conditional Access as Code](https://github.com/AlexFilipin/ConditionalAccess)
- [Kenneth van Surksum Conditional Access baseline 2025-10](https://github.com/kennethvs/cabaseline202510)
- [Aollivierre Modern Conditional Access Baseline](https://github.com/aollivierre/ConditionalAccess)

The comparison is architectural, not a claim that every policy from every project should be copied. Tenant-specific controls, mutually exclusive designs, retired settings, and preview features are deliberately filtered out.

## Comparative position

| Area | This repository | Stronger peer capability | Assessment |
|---|---|---|---|
| CIPP portability | Stable placeholder IDs, group templates, migration mapping, and exact package membership | Kenneth and Aollivierre also ship import mappings and broader supporting artifacts | Strong, with fewer tenant objects to maintain |
| Deployment structure | Five non-overlapping packages with explicit licence/readiness gates | Alex provides multiple P1/P2 policy-set variants | Strong for a standardized MSP service; less flexible for bespoke architectures |
| Policy safety | Every policy is Report-only; emergency access, directory sync, GDAP, registration, and enrollment dependencies are checked | Microsoft provides broader governance guidance and What If/workbook tooling | Strong static safety; tenant-side evidence remains an operator responsibility |
| Determinism | One generator produces every policy, group, and migration mapping; CI rejects drift | Peer repositories primarily contain exported artifacts or broad script collections | Strong |
| Policy breadth | 30 production policies covering P1, Intune, P2, workload, Defender, and Purview paths | Kenneth has 49 CA policies; Alex has a 59-policy library; Aollivierre includes 44 CA policies plus supporting Intune/location artifacts | Intentionally smaller, but no longer missing generally available authentication-transfer protection |
| Supporting configuration | Groups are included; prerequisites and readiness gates are documented | Aollivierre includes authentication strengths, filters, named locations, Terms of Use, MAM, and compliance artifacts | Weaker breadth; some dependencies remain outside this repository |
| Direct automation | Relies on CIPP Standards and CIPP drift management | Alex can deploy/update/remove policies and named locations directly; Aollivierre includes sign-in analysis tooling; Microsoft includes DSC, Terraform, and workbooks | Weaker by design, but CIPP-specific rather than tool-agnostic |
| Reporting and testing | Static validator, acceptance test matrix, and promotion runbook | Microsoft workbooks and Aollivierre sign-in-log analysis provide richer live evidence | Structured and repeatable, but no automated tenant-side What If or report-only analytics |
| Operator clarity | Exact policy matrix, package gates, exception governance, troubleshooting, and source mapping | Kenneth provides a generated visual policy report; Microsoft provides extensive architecture material | Strong written runbook; weaker visualisation |
| Repository governance | Changelog and CI are present | Microsoft and Alex publish explicit licence and contribution/security material | Weaker; licence choice and release governance still need owner decisions |

## What this repository does better

1. **It is a deployable service definition, not a policy dump.** Every shipped policy belongs to exactly one activation package, and every package has a readiness gate.
2. **It reduces cross-tenant object debt.** Sixteen purpose-specific groups cover the suite instead of creating a separate include/exclude pair for nearly every policy.
3. **It prevents known portability and lockout regressions in code.** The validator checks emergency-access mappings, Directory Synchronization Accounts, CIPP/GDAP scope, Device Registration Service, token-protection resources, authentication transfer, retired grants, and package completeness.
4. **It has one declared production path.** Mutually exclusive device models, inert placeholders, and preview-only policies are not mixed into the selectable catalog.
5. **It separates licence boundaries without calling security controls optional.** P2, Workload ID Premium, Defender, and Purview controls are production packages with explicit gates.

## Where it is weaker

1. **Trusted named locations are dependencies, not generated artifacts.** IP ranges and countries are tenant data and must not be fabricated, but the suite still depends on operators creating and validating them in CIPP before Core enforcement.
2. **Intune prerequisites are not bundled.** CA300 and CA302–CA306 require real App Protection and compliance policies. This repository validates the access layer, not the device-management layer beneath it.
3. **There is no live tenant test harness.** Report-only results, Conditional Access What If scenarios, exclusion tests, and rollback drills are manual evidence in the runbook.
4. **There is no visual policy document.** Peers using Conditional Access Documenter are easier to review visually.
5. **Protected-action wiring is not automated.** Requiring authentication context before editing Conditional Access is valuable, but the policy is ineffective until the tenant's authentication context and protected actions are configured.
6. **There are no environment variants.** The baseline deliberately chooses a managed endpoint model; organizations needing hybrid-join alternatives, country blocks, Global Secure Access, or app-specific tiers must extend it deliberately.
7. **Public reuse terms are not explicit.** The repository has no licence file, so a licence must be selected by the owner rather than inferred from peer projects.

## Actions taken from this review

- Moved trusted-location guardrails into the Core P1 package.
- Added CA006 to block authentication transfer with a dedicated exception group.
- Added continuous validation in GitHub Actions.
- Added a package-by-package acceptance test matrix with expected allowed and denied paths.
- Retained named locations, country lists, Terms of Use documents, and protected-action wiring as explicit tenant-owned configuration instead of shipping unsafe placeholders.

## Next improvements

The highest-value remaining work is tenant-side assurance rather than adding more generic policies:

1. automate a post-deployment inventory that proves all 30 policies exist in Report-only with resolved group IDs;
2. export report-only outcomes and exception membership into a reviewable evidence bundle;
3. add a repeatable What If scenario matrix for emergency access, admins, guests, managed devices, unmanaged browsers, service accounts, and service principals;
4. generate a visual policy report for release artifacts;
5. select and publish an explicit licence, security policy, and contribution model;
6. publish versioned releases after CI passes.
