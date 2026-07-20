# Source mapping and policy decisions

This repository does not concatenate frameworks. It maps their objectives, removes duplicate enforcement, modernizes retired controls, and keeps dependency-heavy controls as Disabled modules.

| Objective | Sources reviewed | Blueprint decision |
|---|---|---|
| Legacy authentication | Microsoft, j0eyv, ITProMentor, AlexFilipin | One all-human block policy |
| Human MFA | Microsoft, j0eyv, ITProMentor, AlexFilipin | One internal-user authentication-strength policy plus a dedicated guest policy |
| Administrator protection | Microsoft, j0eyv, AlexFilipin | Phishing-resistant MFA, session hardening, and optional compliant-device/CAE/step-up modules |
| Registration and authentication flows | Microsoft, j0eyv, ITProMentor | Separate security-info, device-registration, device-code, and authentication-transfer policies |
| Platform restriction | Microsoft, j0eyv | Unknown-platform block included Disabled because the platform signal is mutable |
| Location restriction | Microsoft, j0eyv | Portable `AllTrusted` scaffolding included Disabled; customer countries/IPs remain tenant data |
| Guest access | Microsoft, j0eyv, ITProMentor | Dedicated MFA/session policies and admin-portal block; service-provider identities omitted |
| Mobile access | Microsoft, j0eyv, ITProMentor | App Protection is primary; compliant-device policies are Disabled alternatives |
| Desktop compliance | Microsoft, j0eyv, ITProMentor, AlexFilipin | Separate Windows, macOS, and optional Linux policies |
| Unmanaged browser | Microsoft, j0eyv, ITProMentor | Exchange/SharePoint app-enforced restrictions |
| Token protection | Microsoft | Supported Exchange/SharePoint native-client scope; Windows Report-only and Apple Preview Disabled |
| Defender session control | Microsoft | Monitor-only browser template included Disabled pending Defender integration |
| Sign-in and user risk | Microsoft, j0eyv, AlexFilipin | MFA-every-time and 2026 `riskRemediation`; no blanket user-risk block |
| Insider risk | Microsoft and Purview | Elevated-risk block included Disabled pending Adaptive Protection and governance approval |
| Workload identities | Microsoft | High-risk and trusted-location policies using the portable all-service-principals selector |
| Agent identities | Microsoft, j0eyv | Five non-overlapping Preview templates included Disabled |
| Service accounts | Microsoft | No normalized user-service-account persona; migrate to workload identities or managed identities |
| Terms of Use and selected apps | Microsoft | Not fabricated because document and application IDs are tenant-specific |

Conditional Access evaluates every applicable policy. Stronger administrator and device controls therefore layer intentionally, while alternative mobile controls and global location boundaries remain Disabled until a customer makes the corresponding architecture decision.
