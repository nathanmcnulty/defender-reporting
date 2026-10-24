# Bounded finish: admission result and bundled blockers — 2026-10-24

## Authority and source

Nathan adopted [dot's bounded local finish goal at 8159174](https://github.com/nathanmcnulty/defender-reporting/blob/815917468ba72e5f321d0965417820ad5c2fe78d/docs/handoffs/2026-10-24-bounded-qualification-review/next-goal.md). Work started from clean owning head `1cb958bf513f034a5aabbae293ff43581490bbb5` on `fix/issue-70-reviewed-cleanup-20261023`, verified against the remote. All **173** prior runtime/source entries retain identical Git objects, modes and types from `9c240298b2feb9c2d5698fcd179296b37d30d78c`. The intervening owning commits change only the earlier qualification README. The documentation branch's older runtime was read only for instructions, never used as the candidate or merged.

This result is a documentation/evidence checkpoint with bundled resource blockers. No new application, harness, generated source or test change was justified. The accepted cleanup-accounting/singleton milestone remains accepted.

## One admission window; no workload launched

Five physical-memory samples, two seconds apart over approximately eight seconds, were taken once in the existing authorized VM. The minimum was **3,470,831,616 bytes (3.232 GiB)** out of 17,109,004,288 bytes total physical RAM.

| Lane | Existing admission estimate | Decision |
|---|---:|---|
| Coherent small GPU-flag confirmation | 4.25 GiB | REFUSED ADMISSION; no cell launched |
| One timestamp-observed monolithic preflight | 4.5 GiB | REFUSED ADMISSION; no run launched |
| Native full-field/cache-ineligible/representative scale | 5.25 GiB sustained; about 5.5 preferred | REFUSED ADMISSION; no cell launched |

The minimum was 1,092,571,136 bytes (1.018 GiB) below small-native admission. These estimates remain planning margins, not guarantees or resource grants. They are separate from the unchanged **3-GiB physical-free runtime floor**. Native guards remain 240 seconds/2-GiB family cap/3-GiB floor; the monolithic guard remains 900 seconds/3-GiB family cap/3-GiB floor. All inner probe/readiness/virtual-time/cleanup budgets remain unchanged. No process was stopped to manufacture headroom, no limit was relaxed and no repeated admission loop was pursued.

Because a stable, adequately admitted execution window was unavailable, all three lanes stopped before native, supervisor or preflight launch. The elapsed inter-session gap was not ignored: the earlier lone default-GPU pass was not stitched to hypothetical new cells. A future admitted confirmation needs one coherent controlled sequence with a refreshed initial control, identical complete assets, observations, original timeouts and isolated profiles. A discriminating repeatable result must precede any harness repair, independent review and actual checked-in standalone-gate retest.

## Retained outcomes, not new passes

| Evidence | Status retained from prior sessions |
|---|---|
| Exact-source 13-file JavaScript stages | PASS plain 112.656s and 256-MiB 114.187s; component evidence only |
| Monolithic preflight | TIME-CAPPED at 900.438s; not passed; original silent interval unresolved |
| Scratch standalone baseline/compositor | Readiness FAIL at 11.610s/9.609s; requested frame did not fire |
| Scratch removal of explicit disable-GPU flag | One PASS at 10.641s; candidate association only |
| Subsequent missing GPU confirmations | NOT RUN; earlier attempts were refused admission, not failed tests |
| Full-field/cache/worker and historical-scale qualification | Outstanding; no new result in this finish |

No new runtime test ran. Component passes do not establish monolithic continuity; the flag association does not establish hardware-GPU causality, stability, a repaired harness or application exoneration. Preserve the earlier null flag-metadata limitation and runtime/PDF-module parity caveat in [the owning receipt](../2026-10-24-bounded-qualification/README.md).

The earlier six alternating 20k fresh imports and twelve identical-input 120k Hosted/Dual cells retain their original source/scope. Fresh import remains separate from completed-store replay, renderer heap from process-family memory, and field-content proof from counts. Preserve the 120k fresh-import caps, raw HTML comparison failure and its separate strict review that omitted `generatedOnUtc` and canonicalized only the exact-key metadata object's key order, retained interrupted profile, and +6.61%/+6.69% versus later +3.51% replay series. No known capped import or blocked scale cell was repeated unchanged; no baseline was refreshed or speculative optimization made.

Hosted CI `39735467316` passed deterministic preflight and Azure package smoke on original `f341fdd2` after the dated receipt. That remains separate from the earlier capped Windows attempt and is not exact-head CI acceptance.

## Evidence verification and remaining decisions

The owner freshly verified **14 retained reports/archives/review artifacts** by SHA-256. Independent local review verified the consolidated 64-entry package and the later six-entry refused-admission package, their CRCs, the source identities and new admission arithmetic. The earlier consolidated package did exist before publication: SHA-256 `81ccdd1d37a40af30725fe5664745f409cb56020d03aa985cd88e646f29ff357`; consolidated report `b48aa0c030069e5179c3b09e53f7ea253cd2efb47f01013bb47f317064276301`. This resolves the public review's uncertainty about owner-side packaging, without claiming that public hashes alone let outside reviewers inspect private evidence.

New admission receipt SHA-256: `1f0143b64e8c387c06df60916ba66041b86eb586557e6a37a583e2dc7beb3a47` (the admission receipt contains all five raw samples). Source/preservation audit: `2fe2be5e94739c3f1b96b1341204dec8eea858fc4bcaa57935ff3abf02da11f4`. Independent retained-evidence review: `3c060e704cd7d637865ee4fae1e3ac2be43989174163f8fe1b9a202fb61f92e3`. A new consolidated local report/archive and full hash index must be generated and verified before this final sanitized checkpoint is pushed. Commands, complete hashes, raw memory samples, review receipts and private paths remain local; earlier artifacts are not overwritten.

**#67, #69 and #70 remain open.** Historical 50k-device/1.5M-observation import, Automation below-400-MB, representative packaging/LOH, full worker/cache-ineligible envelopes and live/platform qualification remain unmet. PR #93/#92 stay separate; bespoke tests remain in place.

The bundled local prerequisite is one adequately admitted execution window in the already authorized environment. This does not request or authorize RAM purchases, resizing, process termination or another environment. No human action is required to accept this diagnostic checkpoint. If local qualification is resumed later, check admission and conflicting work again; unavailable lanes must stop. Live Automation/Function work requires separate target/access/action authorization. No installation, new credentials/sign-in, Azure/Graph/XDR action, resource change, CI/workflow execution, PR change, deployment, permission change or merge occurred.
