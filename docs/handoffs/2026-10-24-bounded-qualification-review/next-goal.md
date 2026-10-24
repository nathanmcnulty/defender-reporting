# Proposed bounded local qualification finish

**This is proposed work, not current execution authorization. Nathan must explicitly adopt it.** Keep the accepted cleanup/singleton milestone closed; finish the remaining local diagnostic and qualification work as one bounded owner session, not a sequence of routine relays.

## Start from the owning source

Use `nathanmcnulty/defender-reporting`, branch `fix/issue-70-reviewed-cleanup-20261023`, starting at `1cb958bf513f034a5aabbae293ff43581490bbb5`. Verify runtime source remains identical to `9c240298b2feb9c2d5698fcd179296b37d30d78c`, reconcile overlap, and preserve others' work. Do not use or merge the documentation branch's older runtime.

## One bounded session

1. Establish a stable execution window in the already authorized VM. Recheck existing admission thresholds and retain all runtime guards. Small confirmation requires the reported 4.25-GiB admission estimate; monolithic requires 4.5 GiB; native scale requires 5.25 GiB sustained, approximately 5.5 preferred. These are prerequisites, not guarantees or permission to acquire resources, stop unrelated processes or relax limits. Stop unavailable lanes rather than repeat admission indefinitely.
2. Complete a coherent controlled flag-confirmation sequence with identical full assets, observations, original timeouts and isolated profiles. Refresh the initial control if the gap between sessions prevents comparability. Removing `--disable-gpu` is a candidate, not a predetermined fix or proof of hardware-GPU behavior. Preserve both original failures and the lone scratch pass. Only a reproduced discriminating result can justify a minimal harness repair; independently review/retest it and pass the actual checked-in standalone gate, not only an observed scratch copy.
3. When admitted, run one timestamp-observed monolithic preflight under the unchanged 900-second cap, without concurrent qualification work. Preserve its actual outcome. Component passes do not substitute for this single-command gate.
4. Complete only feasible full-field cold/reload, representative worker/cache-ineligible and fair identical-input comparisons under existing limits. Reuse valid exact-source evidence, distinguish fresh import from replay, and do not repeat known capped imports unchanged. Do not optimize speculatively, refresh baselines to hide failures, or change application scheduling without a demonstrated defect.
5. Verify and index the final local evidence package, including the consolidated report/archive, exact command/source identities and every passed, failed, capped, refused-admission and not-run cell. Do not publish raw private observations.

## One final result on adoption

**Nathan's adoption authorizes one final sanitized checkpoint on the existing public owning branch**, after overlap checks and without force-pushing. Include only justified source/harness fixes, regressions and sanitized documentation/results. Exclude private operational reports, raw historical inputs, tenant data, credentials and machine paths.

Return once with the exact pushed revision, independent final review, evidence index and outcome matrix, bundling genuine remaining blockers and the smallest decisions needed. Preserve #67/#69/#70 historical-scale/live gates; retain bespoke tests and keep PR #93/#92 separate. This milestone does not promise historical or live-Azure closure.

No dependency installation, new environment/resource allocation, process stopping to manufacture headroom, weaker guards, raised caps/timeouts, new sign-ins or credentials, Azure/Graph/XDR actions, runtime PR #93 integration, CI/workflow dispatch, PR changes, deployment, permission changes or merge is authorized. Review and publication of these instructions alone grant none of the future execution or checkpoint authority described above.

