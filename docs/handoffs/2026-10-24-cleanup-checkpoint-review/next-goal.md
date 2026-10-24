# Proposed bounded qualification goal

**This goal is proposed, not currently adopted or authorized for execution.** Nathan's explicit adoption starts one finishing session. Accept the cleanup/source milestone already reviewed; do not reopen it as a routine relay.

## Start and scope

Continue in `nathanmcnulty/defender-reporting` from owning checkpoint `9c240298b2feb9c2d5698fcd179296b37d30d78c` on `fix/issue-70-reviewed-cleanup-20261023`. Read [the completed review](review.md) and the pinned owner receipt. This documentation branch contains older runtime code: do not use it as the candidate or merge it into the owning branch. Check current heads and overlapping work first; preserve others' changes and stop on conflicting drift.

Own one bounded qualification session:
1. Diagnose the monolithic preflight's 900-second cap and standalone dump-DOM readiness failure using retained logs and controlled same-source comparisons. Partitioned passes are component evidence, not a full preflight pass. Scheduling is a hypothesis until demonstrated.
2. Make only minimal source or regression repairs justified by a reproduced defect. Independently review and retest them. Do not speculate about performance, optimize lookup serialization without comparative evidence, refresh baselines to hide regressions, or raise timeouts/caps or lower memory floors.
3. Before further scale work, verify sufficient headroom in an already authorized environment under unchanged limits. Do not repeat the blocked 20k cell unchanged. Complete only feasible full-field cold/reload, cache-ineligible worker, fresh-import and identical-input Hosted/Dual comparisons. Reuse valid exact-source evidence; keep replay separate from fresh import and renderer heap separate from process-family memory.
4. Preserve every failed, capped and unrun cell, the retained-profile interruption, the prior HTML comparison failure, and all timing series. Keep historical-scale and live/platform gates for #67/#69/#70 open until actually qualified. Keep PR #93/#92 separate and retain bespoke tests, not Pester.

## One final checkpoint on adoption

**Adoption authorizes one final sanitized source checkpoint on the public repository's existing owning branch**, after overlap checks and without force-pushing. Include only justified source fixes, regressions, harness and sanitized documentation/results. Exclude private operational reports, tenant data, raw historical inputs and credentials. Do not modify this documentation branch as the implementation target.

Return once with the exact pushed revision, independent final review, commands/source hashes, passed/failed/capped/not-run matrix, preserved evidence and issue dispositions. Bundle genuine blockers and the smallest decisions needed while completing unaffected work. If a prerequisite remains unavailable, stop that lane rather than spend the session on unchanged retries.

No dependency installation, new credentials/sign-ins, new environment or resource grants, Azure/Graph/XDR actions, deployment, PR updates, workflow dispatch or CI execution, runtime PR #93 integration, permission changes, merge or resource expansion is authorized. Any such need must remain a separately scoped decision, not an implied extension of adoption.

