# Defender monitor safety review and proposed finishing goal

## Decision

The exact [reviewed owning checkpoint e4da5bdf](https://github.com/nathanmcnulty/defender-reporting/commit/e4da5bdfa9487eac7f18c193c12245716edd1c38) includes inventory commit `03ae6da3310fa3ccb3b564e2df1baa567bdcba1b`. **Cleanup acceptance is blocked by one P1 handle-binding race and two P2 ownership-accounting gaps.** The single-CIM memory correction is accepted narrowly, not as native timeout/performance qualification.

Read [the full review and one consolidated proposed goal](review-and-goal.md). It includes exact source-line links, independent checks, producer-only observations, preserved failures and scope boundaries. The goal is a proposal for the owner to adopt. Publishing this handoff does not authorize execution of that goal.

This documentation branch contains older runtime source. **Do not run qualification against it or merge it into the owning branch.** Future adopted work starts from `e4da5bdfa9487eac7f18c193c12245716edd1c38` on `fix/issue-70-reviewed-cleanup-20261023`, after checking overlap. Runtime/product implementation is unchanged by this additive handoff publication.

## Included material

- [Review and proposed goal](review-and-goal.md).
- [Runnable cleanup counterexamples](Invoke-CleanupOwnershipGapRepro.ps1).
- [Sanitized synthetic results](synthetic-results.json).
- [Reviewed source identities](source-identities.json).
- [Exact upstream PowerShell/.NET source identities](upstream-source-identities.json).
- [SHA-256 manifest](SHA256SUMS), covering every other file in this directory.

Only public-source references, review text, synthetic fixtures and synthetic results are included. No tenant data, credentials, operational reports or private historical inputs are published. Random temporary-directory names in the stored result are replaced with explicit synthetic labels.

## Reproduce offline

Use an existing PowerShell 7 installation. The review used PowerShell 7.6.6 and .NET 10.0.12 on Linux. No installation or native Windows test is requested. Keep this documentation checkout separate from an exact reviewed-source checkout. For example, in a local clone where both commits are already available:

```sh
git worktree add --detach ../defender-monitor-reviewed e4da5bdfa9487eac7f18c193c12245716edd1c38
pwsh -NoProfile -File docs/handoffs/2026-10-24-monitor-safety-review/Invoke-CleanupOwnershipGapRepro.ps1 -SourceRoot ../defender-monitor-reviewed
```

If the exact commit is not locally available, fetch the public owning branch first using your normal repository access. The driver verifies both exercised production-file SHA-256 values before loading them. It intentionally refuses altered source and the old source in this handoff branch. It executes the unmodified helper and the AST-extracted actual finalizer, replacing Windows detection, native profile parsing and every process inventory/termination API with explicit synthetic equivalents. It launches no browser and stops no real process.

By default, filesystem removal is mocked. Optional `-RealTemporaryFiles` creates isolated fixture directories in the operating system temporary directory and lets the actual finalizer remove only those directories. No existing profile or site is used. Run in a disposable PowerShell process, not dot-sourced into a working shell. The publication-adapted driver changes only source-root selection and exact-hash preflight; scenario assertions retain the original reviewed logic.

**Exit 0 means all three counterexamples reproduced the defects, not that product cleanup passed.** The scenarios demonstrate: a late-born child survives a clean verdict; a primary-source-supported post-StartTime PID-reuse model selects a replacement; and repeated cleanup removes a fixture profile after forgetting a known survivor. The last scenario still records the overall outcome as `cleanup-failure`. The PID-reuse model is not a native exploit demonstration. When implementing repairs, turn these into appropriate discriminating regressions and positive controls rather than treating successful reproduction as acceptance.

## Evidence and authorization boundaries

The producer-reported standalone 11.609-second pass and instrumented verification of 826,434 field values per load do not erase the uninstrumented five-second inventory timeout or establish stable native qualification. Private evidence was not accessible to this review. Historical/monolithic/live gates and issues #67/#69/#70 remain open; PR #93 remains separate and #92 retains bespoke tests.

One future adopted goal covers all cleanup fixes, discriminating tests/review, bounded inventory diagnosis and feasible acceptance within existing resources, followed by one sanitized owning-branch checkpoint or one genuine blocker bundle. No current native execution, code fix, resource expansion, unrelated process stop, credential/Azure action, workflow/PR change, deployment or merge is authorized by this handoff.
