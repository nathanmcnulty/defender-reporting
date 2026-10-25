# Defender consolidated cleanup review and proposed next goal

**Accept the three earlier narrow repairs. One inherited P2 remains in the JavaScript cleanup harness; comprehensive cleanup and qualification remain open.** This is an additive documentation/synthetic-evidence handoff, not an implementation change or a merge recommendation.

Start with [the full review and consolidated proposed scope](review-and-goal.md). Reviewed owning head is [f0dd25699f310647c763c29c92aeb250493f5c39](https://github.com/nathanmcnulty/defender-reporting/commit/f0dd25699f310647c763c29c92aeb250493f5c39), containing source repair `c0cedf5902e47d1386620ee30479e55fc1ace17a`. The prior P1 handle-binding race and both standalone accounting findings are repaired. The remaining JS child-born-during-Kill gap also reproduces on baseline `e4da5bdfa9487eac7f18c193c12245716edd1c38`; it is not introduced by c0cedf59.

This documentation branch has older runtime source. **Do not use its runtime for qualification or merge this branch into the owning branch.** A future adopted goal starts from the exact owning f0dd2569 checkpoint after overlap checks. Publication of this package does not itself adopt or authorize that goal.

## Files

- [Full review and one proposed goal](review-and-goal.md).
- [Portable offline JavaScript reproduction](run-js-late-child-repro.js).
- [Sanitized current/baseline synthetic results](synthetic-results.json).
- [Source and original-artifact identities](source-identities.json).
- [SHA-256 manifest](SHA256SUMS), covering all other files here.

The reproduction passes only when the defect is observed: a synthetic child survives, actual cleanup returns zero survivors/no errors, and its freshly created fixture profile is removed. Exit 0 is **not** cleanup acceptance. No real process is inventoried or terminated and no browser is launched. The only actual deletion affects isolated directories created by this diagnostic.

## Run with existing tools, offline

Use existing Node.js and PowerShell 7 installations. Review used Node 24.19.0, PowerShell 7.6.6 and .NET 10.0.12 on Linux. Install nothing for this handoff without separate approval. From a clone containing the exact commits, keep this documentation checkout separate from the reviewed-source worktree:

```sh
git -c core.autocrlf=false worktree add --detach ../defender-reviewed-f0dd f0dd25699f310647c763c29c92aeb250493f5c39
node docs/handoffs/2026-10-25-consolidated-cleanup-review/run-js-late-child-repro.js --source-root ../defender-reviewed-f0dd
```

For the optional old/current comparison, also prepare baseline source and supply it:

```sh
git -c core.autocrlf=false worktree add --detach ../defender-baseline-e4da e4da5bdfa9487eac7f18c193c12245716edd1c38
node docs/handoffs/2026-10-25-consolidated-cleanup-review/run-js-late-child-repro.js --source-root ../defender-reviewed-f0dd --baseline-root ../defender-baseline-e4da
```

If commits are absent, fetch the public owning branch using normal repository access first. The driver verifies exact SHA-256 values before executing any extracted source; old documentation-branch source, changed code and changed line endings are refused. `--pwsh EXISTING_EXECUTABLE` optionally selects an already installed PowerShell executable; otherwise `pwsh` is used from PATH. No downloads occur.

The portable driver adapts the reviewed diagnostic's source locations, adds exact-byte guards, confines generated scripts/profiles/XDG files to a new operating-system temporary directory, sanitizes output paths and removes only that new temporary directory afterward. It retains the actual selected production functions and counterexample. Windows platform/native argv parsing is replaced explicitly; all PowerShell process APIs are fixture functions. It prints JSON evidence to stdout. Common cleanup code is extracted from current source; the relevant cleanup implementation is unchanged from baseline. This is not native fault injection or a complete application run.

## Limits and next decision

The reported plain-inventory 20k candidate/base cold/reload pair checked 826,434 fields per load, but is one correctness pair, not a performance series. Standalone readiness still failed at 12.890 seconds. The 4,874.966-ms ResourceGuard interval includes more than inventory and is not a proved 125-ms timeout margin. Exact-head CI, historical/live gates and previous caps remain unresolved; private operational evidence was not independently accessed.

The proposed consolidated goal closes the remaining JS accounting gap first, then uses existing local traces to investigate readiness/inventory variability before any justified bounded confirmation. Preserve the accepted repairs, failed measurements, unchanged resources, #67/#69/#70, separate PR #93 and bespoke tests. Later adoption includes one final sanitized owning-branch checkpoint or one bundled blocker report. No current code fix, native/live work, resource expansion, credential/Azure action, workflow/PR change, deployment or merge is authorized here.
