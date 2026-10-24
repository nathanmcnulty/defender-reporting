# Defender Reporting cleanup review handoff

This text-only handoff packages one independently reproduced cleanup-accounting defect and one complete finishing goal. It changes no application/runtime files. The owner can fetch it directly from Git; no ZIP or manual file transfer is needed.

## Start here

1. Read [the P1 source review](review.md).
2. Adopt [the end-to-end finishing goal](finish-goal.md) when Nathan passes this instruction to the existing implementation session.
3. Use [the offline reproduction](reproduce-cleanup.js), [synthetic results](synthetic-results.json), and [source identities](source-identities.json) as the starting evidence.
4. [Packet manifest](manifest.json) records the exact text-file hashes. Private operational reports and historical input datasets are not part of this packet.

The reported defect is a false successful cleanup: a skipped child can survive after root disappearance or PID reuse while final inventory reports zero and removes the owned profile. The diagnostic reproduces this using actual pinned selection/termination/cleanup code with mocked process APIs. It is not native Windows validation, and it does not demonstrate an unsafe native kill.

## Fetch without disturbing existing work

Repository: [nathanmcnulty/defender-reporting](https://github.com/nathanmcnulty/defender-reporting).

Handoff branch: `codex/defender-cleanup-review-handoff-20261024`.

From an existing clone whose origin is this repository:

```sh
git fetch origin codex/defender-cleanup-review-handoff-20261024
git show FETCH_HEAD:docs/handoffs/2026-10-24-cleanup-review/README.md
```

Read the files with `git show`, or use a separate clean checkout/worktree of that fetched branch. Do not reset, switch over, or overwrite a dirty owner checkout just to read this packet. The implementation destination remains the existing `fix/issue-70-reviewed-cleanup-20261023` branch, after overlap checks.

## Exact source basis

- Original PR #94 baseline: `f341fdd2cf634451a909b69da5ee636dba02fb9f`.
- Harness prerequisite and parent: `63bf26ad27a274cd84aefc47f1f0779b4d397956`.
- Reviewed cleanup head and sole source parent of this handoff commit: `5fdd5de9a2b0a048dea1235313472d4e5041c7b2`.
- The prerequisite and cleanup commits each change only `tests/Measure-DashboardWorkerTransfer.js` and `tests/README.md`. [Exact Git blob and SHA-256 identities](source-identities.json) are included.
- This packet adds only its dedicated handoff directory. PR #93, PR #94, main, and the implementation branch are not updated by handoff publication.

## Run the offline reproduction

Use existing Git, Node, and PowerShell; install or download nothing for this handoff. Both pinned source commits must be available locally, which a normal fetch of the handoff branch supplies through ancestry.

From a clean checkout/worktree containing this packet:

```sh
node docs/handoffs/2026-10-24-cleanup-review/reproduce-cleanup.js
```

If `pwsh` is not on PATH, set `PWSH_EXECUTABLE` to an already installed executable using the shell's normal environment-variable syntax. The driver reads exact source with `git show`, verifies SHA-256, and prints JSON. It does not use current modified harness bytes.

Expected outcomes in both synthetic scenarios:

| Revision | Remaining processes reported | Profile | Result |
| --- | --- | --- | --- |
| Parent 63bf26ad | 2 | Retained | Fails safely |
| Head 5fdd5de9 | 0 | Removed | False pass while synthetic child 102 survives |

Exit zero confirms that these expected defect cases reproduced. It is not cleanup acceptance. After a repair, add proper integrated regressions for the candidate rather than changing the pinned historical controls to hide a failure.

The runner creates only its own temporary profile/runtime directories and removes them afterward. All process inventories, handles, kills, waits, and Windows root matching are mocked. No native process is queried or killed; no browser, network call, Azure action, authentication, or dependency installation occurs.

## Validation limits

The original four-case diagnostic executed on Linux with Node 24.19.0 and existing PowerShell 7.6.6. Syntax, mock, telemetry, generated-worker semantic, and compressed-cache materialization checks passed against the reviewed source. The published runner keeps the tested diagnostic logic, pins Git-source loading, and avoids copying full source snapshots into this packet.

Neither this packet nor passing offline checks establishes native Edge/CIM/IndexedDB acceptance, historical-scale performance, full preflight on the final future repair, or live Azure behavior. Prior PR #93/#94 CI is separate from the new harness head. See the [full review](review.md) for checked statuses and evidence boundaries.

## Authority and completion boundary

Publishing this handoff was requested; no implementation is performed by this packet. The [finishing goal](finish-goal.md) is proposed for Nathan to adopt in the existing owner session. On adoption it includes one final sanitized source push to the public repository's existing implementation branch, with overlap checks and no force-push, so publication does not create another short relay.

That future checkpoint may contain source fixes, regressions, harness, and sanitized documentation/results only. Keep raw operational reports, tenant data, and historical inputs private. Do not merge, dispatch workflows, change permissions, create credentials or new sign-ins, access Azure/Graph/XDR, install/download dependencies, or expand resources under this goal. Keep runtime PR #93 and issue #92 separate, and leave unmet scale/live gates open.

Return one exact pushed implementation revision with the final review and passed/failed/not-run matrix, or bundle genuine blockers while finishing independent work.

