# bf-2blf — Repo Hygiene Sweep (2026-07-11 corpus-audit follow-up)

**Task:** Automated hygiene sweep — purge tracked artifacts, dead CI workflows,
README badge drift, and gitignore gaps. Run `repo_hygiene.sh` and fix only the
actionable categories, one commit per category.

## Outcome: NO FIXES REQUIRED

All four fixable categories were already at count 0. The only findings reported
by the checker were the two explicitly **report-only** categories
(`dirty-working-tree`, `stash-pileup`), which the task forbids acting on. This
note is the single commit produced by the bead, per the "no file changes →
create `notes/<bead>.md`" rule.

## Checker (initial run)

```
~/.claude/skills/.../repo_hygiene.sh --json /home/coding/SIGIL   (exit 1)
```

Emitted exactly two finding categories — both report-only:

| category | severity | count | action |
|---|---|---|---|
| `dirty-working-tree` | low | 4 | REPORT-ONLY (untouched) |
| `stash-pileup` | low | 34 | REPORT-ONLY (untouched) |

Dirty-tree files (left exactly as-is — NOT staged, NOT stashed, NOT reset):
`M .needle-predispatch-sha`, `M crates/sigil-backend-env/tests/env_backend_tests.rs`,
`M crates/sigil-backend-pass/tests/pass_backend_tests.rs`,
`M crates/sigil-backend-sops/tests/sops_backend_tests.rs`.

## Per-category verification (all clean)

| Task fix category | Checker category | Result |
|---|---|---|
| (a) missing .gitignore entries | `gitignore-gaps` | **0** — `.gitignore` has `**/target/`, `node_modules/`; `git check-ignore target/` confirms. |
| (b) tracked build artifacts / binaries | `tracked-build-artifacts` | **0** — `git ls-files \| grep -E '(target\|node_modules\|dist\|build\|__pycache__\|*.pyc\|.DS_Store)'` → NONE. Also `large-tracked-files` = 0. |
| (c) dead GitHub Actions workflows | `dead-ci-workflows` | **0** — `git ls-files .github/` → empty; no `.github/workflows/*.yml\|yaml` tracked. Consistent with project rule forbidding GH Actions. |
| (d) README badge drift | `readme-version-drift` + `readme-dead-ci-badges` | **0** — latest tag `v0.4.0`; README version badge reads `0.4.0` (match); CI badge correctly points to "Argo Workflows", no Actions URLs. The "2.0" match is the Apache License version, correctly ignored by the checker. |

`readme-version-drift` was genuinely evaluated (not skipped): a latest tag exists
(`v0.4.0`) and `README.md` is present, so the drift branch ran and found no drift.

## Why everything is already clean

- Build artifacts: prior commit `e9a0d904 chore: untrack build artifacts under
  crates/sigil-fuse/target (already gitignored)` already removed the last tracked
  `target/` blob; `**/target/` is gitignored.
- Workflows: SIGIL's `CLAUDE.md` forbids `.github/workflows/` estate-wide and
  mandates their deletion at the start of every iteration.
- README badges: in sync with tag `v0.4.0`; CI badge already names Argo.

## Acceptance criteria (all met)

- tracked build artifacts = 0 ✓
- dead workflow files = 0 ✓
- gitignore gaps = 0 ✓
- (no hook-blocked categories)

## Constraints honored

No source code touched. No `git stash` / `git clean` / `git reset` / no-verify /
force-push. Only this notes file is committed (staged by explicit path), so the
pre-existing dirty-tree changes are not swept into the hygiene commit.
