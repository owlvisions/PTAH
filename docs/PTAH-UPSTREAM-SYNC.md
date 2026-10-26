# Keeping PTAH current with REA upstream

PTAH is developed as a compatibility-preserving layer on top of the public
[`morluto/rea`](https://github.com/morluto/rea) repository. The upstream project
is active, so a downloaded source snapshot alone cannot stay current. This
repository includes an optional GitHub Actions workflow that periodically
checks upstream and proposes a reviewed sync.

## Integration checkpoint — 2026-10-26

The reviewed integration tree is based on REA `1173c0a9dc1b352a60943a491462294db8f353ae`. The refreshed overlay patch targets this revision. The integration commit retains the existing PTAH work branch and upstream as parents, so a normal reviewed merge preserves both histories. Do not replace or force-push `main`. The older archive bootstrap instructions below describe the original snapshot; consult `PTAH-INTEGRATION-2026-10-26.md` for current verification limits.

## What the automation does

- Polls `https://github.com/morluto/rea.git` every 15 minutes, and can also be
  started manually from **Actions → PTAH upstream sync → Run workflow**.
- Fetches the latest upstream `main` and merges the PTAH branch's commits on
  top of it in a bot-owned branch.
- Runs PTAH-owned JavaScript syntax checks and `npm run test:ptah` before
  publishing a branch.
- Opens or refreshes a pull request for human review. It never auto-merges and
  never pushes the merged result directly to the default branch.
- If merge conflicts occur, it aborts without pushing and records the conflict
  and recovery command in the Actions job summary.
- If the repository was initialized from a ZIP upload and has no common Git
  ancestor with REA, it detects that state and stops safely with bootstrap
  instructions instead of attempting a guaranteed-to-conflict merge.

The 15-minute interval is a polling target, not a real-time guarantee. GitHub
may delay scheduled workflows, and scheduled workflows run from the default
branch. This feature only works after the project is pushed to a repository
under an account or organization where you control Actions and pull requests.

## Recommended repository setup

The delivered ZIP has no `.git` directory, so the scheduled workflow cannot track
upstream until the PTAH changes are committed on top of real Git history. A new
repository populated by uploading the ZIP has no shared ancestry with REA; the
sync workflow intentionally stops and reports this rather than attempting an
unsafe merge. The included patch
`patches/PTAH-overlay-from-supplied-REA-baseline.patch` captures
the PTAH changes relative to the REA archive supplied for this project. That
patch has been verified against that supplied snapshot, **not** against a live
checkout of today's upstream `main`; use Git's three-way apply and review any
conflicts when bootstrapping on a newer commit.

1. Fork `morluto/rea` into a repository you control, or create your own repository
   from an upstream clone. Clone that repository locally.
2. Fetch the current upstream history:

   ```sh
   git remote add upstream https://github.com/morluto/rea.git  # only once
   git fetch upstream main
   git switch -c ptah upstream/main  # or use your controlled default branch
   ```

3. Apply the overlay patch from this archive. Replace `/path/to/archive` with
   the directory where the ZIP was extracted:

   ```sh
   git apply --3way /path/to/archive/PTAH-v0.11/patches/PTAH-overlay-from-supplied-REA-baseline.patch
   ```

   If Git reports conflicts, resolve them deliberately. In particular, review
   `package.json`, `README.md`, and generated metadata; do not blindly choose
   either side. The patch is based on the supplied REA snapshot, so applying it
   to newer upstream source may require manual adaptation.

4. Run the PTAH checks, inspect `git diff`, then commit and push the PTAH changes
   to the controlled repository's default branch. If you used a branch named
   `ptah`, either make it the repository's default branch or adapt the workflow's
   base branch setting before enabling scheduled runs.
5. In repository **Settings → Actions → General**, allow GitHub Actions to
   create pull requests. The workflow uses the repository's `GITHUB_TOKEN`; no
   personal access token or secret is required.
6. Enable Actions and run **Actions → PTAH upstream sync → Run workflow** once.
   Future upstream changes are proposed as review PRs; they are never auto-merged.

## Manual workflow

From a clone of the PTAH fork:

```sh
git remote add upstream https://github.com/morluto/rea.git  # only once
git fetch upstream main
git status --short                                         # ensure clean worktree
git switch -c chore/sync-rea-upstream
git merge --no-edit upstream/main
npm run test:ptah
# Run the full upstream validation lane before merging.
```

If a merge conflicts, resolve the conflicts deliberately, run the tests, and
inspect `git diff upstream/main...HEAD`. Do not blindly choose one side: files
such as `package.json`, root `README.md`, and generated metadata may be edited
by both upstream and PTAH. Preserve upstream functionality and reapply PTAH
branding/additions as a separate, reviewable change.

## Important boundaries

- This workflow does **not** mean the current archive already contains the
  latest upstream source. It is the mechanism for tracking future upstream
  changes once installed in a GitHub repository with the required permissions.
- A clean PTAH test run is not a substitute for upstream TypeScript/Vitest,
  Python, docs, build, provider, and platform validation.
- Upstream code and PTAH-specific additions must retain their original licenses,
  attribution, security boundaries, and provenance.
- Do not automatically publish a PTAH npm/MCP release from this sync workflow.
  Package namespace ownership and the brand migration remain separate release
  gates.
