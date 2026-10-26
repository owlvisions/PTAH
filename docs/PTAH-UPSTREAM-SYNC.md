# Keeping PTAH current with REA upstream

PTAH is developed as a compatibility-preserving layer on top of the public
[`morluto/rea`](https://github.com/morluto/rea) repository. The upstream project
is active, so a downloaded source snapshot alone cannot stay current. This
repository merges upstream automatically after validation, from GitHub Actions
or from the local `ptah upstream-sync` command.

## Integration checkpoint — 2026-10-26

The reviewed integration tree is based on REA `1173c0a9dc1b352a60943a491462294db8f353ae`. The refreshed overlay patch targets this revision. The integration commit retains the existing PTAH work branch and upstream as parents, so a normal reviewed merge preserves both histories. Do not replace or force-push `main`. The older archive bootstrap instructions below describe the original snapshot; consult `PTAH-INTEGRATION-2026-10-26.md` for current verification limits.

## What the automation does

The same sync runs locally (`ptah upstream-sync`) and in GitHub Actions
(`.github/workflows/ptah-upstream-sync.yml`), which polls every 15 minutes
(a polling target, not a real-time guarantee; scheduled workflows run from the
default branch):

1. Fetches `https://github.com/morluto/rea.git` `main` and the default branch.
   Stops with `up-to-date` when upstream is already contained, or
   `not-bootstrapped` when the histories share no ancestor.
2. Merges upstream into a temporary detached worktree; the caller's checkout
   and every branch stay untouched until the final push.
3. Resolves conflicts dynamically with the PTAH merge policy
   (`scripts/ptah-merge-policy.mjs`), reporting every decision:
   - PTAH-owned paths (`scripts/ptah*`, `docs/PTAH-*`, `integrations/`,
     `web/ptah/`, PTAH workflows, `README.md`, `SECURITY.md`, `server.json`,
     `install.sh`, release config) keep PTAH's side.
   - `package.json` is merged field by field: PTAH keeps its identity (name,
     MCP name, description, repository, homepage, keywords), `bin`/`files`/
     `scripts` keep both sides' additions, and dependency conflicts take the
     newer version.
   - Generated files (`package-lock.json`, `licenses/npm-*.txt`) are rebuilt
     with `npm install --package-lock-only`, `npm ci`, and `licenses:generate`.
   - Everything else is the inherited REA runtime, where upstream is
     authoritative.
     If a regeneration step fails or conflict markers remain, the merge is
     aborted and reported as `conflict`.
4. Validates the merged tree: `npm run check:fast`, `npm run test:ptah`,
   `npm run build:cached`, and `npm run test:fast`. Any failure stops with
   `validation-failed` and nothing is pushed.
5. Pushes the merge commit to the default branch **without force**. If the
   branch moved meanwhile, the push is rejected (`push-rejected`) and the next
   run starts over from the new tip.

In GitHub Actions, steps 1–4 run in a job with read-only permissions and no
push credentials, because they execute upstream code. A separate job verifies
that the merge commit's parents are exactly the recorded default-branch tip
and upstream commit, then pushes it. Set the repository variable
`PTAH_UPSTREAM_AUTOMERGE` to `false` to receive a draft review PR instead of
a direct merge. Conflicts and failed validation open or update an issue named
"PTAH upstream sync needs attention".

### Running it locally

GitHub Actions is currently disabled for the `owlvisions` account
("Actions has been disabled for this user"), so no workflow in this repository runs
until GitHub Support restores it. The local command provides the same
automation meanwhile:

```sh
node scripts/ptah.mjs upstream-sync              # merge + validate, no push (dry run)
node scripts/ptah.mjs upstream-sync --push       # merge + validate + push to main
node scripts/ptah.mjs upstream-sync --install-timer [--interval hourly|15s]
systemctl --user daemon-reload && systemctl --user enable --now ptah-upstream-sync.timer
```

The timer runs `upstream-sync --push --update-local` from this checkout with
the systemd user manager; it needs Git push credentials for `origin` and
network access. `--interval` takes a calendar expression (`hourly`) or a
monotonic interval such as `15s` or `5min`, which is scheduled with one-second
accuracy. A run with no upstream change only fetches; a run with changes
validates for several minutes, and runs never overlap: a lock in the Git
directory makes a concurrent run report `busy`.

`--update-local` fast-forwards this checkout to the synced branch after each
run, so agents registered with `ptah agents` run current code. It never merges
or touches local edits: a checkout with uncommitted changes reports
`skipped-local-changes`, and one with unpushed commits reports
`skipped-diverged`. User timers stop when you log out unless lingering is
enabled (`loginctl enable-linger`). Inspect runs with
`journalctl --user -u ptah-upstream-sync`.

Exit status 2 means the run stopped (conflict, failed validation, rejected
push, or missing shared history).

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
   create pull requests (needed only when auto-merge is disabled). The workflow uses the repository's `GITHUB_TOKEN`; no
   personal access token or secret is required.
6. Enable Actions and run **Actions → PTAH upstream sync → Run workflow** once.
   Future upstream changes are merged automatically after validation, or
   proposed as draft PRs when `PTAH_UPSTREAM_AUTOMERGE` is `false`.

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
