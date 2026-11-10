# Publication readiness

This page describes how the `build` workflow (`.github/workflows/onpush.yml`)
publishes the `brickflows` package, which safeguards the files in this
repository enforce, and which settings must exist outside the repository
before a release can be uploaded.

## Summary

- Publication uses [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/):
  the publish job exchanges a short-lived GitHub OIDC token for a PyPI upload
  token. The workflow no longer reads `PYPI_USERNAME` or `PYPI_PASSWORD`.
- Publication is disabled until every prerequisite below has been set up and
  the repository variable `PYPI_TRUSTED_PUBLISHING` is set to `ready`. Until
  then, a published release fails the **Publication readiness** job with a
  list of what is missing, and nothing is uploaded. The check reads only
  GitHub settings; it cannot see the PyPI trusted publisher registration, so
  a missing or wrong registration shows up as a failed upload instead.
- The workflow only publishes from `Nike-Inc/brickflow`. Forks, including the
  personal fork this change was prepared in, cannot publish even if they set
  the variable.

## What the workflow enforces

| Control | Where |
|---|---|
| The default `GITHUB_TOKEN` has no permissions; each job asks for what it needs. Test and build jobs get `contents: read`. | top-level and job `permissions` |
| Only the publish job may request an OIDC token (`id-token: write`). | `publish-pypi` |
| The publish job runs only for a `release` event with action `published`, a tag ref, the repository `Nike-Inc/brickflow`, and `vars.PYPI_TRUSTED_PUBLISHING == 'ready'`. | `publish-pypi` `if:` |
| The publish job needs the full test matrix, the build job and the readiness check to pass. | `publish-pypi` `needs:` |
| The publish job runs in the `pypi` environment, so the environment's protection rules apply before the OIDC token is issued. | `publish-pypi` `environment:` |
| The readiness check reads the `pypi` environment and every page of its deployment rules through the GitHub API, and fails unless the release tag and the environment match the policy described under [Readiness check](#readiness-check). | `publication-readiness` |
| Distributions are built once, without credentials, checked with `twine check --strict`, and passed to the publish job as an artifact. The publish job does not check out or run repository code. | `build-distributions` |
| PEP 740 attestations are generated during upload. | `pypa/gh-action-pypi-publish` `attestations: true` |
| Actions are pinned to full commit SHAs and containers to image digests. Checkouts do not persist the token. | all jobs |
| There is no `pull_request_target` or `workflow_run` trigger. | `on:` |

Pull requests, including pull requests from forks, run the tests and the
distribution build. GitHub does not pass secrets other than `GITHUB_TOKEN` to
workflows triggered by pull requests from forks, and that token is read-only
for them ([GitHub documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)).
The readiness and publish jobs do not run for pull requests or pushes.

`tests/test_workflow_security.py` checks these properties statically. It
also runs the readiness step exactly as written in the workflow, under bash,
with a local mock `gh` that records each API call and serves success, error,
empty, malformed, oversized, slow and multi-page responses.

## Readiness check

The **Publication readiness** job runs for every release event and fails,
listing every problem it found, unless all of the following hold:

- The event is a published release of `Nike-Inc/brickflow`, and the
  repository variable `PYPI_TRUSTED_PUBLISHING` is exactly `ready`.
- The ref is a tag of the form `vMAJOR.MINOR.PATCH`, optionally followed by
  `aN`, `bN` or `rcN`, with no leading zeros (for example `v2.1.0` or
  `v2.1.0rc1`). Other tags, such as `v2.1`, `v2.1.0-dirty` or
  `release/v2.1.0`, fail the check.
- `GET repos/{repository}/environments/pypi` succeeds and returns the `pypi`
  environment, which has a `required_reviewers` protection rule listing at
  least one reviewer. Each reviewer entry must be a `User` or `Team` with a
  numeric id. *Prevent self-review* is recommended but not checked.
- The environment's deployment policy is *Selected branches and tags*
  (`custom_branch_policies: true`, `protected_branches: false`). The
  *Protected branches only* and *No restriction* modes fail the check.
- `GET repos/{repository}/environments/pypi/deployment-branch-policies`,
  read 100 rules per page for at most five pages, lists exactly one rule: a
  tag rule named `v*`. Any branch rule, any other tag rule, a missing rule,
  or a total that does not match the rules read fails the check. The release
  tag must also match `v*` under GitHub's name-pattern rules, where `*` does
  not match `/`.

Every `gh api` call must exit with status 0 and return a non-empty JSON body
of at most 1 MiB within 30 seconds, and all calls together must finish within
120 seconds. A non-zero exit status fails the check even when the output looks
valid. The job uses only the `actions: read` permission of the workflow token.

The environment rule `v*` admits any tag that starts with `v`; the stricter
release-tag format above is enforced by this check, not by GitHub. To use a
different tag rule, change `EXPECTED_TAG_RULE` in the workflow in the same
change as the environment.

This check reports whether publication can work. It is not what protects the
upload: GitHub applies the `pypi` environment's actual rules (reviewers and
tag rules) to the publish job before it can obtain an OIDC token, and PyPI
accepts the token only if it matches the registered trusted publisher. The
check reads settings at the start of the run, so a setting changed while the
run waits for approval is enforced by GitHub, not re-checked here.

## Release gates and other workflows

The publish job needs exactly three jobs from this workflow: the full test
matrix, **Build distributions** and **Publication readiness**. Nothing else
gates a release. No dependency or security-advisory audit runs as part of a
release, so an expired advisory exception, a newly published advisory or an
unavailable advisory service does not stop publication. A dependency audit
workflow is being prepared separately; until it is added to this workflow
and to the publish job's `needs`, and tested there, it is advisory CI only
and has no effect on releases. Branch protection and other repository
settings that might require it were not inspected.

## External prerequisites

None of these steps can be performed from the repository files, and none has
been performed as part of this change. They must be done, in this order, by
people who own the corresponding accounts.

1. **Create the `pypi` environment** in `Nike-Inc/brickflow`
   (*Settings → Environments*). Add required reviewers, preferably with
   *Prevent self-review* enabled. Set *Deployment branches and tags* to
   *Selected branches and tags* and add a single **tag** rule named `v*`,
   with no branch rules. GitHub creates a missing environment
   with no protection rules when a job first references it
   ([GitHub documentation](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)),
   which is why the readiness check verifies the rules instead of assuming
   them.
2. **Add a trusted publisher** on the PyPI project `brickflows`
   (*Your projects → Manage → Publishing*) with owner `Nike-Inc`, repository
   `brickflow`, workflow `onpush.yml` and environment `pypi`. This requires
   management rights on the PyPI project.
3. **Set the repository variable** `PYPI_TRUSTED_PUBLISHING=ready`
   (*Settings → Secrets and variables → Actions → Variables*) once steps 1
   and 2 are done.
4. **Verify with a release** (a pre-release version is enough) and confirm on
   PyPI that the files were uploaded by the trusted publisher and carry
   attestations.
5. **Retire the stored credentials.** Delete the `PYPI_USERNAME` and
   `PYPI_PASSWORD` repository secrets and revoke the corresponding PyPI token
   or password. The workflow no longer uses them.

Until all five are done, releases cannot be uploaded by this workflow. That is
intentional: the change removes the stored-credential path and leaves
publication off rather than enabling it on assumed settings.

### Related settings, also not configured

- **Dependabot.** `.github/dependabot.yml` configures update pull requests for
  GitHub Actions and the Dockerfile base image. Python version updates are
  disabled in that file; Python security updates depend on Dependabot security
  updates being enabled in the repository settings. On a fork, version updates
  stay off until the owner enables them in the settings, even with the file
  present ([GitHub documentation](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates)).
- **Default workflow permissions.** Setting the repository's default
  `GITHUB_TOKEN` permission to read-only adds protection for any future
  workflow that forgets to declare `permissions`.
- **Private vulnerability reporting.** See `SECURITY.md` in the repository
  root. No private reporting channel is enabled.

## Keeping pins current

- Dependabot proposes action updates. Review the release notes and confirm
  that the new SHA belongs to the action's own repository before merging.
- Workflow container digests are not updated by the `docker` ecosystem entry,
  which covers the Dockerfile. To refresh them, resolve the multi-platform
  index digest of each `python:<version>` tag from the registry and update
  `onpush.yml`. The `python:3.9` image no longer receives updates because
  Python 3.9 has reached end of life.
- `pypa/gh-action-pypi-publish` is pinned by commit SHA, but at run time it
  generates a Docker action that pulls
  `ghcr.io/pypa/gh-action-pypi-publish:<action SHA>`. That image is selected
  by a registry tag named after the commit, not by digest, so it is not
  immutable in the way the action source is.

## Remaining gaps

- **Publisher CA bundle: UNPERFORMED.** The upload runs inside the PyPA
  action's container, not in the build job's tool environment. Nothing in
  this repository records or verifies that container's Python packages or
  the CA bundle it uses to reach PyPI.
- The build job's **Check build tool certificate bundle** step fails unless
  the build tool environment has `certifi` 2026.10.18 or later (the first
  release with the GHSA-6q48-6c7w-9gw2 fix) and its bundle is a PEM file
  inside that environment, then prints the version and path. That
  environment only builds and checks the files; it makes no upload.

- The test job still installs the latest Poetry on Python 3.10 and later and
  an unpinned `poetry-dynamic-versioning`, as before. The build job pins its
  tools by version but not by hash.
- The workflow has no dependency lockfile for actions; SHA pins are used
  instead.
