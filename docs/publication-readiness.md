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
  list of what is missing, and nothing is uploaded.
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
| The readiness check reads the `pypi` environment through the GitHub API and fails unless it exists, has at least one required reviewer, and restricts deployments to selected branches or tags. | `publication-readiness` |
| Distributions are built once, without credentials, checked with `twine check --strict`, and passed to the publish job as an artifact. The publish job does not check out or run repository code. | `build-distributions` |
| PEP 740 attestations are generated during upload. | `pypa/gh-action-pypi-publish` `attestations: true` |
| Actions are pinned to full commit SHAs and containers to image digests. Checkouts do not persist the token. | all jobs |
| There is no `pull_request_target` or `workflow_run` trigger. | `on:` |

Pull requests, including pull requests from forks, run the tests and the
distribution build. GitHub does not pass secrets other than `GITHUB_TOKEN` to
workflows triggered by pull requests from forks, and that token is read-only
for them ([GitHub documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)).
The readiness and publish jobs do not run for pull requests or pushes.

`tests/test_workflow_security.py` checks these properties statically, and runs
the readiness check against sample environment responses.

## External prerequisites

None of these steps can be performed from the repository files, and none has
been performed as part of this change. They must be done, in this order, by
people who own the corresponding accounts.

1. **Create the `pypi` environment** in `Nike-Inc/brickflow`
   (*Settings → Environments*). Add required reviewers, preferably with
   *Prevent self-review* enabled, and limit deployments to selected tags,
   for example the release tag pattern. GitHub creates a missing environment
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
- `pypa/gh-action-pypi-publish` runs a container image that it selects by the
  action's ref, so pinning the action's SHA also selects the image built for
  that commit.

## Remaining gaps

- The test job still installs the latest Poetry on Python 3.10 and later and
  an unpinned `poetry-dynamic-versioning`, as before. The build job pins its
  tools by version but not by hash.
- The workflow has no dependency lockfile for actions; SHA pins are used
  instead.
