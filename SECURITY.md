# Security policy

## Scope of this repository

This repository is a personal fork of
[Nike-Inc/brickflow](https://github.com/Nike-Inc/brickflow). It is not the
upstream project, and it is not where the `brickflows` package on PyPI is
built or published. Changes made here are not upstream releases.

## Reporting a vulnerability

Do not put vulnerability details, proof-of-concept code, credentials or logs
in public issues, pull requests, discussions or commit messages, here or
upstream.

As of this file's last update:

- This fork has no private vulnerability reporting channel. GitHub private
  vulnerability reporting is not enabled, and the fork's issue tracker is
  disabled.
- The upstream repository has no `SECURITY.md`, and GitHub private
  vulnerability reporting is not enabled there either.
- The upstream `CONTRIBUTING.md` lists
  [opensource@nike.com](mailto:opensource@nike.com) as a general contact for
  questions. It is not documented as a security reporting channel. If you
  use it, ask for a private way to send a security report and leave out the
  details until one is agreed.

No response time, triage process or disclosure timeline is offered for this
fork.

## Supported versions

This fork makes no support commitment for any version. For the published
package, refer to the upstream project.

## Publishing safeguards

The release workflow in this repository cannot upload to PyPI from this fork.
It publishes only from the upstream repository, only for a published release
tag, and only after a readiness check has verified the upstream `pypi`
environment settings it can read through the GitHub API; see
[docs/publication-readiness.md](docs/publication-readiness.md). The PyPI
trusted publisher registration cannot be read by the workflow and is not
checked. All of these prerequisites are account and repository settings that
this repository's files cannot configure, and none of them has been set up as
part of this change.
