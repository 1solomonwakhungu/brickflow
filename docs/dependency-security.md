# Dependency security

This page covers how Brickflow pins security-relevant dependencies, how the
advisory audit decides what blocks a change, and which known advisories are
open and why.

## Security floors

`pyproject.toml` sets minimum versions for packages whose advisories reach
Brickflow's own code paths. They apply to every `pip install brickflows`, not
only to the lockfile.

| Package | Python 3.9 | Python 3.10–3.12 | Why |
|---|---|---|---|
| certifi | ≥ 2026.10.18 | ≥ 2026.10.18 | GHSA-6q48-6c7w-9gw2: compromised emSign intermediate CA keys |
| requests | ≥ 2.32.4 | ≥ 2.33.0 | GHSA-9hjg-9r4m-mvj7 (`.netrc` leak); GHSA-gc5v-m9x4-r6x2 needs 2.33, which requires Python 3.10 |
| Jinja2 | ≥ 3.1.6 | ≥ 3.1.6 | GHSA-cpwx-vrp4-4pq7 |

`tools/dependency_audit_policy.toml` repeats these floors. The audit fails if
the lockfile resolves below them, and the `installed` check fails if an
installed environment does.

## Python support

Python 3.9 through 3.12 stay supported. Some fixes are only published for
newer Python versions. Policy exceptions say why an advisory is open:

* **compatibility-blocked**: a fix exists but cannot be installed on Python
  3.9 without dropping another supported extra or Python 3.9 itself. This
  says nothing about exploitability; several of these are reachable.
* **deferred-upgrade**: a fix exists but needs a separate, larger upgrade.
  These carry short review dates.
* **not-reachable**: the vulnerable code path is not used by Brickflow.
* **accepted-risk**: reviewed and accepted for a bounded time.

The policy only allows `compatibility-blocked` for the Python 3.9 lane. A test
enforces this.

### Python 3.9 limits

* **urllib3 stays on 1.26.20.** Every botocore release (cerberus extra) and
  every snowflake-connector-python release (snowflake extra) that supports
  Python 3.9 requires urllib3 < 2 there. The lockfile covers all extras
  together, so it cannot move. A `pip install brickflows` on Python 3.9
  without those extras resolves urllib3 2.6.3. That fixes GHSA-2xpw-w6gg-jr37,
  GHSA-gm62-xv2j-4w53, GHSA-38jv-5279-wg99 and GHSA-pq67-6m6q-mj2v, but adds
  GHSA-gh4c-6fx4-qh6g (a Deflate streaming loop that read timeouts cannot
  interrupt) and keeps GHSA-mf9v-mfxr-j63j. No urllib3 release that installs
  on Python 3.9 is free of streaming advisories.
* **requests stays on 2.32.5.** 2.33.0 requires Python 3.10. The open advisory
  (GHSA-gc5v-m9x4-r6x2) affects `extract_zipped_paths()`, which requests only
  uses when its CA bundle sits inside a zip archive.

Full remediation for these needs Python 3.10 or later.

## Streaming downloads and urllib3

Brickflow's artifact download (`brickflow/engine/task_executor.py`) streams
responses through requests and urllib3. The urllib3 decompression and
chunk-parsing advisories are therefore reachable from a malicious or
compromised artifact endpoint. Two cautions for application-level limits:

* A cap on decoded bytes does not bound the work an old urllib3 decoder does
  before it hands bytes back (GHSA-gm62-xv2j-4w53, GHSA-2xpw-w6gg-jr37), and
  it does not bound an unterminated chunk-size line (GHSA-vxq7-64xx-v4gw).
  Refusing responses whose `Content-Encoding` is not `identity`, without
  decoding them, avoids the decompressor entirely.
* Per-read timeouts do not bound total time. A slow-drip server, or the
  GHSA-gh4c-6fx4-qh6g loop on urllib3 2.6.2–2.7.x, needs a total deadline.

## Tableau extra

The Tableau extra still uses tableauserverclient 0.25, which pins
urllib3 ~= 1.26.8 and so holds the whole lockfile on urllib3 1.26.20 (DEP-02).
Moving it requires a matching change to the plugin library list that
`brickflow/engine/task.py` installs on Databricks clusters. That list pins
`tableauserverclient==0.25`, and `tests/test_plugins.py` checks it against
`poetry.lock`. The policy carries the Python 3.10–3.12 urllib3 advisories as
`deferred-upgrade` until then.

Constraints for that change, from PyPI metadata and local checks:

* 0.39 is yanked; 0.40 declares Python ≥ 3.9 but fails to import on 3.9
  (`TypeError` from a `X | None` annotation). 0.38 is the newest release that
  works on Python 3.9.
* 0.41 and 0.42 require Python 3.10.
* Every version tested (0.25, 0.38, 0.41, 0.42) re-posts the sign-in request,
  password included, to a cross-origin `Location` after a 301. 0.42 also does
  it for 302, 303, 307 and 308 and across multi-hop chains. It refuses only
  HTTPS-to-HTTP downgrades. Brickflow's Tableau connector should refuse
  cross-origin sign-in redirects itself. Until it does, prefer 0.41 over 0.42.

## Advisory audit

`tools/dependency_audit.py` reads `pyproject.toml` and `poetry.lock`, works out
which locked versions each scope installs on each supported Python version
and platform, and queries [OSV](https://osv.dev) for advisories against those
versions.

Scopes are `runtime`, `extra:<name>` and `group:<name>`. The policy decides
what blocks:

* advisories reachable from `runtime` or any `extra:*` block unless an
  exception covers that exact package version, advisory, Python version and
  (optionally) scope;
* advisories reachable only from the `dev` or `docs` groups are reported but
  do not block;
* lock entries that no scope selects are reported as `unreached-lock-entry`.

An OSV match is not, by itself, a finding. Each blocking match needs either a
fix or a reviewed exception that says why it is open.

Exit codes: `0` passed, `1` policy violation, `2` the audit could not complete.
A network error, timeout, oversized or malformed response, paginated result
or missing advisory record gives `2`, never `0`. Lookups have a per-request
timeout, a total deadline, a response size cap, a request budget and at most
two retries for 408/429/5xx. Redirects are not followed, and plaintext
endpoints are refused except on loopback (for tests).

```shell
# full audit (needs network access to api.osv.dev)
poetry run python tools/dependency_audit.py audit --strict-exceptions --json-report audit.json

# floors and certifi bundle location for any interpreter
poetry run python tools/dependency_audit.py installed --require certifi \
  --python-executable "$(poetry env info --executable)"

# also check that the audit's reachability model matches what is installed
poetry run python tools/dependency_audit.py installed --require certifi --expect-lock \
  --scope runtime --scope group:dev --scope extra:all-plugins \
  --python-executable "$(poetry env info --executable)"
```

`.github/workflows/dependency-audit.yml` runs the audit on dependency changes,
on pushes to `main` and weekly. On each supported Python version it also:

* checks that `poetry.lock` matches `pyproject.toml`;
* installs the locked environment and compares it with the audit model;
* runs the dependency and plugin tests;
* checks floors in fresh `pip install brickflows`, `[tableau]` and
  `[all-plugins]` environments resolved from PyPI;
* checks the certifi bundle in an environment built the way the release job
  installs Twine, outside the Poetry environment.

### Adding or changing an exception

Each `[[exception]]` in `tools/dependency_audit_policy.toml` lists the
package, exact `versions`, `advisories`, `python` versions, a
`classification`, a `review_by` date and a `reason`. Optional `scopes` limit
it further. Write the reason for the next reviewer: say whether Brickflow
reaches the vulnerable code, what blocks the fix and what would unblock it.
Expired exceptions fail the audit. `--strict-exceptions` also fails on
exceptions that no longer match anything, so remove them when the fix lands.

## Open items

| Item | Scope | Status |
|---|---|---|
| urllib3 1.26.20 advisories | all scopes, Python 3.10–3.12 | `deferred-upgrade` until the Tableau extra and cluster library list move (DEP-02) |
| urllib3 1.26.20 and requests 2.32.5 advisories | all scopes, Python 3.9 | `compatibility-blocked` |
| snowflake-connector-python 3.13.2: GHSA-5cc2-282f-jjq2 (critical TLS hostname check), GHSA-qqj6-54q6-cxv6 | snowflake extra | `deferred-upgrade`, review by 2026-12-15. Fixed in 3.18.1 (Python 3.9) and 4.7.1+ (Python 3.10+, major upgrade) |
| cryptography 43.0.3, pyOpenSSL 24.3.0, filelock 3.19.1 | snowflake extra | `deferred-upgrade`; move with the connector |
| development and documentation tools | `dev`, `docs` groups | reported only |
