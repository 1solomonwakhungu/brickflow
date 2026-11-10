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
| urllib3 | ≥ 1.26.20 | ≥ 2.8.0 | Streaming decompression, chunk parsing, redirect and proxy TLS advisories (DEP-02) |
| tableauserverclient (`tableau` extra) | ≥ 0.25, < 0.39 | ≥ 0.41, < 0.42 | Moves the Tableau extra off its urllib3 1.26 pin; see below for the bounds |
| Jinja2 | ≥ 3.1.6 | ≥ 3.1.6 | GHSA-cpwx-vrp4-4pq7 |
| snowflake-connector-python (`snowflake` extra) | ≥ 3.18.1, < 4 | ≥ 4.7.3, < 5 | GHSA-5cc2-282f-jjq2 (TLS hostname check) and GHSA-qqj6-54q6-cxv6 (secrets in logs); see [Snowflake extra](#snowflake-extra) |
| cryptography (`snowflake` extra) | ≥ 43.0.3 | ≥ 50.0.0 | Bundled OpenSSL, PKCS#7, path-building, name-constraint and subgroup advisories |
| pyOpenSSL (`snowflake` extra) | ≥ 24.3.0, < 26 | ≥ 26.0.0 | GHSA-5pwr-322w-8jr4, GHSA-vp96-hxj8-p424 |
| filelock (`snowflake` extra) | ≥ 3.19.1, < 4 | ≥ 3.20.3, < 4 | GHSA-qmgc-5h2g-mvrw, GHSA-w853-jp5j-5j7f |

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
* **The Snowflake extra keeps four advisory sets open.** See
  [Snowflake extra](#snowflake-extra).

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

tableauserverclient 0.25 pinned urllib3 ~= 1.26.8 and held the whole lockfile
on urllib3 1.26.20 (DEP-02). On Python 3.10–3.12 the extra now resolves 0.41
with urllib3 2.8.0. The bounds come from PyPI metadata and local checks:

* 0.39 is yanked; 0.40 declares Python ≥ 3.9 but fails to import on 3.9
  (`TypeError` from a `X | None` annotation). 0.38 is the newest release that
  works on Python 3.9, so the 3.9 range stops below 0.39. The lockfile keeps
  0.25 on Python 3.9 because the snowflake and cerberus extras need urllib3 < 2
  there; `pip install brickflows[tableau]` on 3.9 without them gets 0.38 and
  urllib3 2.6.3.
* 0.41 and 0.42 require Python 3.10.
* Every version tested (0.25, 0.38, 0.41, 0.42) re-posts the sign-in request,
  password included, to a cross-origin `Location` after a 301. 0.42 also does
  it for 302, 303, 307 and 308 and across multi-hop chains, and refuses only
  HTTPS-to-HTTP downgrades.

Brickflow's Tableau connector no longer relies on the client for this. It
accepts only `https://` server URLs and gives tableauserverclient a
`session_factory` (available from 0.25 on) whose sessions refuse to send to
any origin other than the configured scheme, host and port. The check runs on
each actual send, so it covers the client's own 301 handling and redirects
`requests` follows automatically; loopback tests show the refused target
receives nothing on 0.25, 0.38, 0.41 and 0.42. The range still stops below 0.42
because 0.42 is not the tested release for this change: it raises its own
`RedirectError` for downgrades before Brickflow's check, which surfaces as a
different exception.

0.34 renamed the `Workbooks.refresh` parameter from `workbook_id` to
`workbook_item`; the connector now passes the workbook positionally, which
works on every release in the range.

The plugin library list that `brickflow/engine/task.py` installs on Databricks
clusters pins tableauserverclient per Python version with PEP 508 markers,
matching what `poetry.lock` resolves:

* `tableauserverclient==0.25; python_version < "3.10"`
* `tableauserverclient==0.41; python_version >= "3.10"`

`tests/test_plugins.py` evaluates those markers for Python 3.9–3.12 and checks
each pin against the lock entry that Python resolves, and against the
installed version on the interpreter running the tests. The markers rely on
pip evaluating them when Databricks installs the library; that has not been
checked on a Databricks runtime.

Databricks runtime images that ship botocore older than 1.35 declare
urllib3 < 2.1 on Python 3.10+. pip installs the newer urllib3 and reports the
conflict; check boto3-based code on those runtimes.

## Snowflake extra

The `snowflake` package (1.5.x) leaves snowflake-connector-python unpinned,
so Brickflow declares the connector and its TLS chain directly in the
`snowflake` and `all-plugins` extras.

| | Python 3.9 | Python 3.10–3.12 |
|---|---|---|
| Lock | connector 3.18.1, cryptography 43.0.3, pyOpenSSL 24.3.0, filelock 3.19.1 | connector 4.8.0, cryptography 50.0.2, pyOpenSSL 26.4.0, filelock 3.20.3 |
| GHSA-5cc2-282f-jjq2 (critical) | fixed | fixed |
| GHSA-qqj6-54q6-cxv6 | open | fixed |
| cryptography, pyOpenSSL | open | fixed |
| filelock | open | GHSA-69hj-f68j-2879, GHSA-8mx5-7m5m-r77g open |

Why the ranges look the way they do (PyPI and OSV, checked 2026-11-10):

* GHSA-5cc2 lets an on-path attacker present a certificate for the wrong
  host. It is fixed in 3.18.1 and 4.7.1. Releases 4.0–4.5 still install on
  Python 3.9 and are vulnerable, so the Python 3.9 range stays on 3.18.x.
* GHSA-qqj6 (tokens, result keys and pre-signed URLs in connector logs) is
  fixed only in 4.7.3, which requires Python 3.10. On Python 3.9 it is open.
  Brickflow does not raise the connector's log level; anyone who can read
  DEBUG-level connector logs on a Python 3.9 job may see session secrets.
* Connector 3.18.x requires pyOpenSSL < 26, and cryptography 44+ excludes
  Python 3.9.0 and 3.9.1, so the Python 3.9 lock stays on cryptography 43.0.3
  and pyOpenSSL 24.3.0. A fresh pip install on Python 3.9.2 or later gets
  pyOpenSSL 25.3.0 with cryptography 46.0.0: 46.0.1+ needs cffi 2 on Python
  3.9 and the connector requires cffi < 2. 46.0.0 has as many open
  advisories as 43.0.3 (GHSA-537c-gmf6-5ccf and GHSA-jwv3-5hgf-82ww among
  them), so this is not an improvement on Python 3.9.
* The 4.x connector requires filelock < 4, and the filelock fixes for
  GHSA-69hj and GHSA-8mx5 are in 4.2.1, which requires Python 3.11.
  Connector 5.x drops filelock but is a separate major release for Python
  3.11+, so `< 5` stays until it is evaluated. The connector uses filelock's
  `FileLock` only on its OCSP/CRL cache; both advisories need another local
  user who can write in that cache directory, and GHSA-8mx5 is Windows-only.
  The lock keeps 3.20.3, the last release before the ReadWriteLock and
  SoftFileLock code that has further advisories; published installs accept
  any `>= 3.20.3, < 4`, so a fresh install on Python 3.10+ gets the newest
  3.x (3.32.7 on 2026-11-10), whose extra advisories are in code the
  connector does not call.
* Connector 3.18.1 depends on boto3 and botocore. Both are already in the
  lock through the cerberus extra.

Behaviour changes that reach the Snowflake operators:

* **OCSP.** Connector 4.8 turned OCSP revocation checks off unless the
  caller sets `ocsp_fail_open`; 3.x enabled them in fail-open mode by
  default. The operators now pass `ocsp_fail_open=True`, so revocation
  checking stays on, in the same mode, on every supported release.
  `tests/databricks_plugins/test_snowflake_operator.py` runs the installed
  connector's own parameter handling (login stubbed, no network) and checks
  the resulting OCSP mode.
* **Platform detection.** Since 3.17 the connector probes cloud metadata
  endpoints during login to report the platform to Snowflake. It does not
  change authentication. Set `platform_detection_timeout_seconds=0` in the
  connector if that probe is not wanted; the operators do not expose
  connector options.

The plugin library list in `brickflow/engine/task.py` pins the connector per
Python version next to `snowflake==1.5.1`:

* `snowflake-connector-python==3.18.1; python_version < "3.10"`
* `snowflake-connector-python==4.8.0; python_version >= "3.10"`

Without them pip resolves the connector freely on the cluster, which picks
4.5.0 (vulnerable to GHSA-5cc2) on Python 3.9 and 5.x on Python 3.11+.
cryptography, pyOpenSSL and filelock are not pinned there, because forcing
them would replace packages the runtime image ships. pip installs the newest
compatible releases when an upgrade is needed, but keeps a preinstalled
cryptography at or above the connector's floor (46.0.5 for 4.x), and 46.x
still has GHSA-537c-gmf6-5ccf, GHSA-g6cj-pr64-35w5 and GHSA-jwv3-5hgf-82ww.
Neither the pins nor the newer TLS packages have been checked on a
Databricks runtime image.

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
  Poetry 1.8 can keep dead branches when constraints split by Python
  version. Installs never select them; the workflow's `--expect-lock` check
  fails if one ever does.

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
| urllib3 1.26.20 and requests 2.32.5 advisories | runtime and the box, cerberus, snowflake, tableau and all-plugins extras, Python 3.9 | `compatibility-blocked`; exposure through any other blocking scope needs a policy change |
| snowflake-connector-python 3.18.1: GHSA-qqj6-54q6-cxv6 | snowflake and all-plugins extras, Python 3.9 | `compatibility-blocked`, review by 2027-01-31. Fixed only in 4.7.3+, which requires Python 3.10 |
| cryptography 43.0.3, pyOpenSSL 24.3.0, filelock 3.19.1 | snowflake and all-plugins extras, Python 3.9 | `compatibility-blocked`, review by 2027-01-31 |
| filelock 3.20.3: GHSA-69hj-f68j-2879, GHSA-8mx5-7m5m-r77g | snowflake and all-plugins extras, Python 3.10–3.12 | `deferred-upgrade`, review by 2027-01-31. Needs connector 5.x (Python 3.11+); no fixed route on 3.10 |
| development and documentation tools | `dev`, `docs` groups | reported only |
