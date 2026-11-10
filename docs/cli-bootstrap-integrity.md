# Databricks CLI bootstrap integrity

Bundle commands (`deploy`, `destroy`, `validate`, `sync`) download the
Databricks CLI unless `BRICKFLOW_BUNDLE_NO_DOWNLOAD` is set. The default
version is `0.236.1`, overridable with `BRICKFLOW_BUNDLE_CLI_VERSION`.

## What is verified

Before the archive is opened, Brickflow downloads the release's
`databricks_cli_<version>_SHA256SUMS` asset from the same release directory as
the archive and compares the archive's SHA-256 against its entry. A missing
checksum asset, a missing or conflicting entry, a malformed line or a digest
mismatch stops the bootstrap before extraction.

The checksum file and the archive come from the same origin (GitHub releases by
default). A match shows that the archive is the one that release published. It
does not independently prove who published it: anyone able to replace release
assets could replace both files. Brickflow does not check a detached signature or
provenance attestation.

## Download limits

| Limit | Value |
|-------|-------|
| `SHA256SUMS` size | 64 KiB |
| Archive size | 256 MiB |
| Archive members | 64 |
| Expanded size of one member | 512 MiB |
| Declared expanded size of all members | 1 GiB |
| Redirects | 5 |
| Socket inactivity timeout | 60 seconds |

The `0.236.1` archives are about 10 MiB with four members and a binary of about
31 MiB. Downloads request identity encoding and reject other `Content-Encoding`
values. A declared `Content-Length` must match the bytes received. Redirect
bodies are closed unread. URLs must use HTTPS. Plain HTTP is accepted only for
loopback hosts, and never after an HTTPS hop. URLs carrying credentials are
refused. `.netrc` credentials are not attached. Environment proxy settings are
still honoured, as before. The timeout applies per socket operation. There is no
total deadline, so a slow server can prolong the bootstrap.

## Archive layout

The archive must contain exactly one CLI binary: `databricks` on Linux and
macOS, `databricks.exe` on Windows. A second binary in any directory, a binary
for the wrong platform, a missing binary, duplicate names, encrypted members,
unsupported compression, absolute paths, drive letters, backslashes, `..`
components, symlinks and other special files are all rejected. Only the binary is
written to disk. Its CRC and declared size are checked while it is copied.

## Cache

The binary is installed at `.databricks/bin/cli/<version>/` relative to the
working directory, next to a `.brickflow-cli-integrity.json` marker recording the
archive name and the SHA-256 of the archive and binary. The binary is staged in
the same directory, made executable, then renamed into place, so concurrent
bootstraps never expose a partial file. A failed bootstrap leaves no temporary
files and does not alter an existing binary.

A cached binary is reused, without network access, only if the marker exists,
names the same archive and matches the binary's current SHA-256. Otherwise,
including for cache entries written by earlier Brickflow releases and for
symlinked entries, the CLI is downloaded and verified again. The marker sits
beside the binary, so it detects corruption and stale entries, not a local user
who can rewrite both files.

Versions must look like `0.236.1` (optionally with a pre-release or build
suffix) or be `snapshot`, so a version cannot point the cache outside its
directory.

## Snapshot builds

The `snapshot` release is mutable and publishes no `SHA256SUMS`, so it is
rejected by default. Set `BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT=true` to
install it without checksum verification. All size and layout limits still
apply, and its cache entry is reused only while the opt-in stays set.

## Supplying your own CLI

To use a CLI installed and verified by other means, set
`BRICKFLOW_BUNDLE_NO_DOWNLOAD=true` and point `BRICKFLOW_BUNDLE_CLI_EXEC` at the
executable. Brickflow then makes no download and uses that path unchanged.

## Errors

Verification failures raise `CliIntegrityError`, a subclass of
`click.ClickException`, so the CLI reports them as ordinary command errors.
