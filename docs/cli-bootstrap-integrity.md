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
| Archive members (declared and actual) | 64 |
| ZIP central directory | 256 KiB |
| Expanded size of one member | 512 MiB |
| Declared expanded size of all members | 1 GiB |
| Redirects | 5 |
| Socket inactivity timeout | 60 seconds |

The `0.236.1` archives are about 10 MiB with four members and a binary of about
31 MiB. Downloads request identity encoding and reject other `Content-Encoding`
values. A declared `Content-Length` must match the bytes received. Redirects are
followed by Brickflow, one request at a time. Requests' own redirect preparation,
which would read and decode a redirect body and look up `.netrc` before the
caller sees the response, is disabled. Each redirect response is closed without
reading its body. URLs must use HTTPS. Plain HTTP is accepted only for
loopback hosts, and never after an HTTPS hop. URLs carrying credentials are
refused. `.netrc` credentials are not attached. Environment proxy settings are
still honoured, as before. The timeout applies per socket operation. There is no
total deadline, so a slow server can prolong the bootstrap.

## Archive layout

Before Python's `zipfile` parses the archive, Brickflow reads its end-of-central-
directory record and walks the central directory itself. The archive must be a
single-disk, non-ZIP64 file with no data before the first entry or after the end
record, a central directory of at most 256 KiB, and a declared entry count equal
to the number of records actually present, at most 64. Stored names may not
contain NUL bytes. This keeps the metadata `zipfile` allocates proportional to the
member limit, whatever count the archive claims.

The archive must contain exactly one CLI binary: `databricks` on Linux and
macOS, `databricks.exe` on Windows. A second binary in any directory, a binary
for the wrong platform, a missing binary, duplicate names, encrypted members,
unsupported compression, absolute paths, drive letters, backslashes, `..`
components, symlinks and other special files are all rejected. Only the binary is
written to disk. Its CRC and declared size are checked while it is copied.

## Cache

Each install lives in its own directory, relative to the working directory:

```
.databricks/bin/cli/<version>/<archive name without .zip>/
    current                     # SHA-256 of the binary in use
    <binary sha256>/
        databricks              # or databricks.exe
        .brickflow-cli-integrity.json
```

The marker records the archive name, the archive and binary SHA-256 and whether
the archive was verified. The binary and marker are written to a staging
directory, and the binary is made executable. The staging directory is then
renamed to the binary's SHA-256 as a whole, and `current` is replaced
atomically. As a result:

- the marker and binary in one directory always belong to the same install,
  including when two platforms or two downloads of a changed release run at
  once;
- a path returned to one caller is never later rewritten with other bytes, since
  install directories are content-addressed and never modified after publication
  (a corrupt one is moved aside and replaced only after failing verification);
- a failure before `current` is replaced leaves the previous install in use. A
  directory published just before such a failure is complete and is adopted by
  the next bootstrap;
- temporary files and staging directories are removed on every failure path.

A cached binary is reused, without network access, only when `current` names a
directory whose marker names the same archive and whose binary is a regular file
matching the marker's SHA-256. If the execute bits are missing on a verified
binary, they are restored. Otherwise the CLI is downloaded and verified again.
Cache entries written by earlier Brickflow releases (`<version>/databricks`) are
ignored and left in place. Old install directories are not pruned, because
another process may still be running them.

The marker sits beside the binary, so it detects corruption and stale entries,
not a local user who can write to the cache directory. Directory ownership and
permissions follow the existing umask, and symlinks in parent directories are not
checked. Verification and the later execution are separate steps, so a local
writer can still swap the file in between. Use `BRICKFLOW_BUNDLE_NO_DOWNLOAD`
with a CLI in a protected location if that matters.

Versions must look exactly like `0.236.1` (optionally with a pre-release or build
suffix, and no trailing newline) or be `snapshot`, so a version cannot point the cache outside its
directory.

## Snapshot builds

The `snapshot` release is mutable and publishes no `SHA256SUMS`, so it is
rejected by default, before any network access. Set
`BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT=true`, or from Python
`BrickflowProjectDeploymentSettings().brickflow_bundle_cli_allow_unverified_snapshot = True`,
to install it without checksum verification. The setting defaults to false and
has no effect on released versions. With it enabled, whoever controls the
snapshot asset or its delivery path chooses the binary Brickflow will run; only
the size and layout limits still apply. The cache entry is marked unverified and
is reused only while the opt-in stays set.

## Supplying your own CLI

To use a CLI installed and verified by other means, set
`BRICKFLOW_BUNDLE_NO_DOWNLOAD=true` and point `BRICKFLOW_BUNDLE_CLI_EXEC` at the
executable. Brickflow then makes no download and uses that path unchanged.

## Errors

Verification failures raise `CliIntegrityError`, a subclass of
`click.ClickException`, so the CLI reports them as ordinary command errors.
