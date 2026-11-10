# Artifact downloads and generated notebooks

Credentialed artifact URLs must use HTTPS. The Artifactory API key is sent only
while redirects remain on the original scheme, hostname and effective port.
After leaving that origin it is never restored, including on a redirect back.
Cross-origin HTTPS downloads remain supported without that key. Redirects
cannot introduce URL credentials. Unauthenticated HTTP downloads remain supported.

Downloads use a dedicated session with a scoped cookie jar. Implicit `.netrc`
authentication and environment proxy discovery are disabled. Applications that
need a proxy can pass a Requests-compatible `proxies` mapping to
`ArtifactoryClient`; keep any proxy credentials out of logs. Private certificate
authorities can be configured with `ca_bundle`, `REQUESTS_CA_BUNDLE`, or
`CURL_CA_BUNDLE`. The latter two retain their usual precedence order.

The defaults allow five redirects and one GiB of artifact content; callers can
set `max_redirects` and `max_bytes`. These settings currently have no YAML option.
The client requests identity encoding and rejects other Content-Encoding values
before decoding, even if a server ignores that request. Redirect response bodies
are closed without being read. A declared Content-Length must match the complete
identity response before installation. A server that sends fewer bytes than
promised cannot replace an existing artifact.

Each socket operation has an inactivity timeout, but there is no total download
deadline. A sufficiently slow peer can prolong the operation. These limits do
not provide a complete denial-of-service boundary or artifact authenticity.

Files are staged beside the destination and replaced atomically after validation.
Existing regular-file permission bits are retained; new explicit destinations use
the process umask and automatically created temporary destinations are private.
Destination symlinks are replaced without writing through them. Replacement
creates a new inode, so ownership, ACLs, extended attributes and hard-link
relationships are not preserved. This is not an fsync durability guarantee.
Failures raise `ArtifactDownloadError`, a `requests.RequestException` subclass;
callers matching narrower exception subclasses may need adjustment. Outward
error messages omit raw transport exception text. This does not sanitize arbitrary
inspection of Python traceback frames or local variables.

Generated notebook task names must contain 1–100 ASCII letters, digits,
underscores or hyphens. Validation occurs at configuration load and before writing;
previously accepted punctuation, whitespace and non-ASCII names now fail early.
The output directory must be a real directory beneath the working directory.
Static directory symlink escapes are rejected and output-file symlinks are replaced.
This does not sandbox executable templates or prevent a concurrent local process
from replacing directories during a write.
