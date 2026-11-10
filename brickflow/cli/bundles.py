from __future__ import annotations

import functools
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import posixpath
import re
import stat
import tempfile
import zlib
from urllib.parse import urljoin, urlsplit, urlunsplit
import zipfile
from typing import Any, Callable, Optional, Union

import requests
from requests.auth import AuthBase
from click import ClickException
from decouple import config

from brickflow import (
    BrickflowEnvVars,
    _ilog,
    get_bundles_project_env,
    get_entrypoint_python,
)
from brickflow.cli.commands import exec_command
from brickflow.cli.configure import get_entrypoint, log_important_versions
from brickflow.cli.constants import BrickflowDeployMode

ENV_FLAG = "-t"


def pre_bundle_hook(f: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(f)
    def wrapped_bundle_func(*args: Any, **kwargs: Any) -> None:
        bundle_cli_setup()
        bundle_cli = config(
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value, "databricks"
        )
        log_important_versions(bundle_cli)
        bundle_synth(**kwargs)
        return f(*args, **kwargs, bundle_cli=bundle_cli)

    return wrapped_bundle_func


def get_valid_bundle_cli(bundle_cli: Optional[str]) -> str:
    if bundle_cli is None:
        return "databricks"
    return bundle_cli


def _bundle_validate(bundle_cli: Optional[str], target: str) -> None:
    exec_command(
        get_valid_bundle_cli(bundle_cli),
        "bundle",
        ["validate", ENV_FLAG, target],
    )


@pre_bundle_hook
def bundle_validate(bundle_cli: Optional[str] = None, **_: Any) -> None:
    """CLI validate the bundle."""
    _bundle_validate(bundle_cli, get_bundles_project_env())


@pre_bundle_hook
def bundle_sync(
    bundle_cli: Optional[str] = None,
    watch: bool = False,
    debug: bool = False,
    interval_duration: Optional[Union[str, int]] = None,
    full: bool = False,
    **_: Any,
) -> None:
    """CLI deploy the bundle."""
    additional_args = []
    if full is True:
        additional_args.append("--full")
    if watch is True:
        additional_args.append("--watch")
    if interval_duration is not None:
        additional_args.extend(["--interval-duration", str(interval_duration)])
    if debug is True:
        additional_args.append("--debug")

    exec_command(
        get_valid_bundle_cli(bundle_cli),
        "bundle",
        ["sync", ENV_FLAG, get_bundles_project_env(), *additional_args],
    )


def should_deploy() -> bool:
    """This has been added mostly for testing purposes as directly mocking os.path.exists has broader impacts"""
    return os.path.exists("bundle.yml")


def get_force_lock_flag() -> str:
    version_parts = get_bundle_cli_version().split(".")
    # TODO: remove this logic on the major version
    if (
        len(version_parts) > 2
        and version_parts[0] == "0"
        and int(version_parts[1]) <= 202
    ):
        return "--force"
    return "--force-lock"


@pre_bundle_hook
def bundle_deploy(
    bundle_cli: Optional[str] = None,
    fail_on_active_runs: bool = False,
    force_acquire_lock: bool = False,
    auto_approve: bool = False,
    debug: bool = False,
    skip_validate: bool = False,
    **_: Any,
) -> None:
    """CLI deploy the bundle."""
    # If the bundle.yml has not been synthesized, there's nothing to deploy!
    if not should_deploy():
        _ilog.warning("No bundle.yml found, skipping deployment.")
        return

    target = get_bundles_project_env()
    deploy_args = ["deploy", ENV_FLAG, target]
    if fail_on_active_runs is True:
        # TODO: Remove the following message once the CLI is upgraded to >= 0.249.0.
        _ilog.info(
            "Note that, even with `fail-on-active-runs` being enabled, the deployment might fail, "
            "in some edge cases (particularly if the bundle includes some wheel artifacts)."
        )
        deploy_args.append("--fail-on-active-runs")
    if force_acquire_lock is True:
        # fix/issue-32
        deploy_args.append(get_force_lock_flag())
    if auto_approve is True:
        deploy_args.append("--auto-approve")
    if debug is True:
        deploy_args.append("--debug")
    if not skip_validate:
        _bundle_validate(bundle_cli, target)
    exec_command(get_valid_bundle_cli(bundle_cli), "bundle", deploy_args)


@pre_bundle_hook
def bundle_destroy(
    bundle_cli: Optional[str] = None,
    force_acquire_lock: bool = False,
    auto_approve: bool = False,
    debug: bool = False,
    **_: Any,
) -> None:
    """CLI destroy the bundle."""
    destroy_args = ["destroy", ENV_FLAG, get_bundles_project_env()]
    if auto_approve is True:
        destroy_args.append("--auto-approve")
    if force_acquire_lock is True:
        destroy_args.append(get_force_lock_flag())
    if debug is True:
        destroy_args.append("--debug")

    exec_command(get_valid_bundle_cli(bundle_cli), "bundle", destroy_args)


def get_arch() -> str:
    system = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "i386": "386",
        "i686": "386",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    if system not in arch_map:
        raise RuntimeError(f"Unsupported architecture: {system}")
    return arch_map[system]


# Release assets are published by Databricks on GitHub. Tests and mirrors may
# point this at another origin; the checksum file is always fetched from the
# same release directory as the archive.
DATABRICKS_CLI_RELEASE_BASE_URL = "https://github.com/databricks/cli/releases/download"

# Opt-in for the mutable ``snapshot`` release, which publishes no SHA256SUMS
# asset. Resource and layout limits still apply when it is enabled.
BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT = (
    "BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT"
)

CLI_CACHE_ROOT = os.path.join(".databricks", "bin", "cli")
CLI_CACHE_MARKER = ".brickflow-cli-integrity.json"

# Limits sized well above the 0.236.1 release (about 10 MiB archives holding
# four members and a ~31 MiB binary) while bounding memory, disk and CPU use.
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_DOWNLOAD_REDIRECTS = 5
DOWNLOAD_TIMEOUT_SECONDS = 60

_CHUNK_SIZE = 64 * 1024
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_CLI_BINARY_NAMES = frozenset({"databricks", "databricks.exe"})
_VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
_CHECKSUM_LINE_PATTERN = re.compile(r"^([0-9a-fA-F]{64}) [ *]([A-Za-z0-9._+-]+)$")


class CliIntegrityError(ClickException):
    """Raised when the Databricks CLI bootstrap cannot be verified or installed."""


class _NoAmbientAuth(AuthBase):
    """Stops Requests from attaching ``.netrc`` credentials to public downloads."""

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        return r


def bundle_download_path(version: str) -> str:
    system = platform.system().lower()
    arch = get_arch()
    if version == "snapshot":
        return (
            f"{DATABRICKS_CLI_RELEASE_BASE_URL}/"
            f"{version}/databricks_cli_{system}_{arch}.zip"
        )

    return (
        f"{DATABRICKS_CLI_RELEASE_BASE_URL}/"
        f"v{version}/databricks_cli_{version}_{system}_{arch}.zip"
    )


def download_url(url: str) -> requests.Response:
    """Fetch ``url`` in one request.

    Kept for API compatibility. The CLI bootstrap uses the bounded, verified
    path in :func:`download_and_unzip_databricks_cli` instead.
    """
    try:
        return requests.get(
            url, timeout=60
        )  # Set a suitable timeout value (e.g., 10 seconds)
    except requests.exceptions.Timeout:
        _ilog.error("Request timed out. Failed to download the file.")
        raise
    except requests.exceptions.RequestException as e:
        _ilog.error("An error occurred while downloading the file: %s", e)
        raise


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_download_url(url: str, previous_scheme: Optional[str]) -> None:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.username is not None or parsed.password is not None:
        raise CliIntegrityError("Refusing a Databricks CLI URL with credentials.")
    if parsed.scheme == "https" and host:
        return
    # Plain HTTP is accepted only for loopback test servers and never after HTTPS.
    if parsed.scheme == "http" and _is_loopback_host(host):
        if previous_scheme != "https":
            return
    raise CliIntegrityError(
        f"Refusing to download the Databricks CLI over {parsed.scheme or 'an unknown'} "
        f"scheme from {host or 'an unknown host'}."
    )


def _stream_download(url: str, limit: int, sink: Callable[[bytes], None]) -> None:
    """Stream ``url`` into ``sink`` with redirect, scheme, size and length checks."""
    current = url
    previous_scheme: Optional[str] = None
    with requests.Session() as session:
        for _ in range(MAX_DOWNLOAD_REDIRECTS + 1):
            _check_download_url(current, previous_scheme)
            try:
                response = session.get(
                    current,
                    timeout=DOWNLOAD_TIMEOUT_SECONDS,
                    stream=True,
                    allow_redirects=False,
                    auth=_NoAmbientAuth(),
                    headers={"Accept-Encoding": "identity"},
                )
            except requests.exceptions.RequestException as e:
                raise CliIntegrityError(
                    f"Unable to download the Databricks CLI asset from {url}: "
                    f"{type(e).__name__}"
                ) from e
            with response:
                if response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("Location")
                    if not location:
                        raise CliIntegrityError(
                            f"Redirect without a location while downloading {url}."
                        )
                    previous_scheme = urlsplit(current).scheme
                    current = urljoin(current, location)
                    continue
                if response.status_code != 200:
                    _ilog.error(
                        "Failed to download the file from %s. Error code: %s",
                        url,
                        response.status_code,
                    )
                    raise CliIntegrityError(
                        f"Unable to download databricks cli from: {url} "
                        f"(HTTP {response.status_code})"
                    )
                _read_bounded_body(response, url, limit, sink)
                return
    raise CliIntegrityError(
        f"Too many redirects (limit {MAX_DOWNLOAD_REDIRECTS}) while downloading {url}."
    )


def _read_bounded_body(
    response: requests.Response,
    url: str,
    limit: int,
    sink: Callable[[bytes], None],
) -> None:
    encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise CliIntegrityError(
            f"Unexpected content encoding {encoding!r} for {url}; refusing to decode."
        )
    declared: Optional[int] = None
    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            declared = int(raw_length)
        except ValueError as e:
            raise CliIntegrityError(f"Invalid Content-Length for {url}.") from e
        if declared < 0 or declared > limit:
            raise CliIntegrityError(
                f"Databricks CLI asset {url} exceeds the {limit} byte limit."
            )
    received = 0
    try:
        for chunk in response.iter_content(_CHUNK_SIZE):
            if not chunk:
                continue
            received += len(chunk)
            if received > limit:
                raise CliIntegrityError(
                    f"Databricks CLI asset {url} exceeds the {limit} byte limit."
                )
            sink(chunk)
    except requests.exceptions.RequestException as e:
        raise CliIntegrityError(
            f"Truncated or interrupted download from {url}: {type(e).__name__}"
        ) from e
    if declared is not None and received != declared:
        raise CliIntegrityError(
            f"Truncated download from {url}: received {received} of {declared} bytes."
        )


def _parse_sha256sums(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        match = _CHECKSUM_LINE_PATTERN.match(line)
        if match is None:
            raise CliIntegrityError(
                f"Malformed SHA256SUMS line {line_number}; refusing to continue."
            )
        digest, name = match.group(1).lower(), match.group(2)
        if entries.get(name, digest) != digest:
            raise CliIntegrityError(f"Conflicting SHA256SUMS entries for {name}.")
        entries[name] = digest
    return entries


def _fetch_expected_sha256(checksum_url: str, archive_name: str) -> str:
    buffer = bytearray()
    _stream_download(checksum_url, MAX_CHECKSUM_BYTES, buffer.extend)
    try:
        text = buffer.decode("ascii")
    except UnicodeDecodeError as e:
        raise CliIntegrityError("SHA256SUMS is not ASCII text.") from e
    entries = _parse_sha256sums(text)
    if archive_name not in entries:
        raise CliIntegrityError(f"SHA256SUMS has no entry for {archive_name}.")
    return entries[archive_name]


def _validate_cli_version(version: str) -> None:
    if version == "snapshot" or _VERSION_PATTERN.match(version):
        return
    raise CliIntegrityError(
        f"Invalid Databricks CLI version {version!r}; expected e.g. 0.236.1 or snapshot."
    )


def _release_assets(url: str, version: str) -> tuple[str, str, str]:
    """Return the archive name, its checksum URL and the expected binary name."""
    parsed = urlsplit(url)
    archive_name = posixpath.basename(parsed.path)
    if not archive_name.endswith(".zip") or parsed.query or parsed.fragment:
        raise CliIntegrityError(f"Unexpected Databricks CLI archive URL: {url}")
    release_dir = posixpath.dirname(parsed.path)
    checksum_url = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"{release_dir}/databricks_cli_{version}_SHA256SUMS",
            "",
            "",
        )
    )
    binary_name = "databricks.exe" if "_windows_" in archive_name else "databricks"
    return archive_name, checksum_url, binary_name


def _allow_unverified_snapshot() -> bool:
    return bool(
        config(BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT, False, cast=bool)
    )


def _validate_member_name(name: str) -> None:
    parts = name.split("/")
    unsafe_characters = "\\" in name or "\x00" in name or ":" in parts[0]
    escapes_root = name.startswith("/") or ".." in parts
    if not name or unsafe_characters or escapes_root:
        raise CliIntegrityError(f"Unsafe path in Databricks CLI archive: {name!r}")


def _select_cli_member(archive: zipfile.ZipFile, binary_name: str) -> zipfile.ZipInfo:
    """Validate archive layout and return the single expected CLI binary member."""
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise CliIntegrityError(
            f"Databricks CLI archive has {len(members)} members "
            f"(limit {MAX_ARCHIVE_MEMBERS})."
        )
    seen = set()
    total = 0
    candidates = []
    for info in members:
        name = info.filename
        _validate_member_name(name)
        if name in seen:
            raise CliIntegrityError(
                f"Duplicate member in Databricks CLI archive: {name}"
            )
        seen.add(name)
        if info.flag_bits & 0x1:
            raise CliIntegrityError(
                f"Encrypted member in Databricks CLI archive: {name}"
            )
        file_type = stat.S_IFMT(info.external_attr >> 16)
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise CliIntegrityError(
                f"Symlink or special file in Databricks CLI archive: {name}"
            )
        if info.is_dir():
            continue
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise CliIntegrityError(
                f"Unsupported compression in Databricks CLI archive: {name}"
            )
        if info.file_size > MAX_BINARY_BYTES:
            raise CliIntegrityError(f"Databricks CLI archive member too large: {name}")
        total += info.file_size
        if total > MAX_TOTAL_EXPANDED_BYTES:
            raise CliIntegrityError(
                f"Databricks CLI archive expands beyond {MAX_TOTAL_EXPANDED_BYTES} bytes."
            )
        if posixpath.basename(name).lower() in _CLI_BINARY_NAMES:
            candidates.append(info)
    if len(candidates) != 1:
        raise CliIntegrityError(
            f"Expected exactly one Databricks CLI binary in the archive, "
            f"found {len(candidates)}."
        )
    if posixpath.basename(candidates[0].filename) != binary_name:
        raise CliIntegrityError(
            f"Databricks CLI archive holds {candidates[0].filename}, "
            f"expected {binary_name}."
        )
    return candidates[0]


def _extract_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, destination: str
) -> str:
    """Copy one member to ``destination`` with a byte cap; return its SHA-256."""
    digest = hashlib.sha256()
    written = 0
    limit = min(info.file_size, MAX_BINARY_BYTES)
    try:
        with archive.open(info) as source, open(destination, "wb") as target:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    raise CliIntegrityError(
                        f"Databricks CLI binary expands beyond its declared size: "
                        f"{info.filename}"
                    )
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    except (zipfile.BadZipFile, zlib.error, EOFError) as e:
        raise CliIntegrityError(
            f"Corrupt Databricks CLI archive member {info.filename}: {e}"
        ) from e
    if written != info.file_size:
        raise CliIntegrityError(f"Truncated Databricks CLI binary: {info.filename}")
    return digest.hexdigest()


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cached_cli_is_valid(
    binary_path: str, marker_path: str, archive_name: str, allow_unverified: bool
) -> bool:
    """Accept a cache entry only if its marker matches the binary on disk."""
    try:
        if not stat.S_ISREG(os.lstat(binary_path).st_mode):
            return False
        with open(marker_path, "r", encoding="utf-8") as handle:
            marker = json.load(handle)
        if not isinstance(marker, dict) or marker.get("archive") != archive_name:
            return False
        if marker.get("verified") is not True and not allow_unverified:
            return False
        expected = marker.get("binary_sha256")
        if not isinstance(expected, str):
            return False
        return hmac.compare_digest(_file_sha256(binary_path), expected)
    except (OSError, ValueError):
        return False


def _write_marker(
    save_directory: str, marker_path: str, payload: dict[str, Any]
) -> None:
    fd, temp_path = tempfile.mkstemp(
        prefix=".marker-", suffix=".tmp", dir=save_directory
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, marker_path)
    except BaseException:
        _remove_quietly(temp_path)
        raise


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def download_and_unzip_databricks_cli(url: str, version: str) -> str:
    """Download, verify and install the Databricks CLI binary; return its path.

    The archive's SHA-256 must match the release's SHA256SUMS before the ZIP is
    opened. The checksum comes from the same release origin as the archive, so
    it proves consistency with that release, not independent publisher
    authenticity. Installation writes a temporary file and renames it into
    place, so concurrent callers never observe a partial executable.
    """
    _validate_cli_version(version)
    archive_name, checksum_url, binary_name = _release_assets(url, version)
    save_directory = os.path.join(CLI_CACHE_ROOT, version)
    binary_path = os.path.abspath(os.path.join(save_directory, binary_name))
    marker_path = os.path.join(save_directory, CLI_CACHE_MARKER)
    unverified = version == "snapshot"
    allow_unverified = unverified and _allow_unverified_snapshot()
    if unverified and not allow_unverified:
        raise CliIntegrityError(
            "The Databricks CLI snapshot release publishes no checksums. Pin a "
            f"released version, set {BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT}"
            "=true to accept it unverified, or provide a CLI via "
            f"{BrickflowEnvVars.BRICKFLOW_BUNDLE_NO_DOWNLOAD.value}."
        )

    if _cached_cli_is_valid(binary_path, marker_path, archive_name, allow_unverified):
        _ilog.info("Databricks cli already exists. Skipping download.")
        return binary_path
    if os.path.lexists(binary_path):
        _ilog.info("Cached Databricks cli failed verification; reinstalling.")

    expected_sha256: Optional[str] = None
    if not unverified:
        expected_sha256 = _fetch_expected_sha256(checksum_url, archive_name)
    else:
        _ilog.warning("Installing the unverified Databricks CLI snapshot from %s.", url)

    os.makedirs(save_directory, exist_ok=True)
    archive_fd, archive_path = tempfile.mkstemp(
        prefix=".download-", suffix=".zip", dir=save_directory
    )
    binary_fd, binary_temp = tempfile.mkstemp(
        prefix=".databricks-", suffix=".tmp", dir=save_directory
    )
    os.close(binary_fd)
    try:
        archive_digest = hashlib.sha256()

        with os.fdopen(archive_fd, "wb") as archive_file:

            def _sink(chunk: bytes) -> None:
                archive_digest.update(chunk)
                archive_file.write(chunk)

            _stream_download(url, MAX_ARCHIVE_BYTES, _sink)
        actual_sha256 = archive_digest.hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(
            actual_sha256, expected_sha256
        ):
            raise CliIntegrityError(
                f"Checksum mismatch for {archive_name}: expected {expected_sha256}, "
                f"got {actual_sha256}."
            )

        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                member = _select_cli_member(archive, binary_name)
                binary_sha256 = _extract_member(archive, member, binary_temp)
        except zipfile.BadZipFile as e:
            raise CliIntegrityError(f"Invalid Databricks CLI archive: {e}") from e
        os.chmod(binary_temp, 0o755)

        _write_marker(
            save_directory,
            marker_path,
            {
                "archive": archive_name,
                "archive_sha256": actual_sha256,
                "binary_sha256": binary_sha256,
                "verified": expected_sha256 is not None,
            },
        )
        try:
            os.replace(binary_temp, binary_path)
        except PermissionError:
            # Windows cannot replace a running executable; another process
            # may have installed the same verified binary in the meantime.
            if not _cached_cli_is_valid(
                binary_path, marker_path, archive_name, allow_unverified
            ):
                raise
    finally:
        _remove_quietly(archive_path)
        _remove_quietly(binary_temp)

    _ilog.info("Databricks cli %s verified and installed at %s.", version, binary_path)
    return binary_path


def bundle_synth(**kwargs: Any) -> None:
    entrypoint_file = get_entrypoint(**kwargs)
    os.environ[BrickflowEnvVars.BRICKFLOW_DEPLOYMENT_MODE.value] = (
        BrickflowDeployMode.BUNDLE.value
    )
    os.environ[BrickflowEnvVars.BRICKFLOW_MODE.value] = "deploy"
    _ilog.info("Synthesizing bundle...")
    exec_command(get_entrypoint_python(), entrypoint_file, [])


def get_bundle_cli_version() -> str:
    return config(BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value, "0.236.1")


def bundle_cli_setup() -> None:
    # handle download bundle cli
    if config(BrickflowEnvVars.BRICKFLOW_BUNDLE_NO_DOWNLOAD.value, False, cast=bool):
        _ilog.info("Skipping bundle download...")
        return
    brickflow_bundle_version = get_bundle_cli_version()
    cli_download_url = bundle_download_path(brickflow_bundle_version)
    path = download_and_unzip_databricks_cli(cli_download_url, brickflow_bundle_version)
    os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value] = path
