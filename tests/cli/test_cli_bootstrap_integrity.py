"""Integrity and resource-limit tests for the Databricks CLI bootstrap.

Every archive here is synthetic and served from a loopback HTTP server. No
downloaded file is ever executed.
"""

import hashlib
import io
import json
import os
import stat
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterator, List, Optional, Tuple
from unittest.mock import patch

import pytest

from brickflow import BrickflowEnvVars
from brickflow.cli import bundles
from brickflow.cli.bundles import (
    CLI_CACHE_MARKER,
    CliIntegrityError,
    bundle_cli_setup,
    bundle_download_path,
    download_and_unzip_databricks_cli,
)

VERSION = "0.236.1"
ARCHIVE = f"databricks_cli_{VERSION}_linux_amd64.zip"
SUMS = f"databricks_cli_{VERSION}_SHA256SUMS"
BINARY = b"#!/bin/sh\necho synthetic-cli-must-not-run\n" * 64
EXEC_MODE = stat.S_IFREG | 0o755

# Public SHA256SUMS asset for the pinned v0.236.1 release, used only to prove
# the parser accepts the published format.
OFFICIAL_0_236_1_SUMS = """\
09f2083b0badd434212f8bf7c3debe87bc33f2f54818bb586ee253b394aeae04  databricks_cli_0.236.1_darwin_amd64.tar.gz
254802007b45fc894552e4d0132dcda9d968c7756e628cd623afb8ee71f7e74d  databricks_cli_0.236.1_darwin_amd64.zip
024a407ec1d18c1b8e5d0ae9f6d62e746b7220d7f1310be5ffb1f3f255390bcd  databricks_cli_0.236.1_darwin_arm64.tar.gz
c0ffa2fc5b00cd4cd3570bb706514d3a716a1025e356599d51a7df2bc5453164  databricks_cli_0.236.1_darwin_arm64.zip
6570f2e779ea9c0b525272bf465db26e6ce140b0218e7536bfd80733b0cba0e9  databricks_cli_0.236.1_linux_amd64.tar.gz
2bbf3fc1207bd34366f731ab268ef046b54b5ac0cecade3168b90669d92818e6  databricks_cli_0.236.1_linux_amd64.zip
7401da6460efadb74b3bb90da54a4750b18feaeb0ff35d032c920158c8605a1f  databricks_cli_0.236.1_linux_arm64.tar.gz
3e04eca06a643faa1ce3e8e833ae757f628735a57cc0a662479706b7720e42d1  databricks_cli_0.236.1_linux_arm64.zip
5ff86b162d05021627686f0959889cc5de4f568aa314f7d884fb535727f6095f  databricks_cli_0.236.1_windows_amd64.tar.gz
bd740e28427fff04393c2b55bb9a4553e4909a5105ca0ad065b1b350ee895691  databricks_cli_0.236.1_windows_amd64.zip
dd821e79563e201c3bdafef439a338e7f2b45ce6f90f06896511ed458ecae23c  databricks_cli_0.236.1_windows_arm64.tar.gz
8736a10ec40c9e1cab2aacfdb7fde21e00d4d66b1ea4308a0e376dce15db2dd4  databricks_cli_0.236.1_windows_arm64.zip
"""


def make_zip(members: List[Tuple[str, bytes, int]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


def release_zip(binary_name: str = "databricks", binary: bytes = BINARY) -> bytes:
    """Same member layout as the published 0.236.1 archives."""
    return make_zip(
        [
            ("CHANGELOG.md", b"changes\n", stat.S_IFREG | 0o644),
            ("LICENSE", b"license\n", stat.S_IFREG | 0o644),
            ("README.md", b"readme\n", stat.S_IFREG | 0o644),
            (binary_name, binary, EXEC_MODE),
        ]
    )


def sums_for(name: str, payload: bytes) -> bytes:
    return f"{hashlib.sha256(payload).hexdigest()}  {name}\n".encode("ascii")


class Route:
    def __init__(
        self,
        body: bytes = b"",
        status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        content_length: Optional[int] = -1,
    ):
        self.body = body
        self.status = status
        self.headers = headers or {}
        # -1: send the real length; None: omit the header (close-delimited).
        self.content_length = content_length


class ReleaseServer:
    def __init__(self) -> None:
        self.routes: Dict[str, Route] = {}
        self.requests: List[Tuple[str, Dict[str, str]]] = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                with outer.lock:
                    outer.requests.append((self.path, dict(self.headers)))
                    route = outer.routes.get(self.path, Route(b"missing", 404))
                self.send_response(route.status)
                for key, value in route.headers.items():
                    self.send_header(key, value)
                if route.content_length == -1:
                    self.send_header("Content-Length", str(len(route.body)))
                elif route.content_length is not None:
                    self.send_header("Content-Length", str(route.content_length))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(route.body)
                self.wfile.flush()

            def log_message(self, *_: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}/releases"
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    def path(self, name: str, tag: str = f"v{VERSION}") -> str:
        return f"/releases/{tag}/{name}"

    def url(self, name: str, tag: str = f"v{VERSION}") -> str:
        return f"{self.base}/{tag}/{name}"

    def publish(self, archive: bytes, sums: Optional[bytes] = None) -> None:
        self.routes[self.path(ARCHIVE)] = Route(archive)
        self.routes[self.path(SUMS)] = Route(
            sums if sums is not None else sums_for(ARCHIVE, archive)
        )

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(name="server")
def server_fixture(tmp_path, monkeypatch) -> Iterator[ReleaseServer]:
    monkeypatch.chdir(tmp_path)
    for name in (
        BrickflowEnvVars.BRICKFLOW_BUNDLE_NO_DOWNLOAD.value,
        BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value,
        bundles.BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT,
    ):
        monkeypatch.delenv(name, raising=False)
    release = ReleaseServer()
    monkeypatch.setattr(bundles, "DATABRICKS_CLI_RELEASE_BASE_URL", release.base)
    monkeypatch.setattr(bundles.platform, "system", lambda: "Linux")
    monkeypatch.setattr(bundles, "get_arch", lambda: "amd64")
    yield release
    release.close()


def cache_dir(version: str = VERSION) -> str:
    return os.path.join(".databricks", "bin", "cli", version)


def install(_release: ReleaseServer, version: str = VERSION) -> str:
    return download_and_unzip_databricks_cli(bundle_download_path(version), version)


def assert_no_install(version: str = VERSION) -> None:
    directory = cache_dir(version)
    leftovers = os.listdir(directory) if os.path.isdir(directory) else []
    assert not leftovers, leftovers


class TestVerifiedInstall:
    def test_installs_only_verified_binary_atomically(self, server):
        server.publish(release_zip())
        path = install(server)

        assert path == os.path.abspath(os.path.join(cache_dir(), "databricks"))
        with open(path, "rb") as handle:
            assert handle.read() == BINARY
        assert os.stat(path).st_mode & 0o777 == 0o755
        assert sorted(os.listdir(cache_dir())) == [CLI_CACHE_MARKER, "databricks"]
        with open(os.path.join(cache_dir(), CLI_CACHE_MARKER), encoding="utf-8") as fh:
            marker = json.load(fh)
        assert marker["verified"] is True
        assert marker["binary_sha256"] == hashlib.sha256(BINARY).hexdigest()
        # Checksums are fetched before the archive.
        assert [p for p, _ in server.requests] == [
            server.path(SUMS),
            server.path(ARCHIVE),
        ]

    def test_cache_hit_is_offline_and_rechecked(self, server):
        server.publish(release_zip())
        first = install(server)
        server.routes.clear()
        server.requests.clear()

        assert install(server) == first
        assert server.requests == []

    def test_tampered_cache_is_reinstalled(self, server):
        server.publish(release_zip())
        path = install(server)
        with open(path, "wb") as handle:
            handle.write(b"tampered")

        install(server)
        with open(path, "rb") as handle:
            assert handle.read() == BINARY

    def test_legacy_cache_without_marker_is_replaced(self, server):
        os.makedirs(cache_dir())
        legacy = os.path.join(cache_dir(), "databricks")
        with open(legacy, "wb") as handle:
            handle.write(b"unverified legacy binary")
        server.publish(release_zip())

        install(server)
        with open(legacy, "rb") as handle:
            assert handle.read() == BINARY

    def test_symlinked_cache_entry_is_not_trusted(self, server, tmp_path):
        server.publish(release_zip())
        path = install(server)
        target = tmp_path / "elsewhere"
        target.write_bytes(BINARY)
        os.remove(path)
        os.symlink(target, path)

        install(server)
        assert not os.path.islink(path)

    def test_windows_archive_installs_exe(self, server):
        name = f"databricks_cli_{VERSION}_windows_amd64.zip"
        archive = release_zip("databricks.exe")
        server.routes[server.path(name)] = Route(archive)
        server.routes[server.path(SUMS)] = Route(sums_for(name, archive))

        path = download_and_unzip_databricks_cli(server.url(name), VERSION)
        assert os.path.basename(path) == "databricks.exe"

    def test_redirect_to_same_loopback_origin_is_followed(self, server):
        archive = release_zip()
        server.publish(archive)
        server.routes["/assets/blob"] = Route(archive)
        server.routes[server.path(ARCHIVE)] = Route(
            status=302, headers={"Location": "/assets/blob"}
        )
        assert os.path.exists(install(server))

    def test_no_ambient_netrc_credentials(self, server, tmp_path, monkeypatch):
        netrc = tmp_path / "netrc"
        netrc.write_text("machine 127.0.0.1 login user password sentinel-secret\n")
        netrc.chmod(0o600)
        monkeypatch.setenv("NETRC", str(netrc))
        server.publish(release_zip())

        install(server)
        for _, headers in server.requests:
            assert "Authorization" not in headers
            assert headers.get("Accept-Encoding") == "identity"

    def test_concurrent_installs_converge(self, server):
        server.publish(release_zip())
        results: List[str] = []
        errors: List[BaseException] = []

        def worker() -> None:
            try:
                results.append(install(server))
            except BaseException as e:  # pylint: disable=broad-except
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        assert len(set(results)) == 1
        with open(results[0], "rb") as handle:
            assert handle.read() == BINARY
        assert sorted(os.listdir(cache_dir())) == [CLI_CACHE_MARKER, "databricks"]

    def test_failed_reinstall_keeps_previous_binary(self, server):
        server.publish(release_zip())
        path = install(server)
        os.remove(os.path.join(cache_dir(), CLI_CACHE_MARKER))
        server.routes[server.path(ARCHIVE)] = Route(b"tampered")

        with pytest.raises(CliIntegrityError):
            install(server)
        with open(path, "rb") as handle:
            assert handle.read() == BINARY
        assert sorted(os.listdir(cache_dir())) == ["databricks"]


class TestRejectedDownloads:
    def test_tampered_archive(self, server):
        good = release_zip()
        server.publish(release_zip(binary=b"evil"), sums=sums_for(ARCHIVE, good))
        with pytest.raises(CliIntegrityError, match="Checksum mismatch"):
            install(server)
        assert_no_install()

    def test_missing_checksum_asset(self, server):
        server.routes[server.path(ARCHIVE)] = Route(release_zip())
        with pytest.raises(CliIntegrityError, match="HTTP 404"):
            install(server)
        assert_no_install()
        assert [p for p, _ in server.requests] == [server.path(SUMS)]

    @pytest.mark.parametrize(
        "sums",
        [
            b"",
            b"not-a-checksum  " + ARCHIVE.encode(),
            ("a" * 64 + "  other.zip\n").encode(),
            ("a" * 64 + "  " + ARCHIVE + "\n" + "b" * 64 + "  " + ARCHIVE).encode(),
            ("a" * 64 + "  ../" + ARCHIVE).encode(),
            b"\xff" * 70,
        ],
        ids=["empty", "malformed", "no-entry", "conflict", "path", "binary"],
    )
    def test_bad_checksum_file(self, server, sums):
        server.publish(release_zip(), sums=sums)
        with pytest.raises(CliIntegrityError):
            install(server)
        assert_no_install()

    def test_oversized_checksum_file(self, server, monkeypatch):
        monkeypatch.setattr(bundles, "MAX_CHECKSUM_BYTES", 32)
        server.publish(release_zip())
        with pytest.raises(CliIntegrityError, match="byte limit"):
            install(server)

    def test_oversized_declared_length(self, server, monkeypatch):
        archive = release_zip()
        server.publish(archive)
        monkeypatch.setattr(bundles, "MAX_ARCHIVE_BYTES", len(archive) - 1)
        with pytest.raises(CliIntegrityError, match="byte limit"):
            install(server)
        assert_no_install()

    def test_oversized_undeclared_stream(self, server, monkeypatch):
        archive = release_zip()
        server.publish(archive)
        server.routes[server.path(ARCHIVE)] = Route(archive, content_length=None)
        monkeypatch.setattr(bundles, "MAX_ARCHIVE_BYTES", len(archive) - 1)
        with pytest.raises(CliIntegrityError, match="byte limit"):
            install(server)
        assert_no_install()

    def test_truncated_response(self, server):
        archive = release_zip()
        server.publish(archive)
        server.routes[server.path(ARCHIVE)] = Route(
            archive[:-50], content_length=len(archive)
        )
        with pytest.raises(CliIntegrityError, match="[Tt]runcated"):
            install(server)
        assert_no_install()

    def test_truncated_archive_with_matching_checksum(self, server):
        server.publish(release_zip()[:-30])
        with pytest.raises(CliIntegrityError):
            install(server)
        assert_no_install()

    def test_corrupt_member_with_matching_checksum(self, server):
        archive = bytearray(make_zip([("databricks", BINARY, EXEC_MODE)]))
        with zipfile.ZipFile(io.BytesIO(bytes(archive))) as parsed:
            info = parsed.getinfo("databricks")
        # Flip a byte inside the deflate stream of the only member.
        data_start = info.header_offset + 30 + len(info.filename) + len(info.extra)
        archive[data_start + info.compress_size // 2] ^= 0xFF
        server.publish(bytes(archive))
        with pytest.raises(CliIntegrityError):
            install(server)
        assert_no_install()

    def test_gzip_content_encoding(self, server):
        archive = release_zip()
        server.publish(archive)
        server.routes[server.path(ARCHIVE)] = Route(
            archive, headers={"Content-Encoding": "gzip"}
        )
        with pytest.raises(CliIntegrityError, match="content encoding"):
            install(server)

    def test_redirect_loop(self, server):
        server.publish(release_zip())
        server.routes[server.path(ARCHIVE)] = Route(
            status=302, headers={"Location": server.path(ARCHIVE)}
        )
        with pytest.raises(CliIntegrityError, match="Too many redirects"):
            install(server)

    def test_redirect_to_non_loopback_http(self, server):
        server.publish(release_zip())
        server.routes[server.path(ARCHIVE)] = Route(
            status=302, headers={"Location": "http://example.invalid/cli.zip"}
        )
        with pytest.raises(CliIntegrityError, match="Refusing"):
            install(server)
        assert_no_install()

    def test_snapshot_rejected_without_network(self, server):
        with pytest.raises(CliIntegrityError, match="publishes no checksums"):
            install(server, "snapshot")
        assert server.requests == []

    @pytest.mark.parametrize(
        "version", ["../../escape", "0.236.1/../x", "", "v0.236.1"]
    )
    def test_invalid_version(self, server, version):
        with pytest.raises(CliIntegrityError, match="Invalid Databricks CLI version"):
            download_and_unzip_databricks_cli(server.url(ARCHIVE), version)
        assert server.requests == []
        assert not os.path.exists(".databricks")


class TestArchiveLayout:
    def publish_layout(self, server, members: List[Tuple[str, bytes, int]]) -> None:
        server.publish(make_zip(members))

    @pytest.mark.parametrize(
        "members",
        [
            [
                ("databricks", BINARY, EXEC_MODE),
                ("nested/databricks", BINARY, EXEC_MODE),
            ],
            [("databricks", BINARY, EXEC_MODE), ("databricks.exe", BINARY, EXEC_MODE)],
            [("README.md", b"x", stat.S_IFREG | 0o644)],
            [("databricks.exe", BINARY, EXEC_MODE)],
        ],
        ids=["two-binaries", "two-platforms", "no-binary", "wrong-platform"],
    )
    def test_requires_exactly_the_expected_binary(self, server, members):
        self.publish_layout(server, members)
        with pytest.raises(CliIntegrityError, match="[Ee]xpected"):
            install(server)
        assert_no_install()

    @pytest.mark.parametrize(
        "name",
        [
            "../databricks",
            "a/../../databricks",
            "/etc/databricks",
            "C:/databricks",
            "a\\databricks",
        ],
    )
    def test_rejects_traversal(self, server, name):
        self.publish_layout(server, [(name, BINARY, EXEC_MODE)])
        with pytest.raises(CliIntegrityError, match="Unsafe path"):
            install(server)
        assert_no_install()
        assert not os.path.exists(os.path.join("..", "databricks"))

    def test_rejects_symlink_member(self, server):
        self.publish_layout(
            server,
            [
                ("databricks", BINARY, EXEC_MODE),
                ("LICENSE", b"/etc/passwd", stat.S_IFLNK | 0o777),
            ],
        )
        with pytest.raises(CliIntegrityError, match="Symlink"):
            install(server)
        assert_no_install()

    def test_rejects_symlink_binary(self, server):
        self.publish_layout(server, [("databricks", b"/bin/sh", stat.S_IFLNK | 0o777)])
        with pytest.raises(CliIntegrityError, match="Symlink"):
            install(server)
        assert_no_install()

    def test_rejects_duplicate_members(self, server):
        buffer = io.BytesIO()
        with pytest.warns(UserWarning):
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("databricks", BINARY)
                archive.writestr("databricks", b"second")
        server.publish(buffer.getvalue())
        with pytest.raises(CliIntegrityError, match="Duplicate"):
            install(server)

    def test_member_count_limit(self, server, monkeypatch):
        monkeypatch.setattr(bundles, "MAX_ARCHIVE_MEMBERS", 3)
        server.publish(release_zip())
        with pytest.raises(CliIntegrityError, match="members"):
            install(server)
        assert_no_install()

    def test_expanded_total_limit(self, server, monkeypatch):
        archive = release_zip()
        monkeypatch.setattr(bundles, "MAX_TOTAL_EXPANDED_BYTES", len(BINARY))
        server.publish(archive)
        with pytest.raises(CliIntegrityError, match="expands beyond"):
            install(server)
        assert_no_install()

    def test_highly_compressible_binary_limit(self, server, monkeypatch):
        bomb = b"\0" * (4 * 1024 * 1024)
        archive = make_zip([("databricks", bomb, EXEC_MODE)])
        assert len(archive) < 16 * 1024
        monkeypatch.setattr(bundles, "MAX_BINARY_BYTES", 1024 * 1024)
        server.publish(archive)
        with pytest.raises(CliIntegrityError, match="too large"):
            install(server)
        assert_no_install()

    def test_understated_member_size_is_rejected(self, server):
        archive = bytearray(make_zip([("databricks", BINARY, EXEC_MODE)]))
        # Lower the uncompressed size in both the local and central headers.
        size = len(BINARY).to_bytes(4, "little")
        smaller = (len(BINARY) - 10).to_bytes(4, "little")
        assert archive.count(size) == 2
        patched = bytes(archive).replace(size, smaller)
        server.publish(patched)
        with pytest.raises(CliIntegrityError):
            install(server)
        assert_no_install()

    def test_encrypted_member(self, server):
        archive = bytearray(make_zip([("databricks", BINARY, EXEC_MODE)]))
        # Set the encryption flag in the local and central directory headers.
        archive[6] |= 0x1
        central = bytes(archive).rfind(b"PK\x01\x02")
        archive[central + 8] |= 0x1
        server.publish(bytes(archive))
        with pytest.raises(CliIntegrityError, match="Encrypted"):
            install(server)


class TestPolicyAndCompatibility:
    def test_default_download_path_is_official_release(self):
        with (
            patch.object(bundles.platform, "system", return_value="Linux"),
            patch.object(bundles, "get_arch", return_value="amd64"),
        ):
            assert bundle_download_path(VERSION) == (
                "https://github.com/databricks/cli/releases/download/"
                f"v{VERSION}/{ARCHIVE}"
            )
            assert bundle_download_path("snapshot") == (
                "https://github.com/databricks/cli/releases/download/"
                "snapshot/databricks_cli_linux_amd64.zip"
            )

    def test_checksum_url_shares_archive_release_directory(self):
        name, checksum_url, binary = bundles._release_assets(
            "https://github.com/databricks/cli/releases/download/"
            f"v{VERSION}/{ARCHIVE}",
            VERSION,
        )
        assert name == ARCHIVE
        assert binary == "databricks"
        assert checksum_url == (
            "https://github.com/databricks/cli/releases/download/" f"v{VERSION}/{SUMS}"
        )

    def test_parser_accepts_published_0_236_1_format(self):
        entries = bundles._parse_sha256sums(OFFICIAL_0_236_1_SUMS)
        assert len(entries) == 12
        assert entries[ARCHIVE] == (
            "2bbf3fc1207bd34366f731ab268ef046b54b5ac0cecade3168b90669d92818e6"
        )

    def test_default_version_is_pinned(self, monkeypatch):
        monkeypatch.delenv(
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value, raising=False
        )
        assert bundles.get_bundle_cli_version() == VERSION

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/cli.zip",
            "ftp://127.0.0.1/cli.zip",
            "https://user:pass@github.com/cli.zip",
            "file:///tmp/cli.zip",
        ],
    )
    def test_url_policy(self, url):
        with pytest.raises(CliIntegrityError):
            bundles._check_download_url(url, None)

    def test_https_to_http_downgrade_is_refused(self):
        with pytest.raises(CliIntegrityError):
            bundles._check_download_url("http://127.0.0.1/cli.zip", "https")

    def test_unverified_snapshot_opt_in(self, server, monkeypatch):
        archive = release_zip()
        name = "databricks_cli_linux_amd64.zip"
        server.routes[server.path(name, "snapshot")] = Route(archive)
        monkeypatch.setenv(
            bundles.BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT, "true"
        )

        path = install(server, "snapshot")
        with open(
            os.path.join(cache_dir("snapshot"), CLI_CACHE_MARKER), encoding="utf-8"
        ) as fh:
            assert json.load(fh)["verified"] is False
        assert [p for p, _ in server.requests] == [server.path(name, "snapshot")]

        # Without the opt-in the unverified cache entry is not used.
        monkeypatch.delenv(bundles.BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT)
        with pytest.raises(CliIntegrityError):
            install(server, "snapshot")
        assert os.path.exists(path)

    def test_unverified_snapshot_still_checks_layout(self, server, monkeypatch):
        name = "databricks_cli_linux_amd64.zip"
        server.routes[server.path(name, "snapshot")] = Route(
            make_zip([("../databricks", BINARY, EXEC_MODE)])
        )
        monkeypatch.setenv(
            bundles.BRICKFLOW_BUNDLE_CLI_ALLOW_UNVERIFIED_SNAPSHOT, "true"
        )
        with pytest.raises(CliIntegrityError, match="Unsafe path"):
            install(server, "snapshot")
        assert_no_install("snapshot")

    def test_setup_exports_verified_path(self, server, monkeypatch):
        monkeypatch.delenv(
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value, raising=False
        )
        server.publish(release_zip())
        with patch.dict(os.environ, {}):
            bundle_cli_setup()
            exported = os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value]
        assert exported == os.path.abspath(os.path.join(cache_dir(), "databricks"))

    def test_setup_no_download_override_skips_network(self, server, monkeypatch):
        monkeypatch.setenv(BrickflowEnvVars.BRICKFLOW_BUNDLE_NO_DOWNLOAD.value, "true")
        monkeypatch.setenv(
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value, "/opt/cli/databricks"
        )
        bundle_cli_setup()
        assert os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value] == (
            "/opt/cli/databricks"
        )
        assert server.requests == []
        assert not os.path.exists(".databricks")

    @pytest.mark.usefixtures("server")
    def test_setup_failure_is_click_exception(self):
        from click import ClickException  # pylint: disable=import-outside-toplevel

        with pytest.raises(ClickException):
            bundle_cli_setup()
        assert_no_install()
