"""Security regressions for ArtifactoryClient downloads.

All traffic stays on loopback servers started by these tests. Credentials are
synthetic sentinels, and TLS uses a throwaway certificate generated per run.
"""

import datetime
import gzip
import ipaddress
import logging
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple
from unittest.mock import Mock, patch

import pytest
import requests

from brickflow.engine.task_executor import (
    ArtifactDownloadError,
    ArtifactoryClient,
    redact_url,
)

SENTINEL_KEY = "SENTINEL-ARTIFACT-KEY-0d9c7a"
SENTINEL_QUERY_TOKEN = "SENTINEL-QUERY-TOKEN-4b21"
SENTINEL_PASSWORD = "SENTINEL-URL-PASSWORD-77e0"
KEY_HEADER = "X-JFrog-Art-Api"


class _Recorder:
    def __init__(self) -> None:
        self.requests: List[Dict[str, Optional[str]]] = []
        self.lock = threading.Lock()

    def add(self, path: str, headers) -> None:
        with self.lock:
            self.requests.append(
                {
                    "path": path,
                    "key": headers.get(KEY_HEADER),
                    "accept_encoding": headers.get("Accept-Encoding"),
                    "authorization": headers.get("Authorization"),
                }
            )


Route = Callable[[BaseHTTPRequestHandler], None]


class _Server:
    """A loopback HTTP(S) server with per-path routes and a request log."""

    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self.routes: Dict[str, Route] = {}
        self.recorder = _Recorder()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                server.recorder.add(self.path, self.headers)
                route = server.routes.get(path)
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                route(self)

            def log_message(self, *args) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.scheme = "http"
        if ssl_context is not None:
            self.httpd.socket = ssl_context.wrap_socket(
                self.httpd.socket, server_side=True
            )
            self.scheme = "https"
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, args=(0.05,), daemon=True
        )

    @property
    def base(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.httpd.server_port}"

    def url(self, path: str) -> str:
        return self.base + path

    def __enter__(self) -> "_Server":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def body(data: bytes, extra_headers: Optional[Dict[str, str]] = None) -> Route:
    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or {}).items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(data)

    return route


def unbounded_body(data: bytes) -> Route:
    """Respond without Content-Length; the connection close ends the body."""

    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(data)
        handler.close_connection = True

    return route


def redirect(location: str, status: int = 302) -> Route:
    def route(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(status)
        handler.send_header("Location", location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    return route


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("NETRC", str(home / ".netrc"))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("NO_PROXY", "*")
    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "CURL_CA_BUNDLE",
    ):
        monkeypatch.delenv(var, raising=False)
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(temp_root))


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory) -> Tuple[Path, Path]:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def https_server_factory(tls_material, monkeypatch) -> Iterator[Callable[[], _Server]]:
    cert_path, key_path = tls_material
    # requests reads the trust store from this variable (trust_env=True).
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert_path))

    def make() -> _Server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        return _Server(context)

    yield make


@pytest.fixture
def internal_log() -> Iterator[List[str]]:
    """Capture brickflow's internal logger, which does not propagate."""
    records: List[str] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    logger = logging.getLogger("brickflow-internal")
    handler = _Handler(level=logging.DEBUG)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def _credentialed() -> ArtifactoryClient:
    return ArtifactoryClient(username="synthetic-user", api_key=SENTINEL_KEY)


def _leftovers(directory: Path) -> List[str]:
    return sorted(p.name for p in directory.iterdir())


class TestCredentialedRedirects:
    def test_key_not_forwarded_to_other_origin(self, https_server_factory, tmp_path):
        origin_a = https_server_factory()
        origin_b = https_server_factory()
        with origin_a, origin_b:
            origin_b.routes["/artifact.whl"] = body(b"payload-from-b")
            origin_a.routes["/artifact.whl"] = redirect(origin_b.url("/artifact.whl"))
            destination = tmp_path / "out.whl"

            result = _credentialed().download_artifact(
                origin_a.url("/artifact.whl"), destination
            )

        assert result == destination
        assert destination.read_bytes() == b"payload-from-b"
        assert [r["key"] for r in origin_a.recorder.requests] == [SENTINEL_KEY]
        assert [r["key"] for r in origin_b.recorder.requests] == [None]

    def test_key_preserved_on_same_origin_redirect(
        self, https_server_factory, tmp_path
    ):
        origin = https_server_factory()
        with origin:
            origin.routes["/a.whl"] = redirect("/b.whl", status=301)
            origin.routes["/b.whl"] = body(b"same-origin")
            destination = tmp_path / "out.whl"
            _credentialed().download_artifact(origin.url("/a.whl"), destination)

        assert destination.read_bytes() == b"same-origin"
        assert [r["key"] for r in origin.recorder.requests] == [
            SENTINEL_KEY,
            SENTINEL_KEY,
        ]

    def test_key_not_resent_after_returning_to_origin(
        self, https_server_factory, tmp_path
    ):
        origin_a = https_server_factory()
        origin_b = https_server_factory()
        with origin_a, origin_b:
            origin_a.routes["/start.whl"] = redirect(origin_b.url("/hop"))
            origin_b.routes["/hop"] = redirect(origin_a.url("/final.whl"), 307)
            origin_a.routes["/final.whl"] = body(b"final")
            destination = tmp_path / "out.whl"
            _credentialed().download_artifact(origin_a.url("/start.whl"), destination)

        assert destination.read_bytes() == b"final"
        assert [r["key"] for r in origin_a.recorder.requests] == [SENTINEL_KEY, None]
        assert [r["key"] for r in origin_b.recorder.requests] == [None]

    def test_https_to_http_downgrade_refused(self, https_server_factory, tmp_path):
        secure = https_server_factory()
        with secure, _Server() as plain:
            plain.routes["/artifact.whl"] = body(b"should-not-be-fetched")
            secure.routes["/artifact.whl"] = redirect(plain.url("/artifact.whl"))
            destination = tmp_path / "out.whl"

            with pytest.raises(ArtifactDownloadError, match="https to http"):
                _credentialed().download_artifact(
                    secure.url("/artifact.whl"), destination
                )

        assert plain.recorder.requests == []
        assert not destination.exists()
        assert _leftovers(tmp_path) == ["home", "tmp"]

    def test_same_host_different_port_is_cross_origin(
        self, https_server_factory, tmp_path
    ):
        # Both servers share scheme and host; only the port differs.
        first = https_server_factory()
        second = https_server_factory()
        with first, second:
            assert first.httpd.server_port != second.httpd.server_port
            second.routes["/x.whl"] = body(b"x")
            first.routes["/x.whl"] = redirect(second.url("/x.whl"))
            _credentialed().download_artifact(first.url("/x.whl"), tmp_path / "x.whl")

        assert second.recorder.requests[0]["key"] is None

    def test_credentialed_http_url_refused_before_any_request(self, tmp_path):
        with _Server() as plain:
            plain.routes["/artifact.whl"] = body(b"never")
            with pytest.raises(ArtifactDownloadError, match="Refusing to send"):
                _credentialed().download_artifact(
                    plain.url("/artifact.whl"), tmp_path / "out.whl"
                )
        assert plain.recorder.requests == []

    def test_userinfo_url_requires_https(self, tmp_path):
        with _Server() as plain:
            url = plain.url("/a.whl").replace(
                "http://", f"http://synthetic:{SENTINEL_PASSWORD}@"
            )
            with pytest.raises(ArtifactDownloadError) as excinfo:
                ArtifactoryClient().download_artifact(url, tmp_path / "out.whl")
        assert plain.recorder.requests == []
        assert SENTINEL_PASSWORD not in str(excinfo.value)

    def test_redirect_limit(self, https_server_factory, tmp_path):
        origin = https_server_factory()
        with origin:
            for i in range(10):
                origin.routes[f"/r{i}"] = redirect(f"/r{i + 1}")
            origin.routes["/r10"] = body(b"end")
            client = ArtifactoryClient(
                username="synthetic-user", api_key=SENTINEL_KEY, max_redirects=3
            )
            with pytest.raises(ArtifactDownloadError, match="Too many redirects"):
                client.download_artifact(origin.url("/r0"), tmp_path / "out.whl")
            # Initial request plus three permitted redirects.
            assert len(origin.recorder.requests) == 4

            client.max_redirects = 10
            client.download_artifact(origin.url("/r0"), tmp_path / "ok.whl")
        assert (tmp_path / "ok.whl").read_bytes() == b"end"

    def test_redirect_without_location(self, https_server_factory, tmp_path):
        origin = https_server_factory()

        def no_location(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(302)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with origin:
            origin.routes["/a.whl"] = no_location
            with pytest.raises(ArtifactDownloadError, match="Location"):
                _credentialed().download_artifact(
                    origin.url("/a.whl"), tmp_path / "out.whl"
                )


class TestUnauthenticatedDownloads:
    def test_plain_http_still_supported(self, tmp_path):
        with _Server() as first, _Server() as second:
            second.routes["/lib.whl"] = body(b"plain-http")
            first.routes["/lib.whl"] = redirect(second.url("/lib.whl"))
            destination = tmp_path / "lib.whl"
            ArtifactoryClient().download_artifact(first.url("/lib.whl"), destination)

        assert destination.read_bytes() == b"plain-http"
        assert first.recorder.requests[0]["key"] is None

    def test_username_without_key_is_not_credentialed(self, tmp_path):
        with _Server() as plain:
            plain.routes["/lib.whl"] = body(b"ok")
            ArtifactoryClient(username="synthetic-user").download_artifact(
                plain.url("/lib.whl"), tmp_path / "lib.whl"
            )
        assert plain.recorder.requests[0]["key"] is None

    def test_identity_encoding_requested(self, tmp_path):
        with _Server() as plain:
            plain.routes["/lib.whl"] = body(b"ok")
            ArtifactoryClient().download_artifact(
                plain.url("/lib.whl"), tmp_path / "lib.whl"
            )
        assert plain.recorder.requests[0]["accept_encoding"] == "identity"

    @pytest.mark.parametrize(
        "url",
        ["file:///etc/hosts", "ftp://127.0.0.1/a.whl", "127.0.0.1/a.whl"],
    )
    def test_non_http_schemes_rejected(self, url, tmp_path):
        with pytest.raises(ArtifactDownloadError, match="Unsupported"):
            ArtifactoryClient().download_artifact(url, tmp_path / "out.whl")


class TestSizeLimits:
    def test_declared_length_over_limit(self, tmp_path):
        destination = tmp_path / "out.whl"
        destination.write_bytes(b"previous")
        with _Server() as plain:
            plain.routes["/big.whl"] = body(b"x" * 2048)
            with pytest.raises(ArtifactDownloadError, match="exceeds"):
                ArtifactoryClient(max_bytes=1024).download_artifact(
                    plain.url("/big.whl"), destination
                )
        assert destination.read_bytes() == b"previous"
        assert _leftovers(tmp_path) == ["home", "out.whl", "tmp"]

    def test_streamed_body_over_limit(self, tmp_path):
        destination = tmp_path / "out.whl"
        with _Server() as plain:
            plain.routes["/big.whl"] = unbounded_body(b"y" * 50_000)
            with pytest.raises(ArtifactDownloadError, match="exceeds"):
                ArtifactoryClient(max_bytes=10_000).download_artifact(
                    plain.url("/big.whl"), destination
                )
        assert not destination.exists()
        assert _leftovers(tmp_path) == ["home", "tmp"]

    def test_unexpected_compression_is_rejected(self, tmp_path):
        # A small gzip body that inflates far beyond the limit, sent even though
        # the client asked for identity encoding.
        compressed = gzip.compress(b"\0" * 5_000_000)
        assert len(compressed) < 10_000
        destination = tmp_path / "out.whl"
        with _Server() as plain:
            plain.routes["/bomb.whl"] = body(compressed, {"Content-Encoding": "gzip"})
            with pytest.raises(ArtifactDownloadError, match="Content-Encoding"):
                ArtifactoryClient(max_bytes=100_000).download_artifact(
                    plain.url("/bomb.whl"), destination
                )
        assert not destination.exists()
        assert _leftovers(tmp_path) == ["home", "tmp"]

    def test_exact_limit_allowed(self, tmp_path):
        with _Server() as plain:
            plain.routes["/fit.whl"] = body(b"z" * 1024)
            ArtifactoryClient(max_bytes=1024).download_artifact(
                plain.url("/fit.whl"), tmp_path / "fit.whl"
            )
        assert (tmp_path / "fit.whl").stat().st_size == 1024

    @pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_redirects": -1}])
    def test_invalid_limits(self, kwargs):
        with pytest.raises(ValueError):
            ArtifactoryClient(**kwargs)


class TestFilesystemSafety:
    def test_symlinked_destination_is_replaced_not_followed(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"must-not-change")
        workdir = tmp_path / "work"
        workdir.mkdir()
        destination = workdir / "artifact.whl"
        destination.symlink_to(outside)

        with _Server() as plain:
            plain.routes["/a.whl"] = body(b"new-artifact")
            ArtifactoryClient().download_artifact(plain.url("/a.whl"), destination)

        assert outside.read_bytes() == b"must-not-change"
        assert not destination.is_symlink()
        assert destination.read_bytes() == b"new-artifact"
        assert _leftovers(workdir) == ["artifact.whl"]

    def test_failed_download_keeps_previous_file(self, tmp_path):
        destination = tmp_path / "artifact.whl"
        destination.write_bytes(b"previous")
        with _Server() as plain:
            plain.routes["/a.whl"] = unbounded_body(b"q" * 5000)
            with pytest.raises(ArtifactDownloadError):
                ArtifactoryClient(max_bytes=100).download_artifact(
                    plain.url("/a.whl"), destination
                )
        assert destination.read_bytes() == b"previous"

    def test_temporary_destination_removed_on_failure(self, tmp_path):
        temp_root = tmp_path / "tmp"
        with _Server() as plain:
            with pytest.raises(ArtifactDownloadError):
                ArtifactoryClient().download_artifact(plain.url("/missing.whl"))
        assert _leftovers(temp_root) == []

    def test_temporary_destination_suffix_ignores_query(self, tmp_path):
        with _Server() as plain:
            plain.routes["/pkg.whl"] = body(b"wheel")
            result = ArtifactoryClient().download_artifact(
                plain.url(f"/pkg.whl?token={SENTINEL_QUERY_TOKEN}")
            )
        try:
            assert result.parent == tmp_path / "tmp"
            assert result.suffix == ".whl"
            assert SENTINEL_QUERY_TOKEN not in result.name
            assert result.read_bytes() == b"wheel"
            assert oct(result.stat().st_mode & 0o777) == oct(0o600)
        finally:
            result.unlink()


class TestRedaction:
    def test_redact_url(self):
        assert (
            redact_url(f"https://u:{SENTINEL_PASSWORD}@h.example:8443/p.whl?t=1#f")
            == "https://h.example:8443/p.whl?<redacted>#<redacted>"
        )
        assert redact_url("http://h.example/p.whl") == "http://h.example/p.whl"
        assert redact_url("https://[::1]:9/p") == "https://[::1]:9/p"
        assert redact_url("http://h:notaport/p") == "<redacted>"

    def test_http_error_does_not_leak_secrets(
        self, https_server_factory, tmp_path, internal_log
    ):
        origin = https_server_factory()
        with origin:
            url = origin.url(f"/missing.whl?token={SENTINEL_QUERY_TOKEN}")
            with pytest.raises(ArtifactDownloadError) as excinfo:
                _credentialed().download_artifact(url, tmp_path / "out.whl")

        rendered = [str(excinfo.value), repr(excinfo.value)] + internal_log
        assert any("404" in text for text in rendered)
        for text in rendered:
            assert SENTINEL_QUERY_TOKEN not in text
            assert SENTINEL_KEY not in text
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__
        assert isinstance(excinfo.value, requests.RequestException)

    def test_connection_error_does_not_leak_secrets(self, tmp_path, internal_log):
        with _Server() as plain:
            port = plain.httpd.server_port
        # The server is closed, so the connection is refused.
        url = (
            f"https://synthetic:{SENTINEL_PASSWORD}@127.0.0.1:{port}"
            f"/a.whl?token={SENTINEL_QUERY_TOKEN}"
        )
        with pytest.raises(ArtifactDownloadError) as excinfo:
            ArtifactoryClient(
                username="synthetic-user", api_key=SENTINEL_KEY
            ).download_artifact(url, tmp_path / "out.whl")

        rendered = [str(excinfo.value)] + internal_log
        for text in rendered:
            for secret in (SENTINEL_QUERY_TOKEN, SENTINEL_PASSWORD, SENTINEL_KEY):
                assert secret not in text
        assert any("127.0.0.1" in text for text in internal_log)

    def test_redirect_target_query_redacted_in_logs(
        self, https_server_factory, tmp_path, internal_log
    ):
        origin_a = https_server_factory()
        origin_b = https_server_factory()
        with origin_a, origin_b:
            signed = origin_b.url(f"/blob?sig={SENTINEL_QUERY_TOKEN}")
            origin_a.routes["/a.whl"] = redirect(signed)
            origin_b.routes["/blob"] = body(b"signed")
            _credentialed().download_artifact(origin_a.url("/a.whl"), tmp_path / "a")

        # The signed query string still reaches its own origin...
        assert origin_b.recorder.requests[0]["path"].endswith(SENTINEL_QUERY_TOKEN)
        # ...but never the logs.
        assert internal_log
        assert all(SENTINEL_QUERY_TOKEN not in line for line in internal_log)


class TestMockedResponses:
    """Mocked transport checks that do not need sockets."""

    @patch("brickflow.engine.task_executor._ArtifactSession.get")
    def test_redirects_are_never_delegated_to_requests(self, mock_get, tmp_path):
        response = Mock(status_code=200, headers={})
        response.iter_content = Mock(return_value=[b"ok"])
        mock_get.return_value = response

        ArtifactoryClient().download_artifact(
            "https://artifacts.example/a.whl", tmp_path / "a.whl"
        )

        assert mock_get.call_args.kwargs["allow_redirects"] is False
        assert mock_get.call_args.kwargs["timeout"] == ArtifactoryClient.DEFAULT_TIMEOUT
        response.close.assert_called_once()

    @patch("brickflow.engine.task_executor._ArtifactSession.get")
    def test_write_error_is_not_masked(self, mock_get, tmp_path):
        response = Mock(status_code=200, headers={})
        response.iter_content = Mock(return_value=[b"ok"])
        mock_get.return_value = response
        missing_dir = tmp_path / "does-not-exist" / "a.whl"

        with pytest.raises(OSError):
            ArtifactoryClient().download_artifact(
                "https://artifacts.example/a.whl", missing_dir
            )


def test_temp_root_is_isolated(tmp_path):
    import tempfile

    assert Path(tempfile.gettempdir()) == tmp_path / "tmp"
    assert os.environ["HOME"] == str(tmp_path / "home")


def test_redirect_body_is_not_read(tmp_path, monkeypatch):
    from brickflow.engine.task_executor import _ArtifactSession

    observed = []
    original = _ArtifactSession.get

    def recording(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        if response.is_redirect:
            observed.append(response._content)
        return response

    monkeypatch.setattr(_ArtifactSession, "get", recording)
    with _Server() as server:

        def first(handler):
            handler.send_response(302)
            handler.send_header("Location", "/ok")
            # No body is sent. Redirect preparation must not wait for it.
            handler.send_header("Content-Length", "1000000")
            handler.end_headers()
            handler.close_connection = True

        server.routes["/start"] = first
        server.routes["/ok"] = body(b"ok")
        ArtifactoryClient(max_bytes=16).download_artifact(
            server.url("/start"), tmp_path / "out"
        )
    assert observed == [False]
    assert (tmp_path / "out").read_bytes() == b"ok"


def test_same_origin_redirect_cookie_survives(tmp_path):
    cookies = []
    with _Server() as server:

        def first(handler):
            handler.send_response(302)
            handler.send_header("Location", "/ok")
            handler.send_header("Set-Cookie", "ticket=synthetic; Path=/")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        def second(handler):
            cookies.append(handler.headers.get("Cookie"))
            body(b"ok")(handler)

        server.routes["/start"] = first
        server.routes["/ok"] = second
        ArtifactoryClient().download_artifact(server.url("/start"), tmp_path / "out")
    assert cookies == ["ticket=synthetic"]


def test_ambient_netrc_is_not_used(tmp_path):
    Path(os.environ["NETRC"]).write_text(
        "machine localhost login synthetic password secret\n"
    )
    with _Server() as first, _Server() as second:
        first.routes["/start"] = redirect(
            second.url("/ok").replace("127.0.0.1", "localhost")
        )
        second.routes["/ok"] = body(b"ok")
        ArtifactoryClient().download_artifact(first.url("/start"), tmp_path / "out")
    assert second.recorder.requests[0]["authorization"] is None


def test_redirect_cannot_introduce_credentials(tmp_path):
    with _Server() as first, _Server() as second:
        first.routes["/start"] = redirect(
            second.url("/ok").replace("://", "://synthetic:secret@")
        )
        second.routes["/ok"] = body(b"ok")
        with pytest.raises(ArtifactDownloadError, match="introduce"):
            ArtifactoryClient().download_artifact(first.url("/start"), tmp_path / "out")
    assert not second.recorder.requests


def test_truncated_response_preserves_destination(tmp_path):
    destination = tmp_path / "out"
    destination.write_bytes(b"old")
    with _Server() as server:

        def truncated(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", "20")
            handler.end_headers()
            handler.wfile.write(b"short")
            handler.close_connection = True

        server.routes["/file"] = truncated
        with pytest.raises(ArtifactDownloadError):
            ArtifactoryClient().download_artifact(server.url("/file"), destination)
    assert destination.read_bytes() == b"old"
    assert not list(tmp_path.glob(".*.tmp"))


def test_existing_private_mode_is_preserved(tmp_path):
    from brickflow.engine.task_executor import _write_atomically

    destination = tmp_path / "private"
    destination.write_bytes(b"old")
    destination.chmod(0o600)
    _write_atomically(destination, [b"new"], 0o666)
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.read_bytes() == b"new"


def test_compression_rejected_before_decoding(tmp_path):
    response = Mock(status_code=200, headers={"Content-Encoding": "gzip"})
    with patch(
        "brickflow.engine.task_executor._ArtifactSession.get", return_value=response
    ):
        with pytest.raises(ArtifactDownloadError, match="Content-Encoding"):
            ArtifactoryClient().download_artifact(
                "https://example.invalid/a", tmp_path / "out"
            )
    response.iter_content.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost:synthetic_secret/a",
        "https://localhost/a?token=synthetic_secret",
    ],
)
def test_formatted_errors_do_not_expose_url_secrets(tmp_path, url):
    import traceback

    with patch(
        "brickflow.engine.task_executor._ArtifactSession.get",
        side_effect=ValueError(url),
    ):
        with pytest.raises(ArtifactDownloadError) as error:
            ArtifactoryClient().download_artifact(url, tmp_path / "out")
    rendered = "".join(
        traceback.format_exception(
            type(error.value), error.value, error.value.__traceback__
        )
    )
    assert "synthetic_secret" not in rendered
