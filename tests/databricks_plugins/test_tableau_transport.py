"""Request-origin policy for the Tableau connector.

These tests drive the installed tableauserverclient release against loopback
servers only: two HTTPS origins whose certificates come from a throwaway CA
created for the test session, and one plaintext origin. Credentials are
synthetic sentinels. Each server records what it receives, so a test can show
that a refused redirect never reached its target.
"""

import logging
import shutil
import ssl
import threading
from http.server import BaseHTTPRequestHandler
from importlib import metadata
from typing import Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

import pytest
import requests

from brickflow_plugins._origin_policy import (
    CrossOriginRequestError,
    Origin,
    OriginBoundSession,
    https_origin,
    origin_of,
)
from brickflow_plugins.operators import tableau_refresh_operator as tableau
from tests.databricks_plugins.test_connector_tls import (
    CA_ENV_VARS,
    TABLEAU_SENTINEL,
    _format,
    _generate_pki,
    _QuietServer,
)

requires_tableau = pytest.mark.skipif(
    tableau.TSC is None, reason="tableauserverclient is not installed"
)

NS = "http://tableau.com/api"
API = "/api/3.14"
Reply = Tuple[int, Dict[str, str], bytes]
Route = Callable[["_Origin", Dict[str, str]], Reply]


def _xml(body: str) -> Reply:
    payload = f"<?xml version='1.0' encoding='UTF-8'?><tsResponse xmlns=\"{NS}\">{body}</tsResponse>"
    return 200, {"Content-Type": "application/xml"}, payload.encode()


def _redirect(status: int, location: str) -> Reply:
    return status, {"Location": location, "Content-Type": "text/plain"}, b""


SIGNIN_OK = _xml(
    '<credentials token="synthetic-session-token">'
    '<site id="site-id" contentUrl="site"/><user id="user-id"/></credentials>'
)
WORKBOOKS = _xml(
    '<pagination pageNumber="1" pageSize="100" totalAvailable="1"/>'
    '<workbooks><workbook id="wb-1" name="workbook-1">'
    '<project id="p-1" name="project"/><owner id="user-id"/></workbook></workbooks>'
)
DATASOURCES = _xml(
    '<pagination pageNumber="1" pageSize="100" totalAvailable="1"/>'
    '<datasources><datasource id="ds-1" name="datasource-1">'
    '<project id="p-1" name="project"/><owner id="user-id"/></datasource></datasources>'
)
JOB = _xml('<job id="job-1" mode="Asynchronous" type="RefreshExtract"/>')
JOB_DONE = _xml(
    '<job id="job-1" mode="Asynchronous" type="RefreshExtract" finishCode="0" '
    'createdAt="2024-01-01T00:00:00Z" startedAt="2024-01-01T00:00:01Z" '
    'completedAt="2024-01-01T00:00:02Z"/>'
)
EMPTY: Reply = (204, {}, b"")


class _Origin:
    """A loopback server with a mutable route table and a request log."""

    def __init__(self, url: str, server: _QuietServer) -> None:
        self.url = url
        self.server = server
        self.routes: Dict[Tuple[str, str], Route] = {}
        self.received: List[Dict[str, str]] = []

    def route(self, method: str, path: str, reply: Reply) -> None:
        self.routes[(method, path)] = lambda _origin, _request: reply

    def tableau_api(self) -> None:
        """Answer the calls a sign-in and refresh make, at the default paths."""
        site = f"{API}/sites/site-id"
        self.route("POST", f"{API}/auth/signin", SIGNIN_OK)
        self.route("POST", f"{API}/auth/signout", EMPTY)
        self.route("GET", f"{site}/workbooks", WORKBOOKS)
        self.route("GET", f"{site}/datasources", DATASOURCES)
        self.route("POST", f"{site}/workbooks/wb-1/refresh", JOB)
        self.route("POST", f"{site}/datasources/ds-1/refresh", JOB)
        self.route("GET", f"{site}/jobs/job-1", JOB_DONE)

    @property
    def paths(self) -> List[str]:
        """``METHOD path`` for each request received, without the query."""
        return [f"{r['method']} {r['path'].split('?', 1)[0]}" for r in self.received]


def _handler(origin_ref: List[_Origin]):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            origin = origin_ref[0]
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            request = {
                "method": self.command,
                "path": self.path,
                "auth": self.headers.get("X-Tableau-Auth", ""),
                "body": body.decode("utf-8", "replace"),
            }
            origin.received.append(request)
            path = self.path.split("?", 1)[0]
            route = origin.routes.get((self.command, path))
            status, headers, payload = (
                route(origin, request) if route else (404, {}, b"not found")
            )
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _serve  # noqa: N815

        def log_message(self, *_args):
            return

    return Handler


@pytest.fixture(scope="module", name="pki")
def pki_fixture(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl executable is required to create a test CA")
    return _generate_pki(tmp_path_factory.mktemp("tableau-pki"))


def _start(host: str, context: Optional[ssl.SSLContext]):
    ref: List[_Origin] = []
    server = _QuietServer(("127.0.0.1", 0), _handler(ref))
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if context is not None else "http"
    origin = _Origin(f"{scheme}://{host}:{server.server_address[1]}", server)
    ref.append(origin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return origin, thread


@pytest.fixture(name="origins")
def origins_fixture(pki, monkeypatch):
    """Three loopback origins: ``a`` (HTTPS, 127.0.0.1), ``b`` (HTTPS,
    ``localhost``, a different host and port) and ``plain`` (HTTP)."""
    for name in CA_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki["cert"]), str(pki["key"]))
    started = {
        "a": _start("127.0.0.1", context),
        "b": _start("localhost", context),
        "plain": _start("127.0.0.1", None),
    }
    try:
        yield {name: origin for name, (origin, _thread) in started.items()}
    finally:
        for pair in started.values():
            pair[0].server.shutdown()
            pair[0].server.server_close()
            pair[1].join(timeout=5)


@pytest.fixture(name="logs")
def all_logs(caplog, capsys):
    from brickflow_plugins import log as plugin_log

    old_level = plugin_log.level
    plugin_log.setLevel(logging.DEBUG)
    plugin_log.addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG)
    try:
        yield lambda: caplog.text + "".join(capsys.readouterr())
    finally:
        plugin_log.removeHandler(caplog.handler)
        plugin_log.setLevel(old_level)


def _wrapper(url: str, pki, **kwargs) -> "tableau.TableauWrapper":
    kwargs.setdefault("polling_interval", 0)
    return tableau.TableauWrapper(
        server=url,
        username="svc-user",
        password=TABLEAU_SENTINEL,
        site="site",
        ca_bundle=str(pki["ca"]),
        **kwargs,
    )


def _signin_password(request: Dict[str, str]) -> Optional[str]:
    credentials = ElementTree.fromstring(request["body"]).find("credentials")
    return None if credentials is None else credentials.get("password")


# ---------------------------------------------------------------------------
# Origin parsing and the session policy, independent of tableauserverclient.
# ---------------------------------------------------------------------------


def _ok_send(mocker):
    def send(request, **_kwargs):
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response._content = b""  # pylint: disable=protected-access
        return response

    return mocker.patch.object(
        requests.adapters.HTTPAdapter, "send", autospec=True,
        side_effect=lambda _adapter, request, **kw: send(request, **kw),
    )  # fmt: skip


class TestOrigin:
    @pytest.mark.parametrize(
        "url, expected",
        [
            ("https://Tableau.Example.com", Origin("https", "tableau.example.com", 443)),
            ("https://tableau.example.com:443/x?y", Origin("https", "tableau.example.com", 443)),
            ("https://tableau.example.com:8443", Origin("https", "tableau.example.com", 8443)),
            ("http://tableau.example.com", Origin("http", "tableau.example.com", 80)),
            ("https://[::1]:9443/", Origin("https", "::1", 9443)),
        ],
    )  # fmt: skip
    def test_origin_of(self, url, expected):
        assert origin_of(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "http://tableau.example.com",
            "tableau.example.com",
            "ftp://tableau.example.com",
            "https://",
            "https://svc:secret@tableau.example.com",
            "https://tableau.example.com:99999",
            "",
        ],
    )
    def test_https_origin_rejects(self, url):
        with pytest.raises(ValueError) as excinfo:
            https_origin(url)
        assert "secret" not in str(excinfo.value)

    def test_https_origin_normalizes_idna(self):
        assert https_origin("https://bücher.example") == Origin(
            "https", "xn--bcher-kva.example", 443
        )

    def test_session_requires_https_origin(self):
        with pytest.raises(ValueError):
            OriginBoundSession(Origin("http", "tableau.example.com", 80))

    @pytest.mark.parametrize(
        "url",
        [
            "https://other.example.com/api",
            "http://tableau.example.com/api",
            "https://tableau.example.com:8443/api",
            "https://tableau.example.com.evil.example/api",
        ],
    )
    def test_session_refuses_before_adapter(self, mocker, url):
        session = OriginBoundSession(https_origin("https://tableau.example.com"))
        adapter_send = mocker.patch.object(requests.adapters.HTTPAdapter, "send")
        with pytest.raises(CrossOriginRequestError) as excinfo:
            session.post(url, data=TABLEAU_SENTINEL)
        adapter_send.assert_not_called()
        assert TABLEAU_SENTINEL not in _format(excinfo.value)
        assert "/api" not in str(excinfo.value)
        assert isinstance(excinfo.value, requests.exceptions.RequestException)

    def test_session_allows_same_origin_with_explicit_default_port(self, mocker):
        session = OriginBoundSession(https_origin("https://tableau.example.com"))
        adapter_send = _ok_send(mocker)
        session.get("https://TABLEAU.example.com:443/api")
        adapter_send.assert_called_once()

    def test_policy_is_per_session(self, mocker):
        OriginBoundSession(https_origin("https://tableau.example.com"))
        adapter_send = _ok_send(mocker)
        requests.Session().get("https://other.example.com/")
        adapter_send.assert_called_once()


# ---------------------------------------------------------------------------
# The installed tableauserverclient against loopback origins.
# ---------------------------------------------------------------------------


@requires_tableau
class TestTableauTransport:
    def test_server_uses_origin_bound_sessions(self, origins, pki):
        wrapper = _wrapper(origins["a"].url, pki)
        origins["a"].tableau_api()
        with wrapper._authenticate():
            session = wrapper._server.session
            assert isinstance(session, OriginBoundSession)
            assert session.allowed_origin == origin_of(origins["a"].url)
            assert session.verify == str(pki["ca"])

    def test_refresh_workbooks_with_installed_client(self, origins, pki, logs):
        a = origins["a"]
        a.tableau_api()
        results = _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])
        assert [(r["work_book"], r["job_status"]) for r in results] == [
            ("workbook-1", "Success")
        ]
        assert f"POST {API}/sites/site-id/workbooks/wb-1/refresh" in a.paths
        assert TABLEAU_SENTINEL not in logs()

    def test_refresh_datasources_with_installed_client(self, origins, pki):
        a = origins["a"]
        a.tableau_api()
        results = _wrapper(a.url, pki).refresh_datasources(["datasource-1"])
        assert [(r["data_source"], r["job_status"]) for r in results] == [
            ("datasource-1", "Success")
        ]
        assert f"POST {API}/sites/site-id/datasources/ds-1/refresh" in a.paths

    def test_same_origin_signin_redirect_is_followed(self, origins, pki):
        a = origins["a"]
        a.tableau_api()
        a.route("POST", f"{API}/auth/signin", _redirect(301, f"{a.url}/moved/signin"))
        a.route("POST", "/moved/signin", SIGNIN_OK)
        results = _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])
        assert results[0]["job_status"] == "Success"
        signins = [r for r in a.received if r["path"].endswith("signin")]
        assert [r["path"] for r in signins] == [f"{API}/auth/signin", "/moved/signin"]
        assert all(_signin_password(r) == TABLEAU_SENTINEL for r in signins)

    @pytest.mark.parametrize("target", ["other-host", "other-port", "downgrade"])
    def test_cross_origin_signin_redirect_refused(self, origins, pki, logs, target):
        a, b, plain = origins["a"], origins["b"], origins["plain"]
        port_b = b.url.rsplit(":", 1)[1]
        location, victim = {
            # localhost: a different host (and port) with a valid certificate.
            "other-host": (f"{b.url}/signin", b),
            # Same host as ``a``, different port, valid certificate.
            "other-port": (f"https://127.0.0.1:{port_b}/signin", b),
            # HTTPS to HTTP, at a listening plaintext server.
            "downgrade": (f"{plain.url}/signin", plain),
        }[target]
        a.tableau_api()
        a.route("POST", f"{API}/auth/signin", _redirect(301, location))
        for origin in (b, plain):
            origin.tableau_api()
            origin.route("POST", "/signin", SIGNIN_OK)

        with pytest.raises(CrossOriginRequestError) as excinfo:
            _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])

        assert victim.received == []
        assert a.paths == [f"POST {API}/auth/signin"]
        assert TABLEAU_SENTINEL not in _format(excinfo.value)
        assert TABLEAU_SENTINEL not in logs()

    def test_cross_origin_automatic_redirect_refused_after_signin(
        self, origins, pki, logs
    ):
        a, b = origins["a"], origins["b"]
        a.tableau_api()
        b.tableau_api()
        # Multi-hop: same-origin 302, then 307 to another origin.
        workbooks = f"{API}/sites/site-id/workbooks"
        a.route("GET", workbooks, _redirect(302, f"{a.url}/hop1"))
        a.route("GET", "/hop1", _redirect(307, f"{b.url}{workbooks}"))

        with pytest.raises(CrossOriginRequestError):
            _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])

        assert b.received == []
        assert f"GET {workbooks}" in a.paths
        assert "GET /hop1" in a.paths
        assert TABLEAU_SENTINEL not in logs()

    def test_same_origin_automatic_redirect_is_followed(self, origins, pki):
        a = origins["a"]
        a.tableau_api()
        workbooks = f"{API}/sites/site-id/workbooks"
        a.route("GET", workbooks, _redirect(302, f"{a.url}/hop1"))
        a.route("GET", "/hop1", _redirect(308, f"{a.url}/hop2"))
        a.route("GET", "/hop2", WORKBOOKS)
        results = _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])
        assert results[0]["job_status"] == "Success"
        assert "GET /hop2" in a.paths
        token_requests = [r for r in a.received if r["path"].startswith("/hop")]
        assert all(r["auth"] == "synthetic-session-token" for r in token_requests)

    def test_untrusted_certificate_still_raises_ssl_error(self, origins):
        a = origins["a"]
        a.tableau_api()
        wrapper = tableau.TableauWrapper(
            server=a.url, username="svc-user", password=TABLEAU_SENTINEL, site="site"
        )
        with pytest.raises(requests.exceptions.SSLError):
            wrapper.refresh_workbooks(["workbook-1"])
        assert a.received == []

    @pytest.mark.parametrize(
        "server",
        ["http://127.0.0.1:{port}", "127.0.0.1:{port}", "https://u:p@127.0.0.1:{port}"],
    )
    def test_non_https_server_rejected_before_any_request(self, origins, server):
        plain = origins["plain"]
        port = plain.url.rsplit(":", 1)[1]
        url = server.format(port=port)
        with pytest.raises(ValueError):
            tableau.TableauWrapper(
                server=url, username="u", password=TABLEAU_SENTINEL, site="s"
            )
        with pytest.raises(ValueError):
            tableau.TableauRefreshWorkBookOperator(
                workbooks=["wb"],
                server=url,
                username="u",
                password=TABLEAU_SENTINEL,
                site="s",
            )
        assert plain.received == []

    def test_server_changed_after_construction_is_revalidated(self, origins, pki):
        plain = origins["plain"]
        plain.tableau_api()
        wrapper = _wrapper(origins["a"].url, pki)
        wrapper.server = plain.url
        with pytest.raises(ValueError):
            wrapper.refresh_workbooks(["workbook-1"])
        assert plain.received == []

    @pytest.mark.parametrize("content_type", ["application/xml", "text/plain"])
    def test_reflected_password_redacted_from_signin_error(
        self, origins, pki, logs, content_type
    ):
        from xml.sax.saxutils import escape, quoteattr

        a = origins["a"]
        a.tableau_api()
        if content_type == "application/xml":
            body = (
                f"<?xml version='1.0' encoding='UTF-8'?><tsResponse xmlns=\"{NS}\">"
                f'<error code="401001"><summary>Signin Error {escape(TABLEAU_SENTINEL)}'
                f"</summary><detail value={quoteattr(TABLEAU_SENTINEL)}>"
                f"Bad password {escape(TABLEAU_SENTINEL)}</detail></error></tsResponse>"
            ).encode()
        else:
            body = f"denied for password={TABLEAU_SENTINEL}".encode()
        a.route(
            "POST",
            f"{API}/auth/signin",
            (401, {"Content-Type": content_type}, body),
        )

        with pytest.raises(tableau.TableauSignInError) as excinfo:
            _wrapper(a.url, pki).refresh_workbooks(["workbook-1"])

        text = _format(excinfo.value)
        assert TABLEAU_SENTINEL not in text
        assert repr(TABLEAU_SENTINEL)[1:-1] not in text
        assert "***" in str(excinfo.value)
        # The unredacted client exception must not be reachable from the raised
        # error, including through implicit context that tools may walk.
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None
        assert excinfo.value.original_type in {
            "FailedSignInError",
            "ServerResponseError",
            "NonXMLResponseError",
        }
        assert TABLEAU_SENTINEL not in logs()


def test_installed_client_matches_supported_range():
    """The installed release is inside the range pyproject.toml allows."""
    try:
        installed = metadata.version("tableauserverclient")
    except metadata.PackageNotFoundError:
        pytest.skip("tableauserverclient is not installed")
    from packaging.version import Version
    import sys

    version = Version(installed)
    if sys.version_info >= (3, 10):
        assert Version("0.41") <= version < Version("0.42")
    else:
        assert Version("0.25") <= version < Version("0.39")
