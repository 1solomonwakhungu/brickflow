"""TLS verification and credential handling for external connector plugins.

The TLS tests run a loopback-only HTTPS server whose certificate is issued by a
throwaway certificate authority generated for the test session. No external
host is contacted and all credentials are synthetic.
"""

import json
import logging
import shutil
import ssl
import subprocess
import threading
import traceback
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List
from xml.etree import ElementTree

import pytest
import requests

from brickflow_plugins.operators import tableau_refresh_operator as tableau
from brickflow_plugins.sensors.airflow_task_dependency_sensor import (
    AirflowCluster,
    AirflowTaskDependencySensor,
)
from brickflow_plugins.sensors.autosys_sensor import AutosysSensor

TABLEAU_SENTINEL = "Sentinel-Tableau-Pw-6f1c%{x}'\"\\"
SENTINEL_TOKEN = "sentinel-airflow-token-4b8e"
CA_ENV_VARS = ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR")

_TABLEAU_SIGNIN_ERROR = (
    b"<?xml version='1.0' encoding='UTF-8'?>"
    b'<tsResponse xmlns="http://tableau.com/api">'
    b'<error code="401001"><summary>Signin Error</summary>'
    b"<detail>Error signing in to Tableau Server</detail></error></tsResponse>"
)


def _format(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["openssl", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _generate_pki(directory: Path) -> Dict[str, Path]:
    """Create a private CA and a loopback server certificate signed by it."""
    (directory / "ca.ext").write_text(
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    (directory / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    _openssl("genrsa", "-out", "ca.key", "2048", cwd=directory)
    _openssl(
        "req", "-new", "-key", "ca.key", "-subj", "/CN=Brickflow Test CA",
        "-out", "ca.csr", cwd=directory,
    )  # fmt: skip
    _openssl(
        "x509", "-req", "-in", "ca.csr", "-signkey", "ca.key", "-days", "2",
        "-extfile", "ca.ext", "-out", "ca.pem", cwd=directory,
    )  # fmt: skip
    _openssl("genrsa", "-out", "leaf.key", "2048", cwd=directory)
    _openssl(
        "req", "-new", "-key", "leaf.key", "-subj", "/CN=localhost",
        "-out", "leaf.csr", cwd=directory,
    )  # fmt: skip
    _openssl(
        "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-days", "2", "-extfile", "leaf.ext",
        "-out", "leaf.pem", cwd=directory,
    )  # fmt: skip
    return {
        "ca": directory / "ca.pem",
        "cert": directory / "leaf.pem",
        "key": directory / "leaf.key",
    }


class _RecordingHandler(BaseHTTPRequestHandler):
    received: List[Dict[str, str]] = []

    def _record(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).received.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "body": body.decode("utf-8", "replace"),
            }
        )
        return body

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._record()
        if "/taskInstances/" in self.path:
            payload = {"state": "success"}
        elif "/dagRuns" in self.path:
            payload = {
                "dag_runs": [
                    {
                        "dag_run_id": "scheduled__2024-01-01T01:00:00+00:00",
                        "execution_date": "2024-01-01T01:00:00+00:00",
                    }
                ]
            }
        else:
            payload = {"status": "SUCCESS", "lastEndUTC": "2024-01-01T00:55:00Z"}
        self._send(200, json.dumps(payload).encode(), "application/json")

    def do_POST(self):  # noqa: N802
        self._record()
        self._send(401, _TABLEAU_SIGNIN_ERROR, "application/xml")

    def log_message(self, *_args):  # silence request logging
        return


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Failed client handshakes are expected in these tests.
        return


@pytest.fixture(scope="module", name="tls_server")
def tls_server_fixture(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl executable is required to create a test CA")
    pki = _generate_pki(tmp_path_factory.mktemp("pki"))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki["cert"]), str(pki["key"]))
    server = _QuietServer(("127.0.0.1", 0), _RecordingHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"https://127.0.0.1:{server.server_address[1]}", **pki}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(name="received")
def received_requests(monkeypatch):
    for name in CA_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    _RecordingHandler.received = []
    return _RecordingHandler.received


@pytest.fixture(autouse=True)
def no_workspace_client(mocker):
    mocker.patch("brickflow_plugins.sensors.WorkspaceClient", autospec=True)


def _airflow_sensor(cluster: AirflowCluster) -> AirflowTaskDependencySensor:
    sensor = AirflowTaskDependencySensor(
        dag_id="upstream",
        task_id="finish",
        cluster=cluster,
        execution_delta=timedelta(hours=-3),
        poke_interval=0,
    )
    sensor.__dict__["_execution_timestamp"] = datetime(
        2024, 1, 1, 3, tzinfo=timezone.utc
    )
    return sensor


def _autosys_sensor(url: str, **kwargs) -> AutosysSensor:
    sensor = AutosysSensor(
        url=url, job_name="job", poke_interval=0, time_delta={"hours": 1}, **kwargs
    )
    sensor.__dict__["_execution_timestamp"] = datetime(
        2024, 1, 1, 1, tzinfo=timezone.utc
    )
    return sensor


class TestAirflowTls:
    def test_untrusted_certificate_fails_before_token_is_sent(
        self, tls_server, received
    ):
        cluster = AirflowCluster(tls_server["url"], "2.0.2", SENTINEL_TOKEN)
        with pytest.raises(requests.exceptions.SSLError):
            _airflow_sensor(cluster).get_execution_stats(datetime(2024, 1, 1, 3))
        assert received == []

    def test_private_ca_bundle_is_trusted(self, tls_server, received):
        cluster = AirflowCluster(
            tls_server["url"], "2.0.2", SENTINEL_TOKEN, ca_bundle=tls_server["ca"]
        )
        state = _airflow_sensor(cluster).get_execution_stats(datetime(2024, 1, 1, 3))
        assert state == "success"
        assert [r["authorization"] for r in received] == [
            f"Bearer {SENTINEL_TOKEN}"
        ] * 2

    @pytest.mark.parametrize(
        "ca_bundle, expected",
        [(None, True), ("/etc/pki/ca.pem", "/etc/pki/ca.pem")],
    )
    def test_verify_argument_on_every_request(self, mocker, ca_bundle, expected):
        dag_runs = mocker.Mock()
        dag_runs.json.return_value = {
            "dag_runs": [{"dag_run_id": "r1", "execution_date": "2024-01-01"}]
        }
        task = mocker.Mock()
        task.json.return_value = {"state": "success"}
        get = mocker.patch(
            "brickflow_plugins.sensors.airflow_task_dependency_sensor.requests.get",
            side_effect=[dag_runs, task],
        )
        cluster = AirflowCluster(
            "https://airflow.invalid", "2.0.2", SENTINEL_TOKEN, ca_bundle=ca_bundle
        )
        _airflow_sensor(cluster).get_execution_stats(datetime(2024, 1, 1, 3))
        assert get.call_count == 2
        assert [c.kwargs["verify"] for c in get.call_args_list] == [expected] * 2

    def test_pathlike_ca_bundle_is_converted(self):
        cluster = AirflowCluster("https://a.invalid", "2", "t", ca_bundle=Path("/ca"))
        assert cluster.verify == "/ca"

    def test_empty_ca_bundle_rejected(self):
        with pytest.raises(ValueError):
            AirflowCluster("https://a.invalid", "2", "t", ca_bundle="")


class TestAutosysTls:
    def test_untrusted_certificate_fails(self, tls_server, received):
        with pytest.raises(requests.exceptions.SSLError):
            _autosys_sensor(tls_server["url"]).poke()
        assert received == []

    def test_private_ca_bundle_is_trusted(self, tls_server, received):
        sensor = _autosys_sensor(tls_server["url"], ca_bundle=str(tls_server["ca"]))
        assert sensor.poke() is True
        assert [r["path"] for r in received] == ["/job"]

    def test_verify_defaults_to_true(self, mocker):
        response = mocker.Mock(status_code=200)
        response.json.return_value = {
            "status": "SUCCESS",
            "lastEndUTC": "2024-01-01T00:55:00Z",
        }
        get = mocker.patch(
            "brickflow_plugins.sensors.autosys_sensor.requests.get",
            return_value=response,
        )
        assert _autosys_sensor("https://autosys.invalid").poke() is True
        assert get.call_args.kwargs["verify"] is True

    def test_empty_ca_bundle_rejected(self):
        with pytest.raises(ValueError):
            _autosys_sensor("https://autosys.invalid", ca_bundle="")


requires_tableau = pytest.mark.skipif(
    tableau.TSC is None, reason="tableauserverclient is not installed"
)


@pytest.fixture(name="logs")
def all_logs(caplog, capsys):
    """Capture every log level from the plugin logger, dependencies and stdio."""
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


def _operator_kwargs(**overrides):
    kwargs = {
        "server": "https://tableau.invalid",
        "username": "svc-user",
        "password": TABLEAU_SENTINEL,
        "site": "site",
        "project": "project",
    }
    kwargs.update(overrides)
    return kwargs


@requires_tableau
class TestTableauCredentials:
    def test_password_not_logged_and_reaches_authenticator(self, mocker, logs):
        server_cls = mocker.patch.object(tableau.TSC, "Server")
        auth_cls = mocker.patch.object(tableau.TSC, "TableauAuth")
        mocker.patch.object(tableau.TSC, "Pager", return_value=[])
        disable = mocker.patch("urllib3.disable_warnings")
        filters_before = list(warnings.filters)

        operator = tableau.TableauRefreshDataSourceOperator(
            data_sources=["ds"], fail_operator=False, **_operator_kwargs()
        )
        with pytest.raises(tableau.TableauWrapper.UnidentifiedWorkingProjectException):
            operator.execute()
        text = logs()

        assert TABLEAU_SENTINEL not in text
        assert "Tableau wrapper options" in text
        assert "'password': '***'" in text
        auth_cls.assert_called_once_with("svc-user", TABLEAU_SENTINEL, "site")
        server_cls.return_value.add_http_options.assert_called_once_with(
            {"verify": True}
        )
        assert operator.wrapper_options["password"] == TABLEAU_SENTINEL
        assert TABLEAU_SENTINEL not in repr(operator.wrapper_options)
        assert TABLEAU_SENTINEL not in str(operator.wrapper_options)
        assert TABLEAU_SENTINEL not in f"{operator.wrapper_options}"
        assert TABLEAU_SENTINEL not in repr(operator.tableau_wrapper)
        disable.assert_not_called()
        assert list(warnings.filters) == filters_before

    def test_password_absent_from_sign_in_failure(self, mocker, logs):
        server_cls = mocker.patch.object(tableau.TSC, "Server")
        server_cls.return_value.auth.sign_in.side_effect = RuntimeError(
            f"denied {TABLEAU_SENTINEL}"
        )
        wrapper = tableau.TableauWrapper(
            **{k: v for k, v in _operator_kwargs().items() if k != "project"}
        )
        with pytest.raises(tableau.TableauSignInError) as excinfo:
            wrapper.refresh_workbooks(["wb"])
        assert TABLEAU_SENTINEL not in _format(excinfo.value)
        assert str(excinfo.value) == (
            "Tableau sign-in failed (RuntimeError); server response omitted"
        )
        assert excinfo.value.original_type == "RuntimeError"
        assert TABLEAU_SENTINEL not in logs()

    def test_ca_bundle_passed_to_tableau_client(self, mocker):
        server_cls = mocker.patch.object(tableau.TSC, "Server")
        mocker.patch.object(tableau.TSC, "TableauAuth")
        operator = tableau.TableauRefreshWorkBookOperator(
            workbooks=["wb"], **_operator_kwargs(ca_bundle="/etc/pki/tableau.pem")
        )
        tableau.TableauWrapper(**operator.wrapper_options)._authenticate()
        server_cls.return_value.add_http_options.assert_called_once_with(
            {"verify": "/etc/pki/tableau.pem"}
        )

    def test_empty_ca_bundle_rejected(self):
        with pytest.raises(ValueError):
            tableau.TableauRefreshWorkBookOperator(
                workbooks=["wb"], **_operator_kwargs(ca_bundle="")
            )


@requires_tableau
class TestTableauTls:
    def _wrapper(self, url, **kwargs):
        return tableau.TableauWrapper(
            server=url, username="svc-user", password=TABLEAU_SENTINEL, site="site",
            **kwargs,
        )  # fmt: skip

    def test_untrusted_certificate_fails_before_password_is_sent(
        self, tls_server, received
    ):
        with pytest.raises(requests.exceptions.SSLError):
            self._wrapper(tls_server["url"])._authenticate()
        assert received == []

    def test_private_ca_bundle_is_trusted(self, tls_server, received, logs):
        wrapper = self._wrapper(tls_server["url"], ca_bundle=tls_server["ca"])
        with pytest.raises(Exception) as excinfo:
            wrapper._authenticate()
        assert not isinstance(excinfo.value, requests.exceptions.SSLError)
        assert len(received) == 1
        assert received[0]["path"].endswith("/auth/signin")
        credentials = ElementTree.fromstring(received[0]["body"]).find("credentials")
        assert credentials is not None
        assert credentials.get("password") == TABLEAU_SENTINEL
        assert TABLEAU_SENTINEL not in _format(excinfo.value)
        assert TABLEAU_SENTINEL not in logs()
