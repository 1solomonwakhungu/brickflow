"""Deadline, HTTP-bound and pagination-safety tests for the workflow sensors.

Network peers are loopback-only servers; all credentials are synthetic.
"""

import json
import socket
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import ANY, Mock

import pytest
import requests
from urllib3.exceptions import MaxRetryError, ReadTimeoutError

from brickflow_plugins.sensors import workflow_dependency_sensor
from brickflow_plugins.sensors.workflow_dependency_sensor import (
    WorkflowDependencySensor,
    WorkflowDependencySensorException,
    WorkflowDependencySensorTimeOutException,
    WorkflowTaskDependencySensor,
)

TOKEN = "synthetic-token"
GRACE = 0.2
# Allowance for thread start-up and scheduling on a loaded CI host.
SCHEDULING_TOLERANCE = 1.0
REAL_LOOKUP_JOB_ID = WorkflowDependencySensor._lookup_job_id
ABANDONED_CALLS = workflow_dependency_sensor._ABANDONED_CALLS


def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


@pytest.fixture(autouse=True)
def _no_abandoned_calls_leak_between_tests():
    assert wait_for(lambda: ABANDONED_CALLS.count == 0)
    yield
    # Tests release their blocked peers on teardown; abandoned workers must
    # then finish and leave the process-wide count where it started.
    assert wait_for(lambda: ABANDONED_CALLS.count == 0)


@pytest.fixture(autouse=True)
def _offline_collaborators(monkeypatch):
    monkeypatch.setattr(workflow_dependency_sensor, "WorkspaceClient", Mock())
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", lambda _self: 7)
    monkeypatch.setenv("DATABRICKS_REQUEST_RETRY_COUNT", "3")


def make_sensor(host, timeout_seconds=1, poke_interval_seconds=0, **overrides):
    sensor = WorkflowDependencySensor(
        databricks_host=host,
        databricks_token=TOKEN,
        dependency_job_name="upstream-job",
        delta=timedelta(seconds=1),
        timeout_seconds=timeout_seconds,
        poke_interval_seconds=poke_interval_seconds,
    )
    sensor._final_poll_grace_seconds = GRACE
    for name, value in overrides.items():
        setattr(sensor, name, value)
    sensor.get_execution_start_time_unix_milliseconds = Mock(return_value=123000)
    return sensor


class LoopbackPeer:
    """A raw TCP peer on 127.0.0.1 whose behaviour is a per-connection callable."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.stop = threading.Event()
        self.connections = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.url = f"http://127.0.0.1:{self.listener.getsockname()[1]}"
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            conn.recv(65536)
            self.behaviour(conn, self.stop)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)


@pytest.fixture(name="peer")
def _peer():
    peers = []

    def start(behaviour):
        peers.append(LoopbackPeer(behaviour))
        return peers[-1]

    yield start
    for item in peers:
        item.close()


def stall(_conn, stop):
    stop.wait(30)


def trickle_body(conn, stop):
    conn.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 100000\r\n\r\n"
    )
    while not stop.wait(0.05):
        conn.sendall(b" ")


def trickle_headers(conn, stop):
    conn.sendall(b"HTTP/1.1 200 OK\r\n")
    while not stop.wait(0.05):
        conn.sendall(b"X-Slow: a\r\n")


def respond(status, body=b"{}", extra_headers=b""):
    def behaviour(conn, _stop):
        conn.sendall(
            b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n" + extra_headers
            # Close after each response so retries open new connections.
            + b"Connection: close\r\n\r\n" + body
        )

    return behaviour


def timed_execute(sensor, expected=WorkflowDependencySensorTimeOutException):
    started = time.monotonic()
    with pytest.raises(expected) as raised:
        sensor.execute()
    return time.monotonic() - started, raised.value


@pytest.mark.parametrize("behaviour", [stall, trickle_body, trickle_headers])
def test_stalled_or_trickling_peer_cannot_outlive_deadline(peer, behaviour):
    server = peer(behaviour)
    sensor = make_sensor(server.url, timeout_seconds=1)

    elapsed, _ = timed_execute(sensor)

    assert elapsed < 1 + GRACE + SCHEDULING_TOLERANCE
    assert server.connections >= 1


def test_trickling_body_is_not_bounded_by_read_timeout_alone(peer):
    # The read timeout restarts with every byte, so only the watchdog or the
    # in-loop deadline check can stop this response.
    server = peer(trickle_body)
    sensor = make_sensor(server.url, timeout_seconds=1, _read_timeout_seconds=0.5)

    elapsed, _ = timed_execute(sensor)

    assert elapsed < 1 + GRACE + SCHEDULING_TOLERANCE


def test_long_retry_after_is_not_slept_past_deadline(peer):
    server = peer(
        respond(b"429 Too Many Requests", extra_headers=b"Retry-After: 3600\r\n")
    )
    sensor = make_sensor(server.url, timeout_seconds=2)

    elapsed, error = timed_execute(sensor)

    assert elapsed < 1.0
    assert server.connections == 1
    assert "timed out" in str(error)


def test_retry_backoff_stays_within_deadline(peer, monkeypatch):
    monkeypatch.setenv("DATABRICKS_REQUEST_RETRY_COUNT", "10")
    server = peer(respond(b"503 Service Unavailable"))
    sensor = make_sensor(server.url, timeout_seconds=2)

    elapsed, _ = timed_execute(sensor)

    # Back-off grows 0, 2, 4, ... seconds; the 2 s sleep cannot fit, so the
    # sensor times out after the immediate first retry rather than sleeping.
    assert elapsed < 2 + GRACE + SCHEDULING_TOLERANCE
    assert 1 <= server.connections <= 3


def test_retries_exhausted_raise_sensor_exception(peer, monkeypatch):
    monkeypatch.setenv("DATABRICKS_REQUEST_RETRY_COUNT", "1")
    server = peer(respond(b"503 Service Unavailable"))
    sensor = make_sensor(server.url, timeout_seconds=30)
    sensor.get_retry_class(1)  # public helper remains usable
    # Make back-off immediate so only the retry count matters.
    sensor.get_http_session().get_adapter(server.url).max_retries.backoff_factor = 0

    _, error = timed_execute(sensor, WorkflowDependencySensorException)

    assert "exhausting retries" in str(error)
    assert server.connections == 2


@pytest.mark.parametrize(
    "status", [b"401 Unauthorized", b"403 Forbidden", b"404 Not Found"]
)
def test_http_error_status_fails_fast(peer, status):
    server = peer(respond(status, body=b'{"error_code": "PERMISSION_DENIED"}'))
    sensor = make_sensor(server.url, timeout_seconds=30)

    elapsed, error = timed_execute(sensor, WorkflowDependencySensorException)

    assert not isinstance(error, WorkflowDependencySensorTimeOutException)
    assert status.split()[0].decode() in str(error)
    assert TOKEN not in str(error)
    assert elapsed < 5


def test_success_over_loopback(peer):
    body = b'{"runs": [{"run_id": 1, "state": {"result_state": "SUCCESS"}}]}'
    server = peer(respond(b"200 OK", body=body))
    sensor = make_sensor(server.url, timeout_seconds=5)

    sensor.execute()

    assert server.connections == 1


@pytest.fixture(name="fake_clock")
def _fake_clock(monkeypatch):
    clock = SimpleNamespace(now=0.0, sleeps=[])

    def sleep(seconds):
        clock.sleeps.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(
        workflow_dependency_sensor,
        "time",
        SimpleNamespace(
            time=lambda: clock.now, monotonic=lambda: clock.now, sleep=sleep
        ),
    )
    return clock


def scripted_session(pages, calls):
    """A session whose responses come from ``pages`` keyed by page token."""

    def get(url, *, params, headers, timeout, stream):
        assert url == "https://synthetic.invalid/api/2.1/jobs/runs/list"
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        calls.append({"params": dict(params), "timeout": timeout, "stream": stream})
        page = pages(params.get("page_token")) if callable(pages) else pages
        if isinstance(page, BaseException):
            raise page
        if isinstance(page, dict):
            page = json.dumps(page).encode()
        response = Mock()
        response.iter_content = Mock(return_value=iter([page]))
        return response

    return Mock(get=Mock(side_effect=get))


def install_session(sensor, session):
    sensor.get_http_session = lambda: session


def test_sleep_is_clamped_to_remaining_deadline(fake_clock):
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=2.5)
    sensor.poke_interval = 10
    install_session(sensor, scripted_session({"runs": []}, calls))

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor.execute()

    # One sleep up to the deadline, then a final poll at the deadline.
    assert fake_clock.sleeps == [2.5]
    assert len(calls) == 2
    assert fake_clock.now == 2.5


def test_success_in_final_poll_is_accepted(fake_clock):
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=3)
    sensor.poke_interval = 2

    def pages(_token):
        if fake_clock.now >= 3:
            return {"runs": [{"run_id": 5, "state": {"result_state": "SUCCESS"}}]}
        return {"runs": []}

    install_session(sensor, scripted_session(pages, calls))

    sensor.execute()

    assert fake_clock.sleeps == [2, 1]


@pytest.mark.usefixtures("fake_clock")
def test_requests_carry_connect_and_read_timeouts_capped_by_deadline():
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=30)
    sensor.poke_interval = 25
    install_session(sensor, scripted_session({"runs": []}, calls))

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor.execute()

    assert calls[0]["timeout"] == (10.0, 30 + GRACE)
    assert calls[0]["stream"] is True
    # The final poll after sleeping 25 s has 5 s (+ grace) left.
    assert calls[1]["timeout"] == (5 + GRACE, 5 + GRACE)


@pytest.mark.usefixtures("fake_clock")
def test_without_timeout_requests_use_default_socket_timeouts():
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=None)
    install_session(
        sensor,
        scripted_session(
            {"runs": [{"run_id": 1, "state": {"result_state": "SUCCESS"}}]}, calls
        ),
    )

    sensor.execute()

    assert calls[0]["timeout"] == (10.0, 60.0)


def test_repeated_page_token_stops_deterministically(fake_clock):
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)

    # The peer cycles a -> b -> a.
    next_token = {None: "a", "a": "b", "b": "a"}

    def pages(token):
        return {"runs": [], "has_more": True, "next_page_token": next_token[token]}

    install_session(sensor, scripted_session(pages, calls))

    with pytest.raises(
        WorkflowDependencySensorException, match="repeated a page token"
    ):
        sensor.execute()

    assert [call["params"].get("page_token") for call in calls] == [None, "a", "b"]
    assert fake_clock.sleeps == []


@pytest.mark.usefixtures("fake_clock")
def test_self_referencing_page_token_stops():
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
    install_session(
        sensor,
        scripted_session(
            {"runs": [], "has_more": True, "next_page_token": "same"}, calls
        ),
    )

    with pytest.raises(
        WorkflowDependencySensorException, match="repeated a page token"
    ):
        sensor.execute()

    assert len(calls) == 2


@pytest.mark.usefixtures("fake_clock")
def test_page_count_is_capped_per_poll():
    calls = []
    sensor = make_sensor(
        "https://synthetic.invalid", timeout_seconds=600, _max_pages_per_poll=5
    )
    counter = iter(range(1000))
    install_session(
        sensor,
        scripted_session(
            lambda _token: {
                "runs": [],
                "has_more": True,
                "next_page_token": f"page-{next(counter)}",
            },
            calls,
        ),
    )

    with pytest.raises(WorkflowDependencySensorException, match="exceeded 5 pages"):
        sensor.execute()

    assert len(calls) == 5


@pytest.mark.usefixtures("fake_clock")
def test_success_on_last_allowed_page_is_accepted():
    calls = []
    sensor = make_sensor(
        "https://synthetic.invalid", timeout_seconds=600, _max_pages_per_poll=2
    )

    def pages(token):
        if token is None:
            return {"runs": [], "has_more": True, "next_page_token": "two"}
        return {"runs": [{"run_id": 9, "state": {"result_state": "SUCCESS"}}]}

    install_session(sensor, scripted_session(pages, calls))

    sensor.execute()

    assert len(calls) == 2


@pytest.mark.parametrize(
    "page", [{"runs": [], "has_more": True}, {"has_more": True, "next_page_token": ""}]
)
@pytest.mark.usefixtures("fake_clock")
def test_more_pages_without_token_is_rejected(page):
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
    install_session(sensor, scripted_session(page, []))

    with pytest.raises(WorkflowDependencySensorException, match="next_page_token"):
        sensor.execute()


@pytest.mark.parametrize(
    "body, message",
    [(b"not json", "not valid JSON"), (b"[1, 2]", "not a JSON object")],
)
@pytest.mark.usefixtures("fake_clock")
def test_malformed_body_is_rejected(body, message):
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
    install_session(sensor, scripted_session(body, []))

    with pytest.raises(WorkflowDependencySensorException, match=message):
        sensor.execute()


@pytest.mark.usefixtures("fake_clock")
def test_oversized_body_is_rejected():
    sensor = make_sensor(
        "https://synthetic.invalid", timeout_seconds=600, _max_response_bytes=64
    )
    install_session(sensor, scripted_session(b"{" + b" " * 100 + b"}", []))

    with pytest.raises(WorkflowDependencySensorException, match="exceeded 64 bytes"):
        sensor.execute()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ReadTimeout("synthetic read timeout"),
        requests.exceptions.ConnectTimeout("synthetic connect timeout"),
        requests.exceptions.ConnectionError(
            MaxRetryError(None, "/", ReadTimeoutError(None, "/", "read timed out"))
        ),
    ],
)
@pytest.mark.usefixtures("fake_clock")
def test_http_timeouts_become_sensor_timeouts(error):
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
    install_session(sensor, scripted_session(error, []))

    with pytest.raises(WorkflowDependencySensorTimeOutException) as raised:
        sensor.execute()

    assert isinstance(raised.value, TimeoutError)
    assert raised.value.__cause__ is error


@pytest.mark.usefixtures("fake_clock")
def test_non_timeout_connection_errors_keep_requests_type():
    error = requests.exceptions.ConnectionError("synthetic refused connection")
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
    install_session(sensor, scripted_session(error, []))

    with pytest.raises(requests.exceptions.ConnectionError) as raised:
        sensor.execute()

    assert raised.value is error


def test_no_request_starts_after_request_budget(fake_clock):
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=1)
    install_session(sensor, scripted_session({"runs": []}, calls))
    fake_clock.now = 1 + GRACE + 0.01

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor.execute()

    assert not calls


def blocking(release):
    def call(*_args, **_kwargs):
        release.wait(10)
        return Mock()

    return call


def test_stalled_job_lookup_is_bounded():
    release = threading.Event()
    sensor = WorkflowDependencySensor(
        databricks_host="https://synthetic.invalid",
        databricks_token=TOKEN,
        dependency_job_id=7,
        delta=timedelta(seconds=1),
        timeout_seconds=1,
        poke_interval_seconds=0,
    )
    sensor._final_poll_grace_seconds = GRACE
    sensor._workspace_obj = Mock()
    sensor._workspace_obj.jobs.get.side_effect = blocking(release)
    try:
        elapsed, _ = timed_execute(sensor)
    finally:
        release.set()

    assert elapsed < 1 + GRACE + SCHEDULING_TOLERANCE


def test_stalled_task_sensor_listing_is_bounded():
    release = threading.Event()
    sensor = WorkflowTaskDependencySensor(
        databricks_host="https://synthetic.invalid",
        databricks_token=TOKEN,
        dependency_job_name="upstream-job",
        dependency_task_name="task",
        delta=timedelta(seconds=1),
        timeout_seconds=1,
        poke_interval_seconds=0,
    )
    sensor._final_poll_grace_seconds = GRACE
    sensor.get_execution_start_time_unix_milliseconds = Mock(return_value=123000)
    sensor._workspace_obj = Mock()
    sensor._workspace_obj.api_client.do.side_effect = blocking(release)
    try:
        elapsed, _ = timed_execute(sensor)
    finally:
        release.set()

    assert elapsed < 1 + GRACE + SCHEDULING_TOLERANCE


def test_task_sensor_sleep_is_clamped(fake_clock):
    sensor = WorkflowTaskDependencySensor(
        databricks_host="https://synthetic.invalid",
        databricks_token=TOKEN,
        dependency_job_name="upstream-job",
        dependency_task_name="task",
        delta=timedelta(seconds=1),
        timeout_seconds=3,
        poke_interval_seconds=60,
    )
    sensor.get_execution_start_time_unix_milliseconds = Mock(return_value=123000)
    sensor._workspace_obj = Mock()
    sensor._workspace_obj.api_client.do.return_value = {"runs": []}

    with pytest.raises(
        WorkflowDependencySensorTimeOutException, match=r"timed out\.\.\."
    ):
        sensor.execute()

    assert fake_clock.sleeps == [3]
    assert sensor._workspace_obj.api_client.do.call_count == 2


def test_errors_from_sdk_lookup_propagate_unchanged():
    class SyntheticPermissionDenied(Exception):
        pass

    sensor = WorkflowDependencySensor(
        databricks_host="https://synthetic.invalid",
        databricks_token=TOKEN,
        dependency_job_id=7,
        delta=timedelta(seconds=1),
        timeout_seconds=5,
        poke_interval_seconds=0,
    )
    sensor._workspace_obj = Mock()
    sensor._workspace_obj.jobs.get.side_effect = SyntheticPermissionDenied("denied")

    with pytest.raises(SyntheticPermissionDenied):
        sensor.execute()


# --- Page-boundary bounds for SDK-authenticated listing (job lookup, task runs)


def make_task_sensor(timeout_seconds=1, **overrides):
    sensor = WorkflowTaskDependencySensor(
        databricks_host="https://synthetic.invalid",
        databricks_token=TOKEN,
        dependency_job_name="upstream-job",
        dependency_task_name="target",
        delta=timedelta(seconds=1),
        timeout_seconds=timeout_seconds,
        poke_interval_seconds=0,
    )
    sensor._final_poll_grace_seconds = GRACE
    for name, value in overrides.items():
        setattr(sensor, name, value)
    sensor.get_execution_start_time_unix_milliseconds = Mock(return_value=123000)
    sensor._workspace_obj = Mock()
    return sensor


class ScriptedApi:
    """Stands in for ``WorkspaceClient.api_client``; records every request."""

    def __init__(self, page_for, delay=0.0):
        self.page_for = page_for
        self.delay = delay
        self.calls = []
        self.lock = threading.Lock()

    def do(self, method, path, *, query):
        assert method == "GET"
        with self.lock:
            self.calls.append((path, dict(query)))
            index = len(self.calls)
        if self.delay:
            time.sleep(self.delay)
        return self.page_for(index, path, query)

    @property
    def count(self):
        with self.lock:
            return len(self.calls)


def endless_empty_pages(index, _path, _query):
    return {"runs": [], "jobs": [], "next_page_token": f"token-{index}"}


def task_run(run_id, task_key, result_state):
    return {
        "run_id": run_id,
        "tasks": [{"task_key": task_key, "state": {"result_state": result_state}}],
    }


def test_endless_empty_task_pages_stop_requesting_at_the_deadline():
    api = ScriptedApi(endless_empty_pages, delay=0.003)
    sensor = make_task_sensor(timeout_seconds=0.2)
    sensor._workspace_obj.api_client = api

    elapsed, _ = timed_execute(sensor)
    at_timeout = api.count
    time.sleep(0.3)

    assert elapsed < 0.2 + GRACE + SCHEDULING_TOLERANCE
    assert at_timeout >= 2
    # No request is issued once execute() has raised.
    assert api.count == at_timeout
    path, query = api.calls[0]
    assert path == "/api/2.1/jobs/runs/list"
    assert query == {
        "job_id": 7,
        "limit": 25,
        "start_time_from": 123000,
        "expand_tasks": True,
    }
    assert [q.get("page_token") for _, q in api.calls[1:3]] == ["token-1", "token-2"]


def test_abandoned_task_page_does_not_request_further_pages():
    release = threading.Event()

    def page_for(index, path, query):
        if index == 3:
            release.wait(10)
        return endless_empty_pages(index, path, query)

    api = ScriptedApi(page_for)
    sensor = make_task_sensor(timeout_seconds=0.2)
    sensor._workspace_obj.api_client = api

    try:
        timed_execute(sensor)
        assert sensor._abandoned.is_set()
        assert ABANDONED_CALLS.count == 1
    finally:
        release.set()

    # The abandoned worker returns its page but starts no further request.
    assert wait_for(lambda: ABANDONED_CALLS.count == 0)
    time.sleep(0.1)
    assert api.count == 3


def test_endless_empty_job_lookup_pages_stop_requesting(monkeypatch):
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID)
    api = ScriptedApi(endless_empty_pages, delay=0.003)
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=0.2)
    sensor._workspace_obj = Mock(api_client=api)

    timed_execute(sensor)
    at_timeout = api.count
    time.sleep(0.3)

    assert at_timeout >= 2
    assert api.count == at_timeout
    assert sensor.dependency_job_id is None
    assert {path for path, _ in api.calls} == {"/api/2.1/jobs/list"}
    assert api.calls[0][1] == {"name": "upstream-job"}


def test_job_lookup_follows_pages_to_the_first_match(monkeypatch):
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID)

    def page_for(index, _path, _query):
        if index == 1:
            return {"next_page_token": "second"}
        return {"jobs": [{"job_id": 42}, {"job_id": 43}]}

    api = ScriptedApi(page_for)
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=5)
    sensor._workspace_obj = Mock(api_client=api)

    assert sensor._get_job_id == 42
    assert [q for _, q in api.calls] == [
        {"name": "upstream-job"},
        {"name": "upstream-job", "page_token": "second"},
    ]


def test_job_lookup_without_match_raises_value_error(monkeypatch):
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID)
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=5)
    sensor._workspace_obj = Mock(api_client=ScriptedApi(lambda *_: {"jobs": []}))

    with pytest.raises(ValueError, match="No job found with name upstream-job"):
        sensor.execute()


@pytest.mark.parametrize(
    "path_kind", ["task_runs", "job_lookup"], ids=["task-runs", "job-lookup"]
)
def test_repeated_sdk_page_token_stops_after_two_requests(monkeypatch, path_kind):
    api = ScriptedApi(lambda *_: {"runs": [], "jobs": [], "next_page_token": "same"})
    if path_kind == "task_runs":
        sensor = make_task_sensor(timeout_seconds=600)
        sensor._workspace_obj.api_client = api
    else:
        monkeypatch.setattr(
            WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID
        )
        sensor = make_sensor("https://synthetic.invalid", timeout_seconds=600)
        sensor._workspace_obj = Mock(api_client=api)

    with pytest.raises(
        WorkflowDependencySensorException, match="repeated a page token"
    ):
        sensor.execute()

    assert api.count == 2


def test_sdk_page_count_is_capped_without_a_deadline():
    api = ScriptedApi(endless_empty_pages)
    sensor = make_task_sensor(timeout_seconds=None, _max_pages_per_poll=4)
    sensor._workspace_obj.api_client = api

    with pytest.raises(WorkflowDependencySensorException, match="exceeded 4 pages"):
        sensor.execute()

    assert api.count == 4


def test_task_success_on_a_later_page_is_accepted():
    def page_for(index, _path, _query):
        if index == 1:
            return {"runs": [task_run(1, "target", "FAILED")], "next_page_token": "b"}
        return {"runs": [task_run(2, "target", "SUCCESS")]}

    api = ScriptedApi(page_for)
    sensor = make_task_sensor(timeout_seconds=5)
    sensor._workspace_obj.api_client = api

    sensor.execute()

    assert api.count == 2


# --- Late results: evaluation runs inside the bound and is checked on accept


def test_slow_run_evaluation_times_out_instead_of_succeeding():
    # 24 non-matching runs followed by a successful one; logging each run
    # takes 50 ms, so evaluation cannot finish within the 0.07 s budget.
    runs = [{"run_id": i, "state": {"result_state": "FAILED"}} for i in range(24)]
    runs.append({"run_id": 99, "state": {"result_state": "SUCCESS"}})
    calls = []
    logged = []

    def slow_info(message, *_args):
        logged.append(message)
        time.sleep(0.05)

    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=0.02)
    sensor._final_poll_grace_seconds = 0.05
    sensor.log = SimpleNamespace(info=slow_info)
    install_session(sensor, scripted_session({"runs": runs}, calls))

    elapsed, _ = timed_execute(sensor)
    at_timeout = len(logged)
    assert wait_for(lambda: ABANDONED_CALLS.count == 0)

    assert elapsed < 0.07 + SCHEDULING_TOLERANCE
    assert len(calls) == 1
    # The abandoned worker stops at the next run instead of logging them all.
    assert len(logged) <= at_timeout + 1
    assert not any("Found a successful run" in message for message in logged)


@pytest.mark.parametrize("sensor_kind", ["workflow", "task"])
def test_result_completed_after_budget_is_rejected(fake_clock, sensor_kind):
    # The page arrives promptly, but evaluating it moves the (fake) clock
    # past the deadline plus grace before the success is reported.
    def advancing_info(message, *_args):
        if "Found a successful run" in message:
            fake_clock.now += 10

    if sensor_kind == "workflow":
        sensor = make_sensor("https://synthetic.invalid", timeout_seconds=1)
        install_session(
            sensor,
            scripted_session(
                {"runs": [{"run_id": 1, "state": {"result_state": "SUCCESS"}}]}, []
            ),
        )
    else:
        sensor = make_task_sensor(timeout_seconds=1)
        sensor._workspace_obj.api_client = ScriptedApi(
            lambda *_: {"runs": [task_run(1, "target", "SUCCESS")]}
        )
    sensor.log = SimpleNamespace(info=advancing_info)

    with pytest.raises(
        WorkflowDependencySensorTimeOutException, match="could be accepted"
    ):
        sensor.execute()


# --- Abandoned work is bounded across sensor instances


def test_outstanding_abandoned_calls_are_capped(monkeypatch):
    monkeypatch.setattr(WorkflowDependencySensor, "_max_abandoned_calls", 2)
    release = threading.Event()

    def page_for(_index, _path, _query):
        if not release.is_set():
            release.wait(10)
        return {"runs": [task_run(1, "target", "SUCCESS")]}

    api = ScriptedApi(page_for)
    try:
        for _ in range(2):
            sensor = make_task_sensor(timeout_seconds=0.05)
            sensor._workspace_obj.api_client = api
            timed_execute(sensor)
        assert ABANDONED_CALLS.count == 2
        assert api.count == 2

        blocked = make_task_sensor(timeout_seconds=5)
        blocked._workspace_obj.api_client = api
        with pytest.raises(WorkflowDependencySensorException, match="abandoned"):
            blocked.execute()
        # The refused sensor started no worker and sent no request.
        assert api.count == 2
    finally:
        release.set()

    assert wait_for(lambda: ABANDONED_CALLS.count == 0)
    recovered = make_task_sensor(timeout_seconds=5)
    recovered._workspace_obj.api_client = api
    recovered.execute()
    assert api.count == 3


# --- Monotonic deadline


def test_wall_clock_changes_do_not_extend_the_deadline(monkeypatch):
    clock = SimpleNamespace(now=0.0, wall=1000.0)

    def sleep(seconds):
        clock.now += seconds
        clock.wall -= 100  # wall clock steps backwards while sleeping

    monkeypatch.setattr(
        workflow_dependency_sensor,
        "time",
        SimpleNamespace(
            time=lambda: clock.wall, monotonic=lambda: clock.now, sleep=sleep
        ),
    )
    calls = []
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=30)
    sensor.poke_interval = 25
    install_session(sensor, scripted_session({"runs": []}, calls))

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor.execute()

    # Polls at 0, 25 and 30 s of monotonic time, whatever the wall clock says.
    assert [call["timeout"][1] for call in calls] == [30 + GRACE, 5 + GRACE, GRACE]


def test_job_lookup_keeps_logging_sdk_errors_as_missing_job_id(monkeypatch):
    # The earlier get_job_id helper logged SDK/transport errors and returned
    # None; callers such as SLASensor construct sensors relying on that.
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID)
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=5)
    sensor._workspace_obj = Mock()
    sensor._workspace_obj.api_client.do.side_effect = RuntimeError("synthetic")
    sensor.log = Mock()

    assert sensor._get_job_id is None
    sensor.log.info.assert_any_call("An error occurred: %s", ANY)


def test_job_lookup_timeouts_still_propagate(monkeypatch):
    monkeypatch.setattr(WorkflowDependencySensor, "_lookup_job_id", REAL_LOOKUP_JOB_ID)
    api = ScriptedApi(endless_empty_pages, delay=0.003)
    sensor = make_sensor("https://synthetic.invalid", timeout_seconds=0.1)
    sensor._workspace_obj = Mock(api_client=api)

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor._get_job_id  # pylint: disable=pointless-statement


def test_concurrent_workers_reserve_capacity_before_start():
    release = threading.Event()
    start = threading.Barrier(13)
    outcomes = []
    entered = []
    lock = threading.Lock()

    def blocked():
        with lock:
            entered.append(True)
        release.wait(5)

    def caller():
        sensor = make_sensor("https://example.invalid", timeout_seconds=0.2)
        start.wait()
        try:
            sensor._call_before_deadline(blocked)
        except (
            WorkflowDependencySensorException,
            WorkflowDependencySensorTimeOutException,
        ) as error:
            with lock:
                outcomes.append(type(error))

    callers = [threading.Thread(target=caller) for _ in range(12)]
    try:
        for thread in callers:
            thread.start()
        start.wait()
        for thread in callers:
            thread.join(3)
        assert all(not thread.is_alive() for thread in callers)
        assert len(entered) == 8
        assert ABANDONED_CALLS.count == 8
        assert outcomes.count(WorkflowDependencySensorTimeOutException) == 8
        assert outcomes.count(WorkflowDependencySensorException) == 4
    finally:
        release.set()
        for thread in callers:
            thread.join(3)
    assert wait_for(lambda: ABANDONED_CALLS.count == 0)


def test_thread_start_failure_releases_reservation(monkeypatch):
    sensor = make_sensor("https://example.invalid")
    with monkeypatch.context() as scoped:
        scoped.setattr(
            threading.Thread, "start", Mock(side_effect=RuntimeError("start failed"))
        )
        with pytest.raises(RuntimeError, match="start failed"):
            sensor._call_before_deadline(lambda: None)
    assert ABANDONED_CALLS.count == 0
    assert sensor._call_before_deadline(lambda: 42) == 42


def test_worker_error_releases_reservation():
    sensor = make_sensor("https://example.invalid")
    with pytest.raises(ValueError, match="synthetic"):
        sensor._call_before_deadline(Mock(side_effect=ValueError("synthetic")))
    assert ABANDONED_CALLS.count == 0
    assert sensor._call_before_deadline(lambda: 42) == 42
