import re
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from requests_mock.mocker import Mocker as RequestsMocker

from brickflow_plugins.sensors.workflow_dependency_sensor import (
    WorkflowDependencySensor,
    WorkflowDependencySensorTimeOutException,
)
from brickflow_plugins.sensors import workflow_dependency_sensor


@pytest.fixture(name="polling_sensor")
def _polling_sensor(monkeypatch):
    clock = SimpleNamespace(now=0, sleeps=[])
    request_params = []

    def sleep(seconds):
        clock.sleeps.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(
        workflow_dependency_sensor,
        "time",
        SimpleNamespace(time=lambda: clock.now, sleep=sleep),
    )
    monkeypatch.setattr(workflow_dependency_sensor, "WorkspaceClient", Mock())
    monkeypatch.setattr(workflow_dependency_sensor, "get_job_id", lambda **_: 7)

    def make_sensor(pages):
        sensor = WorkflowDependencySensor(
            databricks_host="https://synthetic.invalid",
            databricks_token="synthetic-token",
            dependency_job_name="upstream-job",
            delta=timedelta(seconds=1),
            timeout_seconds=2,
            poke_interval_seconds=1,
        )
        cutoff = Mock(return_value=123000)
        monkeypatch.setattr(
            sensor, "get_execution_start_time_unix_milliseconds", cutoff
        )

        def get(url, *, params, headers):
            assert url == "https://synthetic.invalid/api/2.1/jobs/runs/list"
            assert headers["Authorization"] == "Bearer synthetic-token"
            # Snapshot before the next page mutates the shared request dictionary.
            request_params.append(params.copy())
            page = pages.get((clock.now, params.get("page_token")), {"runs": []})
            return Mock(json=Mock(return_value=page))

        session = Mock(get=Mock(side_effect=get))
        monkeypatch.setattr(sensor, "get_http_session", lambda: session)
        return sensor, cutoff

    return make_sensor, clock, request_params


def successful_page():
    return {"runs": [{"run_id": 42, "state": {"result_state": "SUCCESS"}}]}


def next_page(token):
    return {"runs": [], "has_more": True, "next_page_token": token}


def assert_request_params(request_params, tokens):
    assert request_params == [
        {
            "limit": 25,
            "job_id": 7,
            "start_time_from": 123000,
            **({"page_token": token} if token is not None else {}),
        }
        for token in tokens
    ]


def test_restarts_at_first_page_after_unsuccessful_poll(polling_sensor):
    make_sensor, clock, request_params = polling_sensor
    sensor, cutoff = make_sensor(
        {
            (0, None): next_page("older-page"),
            (0, "older-page"): {"runs": []},
            (1, None): successful_page(),
        }
    )

    sensor.execute()

    assert_request_params(request_params, [None, "older-page", None])
    assert clock.sleeps == [1]
    cutoff.assert_called_once_with()


@pytest.mark.parametrize("page_count", [1, 2, 3])
def test_finds_success_on_any_page_in_same_poll(polling_sensor, page_count):
    make_sensor, clock, request_params = polling_sensor
    tokens = [None, "page-2", "page-3"][:page_count]
    pages = {
        (0, token): next_page(tokens[index + 1])
        for index, token in enumerate(tokens[:-1])
    }
    pages[(0, tokens[-1])] = successful_page()
    sensor, cutoff = make_sensor(pages)

    sensor.execute()

    assert_request_params(request_params, tokens)
    assert clock.sleeps == []
    cutoff.assert_called_once_with()


def test_restarts_pagination_across_multiple_polls(polling_sensor):
    make_sensor, clock, request_params = polling_sensor
    pages = {}
    for poll in range(3):
        pages[(poll, None)] = next_page("page-2")
        pages[(poll, "page-2")] = next_page("page-3")
    pages[(2, "page-3")] = successful_page()
    sensor, cutoff = make_sensor(pages)

    sensor.execute()

    assert_request_params(request_params, [None, "page-2", "page-3"] * 3)
    assert clock.sleeps == [1, 1]
    cutoff.assert_called_once_with()


@pytest.mark.parametrize("page_count", [1, 3])
def test_empty_pages_still_time_out(polling_sensor, page_count):
    make_sensor, clock, request_params = polling_sensor
    tokens = [None, "page-2", "page-3"][:page_count]
    pages = {
        (poll, token): next_page(tokens[index + 1])
        for poll in range(4)
        for index, token in enumerate(tokens[:-1])
    }
    sensor, cutoff = make_sensor(pages)

    with pytest.raises(WorkflowDependencySensorTimeOutException):
        sensor.execute()

    assert_request_params(request_params, tokens * 4)
    assert clock.sleeps == [1, 1, 1]
    cutoff.assert_called_once_with()


class TestWorkflowDependencySensor:
    workspace_url = "https://42.cloud.databricks.com"
    endpoint_url = f"{workspace_url}/api/.*/jobs/get"
    response = {}

    def test_sensor_failure_403(self):
        api = RequestsMocker()
        api.get(re.compile(self.endpoint_url), json=self.response, status_code=int(403))

        # Databricks SDK will throw PermissionDenied exception if the job_id is not found or
        # user doesn't have permission
        from databricks.sdk.errors.platform import PermissionDenied

        with api:
            sensor = WorkflowDependencySensor(
                databricks_host=self.workspace_url,
                databricks_token="token",
                dependency_job_id="1",
                delta=timedelta(seconds=1),
                timeout_seconds=1,
                poke_interval_seconds=1,
            )

            with pytest.raises(PermissionDenied):
                sensor.execute()
