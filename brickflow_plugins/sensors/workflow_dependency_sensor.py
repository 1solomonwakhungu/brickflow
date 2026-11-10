import functools
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from warnings import warn

import requests
from pydantic import SecretStr
from requests.adapters import HTTPAdapter
from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs as jobs_service

from brickflow.context import ctx

_T = TypeVar("_T")


class WorkflowDependencySensorException(Exception):
    pass


class WorkflowDependencySensorTimeOutException(TimeoutError):
    pass


def _caused_by_timeout(exc: BaseException) -> bool:
    """
    Whether a Requests connection error wraps a timeout. Requests reports
    retried read timeouts, and errors raised from retry back-off, as
    ``ConnectionError`` rather than ``Timeout``.
    """
    from urllib3.exceptions import TimeoutError as Urllib3TimeoutError

    pending = [exc]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(
            current, (Urllib3TimeoutError, TimeoutError, requests.exceptions.Timeout)
        ):
            return True
        pending.extend(
            arg
            for arg in (
                *getattr(current, "args", ()),
                getattr(current, "reason", None),
                current.__cause__,
                current.__context__,
            )
            if isinstance(arg, BaseException)
        )
    return False


class _BoundedCall:
    """State shared between a caller and the worker thread running one call."""

    __slots__ = ("result", "error", "finished", "done", "abandoned", "reserved")

    def __init__(self) -> None:
        self.result: Any = None
        self.error: Optional[BaseException] = None
        self.finished = threading.Event()
        self.done = False
        self.abandoned = False
        self.reserved = False


class _AbandonedCalls:
    """
    Process-wide reservations for active and abandoned watchdog calls.

    Python cannot stop a thread blocked in a socket or SDK call, so an
    abandoned call keeps its thread and connection until it returns. This
    registry reserves capacity before starting each worker and releases it only
    when the worker finishes, bounding active plus leftover watchdog work.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def reserve(self, call: _BoundedCall, limit: int) -> None:
        with self._lock:
            if self._count >= limit:
                raise WorkflowDependencySensorException(
                    f"{self._count} active or abandoned Databricks calls are still running "
                    f"(limit {limit}); refusing to start another"
                )
            self._count += 1
            call.reserved = True

    def abandon(self, call: _BoundedCall) -> None:
        with self._lock:
            if not call.done:
                call.abandoned = True

    def finish(self, call: _BoundedCall) -> None:
        with self._lock:
            if not call.done:
                call.done = True
                if call.reserved:
                    self._count -= 1
                    call.reserved = False
        call.finished.set()


_ABANDONED_CALLS = _AbandonedCalls()


class WorkflowDependencySensor:
    """
    This is used to have dependencies on the databricks workflow

    Example Usage in your brickflow task:
        service_principle_pat = ctx.dbutils.secrets.get("brickflow-demo-tobedeleted", "service_principle_id")
        WorkflowDependencySensor(
            databricks_host=https://your_workspace_url.cloud.databricks.com,
            databricks_token=service_principle_pat,
            dependency_job_id=job_id,
            poke_interval=20,
            timeout=60,
            delta=timedelta(days=1)
        )
        In above snippet Databricks secrets is used as a secure service to store the databricks token.
        If you get your token from another secret management service, like AWS Secrets Manager, GCP Secret Manager or Azure Key Vault,
        just pass it in the databricks_token argument.

    Deadline behaviour:
        When ``timeout_seconds`` is set, the deadline is ``timeout_seconds``
        after construction, measured on a monotonic clock. Sleeps between polls
        never extend past the deadline; a poll that starts at the deadline is
        the final one, and its requests may use a further grace period
        (``_final_poll_grace_seconds``).

        ``execute`` makes Databricks requests one page at a time (job lookup,
        start-time lookup and run listing), each in a worker thread. The caller
        waits for each worker only until the deadline plus grace, and checks
        the deadline again before accepting its result, so a run found after
        that point is reported as a timeout, not a success. Evaluating and
        logging the runs of a page happens inside the worker.

        No new page is requested after the deadline plus grace, after the
        watchdog has abandoned a call, after a page token repeats, or after
        ``_max_pages_per_poll`` pages in one scan.

    Limits:
        Python cannot interrupt a thread blocked in a socket read or SDK call.
        An abandoned call keeps its daemon thread and connection until its own
        socket timeout, retry limit or response-size check stops it; it does
        not start another page. While ``_max_abandoned_calls`` such calls are
        still running in the process, sensors refuse to start new calls and
        raise ``WorkflowDependencySensorException``. The caller bound excludes
        Python scheduling delays and logging handlers that block on the
        caller's own thread. Without ``timeout_seconds`` there is no overall
        deadline: each request is bounded only by its per-operation
        connect/read timeouts and retry limits, and each scan by its page
        limits.
    """

    # Per-operation socket timeouts for run-list requests. Each is further
    # capped by the time left before the sensor deadline plus grace.
    _connect_timeout_seconds: float = 10.0
    _read_timeout_seconds: float = 60.0
    # Time allowed past the deadline for the final poll to complete.
    _final_poll_grace_seconds: float = 1.0
    # Upper bound on list pages read in one scan.
    _max_pages_per_poll: int = 1000
    # Upper bound on one decoded run-list response body.
    _max_response_bytes: int = 10 * 1024 * 1024
    _response_chunk_bytes: int = 8192
    # Process-wide limit on abandoned calls that are still running.
    _max_abandoned_calls: int = 8

    def __init__(
        self,
        databricks_host: str,
        databricks_token: Union[str, SecretStr],
        delta: timedelta,
        timeout_seconds: int,
        dependency_job_id: int = None,
        dependency_job_name: str = None,
        poke_interval_seconds: int = 60,
    ):
        self.databricks_host = databricks_host
        self.databricks_token = (
            databricks_token
            if isinstance(databricks_token, SecretStr)
            else SecretStr(databricks_token)
        )
        self.poke_interval = poke_interval_seconds
        self.timeout = timeout_seconds
        self.delta = delta
        self.log = logging
        self.start_time = time.time()
        # Deadline arithmetic uses a monotonic clock so wall-clock changes
        # cannot extend or shorten the sensor timeout.
        self._started_monotonic = time.monotonic()
        # Set when the watchdog abandons a call, so the worker stops early.
        self._abandoned = threading.Event()

        if dependency_job_id:
            warn(
                "Please use 'dependency_job_name' instead of 'dependency_job_id'",
                DeprecationWarning,
                stacklevel=2,
            )

        if not dependency_job_id and not dependency_job_name:
            raise WorkflowDependencySensorException(
                "Either dependency_job_id or dependency_job_name should be provided"
            )

        self.dependency_job_id = dependency_job_id
        self.dependency_job_name = dependency_job_name

        self._workspace_obj = WorkspaceClient(
            host=self.databricks_host, token=self.databricks_token.get_secret_value()
        )

    def get_retry_class(self, max_retries):
        from urllib3 import Retry

        log = self.log
        sensor = self

        class LogRetry(Retry):
            """
            Adding extra logs before making a retry request.

            Back-off and ``Retry-After`` sleeps are limited to the time left
            before the sensor deadline; once no time is left, retrying stops
            with the sensor's timeout exception.
            """

            def __init__(self, *args, **kwargs):
                if (
                    kwargs.get("total", None) != max_retries
                    and kwargs.get("total", None) > 0
                ):
                    log.info(f"Retrying with kwargs: {kwargs}")
                super().__init__(*args, **kwargs)

            def sleep(self, response: Any = None) -> None:
                budget = sensor._remaining_request_seconds()
                if budget is None:
                    super().sleep(response)
                    return
                if budget <= 0 or sensor._abandoned.is_set():
                    sensor._raise_timeout()
                delay = self.get_backoff_time()
                if response is not None and self.respect_retry_after_header:
                    # Mirrors urllib3: a positive Retry-After replaces back-off.
                    retry_after = self.get_retry_after(response)
                    if retry_after:
                        delay = retry_after
                if delay > budget:
                    sensor._raise_timeout(
                        " before the next Databricks request retry could start"
                    )
                if delay > 0:
                    time.sleep(delay)

        return LogRetry

    @functools.lru_cache(maxsize=None)
    def get_http_session(self):
        session = requests.Session()
        max_retries = int(os.getenv("DATABRICKS_REQUEST_RETRY_COUNT", 10))
        retries = self.get_retry_class(max_retries)(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[500, 501, 502, 503, 504, 429],
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        session.mount("http://", HTTPAdapter(max_retries=retries))
        return session

    def _raise_timeout(self, detail: str = "") -> None:
        raise WorkflowDependencySensorTimeOutException(f"The job has timed out{detail}")

    def _remaining_poll_seconds(self) -> Optional[float]:
        """Seconds until the sensor deadline, or ``None`` without a timeout."""
        if self.timeout is None:
            return None
        return self._started_monotonic + self.timeout - time.monotonic()

    def _remaining_request_seconds(self) -> Optional[float]:
        """Seconds that in-flight Databricks work may still use."""
        remaining = self._remaining_poll_seconds()
        if remaining is None:
            return None
        return remaining + self._final_poll_grace_seconds

    def _ensure_request_allowed(self) -> None:
        """Raise the sensor timeout if no further request may start."""
        if self._abandoned.is_set():
            self._raise_timeout()
        budget = self._remaining_request_seconds()
        if budget is not None and budget <= 0:
            self._raise_timeout()

    def _call_before_deadline(self, func: Callable[..., _T], *args: Any) -> _T:
        """
        Run ``func`` and return its result, or raise the sensor timeout once the
        request budget is spent.

        The call runs in a daemon thread so a stalled or trickling peer cannot
        hold the caller past the budget. A result that becomes available only
        after the budget is spent is rejected with the timeout. Errors raised
        by ``func`` propagate unchanged.
        """
        budget = self._remaining_request_seconds()
        if budget is None:
            return func(*args)
        self._ensure_request_allowed()
        call = _BoundedCall()
        _ABANDONED_CALLS.reserve(call, self._max_abandoned_calls)

        def run() -> None:
            try:
                call.result = func(*args)
            except BaseException as exc:  # pylint: disable=broad-except
                call.error = exc
            finally:
                _ABANDONED_CALLS.finish(call)

        try:
            worker = threading.Thread(
                target=run, name="workflow-dependency-sensor-call", daemon=True
            )
            worker.start()
        except BaseException:
            _ABANDONED_CALLS.finish(call)
            raise
        if not call.finished.wait(budget):
            self._abandoned.set()
            _ABANDONED_CALLS.abandon(call)
            self._raise_timeout(" while waiting for a Databricks response")
        if call.error is not None:
            raise call.error
        remaining = self._remaining_request_seconds()
        if remaining is not None and remaining <= 0:
            self._raise_timeout(" before a Databricks result could be accepted")
        return call.result

    def _request_timeout(self) -> Tuple[float, float]:
        connect, read = self._connect_timeout_seconds, self._read_timeout_seconds
        budget = self._remaining_request_seconds()
        if budget is None:
            return connect, read
        self._ensure_request_allowed()
        return min(connect, budget), min(read, budget)

    def _read_limited_body(self, response: requests.Response) -> bytes:
        body = bytearray()
        for chunk in response.iter_content(chunk_size=self._response_chunk_bytes):
            if self._abandoned.is_set():
                self._raise_timeout()
            budget = self._remaining_request_seconds()
            if budget is not None and budget <= 0:
                self._raise_timeout(" while reading a Databricks response")
            body.extend(chunk)
            if len(body) > self._max_response_bytes:
                raise WorkflowDependencySensorException(
                    "Databricks runs list response exceeded "
                    f"{self._max_response_bytes} bytes"
                )
        return bytes(body)

    def _get_runs_page(
        self,
        session: requests.Session,
        url: str,
        params: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        """Fetch and decode one runs-list page within the request budget."""
        try:
            response = session.get(
                url,
                params=params,
                headers=headers,
                timeout=self._request_timeout(),
                stream=True,
            )
            try:
                response.raise_for_status()
                body = self._read_limited_body(response)
            finally:
                response.close()
        except requests.exceptions.Timeout as exc:
            raise WorkflowDependencySensorTimeOutException(
                "The job has timed out: a Databricks runs list request timed out"
            ) from exc
        except requests.exceptions.HTTPError as exc:
            status = getattr(exc.response, "status_code", "unknown")
            raise WorkflowDependencySensorException(
                f"Databricks runs list request failed with HTTP status {status}"
            ) from exc
        except requests.exceptions.RetryError as exc:
            raise WorkflowDependencySensorException(
                "Databricks runs list request failed after exhausting retries"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            if _caused_by_timeout(exc):
                raise WorkflowDependencySensorTimeOutException(
                    "The job has timed out: a Databricks runs list request timed out"
                ) from exc
            raise

        try:
            page = json.loads(body)
        except ValueError as exc:
            raise WorkflowDependencySensorException(
                "Databricks runs list response is not valid JSON"
            ) from exc
        if not isinstance(page, dict):
            raise WorkflowDependencySensorException(
                "Databricks runs list response is not a JSON object"
            )
        return page

    def _evaluate_runs_page(
        self,
        session: requests.Session,
        url: str,
        params: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Fetch one runs-list page and look for a successful run on it.

        Runs inside the bounded call, so the caller does not process or log
        runs after the deadline.
        """
        page = self._get_runs_page(session, url, params, headers)
        for run in self._page_items(page, "runs", "Databricks runs list"):
            if self._abandoned.is_set():
                self._raise_timeout()
            self.log.info(
                f"Found the run_id: {run['run_id']}, and it's result_state is: {run.get('state', {}).get('result_state', None)}"
            )
            if run.get("state", {}).get("result_state", None) == "SUCCESS":
                self.log.info(f"Found a successful run: {run['run_id']}")
                return True, page
        return False, page

    @staticmethod
    def _page_items(page: Any, key: str, source: str) -> List[Any]:
        if not isinstance(page, dict):
            raise WorkflowDependencySensorException(
                f"{source} response is not a JSON object"
            )
        items = page.get(key)
        if items is None:
            return []
        if not isinstance(items, list):
            raise WorkflowDependencySensorException(
                f"{source} response field '{key}' is not a list"
            )
        return items

    def _next_page_token(
        self,
        page: Dict[str, Any],
        seen_tokens: Set[str],
        source: str = "Databricks runs list",
    ) -> str:
        token = page.get("next_page_token")
        if not isinstance(token, str) or not token:
            raise WorkflowDependencySensorException(
                f"{source} reported more pages without a next_page_token"
            )
        if token in seen_tokens:
            raise WorkflowDependencySensorException(
                f"{source} repeated a page token; stopping pagination"
            )
        seen_tokens.add(token)
        return token

    def _sdk_next_page_token(
        self, page: Dict[str, Any], seen_tokens: Set[str], pages_read: int, source: str
    ) -> Optional[str]:
        """
        The token for the next page under the SDK's convention (continue while
        ``next_page_token`` is non-empty), or ``None`` when the scan is done.
        Repeated tokens and scans longer than ``_max_pages_per_poll`` raise.
        """
        if not page.get("next_page_token"):
            return None
        token = self._next_page_token(page, seen_tokens, source)
        if pages_read >= self._max_pages_per_poll:
            raise WorkflowDependencySensorException(
                f"{source} exceeded {self._max_pages_per_poll} pages in one poll"
            )
        return token

    def _sdk_get_page(
        self, path: str, query: Dict[str, Any], source: str
    ) -> Dict[str, Any]:
        """
        Make exactly one Databricks SDK GET request for one list page.

        Uses the workspace client's authentication and its own HTTP timeout
        and retry policy for this single request; pagination stays with the
        caller so every page boundary is checked.
        """
        self._ensure_request_allowed()
        page = self._workspace_obj.api_client.do("GET", path, query=dict(query))
        if not isinstance(page, dict):
            raise WorkflowDependencySensorException(
                f"{source} response is not a JSON object"
            )
        return page

    def _wait_for_next_poll(
        self, timeout_message: str, sleep_message: str = "sleeping for"
    ) -> None:
        """Raise the timeout or sleep until the next poll, never past the deadline."""
        remaining = self._remaining_poll_seconds()
        sleep_for: float
        if remaining is None:
            sleep_for = self.poke_interval
        elif remaining <= 0:
            raise WorkflowDependencySensorTimeOutException(timeout_message)
        else:
            sleep_for = min(self.poke_interval, remaining)
        self.log.info(f"{sleep_message}: {sleep_for}")
        time.sleep(sleep_for)

    def get_execution_start_time_unix_milliseconds(self) -> int:
        run_id = ctx.dbutils_widget_get_or_else("brickflow_parent_run_id", None)
        if run_id is None:
            raise WorkflowDependencySensorException(
                "run_id is empty, brickflow_parent_run_id parameter is not found "
                "or no value present"
            )

        run = self._workspace_obj.jobs.get_run(run_id=run_id)

        # Convert Unix timestamp in milliseconds to datetime object to easily incorporate the delta
        start_time = datetime.fromtimestamp(run.start_time / 1000)
        execution_start_time = start_time - self.delta

        # Convert datetime object back to Unix timestamp in miliseconds
        execution_start_time_unix_miliseconds = int(
            execution_start_time.timestamp() * 1000
        )

        self.log.info(f"This workflow started at {start_time}")
        self.log.info(
            f"Going to check runs for job_id {self.dependency_job_id} from {execution_start_time} onwards"
        )
        self.log.info(
            f"{execution_start_time} in UNIX miliseconds is {execution_start_time_unix_miliseconds}"
        )
        return execution_start_time_unix_miliseconds

    def _find_job_on_page(
        self, query: Dict[str, Any]
    ) -> Tuple[Optional[int], Dict[str, Any]]:
        source = "Databricks jobs list"
        page = self._sdk_get_page("/api/2.1/jobs/list", query, source)
        for job in self._page_items(page, "jobs", source):
            if isinstance(job, dict) and job.get("job_id") is not None:
                self.log.info(
                    "Job id for job '%s' is %s", self.dependency_job_name, job["job_id"]
                )
                return job["job_id"], page
        return None, page

    def _lookup_job_id(self) -> int:
        """
        Resolve ``dependency_job_name`` to a job id, one bounded page at a time.

        Raises ``ValueError`` when no job has that name.
        """
        self.log.info("Searching job id for job name: %s", self.dependency_job_name)
        query: Dict[str, Any] = {"name": self.dependency_job_name}
        seen_tokens: Set[str] = set()
        pages_read = 0
        while True:
            job_id, page = self._call_before_deadline(self._find_job_on_page, query)
            if job_id is not None:
                return job_id
            pages_read += 1
            token = self._sdk_next_page_token(
                page, seen_tokens, pages_read, "Databricks jobs list"
            )
            if token is None:
                raise ValueError(f"No job found with name {self.dependency_job_name}")
            query["page_token"] = token

    @property
    def _get_job_id(self):
        """
        The job id for ``dependency_job_name``.

        Keeps the earlier ``get_job_id`` contract: a missing job raises
        ``ValueError`` and other Databricks or transport errors are logged and
        give ``None``. The sensor's own timeout and pagination-limit
        exceptions propagate.
        """
        try:
            return self._lookup_job_id()
        except (
            ValueError,
            WorkflowDependencySensorException,
            WorkflowDependencySensorTimeOutException,
        ):
            raise
        except Exception as error:  # pylint: disable=broad-except
            self.log.info("An error occurred: %s", error)
            return None

    def execute(self):
        if self.dependency_job_id:
            # Databricks SDK will throw PermissionDenied exception if the job_id is not found or
            # user doesn't have permission
            self._call_before_deadline(
                functools.partial(
                    self._workspace_obj.jobs.get, job_id=self.dependency_job_id
                )
            )

        if not self.dependency_job_id:
            self.dependency_job_id = self._get_job_id

        session = self.get_http_session()
        url = f"{self.databricks_host.rstrip('/')}/api/2.1/jobs/runs/list"
        headers = {
            "Authorization": f"Bearer {self.databricks_token.get_secret_value()}",
            "Content-Type": "application/json",
        }
        params = {
            "limit": 25,
            "job_id": self.dependency_job_id,
            "start_time_from": self._call_before_deadline(
                self.get_execution_start_time_unix_milliseconds
            ),
        }

        while True:
            # Each poll must start from the newest page of runs.
            params.pop("page_token", None)
            page_index = 0
            has_more = True
            seen_tokens: Set[str] = set()
            while has_more is True:
                found, resp = self._call_before_deadline(
                    self._evaluate_runs_page, session, url, params, headers
                )
                if found:
                    return

                has_more = resp.get("has_more", False)
                if has_more:
                    params["page_token"] = self._next_page_token(resp, seen_tokens)
                self.log.info(
                    f"This is page_index: {page_index}, this is has_more: {has_more}"
                )
                page_index += 1
                if has_more is True and page_index >= self._max_pages_per_poll:
                    raise WorkflowDependencySensorException(
                        "Databricks runs list exceeded "
                        f"{self._max_pages_per_poll} pages in one poll"
                    )

            self.log.info("Didn't find a successful run yet")
            self._wait_for_next_poll("The job has timed out")


class WorkflowTaskDependencySensor(WorkflowDependencySensor):
    """
    This is used to have dependencies on the specific task within a databricks workflow

    Example Usage in your brickflow task:
        service_principle_pat = ctx.dbutils.secrets.get("scope", "service_principle_id")
        WorkflowTaskDependencySensor(
            databricks_host=https://your_workspace_url.cloud.databricks.com,
            databricks_token=service_principle_pat,
            dependency_job_name="my_job",
            dependency_task_name="foo",
            poke_interval_seconds=20,
            timeout_seconds=60,
            delta=timedelta(days=1),
            allow_skipped=True  # Optional: treat skipped (EXCLUDED) tasks as successful
        )
        In the above snippet Databricks secrets are used as a secure service to store the databricks token.
        If you get your token from another secret management service, like AWS Secrets Manager, GCP Secret Manager
        or Azure Key Vault, just pass it in the databricks_token argument.

    Args:
        dependency_job_name: Name of the job to monitor
        dependency_task_name: Name of the task within the job to monitor
        delta: Time delta to look back for runs
        timeout_seconds: Maximum time to wait before timing out
        databricks_host: Databricks workspace URL
        databricks_token: Databricks authentication token
        poke_interval_seconds: Interval between checks (default: 60)
        allow_skipped: If True, treat skipped (EXCLUDED) tasks as successful (default: False)
    """

    def __init__(
        self,
        dependency_job_name: str,
        dependency_task_name: str,
        delta: timedelta,
        timeout_seconds: int,
        databricks_host: str = None,
        databricks_token: Union[str, SecretStr] = None,
        poke_interval_seconds: int = 60,
        allow_skipped: bool = False,
    ):
        super().__init__(
            databricks_host=databricks_host,
            databricks_token=databricks_token,
            dependency_job_name=dependency_job_name,
            delta=delta,
            timeout_seconds=timeout_seconds,
            poke_interval_seconds=poke_interval_seconds,
        )

        self.dependency_task_name = dependency_task_name
        self.allow_skipped = allow_skipped

    def _evaluate_task_runs_page(
        self, query: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Fetch one runs-list page and check it for an allowed task state.

        Runs inside the bounded call, so the caller does not process or log
        runs after the deadline.
        """
        source = "Databricks runs list"
        page = self._sdk_get_page("/api/2.1/jobs/runs/list", query, source)
        allowed_states = ["SUCCESS", "EXCLUDED"] if self.allow_skipped else ["SUCCESS"]
        for item in self._page_items(page, "runs", source):
            if self._abandoned.is_set():
                self._raise_timeout()
            run = jobs_service.BaseRun.from_dict(item)
            for task in run.tasks or []:
                if task.task_key != self.dependency_task_name:
                    continue
                task_state = task.state.result_state if task.state else None
                if task_state:
                    self.log.info(
                        f"Found the run_id '{run.run_id}' and '{self.dependency_task_name}' "
                        f"task with state: {task_state.value}"
                    )
                    if task_state.value in allowed_states:
                        if task_state.value == "EXCLUDED":
                            self.log.info(f"Found a skipped task in run: {run.run_id}")
                        else:
                            self.log.info(f"Found a successful run: {run.run_id}")
                        return True, page
                else:
                    self.log.info(
                        f"Found the run_id '{run.run_id}' and '{self.dependency_task_name}' "
                        f"but the task has not started yet..."
                    )
        return False, page

    def _find_allowed_task_run(self) -> bool:
        """Scan runs since the cutoff; ``True`` once the task is in an allowed state."""
        query: Dict[str, Any] = {
            "job_id": self.dependency_job_id,
            "limit": 25,
            "start_time_from": self._call_before_deadline(
                self.get_execution_start_time_unix_milliseconds
            ),
            "expand_tasks": True,
        }
        seen_tokens: Set[str] = set()
        pages_read = 0
        while True:
            found, page = self._call_before_deadline(
                self._evaluate_task_runs_page, query
            )
            if found:
                return True
            pages_read += 1
            token = self._sdk_next_page_token(
                page, seen_tokens, pages_read, "Databricks runs list"
            )
            if token is None:
                return False
            query["page_token"] = token

    def execute(self):
        self.dependency_job_id = self._get_job_id

        while True:
            if self._find_allowed_task_run():
                return

            self.log.info("Didn't find a successful task run yet...")
            self._wait_for_next_poll("The job has timed out...", "Sleeping for")
