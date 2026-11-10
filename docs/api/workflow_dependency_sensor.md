---
search:
  exclude: true
---

# Workflow Dependency Sensor

The `WorkflowDependencySensor` and `WorkflowTaskDependencySensor` allow you to create cross-workflow dependencies in Databricks. Use these sensors to wait for an upstream workflow (or a specific task within it) to complete before proceeding with your own workflow's tasks.

## WorkflowDependencySensor

Monitors an entire Databricks workflow and waits for a successful run within a configurable time window. Suitable when you need to depend on the overall completion of an upstream job.

## WorkflowTaskDependencySensor

Monitors a **specific task** within a Databricks workflow. This provides finer-grained control when you only need a particular task to complete rather than the entire workflow.

### Handling skipped tasks

By default, the sensor only considers tasks with a `SUCCESS` result state as completed. Some workflows use conditional logic that causes certain tasks to be skipped (reported as `EXCLUDED` by Databricks). If a skipped task should be treated as a valid completion state, set the `allow_skipped` parameter to `True`:

```python
sensor = WorkflowTaskDependencySensor(
    dependency_job_name="upstream_job",
    dependency_task_name="conditional_task",
    delta=timedelta(days=1),
    timeout_seconds=300,
    allow_skipped=True,  # treat EXCLUDED tasks as successful
)
sensor.execute()
```

When `allow_skipped=False` (the default), only `SUCCESS` is accepted. When `allow_skipped=True`, both `SUCCESS` and `EXCLUDED` states are accepted.

## Timeouts and request limits

Both sensors measure `timeout_seconds` on a monotonic clock, starting when the sensor is created, so changes to the system clock do not move the deadline.

- The wait between polls is `poke_interval_seconds`, shortened so it never ends past the deadline. A poll that starts at the deadline is the last one; if it does not find an accepted run, the sensor raises `WorkflowDependencySensorTimeOutException`.
- Requests of the final poll may run during a grace period of one second after the deadline. Requests use a 10 second connect timeout and a 60 second read timeout, each reduced to the time left before the deadline plus that grace period.
- `execute()` requests one page at a time: the job lookup by name, the start-time lookup, and each page of the run list. Each request, and the evaluation of the runs on its page, runs in a worker thread. The sensor waits for each worker only until the deadline plus grace, and checks the deadline again before it accepts a result. A run found after that point produces `WorkflowDependencySensorTimeOutException`, not success.
- No new page is requested after the deadline plus grace, after a request has been abandoned, after a page token repeats, or after 1000 pages in one scan. This applies to the job lookup and to both sensors' run listing.
- Run-list responses with an HTTP error status, a body that is not a JSON object, a body larger than 10 MiB (`WorkflowDependencySensor`), a missing or repeated page token, or more than 1000 pages in one scan raise `WorkflowDependencySensorException` instead of being polled until the timeout. A job name with no matching job raises `ValueError`; other Databricks or transport errors during the job lookup are logged and leave the job id unset, as before.

Limits:

- Python cannot interrupt a thread that is blocked in a socket read or Databricks SDK call. When the sensor gives up on a request, that request keeps its daemon thread and connection until its own socket timeout, retry limit, or response-size check stops it. It does not request another page. A connection that trickles bytes can keep it alive for longer than its read timeout, because the read timeout restarts with every byte. Job lookup and `WorkflowTaskDependencySensor` requests use the Databricks SDK's own HTTP timeout and retry policy for each page.
- At most eight active or abandoned watchdog calls may run in one Python process. Capacity is reserved before worker startup and released only when the worker finishes, including failure paths. While that many remain, sensors raise `WorkflowDependencySensorException` instead of starting new requests.
- The bound on `execute()` excludes thread scheduling delays and log handlers that block on the calling thread. Log handlers that block inside a worker delay only that worker.
- Without `timeout_seconds` there is no overall deadline. Each request is then bounded only by its connect/read timeouts and retry limit, and each scan by the page limits.
- Construction of the `WorkspaceClient`, and methods called directly outside `execute()`, are not covered by the deadline.

## API Reference

::: brickflow_plugins.sensors.workflow_dependency_sensor
    handler: python
    options:
        members:
            - WorkflowDependencySensor
            - WorkflowTaskDependencySensor
        filters:
            - "!^_[^_]"
            - "!^__[^__]"

Calls with `timeout_seconds=None` run synchronously and do not use the watchdog capacity pool; they cannot create abandoned watchdog threads.
