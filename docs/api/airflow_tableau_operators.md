---
search:
  exclude: true
---

# Tableau Refresh Operators

`TableauRefreshDataSourceOperator` and `TableauRefreshWorkBookOperator`
refresh Tableau data sources or workbooks by triggering async refresh
jobs and polling the Tableau server until they complete.

Previously these operators subclassed Airflow's `BaseOperator`. They have
been rewritten as plain Python classes with an `execute()` method -- no
`apache-airflow` install is required. The public constructor signature and
behavior remain unchanged apart from no longer accepting `task_id` (which
was an Airflow concept).

```python
from brickflow_plugins import (
    TableauRefreshDataSourceOperator,
    TableauRefreshWorkBookOperator,
)

TableauRefreshDataSourceOperator(
    server="https://tableau.example.com",
    username="me",
    password="pw",
    site="my_site",
    project="my_project",
    data_sources=["ds_a", "ds_b"],
).execute()
```

The Tableau server certificate is verified for HTTPS connections. Configure an
HTTPS endpoint; HTTP URLs remain accepted, and certificate verification does
not restrict redirect destinations. For a server whose
certificate is issued by a private certificate authority, pass
`ca_bundle="/path/to/ca.pem"` (or set `REQUESTS_CA_BUNDLE`). The password is
passed to Tableau authentication unchanged but its field is masked in the
wrapper option log and text representation of `wrapper_options`. Server-derived
errors are not sanitized and may contain sensitive response text.

Requires the `tableauserverclient` library to be installed on the cluster
(via `PypiTaskLibrary("tableauserverclient==0.25")` or the
`brickflow[tableau]` extra during local development).

## API Reference

::: brickflow_plugins.operators.tableau_refresh_operator
    handler: python
    options:
        filters:
            - "!^_[^_]"
            - "!^__[^__]"
