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

`server` must be an `https://` URL. Plaintext (`http://`) and scheme-less
addresses raise `ValueError` when the operator or `TableauWrapper` is created;
there is no plaintext fallback. The server certificate is verified. For a
server whose certificate is issued by a private certificate authority, pass
`ca_bundle="/path/to/ca.pem"` (or set `REQUESTS_CA_BUNDLE`).

The Tableau client's HTTP session is bound to the scheme, host and effective
port of `server`. That check runs on every request the client sends,
including the sign-in redirect tableauserverclient follows itself and
redirects that `requests` follows automatically. Redirects within the same
origin are followed as before. A request for any other origin, including an
HTTPS to HTTP downgrade or another port on the same host, raises
`brickflow_plugins._origin_policy.CrossOriginRequestError` (a
`requests.exceptions.RequestException`) before it is sent, so neither the
password nor the session token reaches that host. The policy applies only to
the Tableau client's own session; it does not change `requests` globally.

The password is masked in the wrapper option log and in the text
representation of `wrapper_options` and `TableauWrapper`. When sign-in fails
for a reason other than a transport error, the operators raise
`TableauSignInError` in place of the tableauserverclient exception
(`FailedSignInError`, `ServerResponseError`, `NonXMLResponseError` and so on).
Its message keeps the original type name and text with the password, in its
raw, XML-, URL- and repr-escaped forms, replaced by `***`; `original_type`
holds the original class name, and the original exception is neither chained
nor kept as implicit context (`__cause__` and `__context__` are `None`).
Transport errors such as `requests.exceptions.SSLError`, `ConnectionError`,
`CrossOriginRequestError` or an `OSError` for an unreadable CA bundle
propagate unchanged. Redaction covers sign-in only: errors and job notes
returned after sign-in carry server text as-is.

Requires the `tableauserverclient` library on the cluster. Brickflow's plugin
library list installs 0.41 on Python 3.10+ and 0.25 on Python 3.9; the
`brickflow[tableau]` extra allows 0.41 on Python 3.10+ and 0.25 to 0.38 on
Python 3.9. If you pin it yourself, use 0.41 on Python 3.10+ clusters.

## API Reference

::: brickflow_plugins.operators.tableau_refresh_operator
    handler: python
    options:
        filters:
            - "!^_[^_]"
            - "!^__[^__]"
