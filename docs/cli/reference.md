---
search:
  exclude: true
---

This page provides documentation for our command line tools.

## Project deployment

`bf projects deploy` synthesizes the bundle, validates it with the Databricks CLI,
and then deploys it. Validation and deployment use the same project and environment
target. A validation failure stops deployment.

```bash
bf projects deploy --project analytics --env dev
```

To bypass validation for a deployment, add `--skip-validate`. Synthesis still runs,
and all other deployment options retain their behavior.

```bash
bf projects deploy --project analytics --env dev --skip-validate
```

The bypass is available only on `projects deploy`. The raw `bf bundle` proxy is
unchanged.


::: mkdocs-click
    :module: brickflow.cli
    :command: cli
    :prog_name: bf
    :depth: 1



