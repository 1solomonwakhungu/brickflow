import contextlib
import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import click
import pytest
from click.testing import CliRunner

from brickflow.cli import bundles


@pytest.fixture(name="sync_boundary")
def _sync_boundary(monkeypatch):
    monkeypatch.setenv("BRICKFLOW_BUNDLE_CLI_EXEC", "/synthetic/databricks")
    monkeypatch.setattr(bundles, "bundle_cli_setup", Mock())
    monkeypatch.setattr(bundles, "log_important_versions", Mock())
    monkeypatch.setattr(bundles, "bundle_synth", Mock())
    monkeypatch.setattr(bundles, "get_bundles_project_env", lambda: "analytics-dev")
    run = Mock()
    monkeypatch.setattr("brickflow.cli.commands.subprocess.run", run)
    return run


@pytest.mark.parametrize("duration", [None, "5s", "500ms", "1m30s", 0, 5])
def test_sync_duration_reaches_subprocess_as_separate_argument(sync_boundary, duration):
    bundles.bundle_sync(interval_duration=duration, watch=True, full=True, debug=True)

    expected = [
        "/synthetic/databricks",
        "bundle",
        "sync",
        "-t",
        "analytics-dev",
        "--full",
        "--watch",
    ]
    if duration is not None:
        expected.extend(["--interval-duration", str(duration)])
    expected.append("--debug")
    assert sync_boundary.call_args.args[0] == expected
    assert sync_boundary.call_args.kwargs["check"] is True
    bundles.bundle_cli_setup.assert_called_once_with()
    bundles.bundle_synth.assert_called_once()


def test_projects_sync_forwards_string_duration(monkeypatch, sync_boundary):
    projects = importlib.import_module("brickflow.cli.projects")
    manager = Mock()
    manager.get_project.return_value = SimpleNamespace(
        path_project_root_to_workflows_dir="workflows"
    )
    manager.get_project_ref.return_value = SimpleNamespace(root_yaml_rel_path=".")
    monkeypatch.setattr(projects, "multi_project_manager", manager)
    monkeypatch.setattr(projects, "use_project", lambda *args: contextlib.nullcontext())
    monkeypatch.setattr(projects, "handle_libraries", Mock())
    project_option = next(
        p for p in projects.sync_project.params if p.name == "project"
    )
    monkeypatch.setattr(project_option, "type", click.Choice(["analytics"]))

    # Restore the environment value changed by Click's callback.
    monkeypatch.setenv("BRICKFLOW_ENV", "local")

    result = CliRunner().invoke(
        projects.sync_project,
        [
            "--project",
            "analytics",
            "--env",
            "dev",
            "--watch",
            "--interval-duration",
            "5s",
        ],
    )

    assert result.exit_code == 0, result.output
    assert sync_boundary.call_args.args[0] == [
        "/synthetic/databricks",
        "bundle",
        "sync",
        "-t",
        "analytics-dev",
        "--watch",
        "--interval-duration",
        "5s",
    ]
