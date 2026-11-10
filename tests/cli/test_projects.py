from pathlib import Path
from contextlib import nullcontext
import importlib
import shutil
import os
from types import SimpleNamespace
import click
from click.testing import CliRunner
import pytest
from brickflow import ConfigFileType
from brickflow.cli import cli
from brickflow.cli.projects import MultiProjectManager, get_brickflow_root


@pytest.mark.parametrize("skip_validate", [False, True])
def test_project_deploy_routes_validation_option(monkeypatch, mocker, skip_validate):
    projects_module = importlib.import_module("brickflow.cli.projects")
    project = SimpleNamespace(path_project_root_to_workflows_dir="synthetic_workflows")
    manager = mocker.Mock()
    manager.get_project.return_value = project
    manager.get_project_ref.return_value.root_yaml_rel_path = "."
    monkeypatch.setattr(projects_module, "multi_project_manager", manager)
    monkeypatch.setattr(projects_module, "use_project", lambda *args: nullcontext())
    monkeypatch.setattr(projects_module, "handle_libraries", lambda **kwargs: None)
    for parameter in projects_module.deploy_project.params:
        if parameter.name == "project":
            monkeypatch.setattr(parameter, "type", click.Choice(["analytics"]))
    deploy = mocker.patch.object(projects_module, "bundle_deploy")
    # Restore environment bindings after Click's callbacks run.
    monkeypatch.setenv("BRICKFLOW_ENV", "local")
    monkeypatch.setenv("DATABRICKS_CONFIG_PROFILE", "synthetic")
    args = [
        "projects",
        "deploy",
        "--project",
        "analytics",
        "--env",
        "dev",
        "--profile",
        "synthetic",
    ]
    if skip_validate:
        args.append("--skip-validate")

    result = CliRunner().invoke(cli, args)

    assert result.exit_code == 0, result.output
    deploy.assert_called_once()
    assert deploy.call_args.kwargs["skip_validate"] is skip_validate
    assert deploy.call_args.kwargs["workflows_dir"] == "synthetic_workflows"
    assert os.environ["BRICKFLOW_ENV"] == "dev"
    assert os.environ["DATABRICKS_CONFIG_PROFILE"] == "synthetic"


@pytest.mark.parametrize("command", ["synth", "sync", "destroy"])
def test_skip_validate_is_only_a_deploy_option(command):
    result = CliRunner().invoke(cli, ["projects", command, "--skip-validate"])
    assert result.exit_code == 2
    assert "No such option: --skip-validate" in result.output


@pytest.mark.parametrize(
    "project_folder,extension",
    [("sample_yml_project", "yml"), ("sample_yaml_project", "yaml")],
)
def test_get_brickflow_root(project_folder, extension):
    cwd = Path.cwd()
    test_folder = Path(__file__).parent.resolve()

    # Creating empty test directories
    test_dir = test_folder / project_folder / "some" / "dummy" / "dir"
    test_dir.mkdir(parents=True, exist_ok=True)

    try:
        os.chdir(test_dir)

        actual = get_brickflow_root()
        expected = test_folder / project_folder / f"brickflow-multi-project.{extension}"
        assert actual.resolve().as_posix() == expected.resolve().as_posix()
    finally:
        # Cleanup
        os.chdir(cwd)
        shutil.rmtree(test_folder / project_folder / "some")


@pytest.mark.parametrize(
    "project_folder, config_type",
    [
        ("sample_yml_project", ConfigFileType.YML),
        ("sample_yaml_project", ConfigFileType.YAML),
    ],
)
def test_multi_project_manager_yaml(project_folder, config_type):
    cwd = Path.cwd()
    test_folder = Path(__file__).parent

    try:
        os.chdir(test_folder)

        config_file_name = (
            test_folder
            / project_folder
            / f"brickflow-multi-project.{config_type.value}"
        )
        manager = MultiProjectManager(
            config_file_name=str(config_file_name), file_type=config_type
        )
        assert manager._brickflow_multi_project_config.version == "v1"
        expected_project_config = {
            "version": "v1",
            "projects": {
                "test_cli_project": {
                    "name": "test_cli_project",
                    "path_from_repo_root_to_project_root": "some/test/path",
                    "path_project_root_to_workflows_dir": "path/to/workflows",
                    "deployment_mode": "bundle",
                    "brickflow_version": "1.2.1",
                    "enable_plugins": False,
                }
            },
        }
        assert manager._project_config_dict["."].model_dump() == expected_project_config
    finally:
        os.chdir(cwd)
