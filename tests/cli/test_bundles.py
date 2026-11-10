import logging
import os
from typing import Optional
from unittest.mock import patch, Mock
from click import ClickException
from pytest import LogCaptureFixture
import pytest

from brickflow import BrickflowEnvVars, _ilog, ctx
from brickflow.cli.bundles import bundle_deploy, bundle_destroy, bundle_validate


@pytest.fixture(name="bundle_lifecycle")
def _bundle_lifecycle(monkeypatch, mocker):
    """Record the lifecycle without downloading or executing a CLI or workflow."""
    events = []
    monkeypatch.setenv(BrickflowEnvVars.BRICKFLOW_ENV.value, "dev")
    monkeypatch.setenv(BrickflowEnvVars.BRICKFLOW_USE_PROJECT_NAME.value, "true")
    monkeypatch.delenv(BrickflowEnvVars.BRICKFLOW_PROJECT_NAME.value, raising=False)
    monkeypatch.setattr(ctx, "_current_project", "analytics")
    monkeypatch.setenv(
        BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value, "/synthetic/databricks"
    )
    mocker.patch(
        "brickflow.cli.bundles.bundle_cli_setup",
        side_effect=lambda: events.append("setup"),
    )
    mocker.patch(
        "brickflow.cli.bundles.log_important_versions",
        side_effect=lambda cli: events.append(("versions", cli)),
    )
    synth = mocker.patch(
        "brickflow.cli.bundles.bundle_synth",
        side_effect=lambda **kwargs: events.append("synth"),
    )
    command = mocker.patch(
        "brickflow.cli.bundles.exec_command",
        side_effect=lambda cli, base, args: events.append((cli, base, args)),
    )
    exists = mocker.patch("brickflow.cli.bundles.should_deploy", return_value=True)
    return events, synth, command, exists


@pytest.mark.parametrize(
    "project,use_project_name,target",
    [
        ("analytics", "true", "analytics-dev"),
        ("analytics", "false", "dev"),
        (None, "true", "dev"),
    ],
)
@pytest.mark.parametrize(
    "version,lock_flag", [("0.201.0", "--force"), ("0.203.0", "--force-lock")]
)
def test_deploy_validates_once_with_matching_target_and_existing_flags(
    bundle_lifecycle, monkeypatch, project, use_project_name, target, version, lock_flag
):
    events, synth, _, _ = bundle_lifecycle
    monkeypatch.setattr(ctx, "_current_project", project)
    monkeypatch.setenv(
        BrickflowEnvVars.BRICKFLOW_USE_PROJECT_NAME.value, use_project_name
    )
    monkeypatch.setenv(BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value, version)

    bundle_deploy(
        workflows_dir="synthetic_workflows",
        fail_on_active_runs=True,
        force_acquire_lock=True,
        auto_approve=True,
        debug=True,
    )

    assert events == [
        "setup",
        ("versions", "/synthetic/databricks"),
        "synth",
        ("/synthetic/databricks", "bundle", ["validate", "-t", target]),
        (
            "/synthetic/databricks",
            "bundle",
            [
                "deploy",
                "-t",
                target,
                "--fail-on-active-runs",
                lock_flag,
                "--auto-approve",
                "--debug",
            ],
        ),
    ]
    synth.assert_called_once()
    assert synth.call_args.kwargs["workflows_dir"] == "synthetic_workflows"


def test_validation_failure_prevents_deployment(bundle_lifecycle):
    _, synth, command, _ = bundle_lifecycle
    command.side_effect = ClickException("invalid synthetic bundle")
    with pytest.raises(ClickException, match="invalid synthetic bundle"):
        bundle_deploy(workflows_dir="synthetic_workflows")
    synth.assert_called_once()
    command.assert_called_once_with(
        "/synthetic/databricks", "bundle", ["validate", "-t", "analytics-dev"]
    )


def test_skip_validate_still_synthesizes_and_deploys(bundle_lifecycle):
    events, synth, command, _ = bundle_lifecycle
    bundle_deploy(workflows_dir="synthetic_workflows", skip_validate=True)
    assert events[:3] == ["setup", ("versions", "/synthetic/databricks"), "synth"]
    synth.assert_called_once()
    command.assert_called_once_with(
        "/synthetic/databricks", "bundle", ["deploy", "-t", "analytics-dev"]
    )


def test_no_bundle_skips_validation_and_deployment(bundle_lifecycle):
    _, synth, command, exists = bundle_lifecycle
    exists.return_value = False
    bundle_deploy(workflows_dir="synthetic_workflows")
    synth.assert_called_once()
    command.assert_not_called()


def test_standalone_validation_synthesizes_once_with_project_target(bundle_lifecycle):
    events, synth, command, _ = bundle_lifecycle
    bundle_validate(workflows_dir="synthetic_workflows")
    assert events[:3] == ["setup", ("versions", "/synthetic/databricks"), "synth"]
    synth.assert_called_once()
    command.assert_called_once_with(
        "/synthetic/databricks", "bundle", ["validate", "-t", "analytics-dev"]
    )


class TestBundles:
    @pytest.fixture(autouse=True)
    def mock_cli_setup(self, mocker, monkeypatch):
        mocker.patch("brickflow.cli.bundles.bundle_cli_setup")
        mocker.patch("brickflow.cli.bundles.log_important_versions")
        monkeypatch.setenv(
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value, "/synthetic/databricks"
        )

    @patch("brickflow.cli.bundles.should_deploy", return_value=True)
    @patch("brickflow.cli.bundles.exec_command")
    @patch.dict(
        os.environ, {BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value: "0.203.0"}
    )
    def test_bundle_deploy_new_cli(self, mock_exec_command: Mock, _: Mock):
        mock_exec_command.side_effect = lambda *args, **kwargs: None
        mock_exec_command.return_value = None
        # workflows_dir needed to make the function work due to bundle sync
        bundle_deploy(
            force_acquire_lock=True,
            workflows_dir="somedir",
            debug=True,
            fail_on_active_runs=True,
        )
        bundle_cli = os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value]
        mock_exec_command.assert_called_with(
            bundle_cli,
            "bundle",
            [
                "deploy",
                "-t",
                "local",
                "--fail-on-active-runs",
                "--force-lock",
                "--debug",
            ],
        )
        bundle_destroy(force_acquire_lock=True, workflows_dir="somedir", debug=True)
        bundle_cli = os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value]
        mock_exec_command.assert_called_with(
            bundle_cli,
            "bundle",
            ["destroy", "-t", "local", "--force-lock", "--debug"],
        )

    @patch("brickflow.cli.bundles.should_deploy", return_value=True)
    @patch("brickflow.cli.bundles.exec_command")
    @patch.dict(
        os.environ,
        {
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value: "0.201.0",
            BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value: "databricks",
        },
    )
    def test_bundle_deploy_old_cli(self, mock_exec_command: Mock, _: Mock):
        mock_exec_command.side_effect = lambda *args, **kwargs: None
        mock_exec_command.return_value = None
        # workflows_dir needed to make the function work due to bundle sync
        bundle_deploy(force_acquire_lock=True, workflows_dir="somedir")
        bundle_cli = os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value]
        mock_exec_command.assert_called_with(
            bundle_cli,
            "bundle",
            ["deploy", "-t", "local", "--force"],
        )
        bundle_destroy(force_acquire_lock=True, workflows_dir="somedir")
        bundle_cli = os.environ[BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_EXEC.value]
        mock_exec_command.assert_called_with(
            bundle_cli,
            "bundle",
            ["destroy", "-t", "local", "--force"],
        )

    @patch("brickflow.cli.bundles.exec_command")
    @patch.dict(
        os.environ, {BrickflowEnvVars.BRICKFLOW_BUNDLE_CLI_VERSION.value: "0.203.0"}
    )
    def test_deploy_no_workflows(
        self, mock_exec_command: Mock, caplog: LogCaptureFixture
    ):
        mock_exec_command.side_effect = lambda *args, **kwargs: None
        mock_exec_command.return_value = None

        # Adjusting the log level and propagating it to the root logger to make sure it's captured by caplog
        _ilog.propagate = True
        _ilog.level = logging.WARN

        with caplog.at_level(logging.WARN):
            # running this should not fail but log a warning stating that no bundle has been found
            bundle_deploy(force_acquire_lock=True, workflows_dir="somedir")

        assert "No bundle.yml found, skipping deployment." in [
            rec.message for rec in caplog.records
        ]

    @pytest.mark.parametrize(
        "input_arch,expected_arch",
        [
            ("x86_64", "amd64"),  # Test one x86_64 variant
            ("amd64", "amd64"),  # Test alternative x86_64 name
            ("i386", "386"),  # Test one 32-bit variant
            ("i686", "386"),  # Test alternative 32-bit name
            ("arm64", "arm64"),  # Test one ARM variant
            ("aarch64", "arm64"),  # Test alternative ARM name
            ("X86_64", "amd64"),  # Test case insensitivity
            ("unsupported_arch", None),  # Test unsupported architecture
        ],
    )
    def test_get_arch_mappings(
        self, input_arch: str, expected_arch: Optional[str]
    ) -> None:
        from brickflow.cli.bundles import get_arch

        with patch("platform.machine") as mock_machine:
            mock_machine.return_value = input_arch

            if expected_arch is None:
                with pytest.raises(RuntimeError) as exc_info:
                    get_arch()
                assert f"Unsupported architecture: {input_arch}" in str(exc_info.value)
            else:
                assert get_arch() == expected_arch
