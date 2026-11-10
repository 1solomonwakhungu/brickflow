import copy
from pathlib import Path
from typing import List
from unittest import mock

import pluggy
import pytest
import toml

from brickflow.engine.task import get_brickflow_tasks_hook, get_plugin_manager


def assert_plugin_manager(
    pm: pluggy.PluginManager, expected_plugins: List[str]
) -> None:
    num_expected_plugins = len(expected_plugins)
    assert (
        len(pm.get_plugins()) == num_expected_plugins
    ), f"import error should only {num_expected_plugins} plugins"
    for plugin in expected_plugins:
        assert pm.has_plugin(plugin), f"plugin manager should have {plugin} plugin"

    all_plugins = set([pm.get_name(plugin_impl) for plugin_impl in pm.get_plugins()])
    assert all_plugins == set(
        expected_plugins
    ), f"plugin manager should have {expected_plugins} plugins and nothing more"


class TestBrickflowPlugins:
    def test_plugins_installed(self):
        pm = copy.deepcopy(get_plugin_manager())
        get_brickflow_tasks_hook(pm)
        # After removing the Airflow dependency, only the default plugin is
        # registered by ``brickflow.engine.task.get_plugin_manager``. The
        # previous "airflow-plugin" impl (which unwrapped Airflow BaseOperator
        # return values) has been removed.
        assert_plugin_manager(pm, ["default"])

    def test_plugins_load_plugins_import_error(self):
        with mock.patch("brickflow_plugins.load_plugins") as load_plugins_mock:
            load_plugins_mock.side_effect = ImportError
            pm = copy.deepcopy(get_plugin_manager())
            get_brickflow_tasks_hook(pm)
            assert_plugin_manager(pm, ["default"])

    def test_plugins_ensure_installation_import_error(self):
        with mock.patch("brickflow_plugins.ensure_installation") as load_plugins_mock:
            load_plugins_mock.side_effect = ImportError
            pm = copy.deepcopy(get_plugin_manager())
            get_brickflow_tasks_hook(pm)
            assert_plugin_manager(pm, ["default"])

    @pytest.mark.parametrize(
        "quartz_cron, expected_unix_cron",
        [
            ("0 * * ? * * *", "* * * * *"),
            ("0 */5 * ? * * *", "*/5 * * * *"),
            ("0 30 * ? * * *", "30 * * * *"),
            ("0 0 12 ? * * *", "0 12 * * *"),
            ("0 0 12 ? * 2 *", "0 12 * * 1"),
            ("0 0 0 10 * ? *", "0 0 10 * *"),
            ("0 0 0 1 1 ? *", "0 0 1 1 *"),
            ("0 0/5 14,18 * * ?", "0/5 14,18 * * *"),
            ("0 0 12 ? * 1,2,5-7 *", "0 12 * * 0,1,4-6"),
            ("0 0 12 ? * SUN,MON,THU-SAT *", "0 12 * * SUN,MON,THU-SAT"),
        ],
    )
    def test_cron_conversion(self, quartz_cron, expected_unix_cron):
        import brickflow_plugins._timing.cronhelper as cronhelper  # noqa

        converted_unix_cron = cronhelper.cron_helper.quartz_to_unix(quartz_cron)
        converted_quartz_cron = cronhelper.cron_helper.unix_to_quartz(
            converted_unix_cron
        )
        converted_unix_cron_second = cronhelper.cron_helper.quartz_to_unix(
            converted_quartz_cron
        )

        assert (
            converted_unix_cron == converted_unix_cron_second
        ), "cron conversion should be idempotent"
        assert converted_unix_cron == expected_unix_cron

    @pytest.mark.parametrize(
        "quartz_cron",
        [
            "0 0 12 ? * L *",
            "0 0 12 ? * 1L *",
            "0 0 12 ? * 1W *",
            "0 0 12 ? * 1#5 *",
        ],
    )
    def test_unsupported_cron_expressions(self, quartz_cron):
        import brickflow_plugins._timing.cronhelper as cronhelper  # noqa

        with pytest.raises(ValueError):
            cronhelper.cron_helper.quartz_to_unix(quartz_cron)

    def test_plugins_dependency_versions(self):
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        from brickflow import BrickflowProjectDeploymentSettings
        from brickflow.engine.task import get_brickflow_libraries

        settings = BrickflowProjectDeploymentSettings()
        settings.brickflow_project_runtime_version = "1.0.0"

        root = Path(__file__).parent.parent
        with open(str(root / "poetry.lock"), "r", encoding="utf-8") as f:
            lock = toml.load(f)
        with open(str(root / "pyproject.toml"), "r", encoding="utf-8") as f:
            constraints = toml.load(f)["tool"]["poetry"]["dependencies"]

        def python_spec(value: str) -> SpecifierSet:
            return SpecifierSet("" if value.strip() == "*" else value)

        locked = {}
        for lib in lock.get("package", []):
            locked.setdefault(lib["name"], []).append(
                (
                    lib["version"],
                    python_spec(lib.get("python-versions", "*")),
                )
            )

        def locked_version(name: str, python: str) -> str:
            """Return the lock entry an install on ``python`` resolves for ``name``."""
            candidates = [
                version for version, pythons in locked[name] if pythons.contains(python)
            ]
            constraint = constraints.get(name)
            if isinstance(constraint, list):
                (selected,) = [
                    item
                    for item in constraint
                    if SpecifierSet(item["python"]).contains(python)
                ]
                versions = SpecifierSet(selected["version"])
                candidates = [v for v in candidates if versions.contains(v)]
            assert len(candidates) == 1, f"{name} on {python}: {candidates}"
            return candidates[0]

        # Libraries used for plugins are installed on clusters and must match the
        # versions poetry.lock resolves for each supported Python version.
        # NOTE: ``apache-airflow`` was previously included here; it has been
        # removed along with the Airflow dependency.
        requirements = [
            Requirement(lib.package)
            for lib in get_brickflow_libraries(enable_plugins=True)
            if not lib.package.startswith("brickflows")
        ]
        names = {req.name for req in requirements}
        for python in ("3.9", "3.10", "3.11", "3.12"):
            env = {"python_version": python, "python_full_version": f"{python}.0"}
            active = [
                req
                for req in requirements
                if req.marker is None or req.marker.evaluate(env)
            ]
            assert sorted(req.name for req in active) == sorted(names), python
            for req in active:
                (spec,) = list(req.specifier)
                assert spec.operator == "==", req
                expected = locked_version(req.name, python)
                assert Version(spec.version) == Version(expected), (
                    f"Version mismatch for {req.name} on Python {python}: "
                    f"expected {expected}, got {spec.version}"
                )

    def test_plugins_dependency_versions_installed(self):
        """The pins for this interpreter match the installed dev environment."""
        from importlib import metadata

        from packaging.requirements import Requirement

        from brickflow.engine.task import get_brickflow_libraries

        for lib in get_brickflow_libraries(enable_plugins=True):
            if lib.package.startswith("brickflows"):
                continue
            req = Requirement(lib.package)
            if req.marker is not None and not req.marker.evaluate():
                continue
            try:
                installed = metadata.version(req.name)
            except metadata.PackageNotFoundError:
                pytest.skip(f"{req.name} is not installed")
            assert req.specifier.contains(
                installed, prereleases=True
            ), f"{req.name}: installed {installed}, cluster pin {req.specifier}"
