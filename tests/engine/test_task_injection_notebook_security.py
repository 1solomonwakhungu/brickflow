"""Containment regressions for injected-task names and generated notebooks."""

import os
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from brickflow.engine.project import _Project
from brickflow.engine.task import TaskType
from brickflow.engine.task_executor import GenericTaskExecutor
from brickflow.engine.task_injection_config import (
    TaskDefinition,
    TaskInjectionConfig,
    validate_task_name,
)
from brickflow.engine.workflow import Workflow

NOTEBOOKS = "_brickflow_injected_notebooks"

VALID_NAMES = [
    "a",
    "etl_task",
    "compliance-check",
    "Task_01-x",
    "_leading_underscore",
    "1",
    "x" * 100,
]

INVALID_NAMES = [
    "",
    ".",
    "..",
    "../escaped-notebook",
    "../../escaped-notebook",
    "a/b",
    "a\\b",
    "/abs/path",
    "C:task",
    "x" * 101,
    "has space",
    "trailing\n",
    "dot.name",
    "café",
    "nul\x00byte",
]


@pytest.fixture(name="project_dir")
def project_directory_fixture(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return project


@pytest.fixture(name="template")
def template_fixture(tmp_path) -> Path:
    path = tmp_path / "template.py.j2"
    path.write_text("print('{{ greeting }}')\n")
    return path


def _executor(name: str, template: Path) -> GenericTaskExecutor:
    return GenericTaskExecutor(
        TaskDefinition(
            task_name=name,
            task_type=TaskType.BRICKFLOW_TASK,
            template_file=str(template),
            template_context={"greeting": "hello"},
        )
    )


def _tree(root: Path) -> List[str]:
    return sorted(
        str(p.relative_to(root)) for p in root.rglob("*") if "home" not in p.parts
    )


class TestTaskNameValidation:
    @pytest.mark.parametrize("name", VALID_NAMES)
    def test_valid_names_accepted(self, name):
        assert validate_task_name(name) == name
        assert TaskDefinition(task_name=name).task_name == name

    @pytest.mark.parametrize("name", INVALID_NAMES)
    def test_invalid_names_rejected(self, name):
        with pytest.raises(ValueError, match="Invalid injected task_name"):
            validate_task_name(name)
        with pytest.raises(ValueError, match="Invalid injected task_name"):
            TaskDefinition(task_name=name)

    @pytest.mark.parametrize("name", [None, 7, ["a"]])
    def test_non_string_rejected(self, name):
        with pytest.raises(ValueError):
            validate_task_name(name)

    def test_yaml_with_traversal_name_rejected(self, tmp_path):
        config = tmp_path / "inject.yaml"
        config.write_text("tasks:\n  - task_name: ../../escaped-notebook\n")
        with pytest.raises(ValueError, match="escaped-notebook"):
            TaskInjectionConfig.from_yaml(str(config))

    def test_yaml_with_valid_names_loads(self, tmp_path):
        config = tmp_path / "inject.yaml"
        config.write_text(
            "tasks:\n  - task_name: etl_task\n  - task_name: data-quality-check\n"
        )
        loaded = TaskInjectionConfig.from_yaml(str(config))
        assert [t.task_name for t in loaded.tasks] == [
            "etl_task",
            "data-quality-check",
        ]


class TestNotebookContainment:
    def test_valid_name_written_inside_directory(self, project_dir, template):
        result = _executor("etl_task", template).render_to_notebook()

        assert result == f"{NOTEBOOKS}/etl_task.py"
        written = project_dir / NOTEBOOKS / "etl_task.py"
        assert written.read_text().startswith("# Databricks notebook source\n\n")
        assert "print('hello')" in written.read_text()
        assert os.listdir(project_dir / NOTEBOOKS) == ["etl_task.py"]

    @pytest.mark.usefixtures("project_dir")
    def test_name_mutated_after_validation_is_rechecked(self, tmp_path, template):
        executor = _executor("etl_task", template)
        executor.task_def.task_name = "../../escaped-notebook"
        before = _tree(tmp_path)

        with pytest.raises(ValueError):
            executor.render_to_notebook()

        assert _tree(tmp_path) == before
        assert not (tmp_path / "escaped-notebook.py").exists()

    def test_symlinked_notebook_directory_refused(
        self, project_dir, tmp_path, template
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (project_dir / NOTEBOOKS).symlink_to(outside, target_is_directory=True)

        with pytest.raises(ValueError, match="real directory"):
            _executor("etl_task", template).render_to_notebook()

        assert not list(outside.iterdir())

    def test_dangling_symlinked_notebook_directory_refused(
        self, project_dir, tmp_path, template
    ):
        target = tmp_path / "not-yet-created"
        (project_dir / NOTEBOOKS).symlink_to(target, target_is_directory=True)

        with pytest.raises(ValueError, match="real directory"):
            _executor("etl_task", template).render_to_notebook()

        assert not target.exists()

    def test_notebook_directory_must_be_directory(self, project_dir, template):
        (project_dir / NOTEBOOKS).write_text("not a directory")
        with pytest.raises((ValueError, OSError)):
            _executor("etl_task", template).render_to_notebook()
        assert (project_dir / NOTEBOOKS).read_text() == "not a directory"

    def test_preexisting_notebook_symlink_replaced_not_followed(
        self, project_dir, tmp_path, template
    ):
        outside = tmp_path / "victim.py"
        outside.write_text("original")
        notebooks = project_dir / NOTEBOOKS
        notebooks.mkdir()
        (notebooks / "etl_task.py").symlink_to(outside)

        _executor("etl_task", template).render_to_notebook()

        assert outside.read_text() == "original"
        generated = notebooks / "etl_task.py"
        assert not generated.is_symlink()
        assert "print('hello')" in generated.read_text()
        assert os.listdir(notebooks) == ["etl_task.py"]

    def test_existing_notebook_regenerated(self, project_dir, template):
        notebooks = project_dir / NOTEBOOKS
        notebooks.mkdir()
        (notebooks / "etl_task.py").write_text("stale")

        _executor("etl_task", template).render_to_notebook()

        assert "print('hello')" in (notebooks / "etl_task.py").read_text()
        assert os.listdir(notebooks) == ["etl_task.py"]

    def test_directory_at_notebook_path_refused(self, project_dir, template):
        notebooks = project_dir / NOTEBOOKS
        (notebooks / "etl_task.py").mkdir(parents=True)

        with pytest.raises(ValueError, match="directory"):
            _executor("etl_task", template).render_to_notebook()

        assert os.listdir(notebooks) == ["etl_task.py"]

    def test_failed_write_leaves_no_temporary_file(self, project_dir, template):
        notebooks = project_dir / NOTEBOOKS
        with patch(
            "brickflow.engine.task_executor.os.replace",
            side_effect=OSError("synthetic replace failure"),
        ):
            with pytest.raises(OSError, match="synthetic"):
                _executor("etl_task", template).render_to_notebook()
        assert os.listdir(notebooks) == []


class TestProjectInjection:
    @pytest.mark.usefixtures("project_dir")
    def test_traversal_name_in_config_fails_without_writing(self, tmp_path, template):
        config = tmp_path / "inject.yaml"
        config.write_text(
            "tasks:\n"
            "  - task_name: ../../escaped-notebook\n"
            "    task_type: BRICKFLOW_TASK\n"
            f"    template_file: {template}\n"
        )
        before = _tree(tmp_path)

        with patch.dict(os.environ, {"BRICKFLOW_INJECT_TASKS_CONFIG": str(config)}):
            project = _Project(
                name="test_project",
                git_repo="https://github.com/test/repo.git",
                provider="github",
                git_reference="main",
            )
            wf = Workflow("test_wf", schedule_quartz_expression="0 0 * * *")
            with pytest.raises(ValueError, match="Invalid injected task_name"):
                project.add_workflow(wf)

        assert _tree(tmp_path) == before


def test_regeneration_preserves_private_permissions(project_dir, template):
    notebooks = project_dir / NOTEBOOKS
    notebooks.mkdir()
    output = notebooks / "private.py"
    output.write_text("old")
    output.chmod(0o600)
    _executor("private", template).render_to_notebook()
    assert output.stat().st_mode & 0o777 == 0o600
    assert "hello" in output.read_text()
