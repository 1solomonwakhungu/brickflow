"""Static checks for the GitHub Actions workflows and Dependabot configuration.

These tests read the YAML files only. They issue no credentials, contact no
service, and run the publication readiness script against local samples.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
BUILD_WORKFLOW = WORKFLOW_DIR / "onpush.yml"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"

PUBLISHING_REPOSITORY = "Nike-Inc/brickflow"
FULL_SHA_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^[A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}$")
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")


def _load(path: Path) -> Dict[Any, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict), path
    return data


def _triggers(workflow: Dict[Any, Any]) -> Dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare key "on" as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    if isinstance(triggers, str):
        return {triggers: None}
    if isinstance(triggers, list):
        return {name: None for name in triggers}
    assert isinstance(triggers, dict)
    return triggers


def _workflow_paths() -> List[Path]:
    paths = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    assert BUILD_WORKFLOW in paths
    return paths


def _all_workflows() -> Iterator[Tuple[Path, Dict[str, Any]]]:
    for path in _workflow_paths():
        yield path, _load(path)


def _steps(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(job.get("steps") or [])


def _build_jobs() -> Dict[str, Any]:
    jobs = _load(BUILD_WORKFLOW)["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def test_no_privileged_triggers() -> None:
    for path, workflow in _all_workflows():
        triggers = _triggers(workflow)
        assert "pull_request_target" not in triggers, path
        assert "workflow_run" not in triggers, path


def test_every_workflow_declares_top_level_permissions() -> None:
    for path, workflow in _all_workflows():
        assert "permissions" in workflow, path
        assert workflow["permissions"] in ({}, {"contents": "read"}), path


def _write_grants(permissions: Any) -> List[str]:
    if permissions is None:
        return []
    if isinstance(permissions, str):
        return [permissions] if permissions != "read-all" else []
    assert isinstance(permissions, dict)
    return [scope for scope, level in permissions.items() if level == "write"]


def test_only_publish_job_has_write_permissions() -> None:
    for path, workflow in _all_workflows():
        assert not _write_grants(workflow.get("permissions")), path
        for name, job in workflow["jobs"].items():
            grants = _write_grants(job.get("permissions"))
            if path == BUILD_WORKFLOW and name == "publish-pypi":
                assert grants == ["id-token"]
            else:
                assert not grants, (path, name, grants)


def test_build_workflow_jobs_declare_permissions() -> None:
    for name, job in _build_jobs().items():
        assert "permissions" in job, name


def test_actions_are_pinned_to_full_commit_shas() -> None:
    for path in _workflow_paths():
        for line in path.read_text(encoding="utf-8").splitlines():
            match = USES_LINE.match(line)
            if not match:
                continue
            reference, rest = match.groups()
            if reference.startswith("./"):
                continue
            assert FULL_SHA_USES.match(reference), (path, reference)
            # The trailing comment names the release the SHA was taken from.
            assert re.match(r"^\s+# v\d+(\.\d+)*\b", rest), (path, line)


def test_checkouts_do_not_persist_credentials() -> None:
    for path, workflow in _all_workflows():
        for name, job in workflow["jobs"].items():
            for step in _steps(job):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert (step.get("with") or {}).get(
                        "persist-credentials"
                    ) is False, (path, name)


def test_build_workflow_containers_are_pinned_by_digest() -> None:
    for name, job in _build_jobs().items():
        container = job.get("container")
        if container is None:
            continue
        image = container["image"] if isinstance(container, dict) else container
        if image == "${{ matrix.image }}":
            matrix = job["strategy"]["matrix"]
            images = {
                entry["python-version"]: entry["image"] for entry in matrix["include"]
            }
            assert set(images) == set(matrix["python-version"]), name
            for version, pinned in images.items():
                assert DIGEST_IMAGE.match(pinned), (name, pinned)
                assert pinned.startswith(f"python:{version}@"), (name, pinned)
        else:
            assert "${{" not in image, (name, image)
            assert DIGEST_IMAGE.match(image), (name, image)


def test_test_matrix_covers_supported_pythons() -> None:
    matrix = _build_jobs()["test-pipeline"]["strategy"]["matrix"]
    assert matrix["python-version"] == ["3.9", "3.10", "3.11", "3.12"]


def test_no_stored_pypi_credentials() -> None:
    for path in _workflow_paths():
        text = path.read_text(encoding="utf-8")
        for name in (
            "PYPI_USERNAME",
            "PYPI_PASSWORD",
            "TWINE_USERNAME",
            "TWINE_PASSWORD",
            "PYPI_API_TOKEN",
        ):
            assert name not in text, (path, name)
        assert "twine upload" not in text, path
    for job in _build_jobs().values():
        for step in _steps(job):
            if str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@"):
                inputs = step.get("with") or {}
                assert not {"user", "password"} & set(inputs)
                assert str(inputs.get("attestations")).lower() == "true"


def test_publish_job_is_gated() -> None:
    jobs = _build_jobs()
    publish = jobs["publish-pypi"]
    assert set(publish["needs"]) == {
        "test-pipeline",
        "build-distributions",
        "publication-readiness",
    }
    assert publish["environment"]["name"] == "pypi"
    assert publish["permissions"] == {"id-token": "write"}
    assert "container" not in publish
    uses = [str(step.get("uses", "")) for step in _steps(publish)]
    assert not any(ref.startswith("actions/checkout@") for ref in uses)
    assert all("run" not in step for step in _steps(publish))
    assert any(ref.startswith("pypa/gh-action-pypi-publish@") for ref in uses)
    assert all("secrets." not in json.dumps(step) for step in _steps(publish))


_CLAUSE_EQ = re.compile(r"^([A-Za-z0-9_.-]+) == '([^']*)'$")
_CLAUSE_STARTS = re.compile(r"^startsWith\(([A-Za-z0-9_.-]+), '([^']*)'\)$")


def _evaluate_conjunction(expression: str, context: Dict[str, str]) -> bool:
    """Evaluate an ``a == 'b' && startsWith(c, 'd')`` job condition.

    Any clause of another form fails the test, so the condition cannot grow
    an unreviewed escape hatch such as ``||``.
    """
    result = True
    for clause in (part.strip() for part in expression.split("&&")):
        equality = _CLAUSE_EQ.match(clause)
        prefix = _CLAUSE_STARTS.match(clause)
        if equality:
            result = result and context.get(equality.group(1), "") == equality.group(2)
        elif prefix:
            result = result and context.get(prefix.group(1), "").startswith(
                prefix.group(2)
            )
        else:
            pytest.fail(f"Unsupported clause in job condition: {clause!r}")
    return result


def _context(
    event: str,
    repository: str,
    ref: str,
    action: str = "",
    flag: str = "",
) -> Dict[str, str]:
    return {
        "github.event_name": event,
        "github.event.action": action,
        "github.repository": repository,
        "github.ref": ref,
        "vars.PYPI_TRUSTED_PUBLISHING": flag,
    }


UPSTREAM_RELEASE = _context(
    "release", PUBLISHING_REPOSITORY, "refs/tags/v2.1.0", "published", "ready"
)


@pytest.mark.parametrize(
    "context, expected",
    [
        (UPSTREAM_RELEASE, True),
        (
            _context(
                "pull_request",
                PUBLISHING_REPOSITORY,
                "refs/pull/1/merge",
                "opened",
                "ready",
            ),
            False,
        ),
        (
            _context(
                "pull_request",
                "someone/brickflow",
                "refs/pull/1/merge",
                "synchronize",
                "ready",
            ),
            False,
        ),
        (
            _context("push", PUBLISHING_REPOSITORY, "refs/heads/main", "", "ready"),
            False,
        ),
        (
            _context(
                "release",
                "1solomonwakhungu/brickflow",
                "refs/tags/v2.1.0",
                "published",
                "ready",
            ),
            False,
        ),
        (
            _context(
                "release", PUBLISHING_REPOSITORY, "refs/tags/v2.1.0", "published", ""
            ),
            False,
        ),
        (
            _context(
                "release",
                PUBLISHING_REPOSITORY,
                "refs/tags/v2.1.0",
                "published",
                "true",
            ),
            False,
        ),
        (
            _context(
                "release", PUBLISHING_REPOSITORY, "refs/tags/v2.1.0", "edited", "ready"
            ),
            False,
        ),
        (
            _context(
                "release",
                PUBLISHING_REPOSITORY,
                "refs/heads/main",
                "published",
                "ready",
            ),
            False,
        ),
    ],
)
def test_publish_condition(context: Dict[str, str], expected: bool) -> None:
    condition = _build_jobs()["publish-pypi"]["if"]
    assert _evaluate_conjunction(condition, context) is expected


def test_readiness_job_runs_only_for_releases_with_read_access() -> None:
    readiness = _build_jobs()["publication-readiness"]
    assert readiness["if"] == "github.event_name == 'release'"
    assert readiness["permissions"] == {"actions": "read"}
    assert "secrets." not in json.dumps(readiness)
    check = _readiness_step()
    assert check["env"]["EXPECTED_REPOSITORY"] == PUBLISHING_REPOSITORY


def test_trigger_set_is_unchanged() -> None:
    triggers = _triggers(_load(BUILD_WORKFLOW))
    assert triggers == {
        "pull_request": {"types": ["opened", "synchronize"]},
        "push": {"branches": ["main"]},
        "release": {"types": ["published"]},
    }


def _readiness_step() -> Dict[str, Any]:
    steps = _steps(_build_jobs()["publication-readiness"])
    matches = [
        step for step in steps if step.get("name") == "Check publication readiness"
    ]
    assert len(matches) == 1
    return matches[0]


def _readiness_script() -> str:
    run = _readiness_step()["run"]
    match = re.search(r"<<'PY'\n(.*?)^PY$", run, re.S | re.M)
    assert match, "readiness script heredoc not found"
    return match.group(1)


READY_ENVIRONMENT: Dict[str, Any] = {
    "name": "pypi",
    "protection_rules": [
        {
            "type": "required_reviewers",
            "prevent_self_review": True,
            "reviewers": [{"type": "User"}],
        },
        {"type": "branch_policy"},
    ],
    "deployment_branch_policy": {
        "protected_branches": False,
        "custom_branch_policies": True,
    },
}

READY_ENV_VARS = {
    "EXPECTED_REPOSITORY": PUBLISHING_REPOSITORY,
    "REPOSITORY": PUBLISHING_REPOSITORY,
    "EVENT_NAME": "release",
    "EVENT_ACTION": "published",
    "GIT_REF": "refs/tags/v2.1.0",
    "READINESS_FLAG": "ready",
}


def _run_readiness(
    tmp_path: Path, overrides: Dict[str, str], environment: Optional[Any]
) -> "subprocess.CompletedProcess[str]":
    response = tmp_path / "pypi-environment.json"
    if environment is not None:
        response.write_text(
            environment if isinstance(environment, str) else json.dumps(environment)
        )
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)}
    env.update(READY_ENV_VARS)
    env.update(overrides)
    return subprocess.run(
        [sys.executable, "-I", "-", str(response)],
        input=_readiness_script(),
        env=env,
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_readiness_passes_only_when_everything_is_verified(tmp_path: Path) -> None:
    result = _run_readiness(tmp_path, {}, READY_ENVIRONMENT)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "overrides, environment, reason",
    [
        (
            {"REPOSITORY": "1solomonwakhungu/brickflow"},
            READY_ENVIRONMENT,
            "is not the publishing repository",
        ),
        ({"READINESS_FLAG": ""}, READY_ENVIRONMENT, "PYPI_TRUSTED_PUBLISHING"),
        ({"READINESS_FLAG": "true"}, READY_ENVIRONMENT, "PYPI_TRUSTED_PUBLISHING"),
        ({"EVENT_NAME": "push"}, READY_ENVIRONMENT, "published release"),
        ({"EVENT_ACTION": "created"}, READY_ENVIRONMENT, "published release"),
        ({"GIT_REF": "refs/heads/main"}, READY_ENVIRONMENT, "not a tag"),
        ({}, None, "does not exist"),
        ({}, "", "does not exist"),
        ({}, {"message": "Not Found", "status": "404"}, "does not exist"),
        ({}, dict(READY_ENVIRONMENT, protection_rules=[]), "no required reviewers"),
        (
            {},
            dict(
                READY_ENVIRONMENT,
                protection_rules=[{"type": "required_reviewers", "reviewers": []}],
            ),
            "no required reviewers",
        ),
        (
            {},
            dict(READY_ENVIRONMENT, deployment_branch_policy=None),
            "every branch and tag",
        ),
    ],
)
def test_readiness_fails_closed(
    tmp_path: Path, overrides: Dict[str, str], environment: Optional[Any], reason: str
) -> None:
    result = _run_readiness(tmp_path, overrides, environment)
    assert result.returncode == 1, result.stdout + result.stderr
    assert reason in result.stdout
    assert "nothing will be uploaded" in result.stdout


def test_dependabot_configuration() -> None:
    config = _load(DEPENDABOT)
    assert config["version"] == 2
    updates = {entry["package-ecosystem"]: entry for entry in config["updates"]}
    assert updates["github-actions"]["directory"] == "/"
    assert "open-pull-requests-limit" not in updates["github-actions"]
    assert updates["docker"]["directory"] == "/"
    # Python version updates stay off; the lockfile is maintained deliberately.
    assert updates["pip"]["open-pull-requests-limit"] == 0
