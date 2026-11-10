"""Static checks for the GitHub Actions workflows and Dependabot configuration.

Most tests read the YAML files only. The publication readiness step is also
executed as written, under bash, with a local mock ``gh`` that records each
call and serves canned API responses. No credential is used and no network
service is contacted.
"""

import json
import re
import shutil
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
    assert readiness["timeout-minutes"] == 5
    assert "secrets." not in json.dumps(readiness)
    assert [step["name"] for step in _steps(readiness)] == [
        "Check publication readiness"
    ]
    env = _readiness_step()["env"]
    assert env["EXPECTED_REPOSITORY"] == PUBLISHING_REPOSITORY
    assert env["EXPECTED_TAG_RULE"] == "v*"
    assert env["GH_TOKEN"] == "${{ github.token }}"


def test_trigger_set_is_unchanged() -> None:
    triggers = _triggers(_load(BUILD_WORKFLOW))
    assert triggers == {
        "pull_request": {"types": ["opened", "synchronize"]},
        "push": {"branches": ["main"]},
        "release": {"types": ["published"]},
    }


# The readiness step is executed as written in the workflow: its ``run``
# script runs under bash with the step's own ``env`` (expressions replaced by
# test values), and ``gh`` is a local mock that records every invocation and
# serves canned responses. Nothing contacts GitHub.

ENV_ENDPOINT = f"repos/{PUBLISHING_REPOSITORY}/environments/pypi"
RULES_ENDPOINT = f"{ENV_ENDPOINT}/deployment-branch-policies"
GH_PREFIX = [
    "api",
    "--method",
    "GET",
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
]
MOCK_TOKEN = "mock-workflow-token"

MOCK_GH = """
import json
import os
import sys
import time

args = sys.argv[1:]
with open(os.environ["MOCK_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({
        "args": args,
        "token": os.environ.get("GH_TOKEN"),
        "prompt_disabled": os.environ.get("GH_PROMPT_DISABLED"),
    }) + "\\n")
with open(os.environ["MOCK_GH_CONFIG"], encoding="utf-8") as handle:
    responses = json.load(handle)
missing = {
    "status": 1,
    "stdout": '{"message": "Not Found", "status": "404"}',
    "stderr": "gh: Not Found (HTTP 404)",
}
response = responses.get(args[-1] if args else "", missing)
time.sleep(response.get("sleep", 0))
sys.stdout.write(response.get("stdout", ""))
sys.stderr.write(response.get("stderr", ""))
sys.exit(response.get("status", 0))
"""

READY_ENVIRONMENT: Dict[str, Any] = {
    "id": 1,
    "name": "pypi",
    "protection_rules": [
        {
            "id": 10,
            "type": "required_reviewers",
            "prevent_self_review": True,
            "reviewers": [
                {"type": "User", "reviewer": {"id": 101, "login": "maintainer"}},
                {"type": "Team", "reviewer": {"id": 202, "slug": "release"}},
            ],
        },
        {"id": 11, "type": "branch_policy"},
    ],
    "deployment_branch_policy": {
        "protected_branches": False,
        "custom_branch_policies": True,
    },
}

READY_CONTEXT = {
    "github.token": MOCK_TOKEN,
    "github.repository": PUBLISHING_REPOSITORY,
    "github.event_name": "release",
    "github.event.action": "published",
    "github.ref": "refs/tags/v2.1.0",
    "vars.PYPI_TRUSTED_PUBLISHING": "ready",
}

_EXPRESSION = re.compile(r"^\$\{\{ ([A-Za-z0-9_.]+) \}\}$")


def _readiness_step() -> Dict[str, Any]:
    steps = _steps(_build_jobs()["publication-readiness"])
    matches = [
        step for step in steps if step.get("name") == "Check publication readiness"
    ]
    assert len(matches) == 1
    return matches[0]


def _rule(name: str, kind: str = "tag", rule_id: int = 1) -> Dict[str, Any]:
    return {"id": rule_id, "node_id": f"node{rule_id}", "name": name, "type": kind}


def _rules_page(page: int) -> str:
    return f"{RULES_ENDPOINT}?per_page=100&page={page}"


def _ok(body: Any) -> Dict[str, Any]:
    return {"status": 0, "stdout": body if isinstance(body, str) else json.dumps(body)}


def _rules_body(rules: List[Dict[str, Any]], total: Optional[int] = None) -> Any:
    return {
        "total_count": len(rules) if total is None else total,
        "branch_policies": rules,
    }


def _ready_responses(**changes: Any) -> Dict[str, Any]:
    responses: Dict[str, Any] = {
        ENV_ENDPOINT: _ok(READY_ENVIRONMENT),
        _rules_page(1): _ok(_rules_body([_rule("v*")])),
    }
    responses.update(changes)
    return responses


def _step_env(context: Dict[str, str]) -> Dict[str, str]:
    env = {}
    for key, value in _readiness_step()["env"].items():
        text = str(value)
        expression = _EXPRESSION.match(text)
        if expression:
            env[key] = context[expression.group(1)]
        else:
            assert "${{" not in text, (key, text)
            env[key] = text
    return env


class ReadinessRun:
    def __init__(self, result: "subprocess.CompletedProcess[str]", log: Path) -> None:
        self.returncode = result.returncode
        self.output = result.stdout + result.stderr
        records = log.read_text().splitlines() if log.exists() else []
        self.records = [json.loads(line) for line in records]
        self.endpoints = [record["args"][-1] for record in self.records]


def _run_step(
    tmp_path: Path,
    responses: Dict[str, Any],
    context: Optional[Dict[str, str]] = None,
    env_overrides: Optional[Dict[str, str]] = None,
    with_gh: bool = True,
) -> ReadinessRun:
    bin_dir = tmp_path / "bin"
    for directory in ("bin", "home", "tmp", "runner"):
        (tmp_path / directory).mkdir()
    python = bin_dir / "python3"
    python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    python.chmod(0o755)
    if with_gh:
        mock = tmp_path / "mock_gh.py"
        mock.write_text(MOCK_GH)
        gh = bin_dir / "gh"
        gh.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{mock}" "$@"\n')
        gh.chmod(0o755)
    config = tmp_path / "responses.json"
    config.write_text(json.dumps(responses))
    log = tmp_path / "gh-calls.jsonl"
    script = tmp_path / "step.sh"
    script.write_text(_readiness_step()["run"])

    env = _step_env(dict(READY_CONTEXT, **(context or {})))
    env.update(env_overrides or {})
    env.update(
        {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "HOME": str(tmp_path / "home"),
            "TMPDIR": str(tmp_path / "tmp"),
            "RUNNER_TEMP": str(tmp_path / "runner"),
            "MOCK_GH_CONFIG": str(config),
            "MOCK_GH_LOG": str(log),
        }
    )
    # GitHub runs bash steps as: bash --noprofile --norc -eo pipefail {0}
    result = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=env,
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return ReadinessRun(result, log)


def _assert_not_ready(run: ReadinessRun, reason: str) -> None:
    assert run.returncode == 1, run.output
    assert "nothing will be uploaded" in run.output
    assert reason in run.output, run.output


def test_readiness_step_passes_with_verified_settings(tmp_path: Path) -> None:
    run = _run_step(tmp_path, _ready_responses())
    assert run.returncode == 0, run.output
    assert "All publication prerequisites" in run.output
    assert [record["args"] for record in run.records] == [
        GH_PREFIX + [ENV_ENDPOINT],
        GH_PREFIX + [_rules_page(1)],
    ]
    for record in run.records:
        # The token reaches gh through the environment, never the command line.
        assert record["token"] == MOCK_TOKEN
        assert record["prompt_disabled"] == "1"
        assert MOCK_TOKEN not in json.dumps(record["args"])


@pytest.mark.parametrize(
    "tag", ["v2.1.0", "v0.0.1", "v10.20.30", "v2.1.0rc1", "v3.0.0a0"]
)
def test_readiness_accepts_release_tags(tmp_path: Path, tag: str) -> None:
    run = _run_step(tmp_path, _ready_responses(), {"github.ref": f"refs/tags/{tag}"})
    assert run.returncode == 0, run.output


@pytest.mark.parametrize(
    "ref, reason",
    [
        ("refs/heads/main", "the release ref is not a tag"),
        ("refs/tags/2.1.0", "is not a release tag"),
        ("refs/tags/v2.1", "is not a release tag"),
        ("refs/tags/v2.1.0-dirty", "is not a release tag"),
        ("refs/tags/v02.1.0", "is not a release tag"),
        ("refs/tags/v2.1.0.post1", "is not a release tag"),
        ("refs/tags/v2.1.0rc", "is not a release tag"),
        ("refs/tags/unreviewed", "is not a release tag"),
        ("refs/tags/release/v2.1.0", "is not allowed by the tag rule v*"),
        ("refs/tags/v２.1.0", "is not a release tag"),
    ],
)
def test_readiness_rejects_other_refs(tmp_path: Path, ref: str, reason: str) -> None:
    run = _run_step(tmp_path, _ready_responses(), {"github.ref": ref})
    _assert_not_ready(run, reason)


@pytest.mark.parametrize(
    "context, reason",
    [
        (
            {"github.repository": "1solomonwakhungu/brickflow"},
            "is not the publishing repository",
        ),
        ({"vars.PYPI_TRUSTED_PUBLISHING": ""}, "PYPI_TRUSTED_PUBLISHING"),
        ({"vars.PYPI_TRUSTED_PUBLISHING": "true"}, "PYPI_TRUSTED_PUBLISHING"),
        ({"github.event_name": "push"}, "published release"),
        ({"github.event.action": "created"}, "published release"),
    ],
)
def test_readiness_rejects_event_gates(
    tmp_path: Path, context: Dict[str, str], reason: str
) -> None:
    _assert_not_ready(_run_step(tmp_path, _ready_responses(), context), reason)


def test_readiness_reads_the_running_repository(tmp_path: Path) -> None:
    fork = "1solomonwakhungu/brickflow"
    run = _run_step(tmp_path, _ready_responses(), {"github.repository": fork})
    _assert_not_ready(run, "is not the publishing repository")
    assert run.endpoints == [f"repos/{fork}/environments/pypi"]
    assert "could not be read: GET repos/1solomonwakhungu" in run.output


def test_readiness_rejects_malformed_repository_without_api_calls(
    tmp_path: Path,
) -> None:
    run = _run_step(tmp_path, _ready_responses(), {"github.repository": "a/b/../c"})
    _assert_not_ready(run, "repository name 'a/b/../c' is malformed")
    assert run.records == []


@pytest.mark.parametrize(
    "response, reason",
    [
        (
            {"status": 1, "stdout": json.dumps(READY_ENVIRONMENT)},
            "failed with exit status 1",
        ),
        (
            {
                "status": 4,
                "stdout": json.dumps(READY_ENVIRONMENT),
                "stderr": "HTTP 403",
            },
            "failed with exit status 4: HTTP 403",
        ),
        (_ok(""), "returned an empty response"),
        (_ok("{"), "returned malformed JSON"),
        (_ok("null"), "the API did not return environment 'pypi'"),
        (_ok("[]"), "the API did not return environment 'pypi'"),
        (_ok({"message": "Not Found"}), "the API did not return environment 'pypi'"),
        (_ok(dict(READY_ENVIRONMENT, name="pypi-test")), "did not return environment"),
        (_ok("x" * (1024 * 1024 + 1)), "returned more than 1048576 bytes"),
    ],
)
def test_readiness_environment_lookup_fails_closed(
    tmp_path: Path, response: Dict[str, Any], reason: str
) -> None:
    run = _run_step(tmp_path, _ready_responses(**{ENV_ENDPOINT: response}))
    _assert_not_ready(run, reason)
    assert run.endpoints == [ENV_ENDPOINT]


def test_readiness_missing_environment_fails(tmp_path: Path) -> None:
    run = _run_step(tmp_path, {})
    _assert_not_ready(run, "failed with exit status 1: gh: Not Found (HTTP 404)")
    assert run.endpoints == [ENV_ENDPOINT]


def test_readiness_api_call_times_out(tmp_path: Path) -> None:
    slow = dict(_ok(READY_ENVIRONMENT), sleep=5)
    run = _run_step(
        tmp_path,
        _ready_responses(**{ENV_ENDPOINT: slow}),
        env_overrides={"API_CALL_TIMEOUT_SECONDS": "1"},
    )
    _assert_not_ready(run, f"GET {ENV_ENDPOINT} timed out")


def test_readiness_without_gh_fails(tmp_path: Path) -> None:
    if shutil.which("gh", path="/usr/bin:/bin"):
        pytest.skip("a system gh is on the restricted PATH")
    run = _run_step(tmp_path, _ready_responses(), with_gh=False)
    _assert_not_ready(run, "could not run gh")


@pytest.mark.parametrize("value", ["0", "61", "", "1.5", "٣٠", "abc"])
def test_readiness_rejects_bad_timeout_settings(tmp_path: Path, value: str) -> None:
    run = _run_step(
        tmp_path, _ready_responses(), env_overrides={"API_CALL_TIMEOUT_SECONDS": value}
    )
    assert run.returncode != 0, run.output
    assert "API_CALL_TIMEOUT_SECONDS must be" in run.output
    assert run.records == []


def _environment(**changes: Any) -> Dict[str, Any]:
    return dict(READY_ENVIRONMENT, **changes)


def _reviewers(*entries: Any) -> List[Dict[str, Any]]:
    return [{"id": 10, "type": "required_reviewers", "reviewers": list(entries)}]


USER = {"type": "User", "reviewer": {"id": 101}}


@pytest.mark.parametrize(
    "environment, reason",
    [
        (
            _environment(
                protection_rules=_reviewers({"type": "User", "reviewer": {"id": 0}})
            ),
            "malformed required reviewer",
        ),
        (_environment(protection_rules=[]), "no required reviewers rule"),
        (_environment(protection_rules=None), "malformed protection rules"),
        (_environment(protection_rules="required"), "malformed protection rules"),
        (_environment(protection_rules=[{"id": 1}]), "malformed protection rules"),
        (
            _environment(
                protection_rules=[
                    {
                        "id": 1,
                        "type": "wait_timer",
                        "wait_timer": 5,
                        "reviewers": [USER],
                    }
                ]
            ),
            "no required reviewers rule",
        ),
        (
            _environment(protection_rules=[{"id": 1, "type": "branch_policy"}]),
            "no required reviewers rule",
        ),
        (_environment(protection_rules=_reviewers()), "rule with no reviewers"),
        (
            _environment(protection_rules=[{"id": 1, "type": "required_reviewers"}]),
            "rule with no reviewers",
        ),
        (_environment(protection_rules=_reviewers({})), "malformed required reviewer"),
        (
            _environment(protection_rules=_reviewers({"type": "User"})),
            "malformed required reviewer",
        ),
        (
            _environment(
                protection_rules=_reviewers({"type": "Bot", "reviewer": {"id": 1}})
            ),
            "malformed required reviewer",
        ),
        (
            _environment(
                protection_rules=_reviewers({"type": "User", "reviewer": {"id": True}})
            ),
            "malformed required reviewer",
        ),
        (
            _environment(
                protection_rules=_reviewers({"type": "User", "reviewer": {"id": "1"}})
            ),
            "malformed required reviewer",
        ),
        (
            _environment(protection_rules=_reviewers(USER, "maintainer")),
            "malformed required reviewer",
        ),
    ],
)
def test_readiness_requires_valid_reviewers(
    tmp_path: Path, environment: Dict[str, Any], reason: str
) -> None:
    run = _run_step(tmp_path, _ready_responses(**{ENV_ENDPOINT: _ok(environment)}))
    _assert_not_ready(run, reason)
    # Reviewer problems are reported alongside, not instead of, the rule check.
    assert run.endpoints == [ENV_ENDPOINT, _rules_page(1)]


@pytest.mark.parametrize(
    "policy, reason",
    [
        (None, "allows deployments from every branch and tag"),
        (
            {"protected_branches": True, "custom_branch_policies": False},
            "does not limit deployments to selected tags",
        ),
        (
            {"protected_branches": False, "custom_branch_policies": False},
            "does not limit deployments to selected tags",
        ),
        (
            {"protected_branches": True, "custom_branch_policies": True},
            "does not limit deployments to selected tags",
        ),
        ({"protected_branches": False}, "malformed deployment policy"),
        (
            {"protected_branches": 0, "custom_branch_policies": 1},
            "malformed deployment policy",
        ),
        ("custom", "malformed deployment policy"),
    ],
)
def test_readiness_requires_selected_tag_mode(
    tmp_path: Path, policy: Any, reason: str
) -> None:
    environment = _environment(deployment_branch_policy=policy)
    run = _run_step(tmp_path, _ready_responses(**{ENV_ENDPOINT: _ok(environment)}))
    _assert_not_ready(run, reason)
    assert run.endpoints == [ENV_ENDPOINT]


@pytest.mark.parametrize(
    "rules, reason",
    [
        ([], "tag rules are [], expected exactly [v*]"),
        ([_rule("*")], "tag rules are [*], expected exactly [v*]"),
        ([_rule("v2.*")], "tag rules are [v2.*], expected exactly [v*]"),
        (
            [_rule("v*"), _rule("unreviewed", rule_id=2)],
            "tag rules are [unreviewed, v*], expected exactly [v*]",
        ),
        ([_rule("v*"), _rule("v*", rule_id=2)], "expected exactly [v*]"),
        (
            [_rule("v*"), _rule("main", "branch", 2)],
            "allows deployments from branches matching main",
        ),
        ([_rule("v*", "branch")], "allows deployments from branches matching v*"),
        ([{"id": 1, "name": "v*"}], "malformed deployment rule"),
        ([_rule("v*", "Tag")], "malformed deployment rule"),
        ([_rule("")], "malformed deployment rule"),
        ([{"id": 1, "name": None, "type": "tag"}], "malformed deployment rule"),
        (["v*"], "malformed deployment rule"),
    ],
)
def test_readiness_requires_exact_tag_rule(
    tmp_path: Path, rules: List[Any], reason: str
) -> None:
    responses = _ready_responses(**{_rules_page(1): _ok(_rules_body(rules))})
    _assert_not_ready(_run_step(tmp_path, responses), reason)


@pytest.mark.parametrize(
    "response, reason",
    [
        (
            {"status": 1, "stdout": json.dumps(_rules_body([_rule("v*")]))},
            "failed with exit status 1",
        ),
        (_ok(""), "returned an empty response"),
        (_ok("not json"), "returned malformed JSON"),
        (_ok([_rule("v*")]), "page 1 is malformed"),
        (_ok({"branch_policies": [_rule("v*")]}), "page 1 is malformed"),
        (_ok({"total_count": "1", "branch_policies": []}), "page 1 is malformed"),
        (_ok({"total_count": -1, "branch_policies": []}), "page 1 is malformed"),
        (_ok({"total_count": True, "branch_policies": []}), "page 1 is malformed"),
        (_ok({"total_count": 1, "branch_policies": None}), "page 1 is malformed"),
        (
            _ok(_rules_body([_rule("v*")], total=2)),
            "read 1 deployment rules, expected 2",
        ),
        (
            _ok(_rules_body([_rule("v*"), _rule("w*", rule_id=2)], total=1)),
            "read 2 deployment rules, expected 1",
        ),
    ],
)
def test_readiness_rule_lookup_fails_closed(
    tmp_path: Path, response: Dict[str, Any], reason: str
) -> None:
    run = _run_step(tmp_path, _ready_responses(**{_rules_page(1): response}))
    _assert_not_ready(run, "deployment rules of environment 'pypi' could not be read")
    assert reason in run.output, run.output


def _full_page(start: int, count: int = 100) -> List[Dict[str, Any]]:
    return [
        _rule(f"b{index}", "branch", index) for index in range(start, start + count)
    ]


def test_readiness_reads_every_rule_page(tmp_path: Path) -> None:
    first = [_rule("v*")] + _full_page(2, 99)
    responses = _ready_responses(
        **{
            _rules_page(1): _ok(_rules_body(first, total=101)),
            _rules_page(2): _ok(_rules_body([_rule("main", "branch", 500)], total=101)),
        }
    )
    run = _run_step(tmp_path, responses)
    _assert_not_ready(run, "allows deployments from branches matching")
    assert "main" in run.output
    assert [record["args"] for record in run.records] == [
        GH_PREFIX + [ENV_ENDPOINT],
        GH_PREFIX + [_rules_page(1)],
        GH_PREFIX + [_rules_page(2)],
    ]


@pytest.mark.parametrize(
    "second_page, reason",
    [
        (_ok(_rules_body([], total=101)), "read 100 deployment rules, expected 101"),
        (
            _ok(_rules_body([_rule("x", "branch", 900)], total=102)),
            "changed while they were read",
        ),
        ({"status": 1, "stdout": "{}"}, "failed with exit status 1"),
    ],
)
def test_readiness_rejects_incomplete_pagination(
    tmp_path: Path, second_page: Dict[str, Any], reason: str
) -> None:
    responses = _ready_responses(
        **{
            _rules_page(1): _ok(_rules_body(_full_page(1), total=101)),
            _rules_page(2): second_page,
        }
    )
    run = _run_step(tmp_path, responses)
    _assert_not_ready(run, reason)
    assert run.endpoints == [ENV_ENDPOINT, _rules_page(1), _rules_page(2)]


def test_readiness_bounds_rule_pages(tmp_path: Path) -> None:
    responses = _ready_responses(
        **{
            _rules_page(page): _ok(_rules_body(_full_page(page * 100), total=500))
            for page in range(1, 7)
        }
    )
    run = _run_step(tmp_path, responses)
    _assert_not_ready(run, "allows deployments from branches matching")
    assert run.endpoints == [ENV_ENDPOINT] + [_rules_page(page) for page in range(1, 6)]


def test_readiness_refuses_oversized_rule_lists(tmp_path: Path) -> None:
    responses = _ready_responses(
        **{_rules_page(1): _ok(_rules_body(_full_page(1), total=501))}
    )
    run = _run_step(tmp_path, responses)
    _assert_not_ready(run, "more than 500 deployment rules")
    assert run.endpoints == [ENV_ENDPOINT, _rules_page(1)]


def test_readiness_reports_every_problem(tmp_path: Path) -> None:
    context = {
        "github.repository": "1solomonwakhungu/brickflow",
        "vars.PYPI_TRUSTED_PUBLISHING": "",
        "github.ref": "refs/tags/latest",
    }
    run = _run_step(tmp_path, {}, context)
    _assert_not_ready(run, "is not the publishing repository")
    assert "PYPI_TRUSTED_PUBLISHING" in run.output
    assert "is not a release tag" in run.output
    assert "environment 'pypi' could not be read" in run.output


def test_publish_gates_are_all_rechecked_by_readiness() -> None:
    """Each clause of the publish condition has a failing readiness case above."""
    condition = _build_jobs()["publish-pypi"]["if"]
    clauses = {part.strip() for part in condition.split("&&")}
    assert clauses == {
        "github.event_name == 'release'",
        "github.event.action == 'published'",
        "github.repository == 'Nike-Inc/brickflow'",
        "startsWith(github.ref, 'refs/tags/')",
        "vars.PYPI_TRUSTED_PUBLISHING == 'ready'",
    }
    expressions = set(_readiness_step()["env"].values())
    for expression in (
        "${{ github.event_name }}",
        "${{ github.event.action }}",
        "${{ github.repository }}",
        "${{ github.ref }}",
        "${{ vars.PYPI_TRUSTED_PUBLISHING }}",
    ):
        assert expression in expressions


def test_dependabot_configuration() -> None:
    config = _load(DEPENDABOT)
    assert config["version"] == 2
    updates = {entry["package-ecosystem"]: entry for entry in config["updates"]}
    assert updates["github-actions"]["directory"] == "/"
    assert "open-pull-requests-limit" not in updates["github-actions"]
    assert updates["docker"]["directory"] == "/"
    # Python version updates stay off; the lockfile is maintained deliberately.
    assert updates["pip"]["open-pull-requests-limit"] == 0


# The build job's certificate bundle step is executed as written, against a
# throwaway virtual environment holding a stand-in certifi package.

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _certifi_step() -> Dict[str, Any]:
    steps = _steps(_build_jobs()["build-distributions"])
    matches = [
        step
        for step in steps
        if step.get("name") == "Check build tool certificate bundle"
    ]
    assert len(matches) == 1
    return matches[0]


def _run_certifi_step(
    tmp_path: Path,
    version: Optional[str],
    bundle: Optional[str] = PEM,
    where: Optional[str] = None,
) -> "subprocess.CompletedProcess[str]":
    tools = tmp_path / "build-tools"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(tools)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    site = subprocess.run(
        [
            str(tools / "bin" / "python"),
            "-I",
            "-c",
            "import site; print(site.getsitepackages()[0])",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()
    if version is not None:
        package = Path(site) / "certifi"
        package.mkdir()
        if bundle is not None:
            (package / "cacert.pem").write_text(bundle)
        location = (
            repr(where)
            if where
            else "os.path.join(os.path.dirname(__file__), 'cacert.pem')"
        )
        (package / "__init__.py").write_text(
            f"import os\n__version__ = {version!r}\n\ndef where():\n    return {location}\n"
        )
    step = _certifi_step()
    assert "/tmp/build-tools/bin/python -I -" in step["run"]
    script = tmp_path / "step.sh"
    script.write_text(step["run"].replace("/tmp/build-tools", str(tools)))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    env.update({key: str(value) for key, value in step["env"].items()})
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=env,
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_build_tools_require_the_certifi_floor() -> None:
    install = next(
        step["run"]
        for step in _steps(_build_jobs()["build-distributions"])
        if step.get("name") == "Install build tools"
    )
    floor = _certifi_step()["env"]["CERTIFI_FLOOR"]
    assert floor == "2026.10.18"
    assert f'"certifi>={floor}"' in install


@pytest.mark.parametrize("version", ["2026.10.18", "2026.10.23", "2027.1.5"])
def test_certifi_step_accepts_current_bundle(tmp_path: Path, version: str) -> None:
    result = _run_certifi_step(tmp_path, version)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"certifi {version}, bundle {tmp_path}" in result.stdout.replace(
        str(tmp_path.resolve()), str(tmp_path)
    )


@pytest.mark.parametrize(
    "version, bundle, where, reason",
    [
        (None, PEM, None, "certifi is not installed"),
        ("2025.1.31", PEM, None, "older than 2026.10.18"),
        ("2026.10.17", PEM, None, "older than 2026.10.18"),
        ("latest", PEM, None, "unexpected certifi version"),
        ("2026.10.18.post1", PEM, None, "unexpected certifi version"),
        ("2026.10.18", "", None, "does not contain a PEM certificate"),
        ("2026.10.18", "not a bundle", None, "does not contain a PEM certificate"),
        ("2026.10.18", PEM, "/etc/hosts", "is outside the build tool environment"),
    ],
)
def test_certifi_step_rejects_bad_environments(
    tmp_path: Path,
    version: Optional[str],
    bundle: Optional[str],
    where: Optional[str],
    reason: str,
) -> None:
    result = _run_certifi_step(tmp_path, version, bundle, where)
    assert result.returncode != 0, result.stdout
    assert reason in result.stderr, result.stderr
