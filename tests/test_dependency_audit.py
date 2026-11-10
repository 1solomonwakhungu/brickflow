"""Tests for tools/dependency_audit.py.

All advisory traffic goes to a loopback stub; nothing here contacts OSV.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "dependency_audit.py"

_spec = importlib.util.spec_from_file_location("dependency_audit", TOOL_PATH)
assert _spec is not None and _spec.loader is not None
audit = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("dependency_audit", audit)
_spec.loader.exec_module(audit)


# ---------------------------------------------------------------------------
# Fixtures: a tiny project, lockfile and loopback OSV stub
# ---------------------------------------------------------------------------

PYPROJECT = """
[tool.poetry.dependencies]
python = ">=3.9,<3.13"
requests = [
    { version = ">=2.32.4,<3", python = "<3.10" },
    { version = ">=2.33.0,<3", python = ">=3.10" },
]
tableauserverclient = { version = ">=0.25", optional = true }

[tool.poetry.extras]
tableau = ["tableauserverclient"]

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
"""

LOCK = """
[[package]]
name = "requests"
version = "2.32.5"
python-versions = ">=3.9"
files = []

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "requests"
version = "2.34.2"
python-versions = ">=3.10"
files = []

[package.dependencies]
urllib3 = ">=1.26,<3"

[[package]]
name = "urllib3"
version = "1.26.20"
python-versions = ">=2.7"
files = []

[[package]]
name = "urllib3"
version = "2.8.0"
python-versions = ">=3.10"
files = []

[[package]]
name = "tableauserverclient"
version = "0.41"
python-versions = ">=3.9"
files = []

[package.dependencies]
defusedxml = ">=0.7.1"
colorama = { version = "*", markers = "sys_platform == \\"win32\\"" }
docs-only = { version = "*", optional = true }

[package.extras]
docs = ["docs-only (*)"]

[[package]]
name = "defusedxml"
version = "0.7.1"
python-versions = "*"
files = []

[[package]]
name = "colorama"
version = "0.4.6"
python-versions = "*"
files = []

[[package]]
name = "docs-only"
version = "1.0"
python-versions = "*"
files = []

[[package]]
name = "pytest"
version = "7.4.4"
python-versions = ">=3.7"
files = []

[[package]]
name = "orphan"
version = "0.1"
python-versions = "*"
files = []
"""

BASE_POLICY = """
[audit]
python_versions = ["3.9", "3.10"]
platforms = ["linux", "win32"]
blocking_scopes = ["runtime", "extra:*"]
"""


def _advisory(
    advisory_id: str,
    package: str,
    fixed: str,
    aliases: Optional[List[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    body = {
        "id": advisory_id,
        "aliases": aliases or [],
        "summary": f"synthetic advisory {advisory_id}",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }
    body.update(extra)
    return body


class OsvStub:
    def __init__(self) -> None:
        self.hits: Dict[tuple, List[str]] = {}
        self.vulns: Dict[str, Dict[str, Any]] = {}
        self.requests: List[str] = []
        self.delay = 0.0
        self.status = 200
        self.raw_body: Optional[bytes] = None
        self.redirect_to: Optional[str] = None


@contextmanager
def osv_server(stub: OsvStub) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _send(self, payload: bytes, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _common(self) -> bool:
            stub.requests.append(f"{self.command} {self.path}")
            if stub.delay:
                time.sleep(stub.delay)
            if stub.redirect_to:
                self.send_response(302)
                self.send_header("Location", stub.redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True
            if stub.raw_body is not None or stub.status != 200:
                self._send(stub.raw_body or b"{}", stub.status)
                return True
            return False

        def do_POST(self) -> None:  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self._common():
                return
            results = []
            for query in body["queries"]:
                key = (query["package"]["name"], query["version"])
                results.append({"vulns": [{"id": i} for i in stub.hits.get(key, [])]})
            self._send(json.dumps({"results": results}).encode(), 200)

        def do_GET(self) -> None:  # noqa: N802
            if self._common():
                return
            advisory_id = self.path.rsplit("/", 1)[-1]
            if advisory_id not in stub.vulns:
                self._send(b'{"message": "not found"}', 404)
                return
            self._send(json.dumps(stub.vulns[advisory_id]).encode(), 200)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(name="project")
def project_fixture(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(LOCK, encoding="utf-8")
    (tmp_path / "policy.toml").write_text(BASE_POLICY, encoding="utf-8")
    return tmp_path


def _run(project: Path, url: str, *extra: str, policy: Optional[str] = None) -> int:
    if policy is not None:
        (project / "policy.toml").write_text(BASE_POLICY + policy, encoding="utf-8")
    return audit.main(
        [
            "audit",
            "--lock",
            str(project / "poetry.lock"),
            "--pyproject",
            str(project / "pyproject.toml"),
            "--policy",
            str(project / "policy.toml"),
            "--osv-url",
            url,
            "--json-report",
            str(project / "report.json"),
            "--today",
            "2026-11-09",
            "--timeout",
            "2",
            "--deadline",
            "10",
            *extra,
        ]
    )


def _report(project: Path) -> Dict[str, Any]:
    return json.loads((project / "report.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Constraint handling and reachability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "constraint,version,expected",
    [
        ("^0.25", "0.25.3", True),
        ("^0.25", "0.26", False),
        ("^1.2", "1.9", True),
        ("^1.2", "2.0", False),
        ("~1.2", "1.2.9", True),
        ("~1.2", "1.3", False),
        (">=1.25.4,<2.2.0 || >2.2.0,<3", "2.2.0", False),
        (">=1.25.4,<2.2.0 || >2.2.0,<3", "2.8.0", True),
        (">=2.28.2 <3.0.0", "2.32.5", True),
        ("*", "9.9", True),
        ("1.2.3", "1.2.3", True),
        ("3.1", "3.1", True),
    ],
)
def test_poetry_constraints(constraint: str, version: str, expected: bool) -> None:
    assert audit.constraint_allows(constraint, version) is expected


@pytest.mark.parametrize(
    "constraint,python,expected",
    [
        ("<3.10", "3.9", True),
        ("<3.10", "3.10", False),
        (">=3.10", "3.12", True),
        ("!=3.0.*,>=2.7", "3.9", True),
    ],
)
def test_python_constraints(constraint: str, python: str, expected: bool) -> None:
    assert audit.python_allows(constraint, python) is expected


def test_reachability_is_scope_python_and_platform_aware(project: Path) -> None:
    graph = audit.build_graph(
        audit.load_roots(project / "pyproject.toml"),
        audit.load_lock(project / "poetry.lock"),
        ["3.9", "3.10"],
        ["linux", "win32"],
    )
    reach = graph.reach
    assert reach[("urllib3", "1.26.20")].pythons == {"3.9"}
    assert reach[("urllib3", "2.8.0")].pythons == {"3.10"}
    assert reach[("requests", "2.32.5")].pythons == {"3.9"}
    assert reach[("requests", "2.34.2")].scopes == {"runtime"}
    assert reach[("tableauserverclient", "0.41")].scopes == {"extra:tableau"}
    assert reach[("pytest", "7.4.4")].scopes == {"group:dev"}
    assert reach[("colorama", "0.4.6")].platforms == {"win32"}
    # optional dependency of a package is not installed unless its extra is requested
    assert ("docs-only", "1.0") not in reach
    assert ("orphan", "0.1") not in reach
    assert not graph.missing


# ---------------------------------------------------------------------------
# Policy gating
# ---------------------------------------------------------------------------


def test_runtime_advisory_blocks(project: Path) -> None:
    stub = OsvStub()
    stub.hits[("requests", "2.34.2")] = ["GHSA-aaaa-bbbb-cccc"]
    stub.vulns["GHSA-aaaa-bbbb-cccc"] = _advisory(
        "GHSA-aaaa-bbbb-cccc", "requests", "2.35.0"
    )
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_POLICY
    finding = _report(project)["findings"][0]
    assert finding["status"] == "blocking"
    assert finding["scopes"] == ["runtime"]
    assert finding["fixed_versions"] == ["2.35.0"]


def test_extra_advisory_blocks_and_dev_only_is_report_only(project: Path) -> None:
    stub = OsvStub()
    stub.hits[("pytest", "7.4.4")] = ["GHSA-dev0-0000-0000"]
    stub.vulns["GHSA-dev0-0000-0000"] = _advisory(
        "GHSA-dev0-0000-0000", "pytest", "9.0.3"
    )
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_OK
    assert _report(project)["findings"][0]["status"] == "report-only"

    stub.hits[("defusedxml", "0.7.1")] = ["GHSA-ext0-0000-0000"]
    stub.vulns["GHSA-ext0-0000-0000"] = _advisory(
        "GHSA-ext0-0000-0000", "defusedxml", "0.8"
    )
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_POLICY
    statuses = {f["package"]: f["status"] for f in _report(project)["findings"]}
    assert statuses == {"defusedxml": "blocking", "pytest": "report-only"}


def test_unreached_lock_entries_are_reported_not_blocking(project: Path) -> None:
    stub = OsvStub()
    stub.hits[("orphan", "0.1")] = ["GHSA-orph-0000-0000"]
    stub.vulns["GHSA-orph-0000-0000"] = _advisory(
        "GHSA-orph-0000-0000", "orphan", "0.2"
    )
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_OK
    assert _report(project)["findings"][0]["status"] == "unreached-lock-entry"


PY39_EXCEPTION = """
[[exception]]
package = "urllib3"
versions = ["1.26.20"]
python = ["3.9"]
advisories = ["GHSA-u3u3-u3u3-u3u3"]
classification = "compatibility-blocked"
review_by = {review_by}
reason = "fixed release requires Python 3.10"
"""


def _urllib3_stub(version: str = "1.26.20") -> OsvStub:
    stub = OsvStub()
    stub.hits[("urllib3", version)] = ["PYSEC-2026-1"]
    stub.vulns["PYSEC-2026-1"] = _advisory(
        "PYSEC-2026-1", "urllib3", "2.8.0", aliases=["GHSA-u3u3-u3u3-u3u3"]
    )
    stub.vulns["GHSA-u3u3-u3u3-u3u3"] = _advisory(
        "GHSA-u3u3-u3u3-u3u3", "urllib3", "2.8.0", aliases=["PYSEC-2026-1"]
    )
    return stub


def test_python_scoped_exception_covers_only_its_lane(project: Path) -> None:
    with osv_server(_urllib3_stub()) as url:
        assert (
            _run(project, url, policy=PY39_EXCEPTION.format(review_by="2027-01-31"))
            == audit.EXIT_OK
        )
    finding = _report(project)["findings"][0]
    assert finding["status"] == "excepted:compatibility-blocked"
    assert (
        finding["advisory"] == "GHSA-u3u3-u3u3-u3u3"
    )  # aliases are merged under the GHSA id
    assert finding["pythons"] == ["3.9"]

    # The same advisory on a version reachable from Python 3.10 is not covered.
    with osv_server(_urllib3_stub("2.8.0")) as url:
        assert (
            _run(project, url, policy=PY39_EXCEPTION.format(review_by="2027-01-31"))
            == audit.EXIT_POLICY
        )
    assert "Python 3.10" in _report(project)["errors"][0]


def test_expired_exception_blocks(project: Path) -> None:
    with osv_server(_urllib3_stub()) as url:
        assert (
            _run(project, url, policy=PY39_EXCEPTION.format(review_by="2026-11-01"))
            == audit.EXIT_POLICY
        )
    assert "expired" in _report(project)["errors"][0]


def test_unused_exception_fails_only_in_strict_mode(project: Path) -> None:
    with osv_server(OsvStub()) as url:
        assert (
            _run(project, url, policy=PY39_EXCEPTION.format(review_by="2027-01-31"))
            == audit.EXIT_OK
        )
        assert _report(project)["unused_exceptions"]
        assert (
            _run(
                project,
                url,
                "--strict-exceptions",
                policy=PY39_EXCEPTION.format(review_by="2027-01-31"),
            )
            == audit.EXIT_POLICY
        )


def test_withdrawn_advisory_is_ignored(project: Path) -> None:
    stub = OsvStub()
    stub.hits[("requests", "2.34.2")] = ["GHSA-wdrn-0000-0000"]
    stub.vulns["GHSA-wdrn-0000-0000"] = _advisory(
        "GHSA-wdrn-0000-0000", "requests", "2.35", withdrawn="2026-01-01T00:00:00Z"
    )
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_OK
    assert _report(project)["findings"] == []


def test_lock_floor_violation_blocks(project: Path) -> None:
    floor = '\n[[floor]]\npackage = "urllib3"\nminimum = "2.8.0"\npython = ["3.10"]\n'
    with osv_server(OsvStub()) as url:
        assert _run(project, url, policy=floor) == audit.EXIT_OK
    floor = '\n[[floor]]\npackage = "urllib3"\nminimum = "2.0.0"\n'
    with osv_server(OsvStub()) as url:
        assert _run(project, url, policy=floor) == audit.EXIT_POLICY
    assert (
        "urllib3 1.26.20 is below the security floor 2.0.0 on Python 3.9"
        in _report(project)["errors"][0]
    )


_EXCEPTION_FIELDS = (
    'package = "x"\nversions = ["1"]\npython = ["3.9"]\nadvisory = "A"\n'
)


@pytest.mark.parametrize(
    "entry",
    [
        _EXCEPTION_FIELDS
        + 'classification = "nope"\nreview_by = 2027-01-01\nreason = "r"',
        _EXCEPTION_FIELDS
        + 'classification = "accepted-risk"\nreview_by = 2027-01-01\nreason = " "',
        _EXCEPTION_FIELDS + 'classification = "accepted-risk"\nreason = "r"',
        _EXCEPTION_FIELDS
        + 'classification = "accepted-risk"\nreview_by = "soon"\nreason = "r"',
    ],
)
def test_invalid_exceptions_are_rejected(project: Path, entry: str) -> None:
    with osv_server(OsvStub()) as url:
        assert (
            _run(project, url, policy="\n[[exception]]\n" + entry + "\n")
            == audit.EXIT_INCOMPLETE
        )


# ---------------------------------------------------------------------------
# Bounded, fail-closed advisory lookups
# ---------------------------------------------------------------------------


def test_http_error_is_incomplete_not_pass(
    project: Path, capsys: pytest.CaptureFixture
) -> None:
    stub = OsvStub()
    stub.status = 400
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_INCOMPLETE
    assert "dependency audit incomplete" in capsys.readouterr().err
    assert len(stub.requests) == 1  # client errors are not retried


def test_server_errors_are_retried_then_fail(project: Path) -> None:
    stub = OsvStub()
    stub.status = 503
    with osv_server(stub) as url:
        start = time.monotonic()
        assert _run(project, url, "--deadline", "30") == audit.EXIT_INCOMPLETE
    assert len(stub.requests) == 3  # one attempt plus two retries
    assert time.monotonic() - start < 15


def test_slow_server_hits_timeout_and_deadline(project: Path) -> None:
    stub = OsvStub()
    stub.delay = 3
    with osv_server(stub) as url:
        start = time.monotonic()
        assert (
            _run(project, url, "--timeout", "0.5", "--deadline", "2")
            == audit.EXIT_INCOMPLETE
        )
        assert time.monotonic() - start < 8


def test_unreachable_endpoint_is_incomplete(project: Path) -> None:
    assert (
        _run(project, "http://127.0.0.1:9", "--deadline", "3") == audit.EXIT_INCOMPLETE
    )


def test_oversized_response_is_rejected(project: Path) -> None:
    stub = OsvStub()
    stub.raw_body = b'{"results": [' + b" " * 4096 + b"]}"
    with osv_server(stub) as url:
        assert (
            _run(project, url, "--max-response-bytes", "1024") == audit.EXIT_INCOMPLETE
        )


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"results": []}',
        b'{"results": [{"next_page_token": "x"}]}',
    ],
)
def test_malformed_or_partial_responses_are_rejected(
    project: Path, body: bytes
) -> None:
    stub = OsvStub()
    stub.raw_body = body
    with osv_server(stub) as url:
        assert _run(project, url, "--batch-size", "1") == audit.EXIT_INCOMPLETE


def test_redirects_are_not_followed(project: Path) -> None:
    stub = OsvStub()
    stub.redirect_to = "http://127.0.0.1:9/elsewhere"
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_INCOMPLETE
    assert len(stub.requests) == 1


def test_missing_advisory_detail_is_incomplete(project: Path) -> None:
    stub = OsvStub()
    stub.hits[("requests", "2.34.2")] = ["GHSA-miss-0000-0000"]
    with osv_server(stub) as url:
        assert _run(project, url) == audit.EXIT_INCOMPLETE


def test_plaintext_remote_endpoint_is_refused(project: Path) -> None:
    assert _run(project, "http://osv.example.invalid") == audit.EXIT_INCOMPLETE


def test_request_budget_is_enforced() -> None:
    client = audit.OsvClient(base_url="http://127.0.0.1:9", max_requests=0)
    with pytest.raises(audit.AuditError, match="limit of 0 requests"):
        client.query([("x", "1")])


def test_batches_respect_batch_size(project: Path) -> None:
    stub = OsvStub()
    with osv_server(stub) as url:
        assert _run(project, url, "--batch-size", "3") == audit.EXIT_OK
    posts = [r for r in stub.requests if r.startswith("POST")]
    assert len(posts) == 4  # 10 locked package versions in batches of 3


# ---------------------------------------------------------------------------
# Installed-environment checks
# ---------------------------------------------------------------------------


def _policy(floors: str) -> Any:
    return audit.Policy(
        ["3.9", "3.10", "3.11", "3.12"],
        ["linux"],
        ["runtime"],
        [],
        [
            audit.Floor(name, minimum, pythons, "")
            for name, minimum, pythons in json.loads(floors)
        ],
    )


def test_installed_floor_check() -> None:
    policy = _policy(
        '[["certifi", "2026.10.18", ["3.9", "3.10"]], ["urllib3", "2.8.0", ["3.10"]]]'
    )
    probe = {
        "python": "3.10",
        "executable": "py",
        "packages": {"certifi": "2025.1.31", "urllib3": "2.8.0"},
    }
    assert audit.check_installed(policy, probe, ["certifi"]) == [
        "certifi 2025.1.31 in py is below the security floor 2026.10.18"
    ]
    probe["packages"] = {"urllib3": "1.26.20"}
    probe["python"] = "3.9"
    assert audit.check_installed(policy, probe, ["certifi"]) == [
        "certifi is not installed in py"
    ]


def test_installed_probe_of_current_interpreter() -> None:
    probe = audit.probe_interpreter(sys.executable)
    assert probe["python"] == f"{sys.version_info[0]}.{sys.version_info[1]}"
    assert "pytest" in probe["packages"]


def test_expected_versions_match_model(project: Path) -> None:
    graph = audit.build_graph(
        audit.load_roots(project / "pyproject.toml"),
        audit.load_lock(project / "poetry.lock"),
        ["3.10"],
        ["linux"],
    )
    expected = audit.expected_from_lock(graph, "3.10", ["runtime"])
    assert expected == {"requests": "2.34.2", "urllib3": "2.8.0"}
    probe = {
        "executable": "py",
        "packages": {"requests": "2.34.2", "urllib3": "1.26.20"},
    }
    assert audit.compare_with_lock(expected, probe) == [
        "urllib3: audit model predicts 2.8.0, py has 1.26.20"
    ]


# ---------------------------------------------------------------------------
# The repository's own lockfile and policy
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", name="repo_graph")
def repo_graph_fixture() -> Any:
    policy = audit.load_policy(REPO_ROOT / "tools" / "dependency_audit_policy.toml")
    graph = audit.build_graph(
        audit.load_roots(REPO_ROOT / "pyproject.toml"),
        audit.load_lock(REPO_ROOT / "poetry.lock"),
        policy.pythons,
        policy.platforms,
    )
    return policy, graph


def test_repository_lock_meets_security_floors(repo_graph: Any) -> None:
    policy, graph = repo_graph
    assert policy.pythons == ["3.9", "3.10", "3.11", "3.12"]
    assert not graph.missing
    assert audit.check_lock_floors(graph, policy) == []


def test_repository_runtime_versions_per_python(repo_graph: Any) -> None:
    _, graph = repo_graph
    for python in ("3.10", "3.11", "3.12"):
        runtime = audit.expected_from_lock(graph, python, ["runtime"])
        assert audit.Version(runtime["requests"]) >= audit.Version("2.33.0")
        assert audit.Version(runtime["certifi"]) >= audit.Version("2026.10.18")
    runtime39 = audit.expected_from_lock(graph, "3.9", ["runtime"])
    assert audit.Version(runtime39["certifi"]) >= audit.Version("2026.10.18")
    assert audit.Version(runtime39["requests"]) >= audit.Version("2.32.4")
    # Python 3.9 support stays: every extra still resolves there.
    for extra in ("box", "cerberus", "snowflake", "tableau", "all-plugins"):
        assert audit.expected_from_lock(graph, "3.9", [f"extra:{extra}"])


def test_repository_policy_exceptions_are_reviewed_and_dated(repo_graph: Any) -> None:
    policy, graph = repo_graph
    for exception in policy.exceptions:
        assert exception.reason
        assert exception.review_by > dt.date(2026, 11, 1)
        # every exception names a locked, reachable package version
        assert any(
            (exception.package, v) in graph.reach for v in exception.versions
        ), exception
        if exception.classification == "compatibility-blocked":
            assert exception.pythons == [
                "3.9"
            ], "only Python 3.9 compatibility gaps may use this class"


@pytest.mark.parametrize(
    "members", [[{"summary": "bad"}], [None], {}, [{"id": "GHSA-valid"}, {}]]
)
def test_malformed_advisory_members_fail_cli(
    project: Path, monkeypatch: Any, members: Any
) -> None:
    def response(_self: Any, _method: str, _path: str, payload: Any = None) -> Any:
        return {"results": [{"vulns": members} for _ in payload["queries"]]}

    monkeypatch.setattr(audit.OsvClient, "_request", response)
    assert _run(project, "http://127.0.0.1:1") == audit.EXIT_INCOMPLETE


@pytest.mark.parametrize(
    "field,value",
    [("affected", {}), ("aliases", [None]), ("affected", [{}]), ("summary", [])],
)
def test_malformed_advisory_detail_is_refused(field: str, value: Any) -> None:
    with pytest.raises(audit.AuditError):
        audit.Advisory.from_osv({"id": "GHSA-valid", field: value})


def test_parent_extra_marker_reaches_blocking_child() -> None:
    child = audit.DependencySpec(
        "child", "*", markers='extra == "feature"', optional=True
    )
    packages = {
        "parent": [
            audit.LockedPackage(
                "parent", "1.0", "*", {"child": [child]}, {"feature": ["child"]}
            )
        ],
        "child": [audit.LockedPackage("child", "1.0", "*", {}, {})],
    }
    graph = audit.build_graph(
        {"runtime": [audit.DependencySpec("parent", "*", extras=("feature",))]},
        packages,
        ["3.12"],
        ["linux"],
    )
    assert graph.reach[("child", "1.0")].scopes == {"runtime"}


def test_repository_selected_extra_paths_are_reached(repo_graph: Any) -> None:
    _, graph = repo_graph
    reached = {name for name, _ in graph.reach}
    assert {"email-validator", "dnspython", "mkdocstrings-python"} <= reached


def test_unsupported_platform_selector_fails_closed() -> None:
    with pytest.raises(audit.AuditError, match="platform selector"):
        audit._parse_dependency_specs("example", {"version": "*", "platform": "win32"})


def test_current_transport_exceptions_do_not_cover_new_scopes(repo_graph: Any) -> None:
    policy, _ = repo_graph
    for exception in policy.exceptions:
        if exception.package in ("urllib3", "requests"):
            assert exception.scopes
            assert "extra:new-service" not in exception.scopes


def test_slow_body_stops_at_remaining_deadline() -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "16")
            self.end_headers()
            try:
                for byte in b'{"value": true }':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = audit.OsvClient(
            base_url=f"http://127.0.0.1:{server.server_port}",
            deadline=0.2,
            timeout=0.15,
            retries=0,
        )
        started = time.monotonic()
        with pytest.raises(audit.AuditError):
            client._request("GET", "/")
        assert time.monotonic() - started < 0.7
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
