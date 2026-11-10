"""Group-aware dependency advisory audit for Brickflow.

The audit reads ``pyproject.toml`` and ``poetry.lock``, works out which locked
packages each dependency scope can install on each supported Python version
and platform, queries OSV for advisories affecting those exact versions, and
applies ``tools/dependency_audit_policy.toml``.

An OSV match is not treated as an exploitable vulnerability on its own. The
policy decides what blocks:

* advisories on packages reachable from the runtime dependencies or a plugin
  extra block, unless a reviewed, unexpired exception covers that package,
  version, advisory and Python version;
* advisories reachable only from development or documentation groups are
  reported but do not block;
* a lookup that cannot complete (network error, timeout, oversized or
  malformed response) is an incomplete audit and never counts as a pass.

Exit codes: 0 passed, 1 policy violation, 2 audit could not complete.

Subcommands:

``audit``      lockfile reachability, security floors and OSV advisories.
``installed``  check the security floors against an installed interpreter
               (for example a Poetry virtualenv or a publishing tool's venv)
               and print where certifi's CA bundle lives.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.9/3.10
    import tomli as _toml  # type: ignore[no-redef]

from packaging.markers import Marker
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name as _canonicalize_name
from packaging.version import InvalidVersion, Version

EXIT_OK = 0
EXIT_POLICY = 1
EXIT_INCOMPLETE = 2

OSV_DEFAULT_URL = "https://api.osv.dev"
RUNTIME_SCOPE = "runtime"

PLATFORM_ENVIRONMENTS: Dict[str, Dict[str, str]] = {
    "linux": {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix"},
    "darwin": {
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "os_name": "posix",
    },
    "win32": {"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt"},
}


def canonicalize_name(name: str) -> str:
    """PEP 503 normalised project name, as a plain string."""
    return str(_canonicalize_name(name))


class AuditError(Exception):
    """The audit could not finish; the result must not be read as a pass."""


# --------------------------------------------------------------------------
# Poetry constraint handling
# --------------------------------------------------------------------------

_CARET = re.compile(r"^\^\s*(\d+(?:\.\d+)*)$")
_TILDE = re.compile(r"^~(?!=)\s*(\d+(?:\.\d+)*)$")
_WILDCARD = re.compile(r"^(\d+(?:\.\d+)*)\.\*$")
_BARE = re.compile(r"^\d+(?:\.\d+)*(?:[a-zA-Z0-9.+-]*)$")


def _bump(parts: List[int], index: int) -> str:
    bumped = parts[: index + 1]
    bumped[index] += 1
    return ".".join(str(p) for p in bumped)


def _poetry_atom_to_pep440(atom: str) -> List[str]:
    atom = atom.strip()
    if not atom or atom == "*":
        return []
    caret = _CARET.match(atom)
    if caret:
        parts = [int(p) for p in caret.group(1).split(".")]
        index = next((i for i, p in enumerate(parts) if p != 0), len(parts) - 1)
        return [f">={caret.group(1)}", f"<{_bump(parts, index)}"]
    tilde = _TILDE.match(atom)
    if tilde:
        parts = [int(p) for p in tilde.group(1).split(".")]
        index = 0 if len(parts) == 1 else 1
        return [f">={tilde.group(1)}", f"<{_bump(parts, index)}"]
    wildcard = _WILDCARD.match(atom)
    if wildcard:
        return [f"=={atom}"]
    if _BARE.match(atom):
        return [f"=={atom}"]
    return [atom]


def poetry_constraint_to_specifiers(constraint: str) -> List[SpecifierSet]:
    """Translate a Poetry constraint into alternative PEP 440 specifier sets.

    Poetry joins alternatives with ``||`` and allows ``^``/``~`` operators,
    spaces as separators and bare versions. Each alternative becomes one
    ``SpecifierSet``; a version satisfies the constraint when it satisfies
    any alternative.
    """
    alternatives: List[SpecifierSet] = []
    for alternative in str(constraint).split("||"):
        atoms: List[str] = []
        for chunk in alternative.split(","):
            chunk = chunk.strip()
            # "<2.0 >=1.0" style: whitespace separated atoms
            for atom in re.split(r"\s+(?=[<>=!~^])", chunk):
                atoms.extend(_poetry_atom_to_pep440(atom))
        try:
            alternatives.append(SpecifierSet(",".join(atoms)))
        except InvalidSpecifier as exc:
            raise AuditError(
                f"cannot interpret version constraint {constraint!r}: {exc}"
            ) from exc
    return alternatives


def constraint_allows(constraint: Optional[str], version: str) -> bool:
    if constraint is None:
        return True
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    return any(
        spec.contains(parsed, prereleases=True)
        for spec in poetry_constraint_to_specifiers(constraint)
    )


def python_allows(constraint: Optional[str], python_version: str) -> bool:
    """Whether a Poetry ``python``/``python-versions`` constraint allows X.Y."""
    if constraint is None or str(constraint).strip() in ("", "*"):
        return True
    # Compare with a full micro version so "<3.10" and ">=3.9" behave as expected.
    return constraint_allows(str(constraint), f"{python_version}.0")


# --------------------------------------------------------------------------
# Lockfile reachability
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Environment:
    python: str
    platform: str

    def markers(self) -> Dict[str, str]:
        env = {
            "python_version": self.python,
            "python_full_version": f"{self.python}.0",
            "implementation_name": "cpython",
            "platform_python_implementation": "CPython",
            "platform_machine": "x86_64",
            "platform_release": "",
            "platform_version": "",
            "implementation_version": f"{self.python}.0",
            "extra": "",
        }
        env.update(PLATFORM_ENVIRONMENTS[self.platform])
        return env


@dataclass(frozen=True)
class DependencySpec:
    name: str
    constraint: Optional[str]
    python: Optional[str] = None
    markers: Optional[str] = None
    extras: Tuple[str, ...] = ()
    optional: bool = False

    def applies(
        self, environment: Environment, parent_extras: Tuple[str, ...] = ()
    ) -> bool:
        if not python_allows(self.python, environment.python):
            return False
        if self.markers:
            try:
                return any(
                    Marker(self.markers).evaluate(
                        {**environment.markers(), "extra": extra}
                    )
                    for extra in ("",) + parent_extras
                )
            except Exception as exc:  # packaging raises several marker error types
                raise AuditError(
                    f"cannot evaluate marker {self.markers!r} for {self.name}: {exc}"
                ) from exc
        return True


def _parse_dependency_specs(name: str, raw: Any) -> List[DependencySpec]:
    entries = raw if isinstance(raw, list) else [raw]
    specs = []
    for entry in entries:
        if isinstance(entry, str):
            specs.append(DependencySpec(canonicalize_name(name), entry))
        elif isinstance(entry, dict):
            if "platform" in entry:
                raise AuditError(
                    f"unsupported platform selector for {name}; use markers"
                )
            if "path" in entry or "git" in entry or "url" in entry:
                specs.append(
                    DependencySpec(
                        canonicalize_name(name),
                        None,
                        entry.get("python"),
                        entry.get("markers"),
                    )
                )
                continue
            specs.append(
                DependencySpec(
                    canonicalize_name(name),
                    entry.get("version"),
                    entry.get("python"),
                    entry.get("markers"),
                    tuple(
                        sorted(canonicalize_name(e) for e in entry.get("extras", []))
                    ),
                    bool(entry.get("optional", False)),
                )
            )
        else:
            raise AuditError(f"unsupported dependency entry for {name}: {entry!r}")
    return specs


_EXTRA_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:\(([^)]*)\))?"
)


@dataclass
class LockedPackage:
    name: str
    version: str
    python_versions: Optional[str]
    dependencies: Dict[str, List[DependencySpec]]
    extras: Dict[str, List[str]]


def load_lock(lock_path: Path) -> Dict[str, List[LockedPackage]]:
    try:
        data = _toml.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(f"cannot read lockfile {lock_path}: {exc}") from exc
    packages: Dict[str, List[LockedPackage]] = {}
    for item in data.get("package", []):
        name = canonicalize_name(item["name"])
        dependencies = {
            canonicalize_name(dep): _parse_dependency_specs(dep, raw)
            for dep, raw in (item.get("dependencies") or {}).items()
        }
        extras = {
            canonicalize_name(extra): [
                canonicalize_name(m.group(1))
                for m in (_EXTRA_REQUIREMENT.match(req) for req in requirements)
                if m
            ]
            for extra, requirements in (item.get("extras") or {}).items()
        }
        packages.setdefault(name, []).append(
            LockedPackage(
                name,
                str(item["version"]),
                item.get("python-versions"),
                dependencies,
                extras,
            )
        )
    if not packages:
        raise AuditError(f"lockfile {lock_path} contains no packages")
    return packages


def load_roots(pyproject_path: Path) -> Dict[str, List[DependencySpec]]:
    """Return dependency roots keyed by scope.

    Scopes are ``runtime``, ``extra:<name>`` and ``group:<name>``.
    """
    try:
        data = _toml.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(f"cannot read {pyproject_path}: {exc}") from exc
    poetry = data.get("tool", {}).get("poetry", {})
    main = {
        k: v for k, v in poetry.get("dependencies", {}).items() if k.lower() != "python"
    }
    extras = {
        canonicalize_name(k): [canonicalize_name(n) for n in v]
        for k, v in poetry.get("extras", {}).items()
    }

    roots: Dict[str, List[DependencySpec]] = {RUNTIME_SCOPE: []}
    for name, raw in main.items():
        for spec in _parse_dependency_specs(name, raw):
            if spec.optional:
                for extra, members in extras.items():
                    if spec.name in members:
                        roots.setdefault(f"extra:{extra}", []).append(spec)
            else:
                roots[RUNTIME_SCOPE].append(spec)
    groups = dict(poetry.get("group", {}))
    if "dev-dependencies" in poetry:
        groups.setdefault("dev", {}).setdefault("dependencies", {}).update(
            poetry["dev-dependencies"]
        )
    for group, body in groups.items():
        for name, raw in (body.get("dependencies") or {}).items():
            roots.setdefault(f"group:{group}", []).extend(
                _parse_dependency_specs(name, raw)
            )
    return roots


@dataclass
class Reach:
    """Where a locked package version is reachable."""

    scopes: Set[str] = field(default_factory=set)
    pythons: Set[str] = field(default_factory=set)
    platforms: Set[str] = field(default_factory=set)
    by_scope_python: Set[Tuple[str, str]] = field(default_factory=set)


@dataclass
class Graph:
    reach: Dict[Tuple[str, str], Reach]
    ambiguities: List[Dict[str, Any]]
    missing: List[Dict[str, Any]]


def _select(
    candidates: List[LockedPackage], spec: DependencySpec, environment: Environment
) -> Tuple[Optional[LockedPackage], List[LockedPackage]]:
    usable = [
        c
        for c in candidates
        if python_allows(c.python_versions, environment.python)
        and constraint_allows(spec.constraint, c.version)
    ]
    if not usable:
        return None, []
    usable.sort(key=lambda c: Version(c.version), reverse=True)
    return usable[0], usable[1:]


def build_graph(
    roots: Dict[str, List[DependencySpec]],
    packages: Dict[str, List[LockedPackage]],
    pythons: Sequence[str],
    platforms: Sequence[str],
) -> Graph:
    reach: Dict[Tuple[str, str], Reach] = {}
    ambiguities: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    missing: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for python in pythons:
        for platform in platforms:
            environment = Environment(python, platform)
            for scope, specs in roots.items():
                visited: Set[Tuple[str, str, Tuple[str, ...]]] = set()
                stack = [(spec, ()) for spec in specs]
                while stack:
                    spec, parent_extras = stack.pop()
                    if not spec.applies(environment, parent_extras):
                        continue
                    candidates = packages.get(spec.name)
                    if not candidates:
                        missing.setdefault(
                            (spec.name, scope),
                            {"package": spec.name, "scope": scope, "pythons": set()},
                        )["pythons"].add(python)
                        continue
                    chosen, alternatives = _select(candidates, spec, environment)
                    if chosen is None:
                        missing.setdefault(
                            (spec.name, scope),
                            {"package": spec.name, "scope": scope, "pythons": set()},
                        )["pythons"].add(python)
                        continue
                    if alternatives:
                        key = (
                            chosen.name,
                            chosen.version,
                            ",".join(a.version for a in alternatives),
                        )
                        entry = ambiguities.setdefault(
                            key,
                            {
                                "package": chosen.name,
                                "selected": chosen.version,
                                "not_selected": [a.version for a in alternatives],
                                "pythons": set(),
                            },
                        )
                        entry["pythons"].add(python)
                    marker = (chosen.name, chosen.version, spec.extras)
                    if marker in visited:
                        continue
                    visited.add(marker)
                    item = reach.setdefault((chosen.name, chosen.version), Reach())
                    item.scopes.add(scope)
                    item.pythons.add(python)
                    item.platforms.add(platform)
                    item.by_scope_python.add((scope, python))
                    enabled: Set[str] = set()
                    for extra in spec.extras:
                        enabled.update(chosen.extras.get(extra, []))
                    for dep_specs in chosen.dependencies.values():
                        for dep in dep_specs:
                            if dep.optional and dep.name not in enabled:
                                continue
                            stack.append((dep, spec.extras))
    for entry in list(ambiguities.values()) + list(missing.values()):
        entry["pythons"] = sorted(entry["pythons"], key=Version)
    return Graph(reach, list(ambiguities.values()), list(missing.values()))


# --------------------------------------------------------------------------
# Bounded OSV client
# --------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        raise urllib.error.HTTPError(
            req.full_url, code, f"refusing redirect to {newurl}", headers, fp
        )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class OsvClient:
    """Small OSV API client with hard limits on time, size and request count."""

    base_url: str = OSV_DEFAULT_URL
    timeout: float = 20.0
    deadline: float = 180.0
    max_response_bytes: int = 8 * 1024 * 1024
    max_requests: int = 400
    retries: int = 2
    batch_size: int = 200
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme == "http" and not _is_loopback(parsed.hostname or ""):
            raise AuditError(
                f"refusing plaintext advisory endpoint {self.base_url}; use https"
            )
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise AuditError(f"invalid advisory endpoint {self.base_url!r}")
        if not 1 <= self.batch_size <= 1000:
            raise AuditError("batch size must be between 1 and 1000 (OSV limit)")
        self._started = self.clock()
        self._requests = 0
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _remaining(self) -> float:
        return self.deadline - (self.clock() - self._started)

    def _request(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = self.base_url.rstrip("/") + path
        last_error: Optional[str] = None
        for attempt in range(self.retries + 1):
            remaining = self._remaining()
            if remaining <= 0:
                raise AuditError(
                    f"advisory lookup exceeded the {self.deadline:.0f}s deadline (last error: {last_error})"
                )
            if self._requests >= self.max_requests:
                raise AuditError(
                    f"advisory lookup exceeded the limit of {self.max_requests} requests"
                )
            self._requests += 1
            body = None if payload is None else json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=body,
                method=method,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "brickflow-dependency-audit",
                },
            )
            try:
                with self._opener.open(
                    request, timeout=min(self.timeout, remaining)
                ) as response:
                    chunks = []
                    received = 0
                    while True:
                        remaining = self._remaining()
                        if remaining <= 0:
                            raise AuditError("advisory response exceeded the deadline")
                        # urllib's HTTPResponse exposes the socket through its
                        # buffered reader. Fail closed if that implementation
                        # changes rather than losing the remaining-time bound.
                        reader = response.fp
                        if reader is None:
                            break
                        sock = getattr(getattr(reader, "raw", None), "_sock", None)
                        if sock is None or not hasattr(response, "read1"):
                            raise AuditError(
                                "cannot enforce advisory response deadline"
                            )
                        sock.settimeout(min(self.timeout, remaining))
                        chunk = response.read1(
                            min(65536, self.max_response_bytes + 1 - received)
                        )
                        if self._remaining() <= 0:
                            raise AuditError("advisory response exceeded the deadline")
                        if not chunk:
                            break
                        chunks.append(chunk)
                        received += len(chunk)
                        if received > self.max_response_bytes:
                            raise AuditError("advisory response exceeds the byte limit")
                    raw = b"".join(chunks)
                if len(raw) > self.max_response_bytes:
                    raise AuditError(
                        f"{method} {url} returned more than {self.max_response_bytes} bytes"
                    )
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise AuditError(
                        f"{method} {url} returned malformed JSON: {exc}"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise AuditError(
                        f"{method} {url} returned JSON that is not an object"
                    )
                if self._remaining() <= 0:
                    raise AuditError("advisory response exceeded the deadline")
                return decoded
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code}"
                if exc.code not in (408, 429, 500, 502, 503, 504):
                    raise AuditError(
                        f"{method} {url} failed with HTTP {exc.code}"
                    ) from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = str(getattr(exc, "reason", exc))
            if attempt < self.retries:
                self.sleep(min(2.0 * (attempt + 1), max(self._remaining(), 0)))
        raise AuditError(
            f"{method} {url} failed after {self.retries + 1} attempts: {last_error}"
        )

    def query(
        self, pairs: Sequence[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], List[str]]:
        result: Dict[Tuple[str, str], List[str]] = {}
        for start in range(0, len(pairs), self.batch_size):
            chunk = pairs[start : start + self.batch_size]
            payload = {
                "queries": [
                    {"package": {"ecosystem": "PyPI", "name": n}, "version": v}
                    for n, v in chunk
                ]
            }
            response = self._request("POST", "/v1/querybatch", payload)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise AuditError(
                    "OSV querybatch response does not match the number of queries"
                )
            for pair, item in zip(chunk, results):
                if not isinstance(item, dict):
                    raise AuditError(
                        f"OSV querybatch returned a malformed result for {pair[0]} {pair[1]}"
                    )
                if item.get("next_page_token"):
                    raise AuditError(
                        f"OSV result for {pair[0]} {pair[1]} is paginated; refusing a partial audit"
                    )
                vulnerabilities = item.get("vulns", [])
                if not isinstance(vulnerabilities, list) or any(
                    not isinstance(v, dict)
                    or not isinstance(v.get("id"), str)
                    or not re.fullmatch(r"[A-Za-z0-9._:-]+", v["id"])
                    for v in vulnerabilities
                ):
                    raise AuditError(
                        "OSV querybatch contains malformed advisory records"
                    )
                result[pair] = sorted(v["id"] for v in vulnerabilities)
        return result

    def vulnerability(self, advisory_id: str) -> Dict[str, Any]:
        if not re.match(r"^[A-Za-z0-9._:-]+$", advisory_id):
            raise AuditError(
                f"refusing to fetch advisory with unexpected id {advisory_id!r}"
            )
        data = self._request("GET", f"/v1/vulns/{urllib.parse.quote(advisory_id)}")
        if data.get("id") != advisory_id:
            raise AuditError("OSV advisory detail identity does not match the request")
        _validate_advisory(data)
        return data


# --------------------------------------------------------------------------
# Advisories and policy
# --------------------------------------------------------------------------


def _validate_advisory(data: Dict[str, Any]) -> None:
    """Reject incomplete record shapes rather than silently dropping coverage."""
    if not isinstance(data.get("id"), str) or not data["id"]:
        raise AuditError("OSV advisory requires a nonempty ID")
    for key in ("aliases", "affected"):
        if key in data and not isinstance(data[key], list):
            raise AuditError(f"OSV advisory {key} must be a list")
    if any(
        not isinstance(alias, str) or not alias for alias in data.get("aliases", [])
    ):
        raise AuditError("OSV advisory aliases must be nonempty strings")
    for affected in data.get("affected", []):
        if not isinstance(affected, dict) or not isinstance(
            affected.get("package"), dict
        ):
            raise AuditError("OSV affected package is malformed")
        package = affected["package"]
        if not all(
            isinstance(package.get(key), str) and package[key]
            for key in ("name", "ecosystem")
        ):
            raise AuditError("OSV affected package identity is malformed")
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            raise AuditError("OSV affected ranges must be a list")
        for item in ranges:
            if not isinstance(item, dict) or not isinstance(item.get("events"), list):
                raise AuditError("OSV affected range is malformed")
            for event in item["events"]:
                if (
                    not isinstance(event, dict)
                    or len(event) != 1
                    or not all(
                        key in ("introduced", "fixed", "last_affected", "limit")
                        and isinstance(value, str)
                        and value
                        for key, value in event.items()
                    )
                ):
                    raise AuditError("OSV range event is malformed")
    for key in ("summary", "details", "withdrawn"):
        if key in data and not isinstance(data[key], str):
            raise AuditError(f"OSV advisory {key} must be a string")
    if "database_specific" in data and not isinstance(data["database_specific"], dict):
        raise AuditError("OSV database_specific must be an object")


@dataclass
class Advisory:
    id: str
    aliases: Set[str]
    summary: str
    severity: str
    withdrawn: bool
    fixed: Dict[str, List[str]]

    @classmethod
    def from_osv(cls, data: Dict[str, Any]) -> "Advisory":
        _validate_advisory(data)
        fixed: Dict[str, List[str]] = {}
        for affected in data.get("affected", []) or []:
            package = canonicalize_name(
                ((affected.get("package") or {}).get("name")) or ""
            )
            for rng in affected.get("ranges", []) or []:
                for event in rng.get("events", []) or []:
                    if "fixed" in event:
                        fixed.setdefault(package, []).append(str(event["fixed"]))
        severity = str(
            ((data.get("database_specific") or {}).get("severity")) or "UNKNOWN"
        ).upper()
        return cls(
            id=str(data["id"]),
            aliases=set(str(a) for a in data.get("aliases", []) or []),
            summary=str(data.get("summary") or data.get("details", "")[:120] or ""),
            severity=severity,
            withdrawn=bool(data.get("withdrawn")),
            fixed=fixed,
        )

    def all_ids(self) -> Set[str]:
        return {self.id} | self.aliases


def canonical_id(ids: Iterable[str]) -> str:
    ordered = sorted(ids)
    for prefix in ("GHSA-", "PYSEC-", "CVE-"):
        for item in ordered:
            if item.startswith(prefix):
                return item
    return ordered[0]


@dataclass
class PolicyException:
    advisory: str
    package: str
    versions: List[str]
    pythons: List[str]
    classification: str
    reason: str
    review_by: _dt.date
    scopes: Optional[List[str]] = None
    used: bool = False


VALID_CLASSIFICATIONS = {
    # A fixed release exists but cannot be installed on a supported Python
    # version without dropping that version or another supported extra.
    "compatibility-blocked",
    # The vulnerable code path is not used by Brickflow.
    "not-reachable",
    # A fix exists but needs a separate, larger upgrade; keep review_by short.
    "deferred-upgrade",
    # Reviewed and accepted for a bounded time.
    "accepted-risk",
}


@dataclass
class Floor:
    package: str
    minimum: str
    pythons: List[str]
    reason: str


@dataclass
class Policy:
    pythons: List[str]
    platforms: List[str]
    blocking_scopes: List[str]
    exceptions: List[PolicyException]
    floors: List[Floor]

    def is_blocking_scope(self, scope: str) -> bool:
        return any(
            scope == pattern
            or (pattern.endswith(":*") and scope.startswith(pattern[:-1]))
            for pattern in self.blocking_scopes
        )


def load_policy(path: Path) -> Policy:
    try:
        data = _toml.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(f"cannot read policy {path}: {exc}") from exc
    audit = data.get("audit", {})
    pythons = [str(p) for p in audit.get("python_versions", [])]
    platforms = [str(p) for p in audit.get("platforms", ["linux"])]
    if not pythons:
        raise AuditError("policy must list audit.python_versions")
    unknown = [p for p in platforms if p not in PLATFORM_ENVIRONMENTS]
    if unknown:
        raise AuditError(f"policy lists unknown platforms: {unknown}")
    exceptions = []
    for raw in data.get("exception", []):
        try:
            review_by = raw["review_by"]
            if isinstance(review_by, str):
                review_by = _dt.date.fromisoformat(review_by)
            if not isinstance(review_by, _dt.date):
                raise ValueError("review_by must be a date")
            advisory_ids = (
                raw["advisories"] if "advisories" in raw else [raw["advisory"]]
            )
            if not advisory_ids or not all(
                isinstance(a, str) and a for a in advisory_ids
            ):
                raise ValueError("advisories must be a non-empty list of ids")
            items = [
                PolicyException(
                    advisory=advisory_id,
                    package=canonicalize_name(raw["package"]),
                    versions=[str(v) for v in raw["versions"]],
                    pythons=[str(p) for p in raw["python"]],
                    classification=str(raw["classification"]),
                    reason=" ".join(str(raw["reason"]).split()),
                    review_by=review_by,
                    scopes=[str(s) for s in raw["scopes"]] if "scopes" in raw else None,
                )
                for advisory_id in advisory_ids
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditError(f"invalid exception entry {raw!r}: {exc}") from exc
        for item in items:
            if item.classification not in VALID_CLASSIFICATIONS:
                raise AuditError(
                    f"exception {item.advisory} has unknown classification {item.classification!r}"
                )
            if not item.reason:
                raise AuditError(f"exception {item.advisory} needs a reason")
        exceptions.extend(items)
    floors = []
    for raw in data.get("floor", []):
        try:
            Version(str(raw["minimum"]))
            floors.append(
                Floor(
                    canonicalize_name(raw["package"]),
                    str(raw["minimum"]),
                    [str(p) for p in raw.get("python", pythons)],
                    str(raw.get("reason", "")),
                )
            )
        except (KeyError, InvalidVersion) as exc:
            raise AuditError(f"invalid floor entry {raw!r}: {exc}") from exc
    return Policy(
        pythons,
        platforms,
        [str(s) for s in audit.get("blocking_scopes", [RUNTIME_SCOPE, "extra:*"])],
        exceptions,
        floors,
    )


@dataclass
class Finding:
    package: str
    version: str
    advisory: Advisory
    scopes: List[str]
    pythons: List[str]
    status: str
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "advisory": self.advisory.id,
            "aliases": sorted(self.advisory.aliases),
            "summary": self.advisory.summary,
            "severity": self.advisory.severity,
            "fixed_versions": sorted(
                set(self.advisory.fixed.get(self.package, [])), key=_version_key
            ),
            "scopes": self.scopes,
            "pythons": self.pythons,
            "status": self.status,
            "detail": self.detail,
        }


def _version_key(value: str) -> Tuple[int, Any]:
    try:
        return (0, Version(value))
    except InvalidVersion:
        return (1, value)


def evaluate(
    graph: Graph,
    advisories_by_package: Dict[Tuple[str, str], List[Advisory]],
    policy: Policy,
    today: _dt.date,
) -> Tuple[List[Finding], List[str]]:
    """Classify each advisory match and return findings plus policy errors."""
    findings: List[Finding] = []
    errors: List[str] = []
    for (name, version), advisories in sorted(advisories_by_package.items()):
        reach = graph.reach.get((name, version))
        if reach is None:
            for advisory in advisories:
                findings.append(
                    Finding(
                        name,
                        version,
                        advisory,
                        [],
                        [],
                        "unreached-lock-entry",
                        "locked but not selected for any audited scope, Python version or platform",
                    )
                )
            continue
        for advisory in advisories:
            blocking_pairs = sorted(
                {
                    (s, p)
                    for s, p in reach.by_scope_python
                    if policy.is_blocking_scope(s)
                },
                key=lambda x: (x[0], Version(x[1])),
            )
            scopes = sorted(reach.scopes)
            pythons = sorted(reach.pythons, key=Version)
            if not blocking_pairs:
                findings.append(
                    Finding(
                        name,
                        version,
                        advisory,
                        scopes,
                        pythons,
                        "report-only",
                        "reachable only from non-blocking groups",
                    )
                )
                continue
            remaining = list(blocking_pairs)
            matched: List[PolicyException] = []
            for exception in policy.exceptions:
                if exception.package != name or version not in exception.versions:
                    continue
                if exception.advisory not in advisory.all_ids():
                    continue
                covered = [
                    (s, p)
                    for s, p in remaining
                    if p in exception.pythons
                    and (exception.scopes is None or s in exception.scopes)
                ]
                if covered:
                    exception.used = True
                    matched.append(exception)
                    remaining = [pair for pair in remaining if pair not in covered]
            expired = [e for e in matched if e.review_by < today]
            if expired:
                for exception in expired:
                    errors.append(
                        f"exception for {exception.advisory} on {name} {version} "
                        f"(Python {', '.join(exception.pythons)}) expired on {exception.review_by.isoformat()}"
                    )
                findings.append(
                    Finding(
                        name,
                        version,
                        advisory,
                        scopes,
                        pythons,
                        "blocking",
                        "exception expired",
                    )
                )
                continue
            if remaining:
                uncovered = ", ".join(f"{s} on Python {p}" for s, p in remaining)
                errors.append(
                    f"{advisory.id} ({advisory.severity}) affects {name} {version} via {uncovered}: {advisory.summary}"
                )
                findings.append(
                    Finding(
                        name,
                        version,
                        advisory,
                        scopes,
                        pythons,
                        "blocking",
                        f"not covered: {uncovered}",
                    )
                )
                continue
            classes = sorted({e.classification for e in matched})
            detail = " | ".join(
                f"Python {', '.join(e.pythons)}: {e.classification}, review by {e.review_by.isoformat()}: {e.reason}"
                for e in matched
            )
            findings.append(
                Finding(
                    name,
                    version,
                    advisory,
                    scopes,
                    pythons,
                    "excepted:" + "+".join(classes),
                    detail,
                )
            )
    return findings, errors


def check_lock_floors(graph: Graph, policy: Policy) -> List[str]:
    errors = []
    for floor in policy.floors:
        minimum = Version(floor.minimum)
        for (name, version), reach in graph.reach.items():
            if name != floor.package:
                continue
            for python in sorted(reach.pythons & set(floor.pythons), key=Version):
                if Version(version) < minimum:
                    errors.append(
                        f"locked {name} {version} is below the security floor {floor.minimum} on Python {python}"
                    )
    return errors


def fetch_advisories(
    client: OsvClient, pairs: Sequence[Tuple[str, str]]
) -> Dict[Tuple[str, str], List[Advisory]]:
    hits = client.query(pairs)
    details: Dict[str, Advisory] = {}
    for advisory_id in sorted({i for ids in hits.values() for i in ids}):
        if advisory_id in details:
            continue
        advisory = Advisory.from_osv(client.vulnerability(advisory_id))
        for alias in advisory.all_ids():
            details.setdefault(alias, advisory)
    grouped: Dict[Tuple[str, str], List[Advisory]] = {}
    for pair, ids in hits.items():
        seen: Dict[str, Advisory] = {}
        for advisory_id in ids:
            advisory = details[advisory_id]
            key = canonical_id(
                advisory.all_ids() | {i for i in ids if i in advisory.all_ids()}
            )
            if advisory.withdrawn:
                continue
            if key in seen:
                seen[key].aliases |= advisory.all_ids()
                continue
            merged = Advisory(
                key,
                advisory.all_ids() - {key},
                advisory.summary,
                advisory.severity,
                False,
                advisory.fixed,
            )
            seen[key] = merged
        if seen:
            grouped[pair] = sorted(seen.values(), key=lambda a: a.id)
    return grouped


def run_audit(
    args: argparse.Namespace, client_factory: Callable[..., OsvClient] = OsvClient
) -> int:
    policy = load_policy(Path(args.policy))
    packages = load_lock(Path(args.lock))
    roots = load_roots(Path(args.pyproject))
    graph = build_graph(roots, packages, policy.pythons, policy.platforms)
    today = _dt.date.fromisoformat(args.today) if args.today else _dt.date.today()

    errors: List[str] = []
    for item in graph.missing:
        errors.append(
            f"{item['package']} is required by {item['scope']} on Python {', '.join(item['pythons'])} but no locked version fits"
        )
    errors.extend(check_lock_floors(graph, policy))

    # Query every locked version, including entries the reachability model does
    # not select, so nothing in the lockfile escapes the report.
    pairs = sorted(
        {(p.name, p.version) for entries in packages.values() for p in entries}
    )
    client = client_factory(
        base_url=args.osv_url,
        timeout=args.timeout,
        deadline=args.deadline,
        max_response_bytes=args.max_response_bytes,
        batch_size=args.batch_size,
    )
    advisories = fetch_advisories(client, pairs)
    findings, policy_errors = evaluate(graph, advisories, policy, today)
    errors.extend(policy_errors)
    stale = [e for e in policy.exceptions if not e.used]

    report = {
        "lockfile": str(args.lock),
        "audited_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "advisory_source": args.osv_url,
        "python_versions": policy.pythons,
        "platforms": policy.platforms,
        "packages_audited": len(pairs),
        "packages_reachable": len(graph.reach),
        "packages_with_advisories": len(advisories),
        "findings": [f.as_dict() for f in findings],
        "unused_exceptions": [
            {"advisory": e.advisory, "package": e.package, "versions": e.versions}
            for e in stale
        ],
        "resolution_ambiguities": graph.ambiguities,
        "errors": errors,
    }
    if args.json_report:
        Path(args.json_report).write_text(
            json.dumps(report, indent=2, sort_keys=True, default=sorted) + "\n",
            encoding="utf-8",
        )
    _print_summary(report)
    if args.strict_exceptions and stale:
        print(
            "error: unused policy exceptions (remove them or fix the policy):",
            file=sys.stderr,
        )
        return EXIT_POLICY
    return EXIT_POLICY if errors else EXIT_OK


def _print_summary(report: Dict[str, Any]) -> None:
    findings = report["findings"]
    counts: Dict[str, int] = {}
    for finding in findings:
        bucket = finding["status"].split(":")[0]
        counts[bucket] = counts.get(bucket, 0) + 1
    print(
        f"Audited {report['packages_audited']} locked package versions for Python {', '.join(report['python_versions'])} "
        f"on {', '.join(report['platforms'])}; {report['packages_with_advisories']} have advisories."
    )
    print(
        "Advisory matches by status: "
        + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")
    )
    for finding in findings:
        if finding["status"] in ("report-only", "unreached-lock-entry"):
            continue
        print(
            f"  [{finding['status']}] {finding['package']} {finding['version']} {finding['advisory']} "
            f"({finding['severity']}) Python {','.join(finding['pythons'])} scopes {','.join(finding['scopes'])}"
        )
    for item in report["unused_exceptions"]:
        print(
            f"  [unused-exception] {item['advisory']} {item['package']} {','.join(item['versions'])}"
        )
    for item in report["resolution_ambiguities"]:
        print(
            f"  [ambiguous-lock] {item['package']}: selected {item['selected']} over {','.join(item['not_selected'])} "
            f"on Python {','.join(item['pythons'])}"
        )
    for error in report["errors"]:
        print(f"error: {error}", file=sys.stderr)


# --------------------------------------------------------------------------
# Installed-environment floor check
# --------------------------------------------------------------------------

_PROBE = r"""
import json, sys
from importlib import metadata
out = {"python": "%d.%d" % sys.version_info[:2], "executable": sys.executable, "sys_platform": sys.platform, "packages": {}}
for dist in metadata.distributions():
    name = (dist.metadata["Name"] or "").lower().replace("_", "-").replace(".", "-")
    if name:
        out["packages"][name] = dist.version
try:
    import certifi
    out["certifi_where"] = certifi.where()
except Exception as exc:
    out["certifi_where"] = None
    out["certifi_error"] = repr(exc)
print(json.dumps(out))
"""


def probe_interpreter(executable: str, timeout: float = 60.0) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            [executable, "-I", "-c", _PROBE],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f"cannot run {executable}: {exc}") from exc
    if completed.returncode != 0:
        raise AuditError(f"{executable} probe failed: {completed.stderr.strip()[:500]}")
    try:
        return json.loads(completed.stdout)
    except ValueError as exc:
        raise AuditError(f"{executable} probe returned malformed output") from exc


def check_installed(
    policy: Policy, probe: Dict[str, Any], required: Sequence[str]
) -> List[str]:
    errors = []
    python = probe["python"]
    installed = {canonicalize_name(k): v for k, v in probe["packages"].items()}
    for name in required:
        if canonicalize_name(name) not in installed:
            errors.append(f"{name} is not installed in {probe['executable']}")
    for floor in policy.floors:
        if python not in floor.pythons or floor.package not in installed:
            continue
        if Version(installed[floor.package]) < Version(floor.minimum):
            errors.append(
                f"{floor.package} {installed[floor.package]} in {probe['executable']} is below the security floor {floor.minimum}"
            )
    return errors


def expected_from_lock(
    graph: Graph, python: str, scopes: Sequence[str]
) -> Dict[str, str]:
    """Versions the reachability model predicts for ``scopes`` on ``python``."""
    expected: Dict[str, str] = {}
    for (name, version), reach in graph.reach.items():
        if any((scope, python) in reach.by_scope_python for scope in scopes):
            if name in expected and expected[name] != version:
                raise AuditError(
                    f"model selects two versions of {name} on Python {python}: {expected[name]} and {version}"
                )
            expected[name] = version
    return expected


def compare_with_lock(expected: Dict[str, str], probe: Dict[str, Any]) -> List[str]:
    installed = {canonicalize_name(k): v for k, v in probe["packages"].items()}
    errors = []
    for name, version in sorted(expected.items()):
        actual = installed.get(name)
        if actual is None:
            errors.append(
                f"{name} {version} is predicted by the audit model but not installed in {probe['executable']}"
            )
        elif Version(actual) != Version(version):
            errors.append(
                f"{name}: audit model predicts {version}, {probe['executable']} has {actual}"
            )
    return errors


def run_installed(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy))
    roots = load_roots(Path(args.pyproject)) if args.expect_lock else {}
    packages = load_lock(Path(args.lock)) if args.expect_lock else {}
    status = EXIT_OK
    for executable in args.python_executable:
        probe = probe_interpreter(executable)
        tracked = sorted({f.package for f in policy.floors})
        versions = ", ".join(
            f"{name}={probe['packages'].get(name, 'absent')}" for name in tracked
        )
        print(f"{probe['executable']} (Python {probe['python']}): {versions}")
        print(
            f"  certifi CA bundle: {probe.get('certifi_where') or 'unavailable: ' + str(probe.get('certifi_error'))}"
        )
        if args.expect_lock:
            if probe.get("sys_platform") not in PLATFORM_ENVIRONMENTS:
                raise AuditError(
                    f"unsupported platform {probe.get('sys_platform')!r} for lock comparison"
                )
            graph = build_graph(
                roots, packages, [probe["python"]], [probe["sys_platform"]]
            )
            expected = expected_from_lock(
                graph, probe["python"], args.scope or [RUNTIME_SCOPE]
            )
            mismatches = compare_with_lock(expected, probe)
            print(
                f"  lock comparison: {len(expected)} predicted packages, {len(mismatches)} mismatches"
            )
            for error in mismatches:
                print(f"error: {error}", file=sys.stderr)
                status = EXIT_POLICY
        for error in check_installed(policy, probe, args.require):
            print(f"error: {error}", file=sys.stderr)
            status = EXIT_POLICY
    return status


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n", maxsplit=1)[0]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit the lockfile against OSV advisories")
    audit.add_argument("--lock", default=str(root / "poetry.lock"))
    audit.add_argument("--pyproject", default=str(root / "pyproject.toml"))
    audit.add_argument(
        "--policy", default=str(root / "tools" / "dependency_audit_policy.toml")
    )
    audit.add_argument("--osv-url", default=OSV_DEFAULT_URL)
    audit.add_argument(
        "--timeout", type=float, default=20.0, help="per-request timeout in seconds"
    )
    audit.add_argument(
        "--deadline",
        type=float,
        default=180.0,
        help="total time budget for advisory lookups",
    )
    audit.add_argument("--max-response-bytes", type=int, default=8 * 1024 * 1024)
    audit.add_argument("--batch-size", type=int, default=200)
    audit.add_argument("--json-report", help="write the full report to this path")
    audit.add_argument("--today", help="evaluate exception expiry as of this ISO date")
    audit.add_argument(
        "--strict-exceptions",
        action="store_true",
        help="fail when a policy exception matched nothing",
    )

    installed = sub.add_parser(
        "installed", help="check security floors in installed interpreters"
    )
    installed.add_argument(
        "--policy", default=str(root / "tools" / "dependency_audit_policy.toml")
    )
    installed.add_argument("--python-executable", action="append", required=True)
    installed.add_argument(
        "--require", action="append", default=[], help="package that must be installed"
    )
    installed.add_argument(
        "--expect-lock",
        action="store_true",
        help="fail if installed versions differ from the audit model's prediction for --scope",
    )
    installed.add_argument("--lock", default=str(root / "poetry.lock"))
    installed.add_argument("--pyproject", default=str(root / "pyproject.toml"))
    installed.add_argument(
        "--scope",
        action="append",
        help="scope installed in the environment (default: runtime)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "audit":
            return run_audit(args)
        return run_installed(args)
    except AuditError as exc:
        print(f"error: dependency audit incomplete: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(main())
