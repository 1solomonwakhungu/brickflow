"""Generic task executor for injected tasks."""

import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from jinja2 import Template
from brickflow import _ilog as log
from brickflow.engine.task_injection_config import TaskDefinition

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_SAFE_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,16}$")
_REDACTED = "<redacted>"


class ArtifactDownloadError(requests.RequestException):
    """Raised when an artifact download is refused or fails.

    Messages never contain URL user-info or query strings.
    """


def redact_url(url: str) -> str:
    """Return ``url`` without user-info, and with its query and fragment masked."""
    try:
        parts = urlsplit(url)
        netloc = parts.hostname or ""
        if ":" in netloc:
            netloc = f"[{netloc}]"
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"
    except ValueError:
        return _REDACTED
    return urlunsplit(
        (
            parts.scheme,
            netloc,
            parts.path,
            _REDACTED if parts.query else "",
            _REDACTED if parts.fragment else "",
        )
    )


def _origin(url: str) -> Tuple[str, str, int]:
    """Return the (scheme, host, port) origin of an http(s) URL."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as e:
        raise ArtifactDownloadError(f"Invalid artifact URL: {redact_url(url)}") from e
    if scheme not in _DEFAULT_PORTS or not host:
        raise ArtifactDownloadError(
            f"Unsupported artifact URL (only http and https are allowed): "
            f"{redact_url(url)}"
        )
    return scheme, host, port if port is not None else _DEFAULT_PORTS[scheme]


def _has_userinfo(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return parts.username is not None or parts.password is not None
    except ValueError:
        return False


def _sanitize_message(message: str, urls: Iterable[str]) -> str:
    """Remove user-info and query strings of the given URLs from ``message``."""
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        message = message.replace(url, redact_url(url))
        if parts.query:
            message = message.replace(parts.query, _REDACTED)
        if parts.fragment:
            message = message.replace(parts.fragment, _REDACTED)
        userinfo, sep, _ = parts.netloc.rpartition("@")
        if sep and userinfo:
            message = message.replace(userinfo + "@", "")
            message = message.replace(userinfo, _REDACTED)
    return message


def _content_length(response: requests.Response) -> Optional[int]:
    raw = response.headers.get("Content-Length")
    if not isinstance(raw, str):
        return None
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def _open_exclusive_sibling(target: Path, mode: int) -> Tuple[int, Path]:
    """Create a new, uniquely named file next to ``target``.

    The file is created with ``O_EXCL`` (and ``O_NOFOLLOW`` where available), so
    it can never be an existing file or a symlink planted at that name.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    for _ in range(100):
        candidate = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
        try:
            return os.open(candidate, flags, mode), candidate
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a temporary file next to {target}")


def _write_atomically(target: Path, chunks: Iterable[bytes], mode: int) -> None:
    """Write ``chunks`` to a sibling temporary file, then rename it over ``target``.

    ``os.replace`` swaps the directory entry itself, so a pre-existing symlink at
    ``target`` is replaced rather than followed. The temporary file is removed if
    anything fails.
    """
    fd, staging = _open_exclusive_sibling(target, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            for chunk in chunks:
                f.write(chunk)
        os.replace(staging, target)
    except BaseException:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass
        raise


class ArtifactoryClient:
    """Client for downloading artifacts from Artifactory.

    When both ``username`` and ``api_key`` are set, downloads are credentialed:

    * the artifact URL must use HTTPS;
    * redirects are followed manually, at most ``max_redirects`` times;
    * the API key header is sent only while the request stays on the original
      origin (scheme, host and port). After the first cross-origin redirect it
      is never sent again;
    * a redirect to a non-HTTPS URL is refused.

    URLs containing user-info are treated as credentialed as well. Downloads
    without credentials may use plain HTTP, as before.

    Every download is limited to ``max_bytes`` of (decoded) content and is
    written to a temporary file that is atomically renamed into place.
    """

    API_KEY_HEADER = "X-JFrog-Art-Api"
    DEFAULT_MAX_REDIRECTS = 5
    DEFAULT_MAX_BYTES = 1024 * 1024 * 1024  # 1 GiB
    DEFAULT_TIMEOUT = 300
    CHUNK_SIZE = 8192

    def __init__(
        self,
        username: Optional[str] = None,
        api_key: Optional[str] = None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        if max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.username = username
        self.api_key = api_key
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    @property
    def has_credentials(self) -> bool:
        return bool(self.username and self.api_key)

    def download_artifact(self, url: str, destination: Optional[Path] = None) -> Path:
        """
        Download artifact from Artifactory.

        Args:
            url: URL of the artifact
            destination: Optional destination path. If not provided, creates temp file.

        Returns:
            Path to downloaded artifact

        Raises:
            ArtifactDownloadError: if the URL or a redirect violates the download
                policy, the response is too large, or the HTTP request fails.
        """
        safe_url = redact_url(url)
        log.info("Downloading artifact from: %s", safe_url)

        seen_urls: List[str] = [url]
        created_destination: Optional[Path] = None
        succeeded = False
        try:
            response = self._open(url, seen_urls)
            try:
                declared = _content_length(response)
                if declared is not None and declared > self.max_bytes:
                    raise ArtifactDownloadError(
                        f"Artifact {safe_url} is {declared} bytes, "
                        f"which exceeds the {self.max_bytes}-byte limit"
                    )

                if destination is None:
                    created_destination = self._create_temp_destination(url)
                    destination = created_destination
                    file_mode = 0o600
                else:
                    destination = Path(destination)
                    file_mode = 0o666

                _write_atomically(
                    destination, self._bounded_chunks(response, safe_url), file_mode
                )
            finally:
                response.close()

            succeeded = True
            log.info("Downloaded artifact to: %s", destination)
            return destination

        except Exception as e:
            message = _sanitize_message(str(e), seen_urls)
            log.error(
                "Failed to download artifact from %s: %s: %s",
                safe_url,
                type(e).__name__,
                message,
            )
            if isinstance(e, ArtifactDownloadError):
                raise
            if isinstance(e, requests.RequestException):
                # Re-raise without chaining: the original message and traceback
                # can contain the URL's user-info or query string.
                raise ArtifactDownloadError(
                    f"{type(e).__name__}: {message}",
                    response=getattr(e, "response", None),
                ) from None
            raise
        finally:
            if not succeeded and created_destination is not None:
                try:
                    created_destination.unlink()
                except FileNotFoundError:
                    pass

    def _open(self, url: str, seen_urls: List[str]) -> requests.Response:
        """Issue the GET request, following redirects under the download policy."""
        credentialed = self.has_credentials or _has_userinfo(url)
        initial_origin = _origin(url)
        if credentialed and initial_origin[0] != "https":
            raise ArtifactDownloadError(
                f"Refusing to send credentials over {initial_origin[0]}: "
                f"{redact_url(url)} (use an https URL)"
            )

        send_api_key = self.has_credentials
        current = url
        redirects = 0
        while True:
            origin = _origin(current)
            if credentialed and origin[0] != "https":
                raise ArtifactDownloadError(
                    f"Refusing redirect from https to {origin[0]}: {redact_url(current)}"
                )
            if send_api_key and origin != initial_origin:
                # Never forward the API key to another origin, nor resume
                # sending it if a later redirect points back.
                send_api_key = False

            headers = {"Accept-Encoding": "identity"}
            if send_api_key:
                headers[self.API_KEY_HEADER] = self.api_key  # type: ignore[assignment]

            response = requests.get(
                current,
                headers=headers,
                stream=True,
                timeout=self.DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            if response.status_code not in _REDIRECT_STATUSES:
                try:
                    response.raise_for_status()
                except BaseException:
                    response.close()
                    raise
                return response

            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ArtifactDownloadError(
                    f"Redirect without a Location header from {redact_url(current)}"
                )
            if redirects >= self.max_redirects:
                raise ArtifactDownloadError(
                    f"Too many redirects (limit {self.max_redirects}) "
                    f"while downloading {redact_url(url)}"
                )
            redirects += 1
            current = urljoin(current, location)
            seen_urls.append(current)
            log.info("Following artifact redirect to: %s", redact_url(current))

    def _bounded_chunks(
        self, response: requests.Response, safe_url: str
    ) -> Iterable[bytes]:
        total = 0
        for chunk in response.iter_content(chunk_size=self.CHUNK_SIZE):
            if not chunk:
                continue
            total += len(chunk)
            if total > self.max_bytes:
                raise ArtifactDownloadError(
                    f"Artifact {safe_url} exceeds the {self.max_bytes}-byte limit"
                )
            yield chunk

    @staticmethod
    def _create_temp_destination(url: str) -> Path:
        try:
            suffix = Path(urlsplit(url).path).suffix
        except ValueError:
            suffix = ""
        if not _SAFE_SUFFIX.match(suffix):
            suffix = ".whl"
        fd, name = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return Path(name)


class GenericTaskExecutor:
    """Executor for generic injected tasks with template support."""

    DEFAULT_TEMPLATE_PATH = (
        Path(__file__).parent.parent / "templates" / "injected_task_default.py.j2"
    )

    def __init__(self, task_def: TaskDefinition):
        self.task_def = task_def
        self.artifactory_client = None

        if task_def.artifact:
            self.artifactory_client = ArtifactoryClient(
                username=task_def.artifact.username, api_key=task_def.artifact.api_key
            )

    def create_task_function(self) -> Callable:
        """
        Create the task function that will be executed on Databricks.

        This function:
        1. Downloads artifact if needed (at task runtime on cluster)
        2. Renders the Python template with provided context
        3. Executes the rendered code

        Returns:
            Callable task function
        """
        task_def = self.task_def

        def injected_task_function() -> Any:
            """Dynamically generated task function."""
            # Download and setup artifact if specified
            if task_def.artifact:
                artifact_path = self._download_and_setup_artifact(
                    task_def.artifact.url,
                    task_def.artifact.username,
                    task_def.artifact.api_key,
                )
                log.info("Artifact setup complete: %s", artifact_path)

            # Load and render template
            template_code = self._load_and_render_template(task_def)

            # Execute the rendered code
            log.info("Executing task: %s", task_def.task_name)
            local_vars: Dict[str, Any] = {}
            exec(template_code, globals(), local_vars)  # pylint: disable=exec-used

            # Return result if present
            return local_vars.get("result")

        # Set function name for better debugging
        injected_task_function.__name__ = task_def.task_name

        return injected_task_function

    def _load_and_render_template(self, task_def: TaskDefinition) -> str:
        """
        Load Python template file and render with Jinja2.

        Args:
            task_def: Task definition with template info

        Returns:
            Rendered Python code as string
        """
        # Determine template file to use
        if task_def.template_file:
            template_path = Path(task_def.template_file)
            if not template_path.is_absolute():
                # Resolve relative to workspace or config file location
                template_path = Path.cwd() / template_path

            if not template_path.exists():
                log.warning(
                    "Custom template file not found: %s. Using default.",
                    template_path,
                )
                template_path = self.DEFAULT_TEMPLATE_PATH
        else:
            template_path = self.DEFAULT_TEMPLATE_PATH

        log.info("Using template: %s", template_path)

        # Load template
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

        # Render template with context
        template = Template(template_content)
        rendered_code = template.render(**task_def.template_context)

        log.debug("Rendered template for %s:\n%s", task_def.task_name, rendered_code)

        return rendered_code

    @staticmethod
    def _download_and_setup_artifact(
        url: str, username: Optional[str], api_key: Optional[str]
    ) -> Path:
        """
        Download artifact and add to sys.path if needed.

        This runs at task execution time on the Databricks cluster.
        """
        client = ArtifactoryClient(username=username, api_key=api_key)
        artifact_path = client.download_artifact(url)

        # If it's a wheel or zip, add to sys.path
        if artifact_path.suffix in [".whl", ".zip"]:
            sys.path.insert(0, str(artifact_path))
            log.info("Added %s to sys.path", artifact_path)

        return artifact_path

    def render_to_notebook(self) -> str:
        """
        Render template directly to a Databricks Python notebook file.

        Single pass: template rendered once, written as notebook, executed natively.
        No exec() needed - Databricks runs this as a standard notebook.

        Returns:
            Relative path to generated notebook for NOTEBOOK_TASK reference
        """
        # Render template once
        rendered_code = self._load_and_render_template(self.task_def)

        # Create notebooks directory
        notebooks_dir = Path("_brickflow_injected_notebooks")
        notebooks_dir.mkdir(parents=True, exist_ok=True)

        # Add Databricks notebook header
        # This magic comment is required for Databricks to recognize .py files as notebooks
        notebook_content = f"# Databricks notebook source\n\n{rendered_code}"

        # Write as Python notebook (.py format)
        # Databricks recognizes .py files as notebooks when source=WORKSPACE
        notebook_file = notebooks_dir / f"{self.task_def.task_name}.py"
        notebook_file.write_text(notebook_content, encoding="utf-8")

        log.info("Generated notebook: %s", notebook_file)

        # Return workspace-relative path for NOTEBOOK_TASK reference
        return f"_brickflow_injected_notebooks/{self.task_def.task_name}.py"
