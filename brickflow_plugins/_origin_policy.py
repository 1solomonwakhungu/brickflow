"""Per-client request-origin policy for connector HTTP sessions.

A connector that sends credentials to a configured server can bind its
``requests`` session to that server's origin. :class:`OriginBoundSession`
checks the URL of every request immediately before it is handed to a
transport adapter, which covers requests the client library issues itself
(including redirects it follows by hand) and redirects that ``requests``
follows automatically. A request for any other origin raises
:class:`CrossOriginRequestError` before a connection is opened, so neither
headers nor body reach that host.

The policy is scoped to the session instance it is installed on. It does not
patch ``requests`` globally and does not affect other clients.
"""

from __future__ import annotations

from typing import Any, NamedTuple, Union
from urllib.parse import urlsplit

import requests
from requests.models import PreparedRequest

_DEFAULT_PORTS = {"http": 80, "https": 443}


class Origin(NamedTuple):
    """A URL origin: scheme, lower-case host and effective port."""

    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


class CrossOriginRequestError(requests.exceptions.RequestException):
    """Raised instead of sending a request whose origin is not allowed.

    No connection is opened for the refused request. The message names the
    refused and the allowed origins only; it never contains the path, query,
    headers or body of the refused request.
    """


def _normalized_url(url: str) -> str:
    """Normalize ``url`` the same way ``requests`` does before sending."""
    prepared = PreparedRequest()
    prepared.prepare_url(url, None)
    return prepared.url or ""


def origin_of(url: str) -> Origin:
    """Return the origin of an absolute ``http``/``https`` URL.

    Raises :class:`ValueError` when the URL has no host, an unsupported
    scheme or an invalid port.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"Unsupported URL scheme {parts.scheme!r}.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError("URL has no host.")
    port = parts.port  # raises ValueError for an out-of-range port
    return Origin(scheme, host.lower(), port or _DEFAULT_PORTS[scheme])


def https_origin(url: str, *, setting: str = "server") -> Origin:
    """Validate a configured server URL and return its HTTPS origin.

    The URL must be absolute, use ``https`` and carry no user information.
    There is no plaintext fallback: ``http://`` and scheme-less addresses are
    rejected with :class:`ValueError`.
    """
    if not isinstance(url, str) or not url:
        raise ValueError(f"'{setting}' must be a non-empty HTTPS URL.")
    if urlsplit(url).scheme.lower() != "https":
        raise ValueError(
            f"'{setting}' must be an https:// URL; plaintext and scheme-less "
            "addresses are not supported."
        )
    try:
        normalized = _normalized_url(url)
        parts = urlsplit(normalized)
        origin = origin_of(normalized)
    except (ValueError, requests.exceptions.RequestException) as exc:
        raise ValueError(f"'{setting}' is not a valid HTTPS URL.") from exc
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"'{setting}' must not contain user information.")
    return origin


def _request_origin(url: Union[str, bytes, None]) -> Union[Origin, None]:
    if isinstance(url, bytes):
        url = url.decode("utf-8", "replace")
    try:
        return origin_of(url or "")
    except ValueError:
        return None


class OriginBoundSession(requests.Session):
    """A ``requests`` session that only sends to one HTTPS origin.

    ``Session.send`` is the single path through which both direct requests and
    automatically followed redirects reach the transport adapter, so the
    origin check runs once per actual send, including every redirect hop.
    Same-origin redirects keep working; cross-origin redirects and HTTPS to
    HTTP downgrades raise :class:`CrossOriginRequestError` before the request
    is sent.
    """

    __attrs__ = requests.Session.__attrs__ + ["allowed_origin"]

    def __init__(self, allowed_origin: Origin) -> None:
        super().__init__()
        if allowed_origin.scheme != "https":
            raise ValueError("OriginBoundSession requires an HTTPS origin.")
        self.allowed_origin = allowed_origin

    def send(self, request: PreparedRequest, **kwargs: Any) -> requests.Response:
        target = _request_origin(request.url)
        if target != self.allowed_origin:
            refused = str(target) if target is not None else "an unparseable URL"
            raise CrossOriginRequestError(
                f"Refused to send a request to {refused}; this client may only "
                f"send to {self.allowed_origin}."
            )
        return super().send(request, **kwargs)
