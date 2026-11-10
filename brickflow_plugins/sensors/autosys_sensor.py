"""
Autosys Sensor.

Native brickflow sensor that polls the Autosys REST API to wait for a job
to reach a successful state. Requires only ``requests`` -- no
``apache-airflow`` package needs to be installed on the Databricks cluster.
"""

from __future__ import annotations

import os
import time
from datetime import timedelta
from typing import Optional, Union

import pytz
import requests
from dateutil.parser import parse  # type: ignore[import-untyped]
from requests import HTTPError

from brickflow_plugins import log
from brickflow_plugins.sensors import Sensor


def _resolve_tls_verify(
    ca_bundle: Optional[Union[str, "os.PathLike[str]"]],
) -> Union[bool, str]:
    """Return the ``requests`` ``verify`` value; verification is always on."""
    if ca_bundle is None:
        return True
    ca_path = os.fspath(ca_bundle)
    if not isinstance(ca_path, str) or not ca_path:
        raise ValueError("'ca_bundle' must be a non-empty filesystem path.")
    return ca_path


class AutosysSensor(Sensor):
    """
    Sensor that polls an Autosys REST endpoint for the given ``job_name``
    and waits until it reports a successful status recent enough to satisfy
    ``time_delta``.

    The server certificate is always verified. Pass ``ca_bundle`` (a CA
    bundle file or OpenSSL hashed certificate directory) to trust a private
    certificate authority; otherwise the default trust store is used
    (``requests`` also honors the ``REQUESTS_CA_BUNDLE`` environment variable).

    Example
    -------
    ::

        sensor = AutosysSensor(
            url="https://autosys.example.com/api/jobs",
            job_name="my_upstream_job",
            poke_interval=60,
            time_delta=timedelta(hours=1),
        )
        sensor.poke()
    """

    def __init__(
        self,
        url: str,
        job_name: str,
        poke_interval: int,
        time_delta: Union[timedelta, dict] = timedelta(days=0),
        ca_bundle: Optional[Union[str, "os.PathLike[str]"]] = None,
    ) -> None:
        self.ca_bundle = ca_bundle
        self._verify = _resolve_tls_verify(ca_bundle)
        super().__init__()
        self.url = str(url).rstrip("/")
        self.job_name = job_name
        self.poke_interval = poke_interval
        self.time_delta = time_delta

    def poke(self):  # type: ignore[override]
        """Poke the Autosys API once. Recurses (via ``time.sleep`` + self-call) until success."""
        url = f"{self.url}/{self.job_name}"
        log.info("Poking: %s", url)

        headers = {
            "Accept": "application/json",
            "cache-control": "no-cache",
        }

        response = requests.get(
            url,
            headers=headers,
            verify=self._verify,
            timeout=10,
        )

        if response.status_code != 200:
            raise HTTPError(
                f"Request failed with '{response.status_code}' code. \n{response.text}"
            )

        status = response.json()["status"][:2].upper()

        last_end_timestamp = None
        if last_end_utc := response.json().get("lastEndUTC"):
            last_end_timestamp = parse(last_end_utc).replace(tzinfo=pytz.UTC)

        time_delta = (
            self.time_delta
            if isinstance(self.time_delta, timedelta)
            else timedelta(**self.time_delta)
        )

        run_timestamp = self._execution_timestamp - time_delta

        if (
            "SU" in status
            and last_end_timestamp
            and last_end_timestamp >= run_timestamp
        ):
            log.info(
                "Last End: %s, Run Timestamp: %s", last_end_timestamp, run_timestamp
            )
            log.info("Success criteria met. Exiting")
            return True

        log.info("Last End: %s, Run Timestamp: %s", last_end_timestamp, run_timestamp)
        time.sleep(self.poke_interval)
        log.info("Poking again")
        return AutosysSensor.poke(self)
