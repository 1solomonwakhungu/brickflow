"""Offline tests for the Snowflake operator against the installed connector.

Nothing here opens a network connection. Connection tests run the real
connector's parameter handling and stub only the step that would open the
login session, so they exercise the API of whichever connector release the
current Python version installs (3.18.x on Python 3.9, 4.x on 3.10+).
"""

import logging
import sys
from unittest import mock

import pytest
import snowflake.connector
from packaging.version import Version
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.constants import OCSPMode

from brickflow_plugins.operators import uc_to_snowflake_operator as sf_op

CONNECTOR_VERSION = Version(snowflake.connector.__version__)

SECRETS = {
    "username": "synthetic_user",
    "password": "synthetic-password-0000",
    "account": "synthetic_account",
    "warehouse": "synthetic_wh",
    "database": "synthetic_db",
    "role": "synthetic_role",
}


def _secrets(with_authenticator=False):
    values = dict(SECRETS)
    if with_authenticator:
        values["authenticator"] = "snowflake"

    def get(_scope, key):
        if key not in values:
            raise KeyError(key)
        return values[key]

    return get


@pytest.fixture(name="operator_ctx")
def operator_ctx_fixture():
    with mock.patch.object(sf_op, "ctx") as ctx:
        ctx.dbutils.secrets.get.side_effect = _secrets()
        yield ctx


@pytest.fixture(name="no_login")
def no_login_fixture():
    """Run the real connection setup but never open the login session."""
    opened = []

    def fake_open(self):
        opened.append(self)

    with mock.patch.object(
        SnowflakeConnection, "_SnowflakeConnection__open_connection", fake_open
    ):
        yield opened


def test_installed_connector_has_the_advisory_fixes():
    if sys.version_info < (3, 10):
        # GHSA-5cc2-282f-jjq2 is fixed in 3.18.1. 4.0-4.5 install on 3.9 but
        # are vulnerable, so the 3.9 range stays on 3.18.x.
        assert Version("3.18.1") <= CONNECTOR_VERSION < Version("4")
    else:
        # GHSA-qqj6-54q6-cxv6 is fixed in 4.7.3 (GHSA-5cc2 in 4.7.1).
        assert Version("4.7.3") <= CONNECTOR_VERSION < Version("5")


@pytest.mark.parametrize("with_authenticator", [False, True])
def test_connection_keeps_ocsp_revocation_checks_on(
    operator_ctx, no_login, with_authenticator
):
    operator_ctx.dbutils.secrets.get.side_effect = _secrets(with_authenticator)
    operator = sf_op.SnowflakeOperator(secret_scope="scope", query_string="select 1")

    conn = operator.get_snowflake_connection()

    assert isinstance(conn, SnowflakeConnection)
    assert no_login == [conn]
    # 4.8 disables OCSP unless the caller opts in; the operator opts in on
    # every release, matching the 3.x fail-open default.
    assert conn._ocsp_mode() == OCSPMode.FAIL_OPEN
    assert conn.user == SECRETS["username"]
    assert conn.account == SECRETS["account"]
    assert conn.host == "synthetic_account.snowflakecomputing.com"
    assert conn.database == SECRETS["database"]
    assert conn.warehouse == SECRETS["warehouse"]
    assert conn.role == SECRETS["role"]
    if with_authenticator:
        assert conn._authenticator.upper() == "SNOWFLAKE"


@pytest.mark.usefixtures("no_login")
def test_connector_default_ocsp_mode_is_why_the_operator_opts_in():
    conn = SnowflakeConnection(
        user="u", password="p", account="synthetic_account", database="d"
    )
    expected = (
        OCSPMode.DISABLE_OCSP_CHECKS
        if CONNECTOR_VERSION >= Version("4.8")
        else OCSPMode.FAIL_OPEN
    )
    assert conn._ocsp_mode() == expected


@pytest.mark.usefixtures("operator_ctx", "no_login")
def test_revocation_setting_is_not_shared_mutable_state():
    operator = sf_op.SnowflakeOperator(secret_scope="scope", query_string="select 1")
    operator.get_snowflake_connection()
    operator.get_snowflake_connection()
    assert sf_op._REVOCATION_CHECK == {"ocsp_fail_open": True}


@pytest.mark.usefixtures("operator_ctx")
def test_programming_error_from_connect_is_reported():
    error = snowflake.connector.errors.ProgrammingError(
        msg="Incorrect username or password was specified.",
        errno=251005,
        sqlstate="08001",
        sfqid="synthetic-qid",
    )
    operator = sf_op.SnowflakeOperator(secret_scope="scope", query_string="select 1")
    with mock.patch.object(snowflake.connector, "connect", side_effect=error):
        with pytest.raises(ValueError) as excinfo:
            operator.get_cursor()
    message = str(excinfo.value)
    assert "251005" in message and "08001" in message and "synthetic-qid" in message
    assert SECRETS["password"] not in message


@pytest.mark.usefixtures("operator_ctx")
def test_execute_runs_each_statement_and_closes(caplog):
    connection = mock.MagicMock()
    cursor = connection.cursor.return_value
    operator = sf_op.SnowflakeOperator(
        secret_scope="scope",
        query_string="select $value; select 2",
        parameters={"value": "1"},
    )
    with (
        mock.patch.object(
            snowflake.connector, "connect", return_value=connection
        ) as connect,
        caplog.at_level(logging.INFO),
    ):
        operator.execute()

    kwargs = connect.call_args.kwargs
    assert kwargs["ocsp_fail_open"] is True
    assert kwargs["password"] == SECRETS["password"]
    executed = [c.args[0] for c in cursor.execute.call_args_list]
    assert executed == ["use synthetic_db", "select 1", " select 2"]
    connection.close.assert_called_once_with()
    assert SECRETS["password"] not in caplog.text


@pytest.mark.usefixtures("operator_ctx")
def test_statement_error_maps_programming_error():
    connection = mock.MagicMock()
    cursor = connection.cursor.return_value
    cursor.execute.side_effect = [
        None,
        snowflake.connector.errors.ProgrammingError(
            msg="SQL compilation error", errno=1003, sqlstate="42000", sfqid="q-1"
        ),
    ]
    operator = sf_op.SnowflakeOperator(secret_scope="scope", query_string="select x")
    with mock.patch.object(snowflake.connector, "connect", return_value=connection):
        with pytest.raises(ValueError, match=r"Error 1003 \(42000\).*\(q-1\)"):
            operator.execute()
    connection.close.assert_called_once_with()
