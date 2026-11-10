import base64
import datetime
import decimal
import json
import math
import pickle
import uuid
from collections import OrderedDict
from pathlib import Path
from unittest.mock import Mock

import pytest

from brickflow import BrickflowEnvVars
from brickflow.context import (
    BRANCH_SKIP_EXCEPT,
    RETURN_VALUE_KEY,
    BrickflowTaskComs,
    BrickflowTaskComsObject,
    ctx,
)
from brickflow.context.context import (
    LegacyPickleTaskValueError,
    LegacyPickleTaskValueWarning,
    TaskValueLegacyPickleMode,
    TaskValueLimits,
    TaskValueSerializationError,
    decode_task_value,
    encode_task_value,
    resolve_legacy_pickle_mode,
)

LEGACY_ENV = BrickflowEnvVars.BRICKFLOW_TASK_VALUES_LEGACY_PICKLE.value
PREFIX = '{"__brickflow_task_value__":1,"value":'


@pytest.fixture(autouse=True)
def _isolate_ctx(monkeypatch):
    """Restore the ctx singleton state other tests may leak (e.g. a Mock dbutils)."""
    saved = (ctx._dbutils, ctx._task_coms, ctx._current_task)
    monkeypatch.delenv(LEGACY_ENV, raising=False)
    yield
    ctx._dbutils, ctx._task_coms, ctx._current_task = saved


class _MarkerPayload:
    """Synthetic legacy payload: unpickling creates an empty marker file."""

    def __init__(self, marker: Path):
        self.marker = marker

    def __reduce__(self):
        return open, (str(self.marker), "w")


def _malicious_legacy_value(marker: Path) -> str:
    return base64.b64encode(pickle.dumps(_MarkerPayload(marker))).decode("utf-8")


def _trusted_legacy_value(value) -> str:
    obj = BrickflowTaskComsObject._TaskComsObject(value)
    return base64.b64encode(pickle.dumps(obj)).decode("utf-8")


def _same(a, b) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, float) and math.isnan(a):
        return math.isnan(b)
    if isinstance(a, decimal.Decimal) and a.is_nan():
        return b.is_nan()
    if isinstance(a, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return list(a) == list(b) and all(_same(a[k], b[k]) for k in a)
    return a == b


ROUND_TRIP_VALUES = [
    None,
    True,
    False,
    0,
    -17,
    10**200,
    1.5,
    float("inf"),
    float("-inf"),
    float("nan"),
    "",
    "hello-world",
    'unicode ✓ \u0000 "quoted" \\ back',
    "dGVzdA==",
    [],
    [1, "a", None, [2.5, [True]]],
    (),
    (1, (2, 3), [4]),
    {"a": 1, "b": {"c": [1, 2]}},
    {1: "int-key", (1, 2): "tuple-key", None: 0, "s": "str-key"},
    {"$bf": "tuple", "v": [1]},
    {"__brickflow_task_value__": 1, "value": 2},
    {1, 2, 3},
    frozenset({"a", (1, 2)}),
    set(),
    b"\x00\x80\xffbytes",
    datetime.datetime(2026, 11, 9, 12, 30, 1, 123456),
    datetime.datetime(2026, 11, 9, 12, 30, tzinfo=datetime.timezone.utc),
    datetime.date(2026, 11, 9),
    datetime.time(23, 59, 59, 1),
    datetime.timedelta(days=-1, seconds=5, microseconds=7),
    decimal.Decimal("12345.678900"),
    decimal.Decimal("NaN"),
    uuid.UUID("12345678-1234-5678-1234-567812345678"),
    {"nested": [({"x": frozenset({1})},)]},
]


@pytest.mark.parametrize("value", ROUND_TRIP_VALUES, ids=repr)
def test_round_trip_preserves_value_and_type(value):
    encoded = BrickflowTaskComsObject(value).to_encoded_value
    assert encoded.startswith(PREFIX)
    json.loads(encoded)  # standard JSON, no NaN/Infinity literals
    decoded = BrickflowTaskComsObject.from_encoded_value(encoded).value
    if isinstance(value, (set, frozenset)):
        assert type(decoded) is type(value) and decoded == value
    else:
        assert _same(decoded, value)


def test_plain_json_values_are_readable_json():
    encoded = encode_task_value({"rows": [1, 2], "ok": True, "name": "x"})
    assert json.loads(encoded) == {
        "__brickflow_task_value__": 1,
        "value": {"rows": [1, 2], "ok": True, "name": "x"},
    }


@pytest.mark.parametrize(
    "value",
    [object(), OrderedDict(a=1), Path("x"), [1, object()], {"k": {1, object()}}],
    ids=repr,
)
def test_unsupported_types_fail_at_put(value):
    task_comms = BrickflowTaskComs()
    with pytest.raises(
        TaskValueSerializationError, match="Unsupported task value type"
    ):
        task_comms.put("task", "key", value)
    assert not task_comms.storage


def test_put_error_names_task_and_key():
    with pytest.raises(TaskValueSerializationError, match="task 't1', key 'k1'"):
        BrickflowTaskComs().put("t1", "k1", object())


class TestStringSerialization:
    def test_raw_values_stored_and_returned_unchanged(self):
        dbutils = Mock()
        task_comms = BrickflowTaskComs(dbutils)
        task_comms.put("t", "k", {"a": 1}, string_serialization=True)
        dbutils.jobs.taskValues.set.assert_called_once_with("k", {"a": 1})
        dbutils.jobs.taskValues.get.return_value = {"a": 1}
        assert task_comms.get("t", "k", string_serialization=True) == {"a": 1}

    @pytest.mark.parametrize("raw", ["value 1", "plain", "dGVzdA==", 42, ["x"]])
    def test_default_get_falls_back_to_raw_value(self, raw):
        dbutils = Mock()
        dbutils.jobs.taskValues.get.return_value = raw
        assert BrickflowTaskComs(dbutils).get("t", "k") == raw

    def test_debug_value_outside_jobs(self):
        dbutils = Mock()
        dbutils.jobs.taskValues.get.return_value = "debug"
        assert BrickflowTaskComs(dbutils).get("t", "k") == "debug"

    def test_string_serialization_get_does_not_decode_envelope(self):
        encoded = encode_task_value((1, 2))
        task_comms = BrickflowTaskComs()
        task_comms.put("t", "k", encoded, string_serialization=True)
        assert task_comms.get("t", "k", string_serialization=True) == encoded


class TestLegacyPickleRefusedByDefault:
    def test_from_encoded_value_does_not_execute(self, tmp_path):
        marker = tmp_path / "marker"
        with pytest.raises(LegacyPickleTaskValueError, match=LEGACY_ENV):
            BrickflowTaskComsObject.from_encoded_value(_malicious_legacy_value(marker))
        with pytest.raises(LegacyPickleTaskValueError):
            BrickflowTaskComsObject.from_encoded_value(
                _malicious_legacy_value(marker).encode("utf-8")
            )
        assert not marker.exists()

    def test_dbutils_get_does_not_execute(self, tmp_path):
        marker = tmp_path / "marker"
        dbutils = Mock()
        dbutils.jobs.taskValues.get.return_value = _malicious_legacy_value(marker)
        task_comms = BrickflowTaskComs(dbutils)
        with pytest.raises(LegacyPickleTaskValueError, match="task 'up', key 'k'"):
            task_comms.get("up", "k")
        with pytest.raises(LegacyPickleTaskValueError):
            _ = task_comms.get("up")["k"]
        assert not marker.exists()

    def test_context_return_value_does_not_execute(self, tmp_path):
        marker = tmp_path / "marker"
        ctx._task_coms = BrickflowTaskComs()
        ctx._task_coms.storage["up::" + RETURN_VALUE_KEY] = _malicious_legacy_value(
            marker
        )
        with pytest.raises(LegacyPickleTaskValueError):
            ctx.get_return_value("up")
        assert not marker.exists()

    @pytest.mark.parametrize("setting", ["", "disabled", "false", "OFF", "0"])
    def test_disabled_settings_do_not_execute(self, tmp_path, monkeypatch, setting):
        marker = tmp_path / "marker"
        monkeypatch.setenv(LEGACY_ENV, setting)
        with pytest.raises(LegacyPickleTaskValueError):
            BrickflowTaskComsObject.from_encoded_value(_malicious_legacy_value(marker))
        assert not marker.exists()

    @pytest.mark.parametrize("setting", ["true", "yes", "pickle", "readwrite"])
    def test_unrecognized_setting_fails_closed(self, tmp_path, monkeypatch, setting):
        marker = tmp_path / "marker"
        monkeypatch.setenv(LEGACY_ENV, setting)
        with pytest.raises(ValueError, match=LEGACY_ENV):
            BrickflowTaskComsObject.from_encoded_value(_malicious_legacy_value(marker))
        assert not marker.exists()

    def test_trusted_legacy_value_also_refused(self):
        with pytest.raises(LegacyPickleTaskValueError):
            BrickflowTaskComsObject.from_encoded_value(_trusted_legacy_value("x"))


class TestTrustedLegacyOptIn:
    @pytest.mark.parametrize("value", ["hello", {"a": (1, 2)}, OrderedDict(b=2)])
    def test_read_mode_decodes_trusted_value_with_warning(self, value):
        with pytest.warns(LegacyPickleTaskValueWarning, match="arbitrary code"):
            decoded = BrickflowTaskComsObject.from_encoded_value(
                _trusted_legacy_value(value),
                legacy_pickle=TaskValueLegacyPickleMode.READ,
            ).value
        assert _same(decoded, value)

    def test_env_opt_in_read_mode_still_writes_json(self, monkeypatch):
        monkeypatch.setenv(LEGACY_ENV, "read")
        dbutils = Mock()
        task_comms = BrickflowTaskComs(dbutils)
        task_comms.put("t", "k", "v")
        dbutils.jobs.taskValues.set.assert_called_once_with("k", PREFIX + '"v"}')
        dbutils.jobs.taskValues.get.return_value = _trusted_legacy_value([1])
        with pytest.warns(LegacyPickleTaskValueWarning):
            assert task_comms.get("t", "k") == [1]

    def test_read_write_mode_writes_legacy_format(self):
        task_comms = BrickflowTaskComs(legacy_pickle="read_write")
        with pytest.warns(LegacyPickleTaskValueWarning):
            task_comms.put("t", "k", {"a": object.__name__})
        stored = dict(task_comms.storage)["t::k"]
        assert not stored.startswith(PREFIX)
        # readable by the pre-JSON decoder: base64 of a pickled _TaskComsObject
        assert pickle.loads(base64.b64decode(stored)).value == {"a": "object"}
        with pytest.warns(LegacyPickleTaskValueWarning):
            assert task_comms.get("t", "k") == {"a": "object"}

    def test_instance_setting_overrides_environment(self, monkeypatch):
        monkeypatch.setenv(LEGACY_ENV, "read")
        with pytest.raises(LegacyPickleTaskValueError):
            BrickflowTaskComs(legacy_pickle="disabled")._decode_value(
                _trusted_legacy_value(1), False, "disabled"
            )

    def test_unpickled_object_must_be_task_value(self):
        foreign = base64.b64encode(pickle.dumps({"not": "wrapped"})).decode()
        with pytest.raises(TaskValueSerializationError, match="did not contain"):
            BrickflowTaskComsObject.from_encoded_value(foreign, legacy_pickle="read")

    def test_mode_resolution(self, monkeypatch):
        assert resolve_legacy_pickle_mode() is TaskValueLegacyPickleMode.DISABLED
        monkeypatch.setenv(LEGACY_ENV, " Read_Write ")
        assert resolve_legacy_pickle_mode() is TaskValueLegacyPickleMode.READ_WRITE
        assert (
            resolve_legacy_pickle_mode(TaskValueLegacyPickleMode.READ)
            is TaskValueLegacyPickleMode.READ
        )


def _nested_list(depth: int):
    value: list = []
    for _ in range(depth):
        value = [value]
    return value


class TestBounds:
    limits = TaskValueLimits(
        max_encoded_chars=2000, max_depth=5, max_items=50, max_int_digits=20
    )

    def test_depth_limit_on_encode_and_decode(self):
        encode_task_value(_nested_list(5), self.limits)
        with pytest.raises(TaskValueSerializationError, match="nesting depth"):
            encode_task_value(_nested_list(6), self.limits)
        deep = encode_task_value(_nested_list(6))
        with pytest.raises(TaskValueSerializationError, match="nesting depth"):
            decode_task_value(deep, self.limits)

    def test_tagged_containers_at_max_depth_round_trip(self):
        nested_dicts: object = 0
        for _ in range(5):
            nested_dicts = {1: nested_dicts}
        tuple_key = {((((1,),),),): "v"}
        for value in (nested_dicts, tuple_key):
            encoded = encode_task_value(value, self.limits)
            assert decode_task_value(encoded, self.limits) == value

    def test_deeply_nested_input_rejected_before_parsing(self):
        crafted = PREFIX + "[" * 200_000 + "]" * 200_000 + "}"
        with pytest.raises(TaskValueSerializationError):
            decode_task_value(crafted)

    def test_brackets_inside_strings_do_not_count(self):
        value = "[" * 500 + '{"\\"' + "]" * 3
        assert decode_task_value(encode_task_value(value)) == value

    def test_size_limit(self):
        with pytest.raises(TaskValueSerializationError, match="maximum is 2000"):
            encode_task_value("x" * 2000, self.limits)
        oversized = encode_task_value("x" * 2000)
        with pytest.raises(TaskValueSerializationError, match="maximum is 2000"):
            decode_task_value(oversized, self.limits)

    def test_item_limit(self):
        with pytest.raises(TaskValueSerializationError, match="maximum of 50 items"):
            encode_task_value(list(range(50)), self.limits)
        with pytest.raises(TaskValueSerializationError, match="maximum of 50 items"):
            decode_task_value(encode_task_value(list(range(50))), self.limits)

    def test_integer_digit_limit(self):
        encode_task_value(10**19, self.limits)
        with pytest.raises(TaskValueSerializationError, match="20 digits"):
            encode_task_value(10**20, self.limits)
        with pytest.raises(TaskValueSerializationError, match="digits"):
            decode_task_value(PREFIX + "1" * 5000 + "}")
        with pytest.raises(TaskValueSerializationError, match="digits"):
            encode_task_value(1 << 100_000)

    def test_limits_apply_through_task_comms(self):
        dbutils = Mock()
        dbutils.jobs.taskValues.get.return_value = encode_task_value(list(range(60)))
        with pytest.raises(TaskValueSerializationError, match="key 'k'"):
            BrickflowTaskComs(dbutils, limits=self.limits).get("t", "k")


@pytest.mark.parametrize(
    "crafted",
    [
        PREFIX + "NaN}",
        PREFIX + "Infinity}",
        PREFIX + '{"a":1,"a":2}}',
        PREFIX + '{"$bf":"dict","v":[[1,1],[1,2]]}}',
        PREFIX + '{"$bf":"pickle","v":"gASV"}}',
        PREFIX + '{"$bf":"tuple","v":[1],"x":1}}',
        PREFIX + '{"$bf":"tuple","v":"abc"}}',
        PREFIX + '{"$bf":"set","v":[[1]]}}',
        PREFIX + '{"$bf":"dict","v":[[[1],2]]}}',
        PREFIX + '{"$bf":"dict","v":[[1]]}}',
        PREFIX + '{"$bf":"float","v":"1e999"}}',
        PREFIX + '{"$bf":"bytes","v":"***"}}',
        PREFIX + '{"$bf":"datetime","v":"not-a-date"}}',
        PREFIX + '{"$bf":"timedelta","v":[1,2]}}',
        PREFIX + '{"$bf":"decimal","v":"abc"}}',
        PREFIX + '{"$bf":"uuid","v":"abc"}}',
        PREFIX + '"x","extra":1}',
        '{"__brickflow_task_value__":2,"value":1}',
        '{"__brickflow_task_value__":true,"value":1}',
        '{"__brickflow_task_value__":"1","value":1}',
        PREFIX + "[1,}",
        PREFIX + '"unterminated}',
    ],
)
def test_malformed_envelopes_rejected(crafted):
    with pytest.raises(TaskValueSerializationError):
        BrickflowTaskComsObject.from_encoded_value(crafted)


class TestContextIntegration:
    def test_branch_markers_and_return_values_round_trip(self):
        ctx._task_coms = BrickflowTaskComs()
        ctx._set_current_task("brancher")
        ctx.skip_all_except("chosen")
        ctx._reset_current_task()
        stored = ctx.task_coms.storage["brancher::" + BRANCH_SKIP_EXCEPT]
        assert stored == PREFIX + '"chosen"}'
        assert ctx.task_coms.get("brancher", BRANCH_SKIP_EXCEPT) == "chosen"
        ctx.task_coms.put("producer", RETURN_VALUE_KEY, {"rows": (1, 2)})
        assert ctx.get_return_value("producer") == {"rows": (1, 2)}

    def test_fixture_restores_leaked_dbutils(self):
        _BEFORE_LEAK.append((ctx._dbutils, ctx._task_coms))
        ctx._dbutils = Mock()
        ctx._task_coms = BrickflowTaskComs(Mock())

    def test_ctx_state_restored_after_leak(self):
        assert _BEFORE_LEAK == [(ctx._dbutils, ctx._task_coms)]


_BEFORE_LEAK: list = []


@pytest.mark.parametrize("number", ["1e999", "-1e999", "1" * 5000 + ".0"])
def test_untagged_float_overflow_is_refused(number):
    with pytest.raises(TaskValueSerializationError):
        decode_task_value(PREFIX + number + "}")


@pytest.mark.parametrize(
    "tag", ["bytes", "datetime", "date", "time", "decimal", "uuid", "float"]
)
def test_scalar_tags_require_string_payloads(tag):
    with pytest.raises(TaskValueSerializationError):
        decode_task_value(PREFIX + json.dumps({"$bf": tag, "v": []}) + "}")


def test_wide_json_is_rejected_before_parser_allocation(mocker):
    parser = mocker.patch("brickflow.context.context.json.loads", wraps=json.loads)
    wire = PREFIX + "[" + ",".join(["0"] * 1000) + "]}"
    with pytest.raises(TaskValueSerializationError):
        decode_task_value(wire, TaskValueLimits(max_items=2))
    parser.assert_not_called()


@pytest.mark.parametrize("rule", ["ALL_SUCCESS", "NONE_FAILED"])
@pytest.mark.parametrize("wire_kind", ["legacy", "malformed", "future"])
def test_invalid_branch_marker_stops_consumption(rule, wire_kind):
    from types import SimpleNamespace
    from brickflow.engine.task import Task, BrickflowTriggerRule

    if wire_kind == "legacy":
        wire = base64.b64encode(
            pickle.dumps(BrickflowTaskComsObject._TaskComsObject("chosen"))
        ).decode()
    elif wire_kind == "malformed":
        wire = PREFIX + "[}"
    else:
        wire = '{"__brickflow_task_value__":99,"value":"chosen"}'
    ctx._task_coms = BrickflowTaskComs()
    ctx._task_coms.storage["parent::" + BRANCH_SKIP_EXCEPT] = wire
    child = SimpleNamespace(
        parents=["parent"],
        name="unselected",
        trigger_rule=getattr(BrickflowTriggerRule, rule),
        _get_skip_with_reason=Task._get_skip_with_reason,
    )
    with pytest.raises(TaskValueSerializationError):
        Task.should_skip(child)


@pytest.mark.parametrize("rule", ["ALL_SUCCESS", "NONE_FAILED"])
def test_valid_and_absent_branch_decisions_remain_compatible(rule):
    from types import SimpleNamespace
    from brickflow.engine.task import Task, BrickflowTriggerRule

    ctx._task_coms = BrickflowTaskComs()
    child = SimpleNamespace(
        parents=["parent"],
        name="unselected",
        trigger_rule=getattr(BrickflowTriggerRule, rule),
        _get_skip_with_reason=Task._get_skip_with_reason,
    )
    assert Task.should_skip(child) == (False, None)
    ctx._task_coms.put("parent", BRANCH_SKIP_EXCEPT, "chosen")
    assert Task.should_skip(child)[0] is True
    ctx._task_coms.put("parent", BRANCH_SKIP_EXCEPT, "unselected")
    assert Task.should_skip(child) == (False, None)
