import base64
import datetime
import decimal
import json
import math
import time
import uuid
import warnings

import binascii
import copy
import functools
import logging
import pickle
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Optional,
    Any,
    Union,
    Callable,
    Dict,
    List,
    TypeVar,
    Iterator,
)
from collections.abc import Hashable

from decouple import config

from brickflow import log, _ilog, BrickflowEnvVars, BrickflowDefaultEnvs, deprecated

BRANCH_SKIP_EXCEPT = "branch_skip_except"
SKIP_EXCEPT_HACK = "brickflow_hack_skip_all"
RETURN_VALUE_KEY = "return_value"

T = TypeVar("T")


# TODO: remove
class ContextMode(Enum):
    databricks = "databricks"
    not_databricks = "not_databricks"


class BrickflowBuiltInTaskVariables(Enum):
    # key is the {{ }} and value is the key
    job_id = "brickflow_job_id"
    run_id = "brickflow_run_id"
    start_date = "brickflow_start_date"
    start_time = "brickflow_start_time"
    task_retry_count = "brickflow_task_retry_count"
    parent_run_id = "brickflow_parent_run_id"
    task_key = "brickflow_task_key"


class BrickflowInternalVariables(Enum):
    workflow_id = "brickflow_internal_workflow_name"
    task_id = "brickflow_internal_task_name"
    only_run_tasks = "brickflow_internal_only_run_tasks"
    workflow_prefix = "brickflow_internal_workflow_prefix"
    workflow_suffix = "brickflow_internal_workflow_suffix"
    env = BrickflowEnvVars.BRICKFLOW_ENV.value.lower()


def bind_variable(builtin: BrickflowBuiltInTaskVariables) -> Callable:
    def wrapper(f: Callable) -> Callable:
        @functools.wraps(f)
        def func(*args, **kwargs):  # type: ignore
            _self: Context = args[0]  # type: ignore
            debug = kwargs["debug"]
            f(*args, **kwargs)  # no-op
            if _self.dbutils is not None:
                return _self.get_parameter(builtin.value, debug)
            return debug

        return func

    return wrapper


class TaskComsObjectResult(Enum):
    NO_RESULTS = "NO_RESULTS"


class TaskValueSerializationError(ValueError):
    """A task value could not be encoded or decoded safely."""


class LegacyPickleTaskValueError(TaskValueSerializationError):
    """A legacy pickle+base64 task value was refused because legacy pickle decoding is not enabled."""


class LegacyPickleTaskValueWarning(UserWarning):
    """Emitted whenever the trusted-only legacy pickle task value transport is used."""


class TaskValueLegacyPickleMode(Enum):
    """Controls the legacy pickle+base64 task value transport.

    DISABLED: values are written as versioned JSON; legacy pickle values are refused, never unpickled.
    READ: values are written as versioned JSON; legacy pickle values from trusted producers are unpickled.
    READ_WRITE: values are written and read as legacy pickle+base64 (pre-JSON behavior) for consumers
        that still run an older brickflow version.
    """

    DISABLED = "disabled"
    READ = "read"
    READ_WRITE = "read_write"


_LEGACY_PICKLE_DISABLED_ALIASES = {"", "disabled", "false", "no", "off", "0", "none"}


def resolve_legacy_pickle_mode(
    mode: Optional[Union[str, TaskValueLegacyPickleMode]] = None,
) -> TaskValueLegacyPickleMode:
    """Resolve the legacy pickle mode from an explicit value or the
    BRICKFLOW_TASK_VALUES_LEGACY_PICKLE environment variable (default: disabled).
    Unrecognized values raise instead of silently enabling or disabling pickle."""
    if isinstance(mode, TaskValueLegacyPickleMode):
        return mode
    raw = (
        mode
        if mode is not None
        else config(BrickflowEnvVars.BRICKFLOW_TASK_VALUES_LEGACY_PICKLE.value, "")
    )
    normalized = str(raw).strip().lower()
    if normalized in _LEGACY_PICKLE_DISABLED_ALIASES:
        return TaskValueLegacyPickleMode.DISABLED
    for member in TaskValueLegacyPickleMode:
        if normalized == member.value:
            return member
    raise TaskValueSerializationError(
        f"Invalid {BrickflowEnvVars.BRICKFLOW_TASK_VALUES_LEGACY_PICKLE.value} value: {raw!r}; "
        f"expected one of {[m.value for m in TaskValueLegacyPickleMode]}"
    )


@dataclass(frozen=True)
class TaskValueLimits:
    """Bounds applied when encoding and decoding task values.

    max_encoded_chars: maximum length of an encoded task value string.
    max_depth: maximum container nesting depth of the logical value.
    max_items: maximum total number of values (containers and scalars) in the logical value.
    max_int_digits: maximum number of digits in an integer.
    """

    max_encoded_chars: int = 1024 * 1024
    max_depth: int = 64
    max_items: int = 100_000
    max_int_digits: int = 4300


DEFAULT_TASK_VALUE_LIMITS = TaskValueLimits()

TASK_VALUE_ENVELOPE_KEY = "__brickflow_task_value__"
TASK_VALUE_ENVELOPE_VERSION = 1
_ENVELOPE_PREFIX = '{"' + TASK_VALUE_ENVELOPE_KEY + '":'
_TYPE_TAG = "$bf"
_SUPPORTED_TYPES_DESCRIPTION = (
    "None, bool, int, float, str, bytes, list, tuple, dict, set, frozenset, "
    "datetime.datetime, datetime.date, datetime.time, datetime.timedelta, decimal.Decimal, uuid.UUID"
)


class _Budget:
    def __init__(self, limits: TaskValueLimits) -> None:
        self.limits = limits
        self.items = 0

    def visit(self, depth: int) -> None:
        self.items += 1
        if self.items > self.limits.max_items:
            raise TaskValueSerializationError(
                f"Task value exceeds the maximum of {self.limits.max_items} items"
            )
        if depth > self.limits.max_depth:
            raise TaskValueSerializationError(
                f"Task value exceeds the maximum nesting depth of {self.limits.max_depth}"
            )


def _tagged(tag: str, value: Any) -> Dict[str, Any]:
    return {_TYPE_TAG: tag, "v": value}


def _check_int_digits(value: int, limits: TaskValueLimits) -> None:
    # bit_length bounds the digit count without an expensive str() of a huge integer
    too_long = value.bit_length() > limits.max_int_digits * 4
    if not too_long:
        try:
            too_long = len(str(abs(value))) > limits.max_int_digits
        except ValueError:  # interpreter int/str conversion limit
            too_long = True
    if too_long:
        raise TaskValueSerializationError(
            f"Integer task value exceeds {limits.max_int_digits} digits"
        )


# Each supported wire type has its own explicit return.
# pylint: disable-next=too-many-return-statements
def _to_json_tree(value: Any, budget: _Budget, depth: int = 0) -> Any:
    budget.visit(depth)
    value_type = type(value)
    if value is None or value_type in (bool, str):
        return value
    if value_type is int:
        _check_int_digits(value, budget.limits)
        return value
    if value_type is float:
        if math.isfinite(value):
            return value
        return _tagged("float", repr(value))
    if value_type is list:
        return [_to_json_tree(v, budget, depth + 1) for v in value]
    if value_type is tuple:
        return _tagged("tuple", [_to_json_tree(v, budget, depth + 1) for v in value])
    if value_type in (set, frozenset):
        return _tagged(
            value_type.__name__, [_to_json_tree(v, budget, depth + 1) for v in value]
        )
    if value_type is dict:
        if all(k.__class__ is str for k in value) and _TYPE_TAG not in value:
            return {k: _to_json_tree(v, budget, depth + 1) for k, v in value.items()}
        return _tagged(
            "dict",
            [
                [
                    _to_json_tree(k, budget, depth + 1),
                    _to_json_tree(v, budget, depth + 1),
                ]
                for k, v in value.items()
            ],
        )
    if value_type is bytes:
        return _tagged("bytes", base64.b64encode(value).decode("ascii"))
    if value_type is datetime.datetime:
        return _tagged("datetime", value.isoformat())
    if value_type is datetime.date:
        return _tagged("date", value.isoformat())
    if value_type is datetime.time:
        return _tagged("time", value.isoformat())
    if value_type is datetime.timedelta:
        return _tagged("timedelta", [value.days, value.seconds, value.microseconds])
    if value_type is decimal.Decimal:
        return _tagged("decimal", str(value))
    if value_type is uuid.UUID:
        return _tagged("uuid", str(value))
    raise TaskValueSerializationError(
        f"Unsupported task value type: {value_type.__module__}.{value_type.__qualname__}. "
        f"Supported types: {_SUPPORTED_TYPES_DESCRIPTION}. Convert the value, use "
        f"string_serialization=True for JSON-compatible values, or see docs/task-value-transport.md "
        f"for the trusted-only legacy pickle transport."
    )


def _expect(cond: bool, message: str) -> None:
    if not cond:
        raise TaskValueSerializationError(f"Malformed task value: {message}")


# Each supported wire type has its own explicit return.
# pylint: disable-next=too-many-return-statements
def _from_json_tree(node: Any, budget: _Budget, depth: int = 0) -> Any:
    budget.visit(depth)
    if node is None or isinstance(node, (bool, str, int, float)):
        return node
    if isinstance(node, list):
        return [_from_json_tree(v, budget, depth + 1) for v in node]
    _expect(isinstance(node, dict), f"unexpected JSON node {type(node).__name__}")
    if _TYPE_TAG not in node:
        return {k: _from_json_tree(v, budget, depth + 1) for k, v in node.items()}
    _expect(
        set(node) == {_TYPE_TAG, "v"}, "tagged value must have exactly '$bf' and 'v'"
    )
    tag, payload = node[_TYPE_TAG], node["v"]
    try:
        if tag == "dict":
            _expect(isinstance(payload, list), "dict payload must be a list")
            result = {}
            for pair in payload:
                _expect(
                    isinstance(pair, list) and len(pair) == 2,
                    "dict payload must contain [key, value] pairs",
                )
                k = _from_json_tree(pair[0], budget, depth + 1)
                _expect(k not in result, f"duplicate key {k!r}")
                result[k] = _from_json_tree(pair[1], budget, depth + 1)
            return result
        if tag in ("tuple", "set", "frozenset"):
            _expect(isinstance(payload, list), f"{tag} payload must be a list")
            items = [_from_json_tree(v, budget, depth + 1) for v in payload]
            if tag == "tuple":
                return tuple(items)
            if tag == "set":
                return set(items)
            return frozenset(items)
        _expect(
            (
                isinstance(payload, list)
                if tag == "timedelta"
                else isinstance(payload, str)
            ),
            f"{tag!s} payload has wrong type",
        )
        if tag == "float":
            _expect(payload in ("nan", "inf", "-inf"), "invalid non-finite float")
            return float(payload)
        if tag == "bytes":
            return base64.b64decode(payload, validate=True)
        if tag == "datetime":
            return datetime.datetime.fromisoformat(payload)
        if tag == "date":
            return datetime.date.fromisoformat(payload)
        if tag == "time":
            return datetime.time.fromisoformat(payload)
        if tag == "timedelta":
            _expect(
                isinstance(payload, list)
                and len(payload) == 3
                and all(p.__class__ is int for p in payload),
                "timedelta payload must be [days, seconds, microseconds]",
            )
            return datetime.timedelta(
                days=payload[0], seconds=payload[1], microseconds=payload[2]
            )
        if tag == "decimal":
            return decimal.Decimal(payload)
        if tag == "uuid":
            return uuid.UUID(payload)
    except TaskValueSerializationError:
        raise
    except (TypeError, ValueError, OverflowError, decimal.InvalidOperation) as e:
        raise TaskValueSerializationError(
            f"Malformed task value: invalid {tag!s} payload"
        ) from e
    raise TaskValueSerializationError(f"Malformed task value: unknown type tag {tag!r}")


def _json_tokens(text: str) -> Iterator[str]:
    """Scan forward once, including on malformed or unterminated strings.

    Syntax validation remains with the JSON parser. This scan bounds its input
    structure without retrying token matches at embedded escaped quotes.
    """
    position = 0
    while position < len(text):
        start = position
        char = text[position]
        position += 1
        if char in " \t\r\n,:":
            continue
        if char == '"':
            while position < len(text):
                char = text[position]
                position += 1
                if char == "\\":
                    position += 1
                elif char == '"':
                    break
            else:
                raise TaskValueSerializationError("Unterminated JSON string")
        elif char not in "{}[]":
            while position < len(text) and text[position] not in ' \t\r\n,:{}[]"':
                position += 1
        yield text[start:position]


def _json_nesting_depth(text: str) -> int:
    depth = max_depth = 0
    for token in _json_tokens(text):
        if token in ("[", "{"):
            depth += 1
            max_depth = max(max_depth, depth)
        elif token in ("]", "}"):
            depth -= 1
    return max_depth


def _preflight_json_nodes(text: str, limits: TaskValueLimits) -> None:
    """Bound parser allocations, including the typed envelope's overhead.

    A logical value contributes at most eight JSON nodes (the timedelta tag
    is the largest scalar representation); the outer envelope contributes four.
    Exact logical item and depth limits are also checked after parsing.
    """
    count = 0
    for value in _json_tokens(text):
        if value not in ("}", "]"):
            count += 1
        if count > 8 * limits.max_items + 4:
            raise TaskValueSerializationError(
                "Task value exceeds the parser node budget"
            )
        if value[0] in "-0123456789" and len(value.lstrip("-")) > limits.max_int_digits:
            raise TaskValueSerializationError(
                "Task value numeric token exceeds the digits limit"
            )


def _reject_duplicate_keys(pairs: List[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise TaskValueSerializationError(
                f"Malformed task value: duplicate key {k!r}"
            )
        result[k] = v
    return result


def _reject_constant(name: str) -> Any:
    raise TaskValueSerializationError(
        f"Malformed task value: non-standard JSON constant {name}"
    )


def encode_task_value(
    value: Any, limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS
) -> str:
    """Encode a value as a versioned, typed JSON task value string."""
    tree = _to_json_tree(value, _Budget(limits))
    encoded = (
        _ENVELOPE_PREFIX
        + json.dumps(TASK_VALUE_ENVELOPE_VERSION)
        + ',"value":'
        + json.dumps(tree, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        + "}"
    )
    if len(encoded) > limits.max_encoded_chars:
        raise TaskValueSerializationError(
            f"Encoded task value is {len(encoded)} characters; the maximum is {limits.max_encoded_chars}"
        )
    return encoded


def is_encoded_task_value(value: Any) -> bool:
    """True if the value is (claims to be) a versioned JSON task value."""
    return isinstance(value, str) and value.startswith(_ENVELOPE_PREFIX)


def decode_task_value(
    encoded: str, limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS
) -> Any:
    """Decode a versioned JSON task value string produced by encode_task_value.
    Never executes code; raises TaskValueSerializationError on malformed or oversized input.
    """
    _expect(is_encoded_task_value(encoded), "missing task value envelope")
    if len(encoded) > limits.max_encoded_chars:
        raise TaskValueSerializationError(
            f"Encoded task value is {len(encoded)} characters; the maximum is {limits.max_encoded_chars}"
        )
    # a logical level adds at most three JSON levels (tagged object, payload list, dict pair),
    # plus the envelope; this cheap pre-scan keeps the JSON parser away from deep recursion
    if _json_nesting_depth(encoded) > 3 * (limits.max_depth + 1) + 1:
        raise TaskValueSerializationError(
            f"Task value exceeds the maximum nesting depth of {limits.max_depth}"
        )

    _preflight_json_nodes(encoded, limits)

    def _parse_float(text: str) -> float:
        value = float(text)
        if not math.isfinite(value):
            raise TaskValueSerializationError(
                "Non-finite floats require an explicit type tag"
            )
        return value

    def _parse_int(text: str) -> int:
        if len(text.lstrip("-")) > limits.max_int_digits:
            raise TaskValueSerializationError(
                f"Integer task value exceeds {limits.max_int_digits} digits"
            )
        return int(text)

    try:
        envelope = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except TaskValueSerializationError:
        raise
    except (ValueError, RecursionError) as e:
        raise TaskValueSerializationError("Malformed task value: invalid JSON") from e
    _expect(
        isinstance(envelope, dict)
        and set(envelope) == {TASK_VALUE_ENVELOPE_KEY, "value"},
        "envelope must have exactly the version and value keys",
    )
    version = envelope[TASK_VALUE_ENVELOPE_KEY]
    if version.__class__ is not int or version != TASK_VALUE_ENVELOPE_VERSION:
        raise TaskValueSerializationError(
            f"Unsupported task value envelope version: {version!r}; "
            f"this brickflow version supports {TASK_VALUE_ENVELOPE_VERSION}"
        )
    return _from_json_tree(envelope["value"], _Budget(limits))


_PICKLE_PROTOCOLS = range(2, 6)


def _legacy_pickle_bytes(value: str, limits: TaskValueLimits) -> Optional[bytes]:
    """Return the decoded bytes if the value has the shape of a legacy pickle+base64 task value."""
    if len(value) > limits.max_encoded_chars or len(value) < 8:
        return None
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    if (
        len(raw) >= 3
        and raw[0] == 0x80
        and raw[1] in _PICKLE_PROTOCOLS
        and raw.endswith(b".")
    ):
        return raw
    return None


def _warn_legacy_pickle(action: str) -> None:
    message = (
        f"{action} a task value with the legacy pickle transport "
        f"({BrickflowEnvVars.BRICKFLOW_TASK_VALUES_LEGACY_PICKLE.value} is enabled). Unpickling can execute "
        f"arbitrary code; only use it while every producer of task values is trusted and migrate to the "
        f"default JSON transport. See docs/task-value-transport.md."
    )
    warnings.warn(message, LegacyPickleTaskValueWarning, stacklevel=3)
    _ilog.warning(message)


@dataclass
class BrickflowTaskComsObject:
    # Wrapper kept so legacy pickle payloads (which reference this class) can still be read when opted in.
    @dataclass(frozen=True)
    class _TaskComsObject:
        value: Hashable

    _value: Any = None
    _task_coms_obj: _TaskComsObject = field(init=False)

    def __post_init__(self) -> None:
        self._task_coms_obj = self._TaskComsObject(self._value)

    @property
    def value(self) -> Any:
        return self._task_coms_obj.value

    def encode(
        self,
        legacy_pickle: Optional[Union[str, TaskValueLegacyPickleMode]] = None,
        limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS,
    ) -> str:
        """Encode as versioned JSON, or as legacy pickle+base64 only in READ_WRITE legacy mode."""
        if (
            resolve_legacy_pickle_mode(legacy_pickle)
            is TaskValueLegacyPickleMode.READ_WRITE
        ):
            _warn_legacy_pickle("Writing")
            results_bytes = pickle.dumps(self._task_coms_obj)
            return base64.b64encode(results_bytes).decode("utf-8")
        return encode_task_value(self.value, limits)

    @property
    def to_encoded_value(self) -> str:
        return self.encode()

    @classmethod
    def from_encoded_value(
        cls,
        encoded_value: Any,
        legacy_pickle: Optional[Union[str, TaskValueLegacyPickleMode]] = None,
        limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS,
    ) -> "BrickflowTaskComsObject":
        """Decode a task value.

        - Versioned JSON values are decoded with type and size/depth bounds.
        - Legacy pickle+base64 values are refused with LegacyPickleTaskValueError unless legacy
          pickle reading is explicitly enabled; they are never unpickled by default.
        - Any other value (for example a plain string stored with string_serialization=True) is
          returned unchanged.
        """
        if isinstance(encoded_value, bytes):
            try:
                encoded_value = encoded_value.decode("utf-8")
            except UnicodeDecodeError as e:
                raise TaskValueSerializationError(
                    "Task value bytes are not valid UTF-8"
                ) from e
        if not isinstance(encoded_value, str):
            return cls(encoded_value)
        if is_encoded_task_value(encoded_value):
            return cls(decode_task_value(encoded_value, limits))
        legacy_bytes = _legacy_pickle_bytes(encoded_value, limits)
        if legacy_bytes is None:
            return cls(encoded_value)
        if (
            resolve_legacy_pickle_mode(legacy_pickle)
            is TaskValueLegacyPickleMode.DISABLED
        ):
            raise LegacyPickleTaskValueError(
                "Refusing to unpickle a legacy pickle+base64 task value. Re-run the producer with this "
                "brickflow version to write the JSON format, or, only if every producer is trusted, set "
                f"{BrickflowEnvVars.BRICKFLOW_TASK_VALUES_LEGACY_PICKLE.value}=read. "
                "See docs/task-value-transport.md."
            )
        _warn_legacy_pickle("Reading")
        try:
            # explicit trusted-only opt-in; see docs/task-value-transport.md
            obj = pickle.loads(legacy_bytes)  # nosec B301
        except Exception as e:
            raise TaskValueSerializationError(
                "Unable to unpickle legacy task value"
            ) from e
        if not isinstance(obj, cls._TaskComsObject):
            raise TaskValueSerializationError(
                "Legacy task value did not contain a brickflow task value object"
            )
        return cls(obj.value)


@dataclass
class BrickflowTaskComsDict:
    task_id: str
    task_coms: "BrickflowTaskComs"

    def __getitem__(self, key: str) -> Any:
        # fake behavior in airflow for: {{ ti.xcom_pull(task_ids='task_id')['arg'] }}
        return self.task_coms.get(task_id=self.task_id, key=key)


@dataclass(frozen=True)
class BrickflowTaskComs:
    dbutils: Optional[Any] = None
    storage: Dict[str, Any] = field(init=False, default_factory=lambda: {})
    # None defers to the BRICKFLOW_TASK_VALUES_LEGACY_PICKLE environment variable (default: disabled)
    legacy_pickle: Optional[Union[str, TaskValueLegacyPickleMode]] = None
    limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS

    @staticmethod
    def _key(task_id: str, key: str) -> str:
        return f"{task_id}::{key}"

    @staticmethod
    def _decode_value(
        value: Any,
        string_serialization: bool,
        legacy_pickle: Optional[Union[str, TaskValueLegacyPickleMode]] = None,
        limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS,
    ) -> Any:
        return (
            BrickflowTaskComsObject.from_encoded_value(
                value, legacy_pickle=legacy_pickle, limits=limits
            ).value
            if not string_serialization
            else value
        )

    @staticmethod
    def _encode_value(
        value: Any,
        string_serialization: bool,
        legacy_pickle: Optional[Union[str, TaskValueLegacyPickleMode]] = None,
        limits: TaskValueLimits = DEFAULT_TASK_VALUE_LIMITS,
    ) -> Any:
        return (
            BrickflowTaskComsObject(value).encode(
                legacy_pickle=legacy_pickle, limits=limits
            )
            if not string_serialization
            else value
        )

    def put(
        self, task_id: str, key: str, value: Any, string_serialization: bool = False
    ) -> None:
        """Put a value in the task coms. By default the value is encoded as versioned, typed JSON
        (see docs/task-value-transport.md for supported types). Provide string_serialization=True to store
        the value as-is (it must then be JSON serializable for Databricks task values).
        """
        try:
            encoded_value = BrickflowTaskComs._encode_value(
                value, string_serialization, self.legacy_pickle, self.limits
            )
        except TaskValueSerializationError as e:
            raise type(e)(f"task {task_id!r}, key {key!r}: {e}") from e
        if self.dbutils is not None:
            self.dbutils.jobs.taskValues.set(key, encoded_value)
        else:
            # TODO: logging using local task coms
            self.storage[self._key(task_id, key)] = encoded_value

    def get(
        self,
        task_id: str,
        key: Optional[str] = None,
        string_serialization: bool = False,
    ) -> Any:
        """Get a value from the task coms. Provide string_serialization=True to return the stored value as-is.
        Legacy pickle+base64 values are refused unless legacy pickle reading is explicitly enabled.
        """
        if key is None:
            return BrickflowTaskComsDict(task_id=task_id, task_coms=self)
        if self.dbutils is not None:
            encoded_value = self.dbutils.jobs.taskValues.get(
                key=key, taskKey=task_id, debugValue="debug"
            )
        else:
            # TODO: logging using local task coms
            encoded_value = self.storage[self._key(task_id, key)]
        try:
            return BrickflowTaskComs._decode_value(
                encoded_value, string_serialization, self.legacy_pickle, self.limits
            )
        except TaskValueSerializationError as e:
            raise type(e)(f"task {task_id!r}, key {key!r}: {e}") from e


class Context:
    def __init__(self) -> None:
        # Order of init matters todo: fix this

        self._dbutils: Optional[Any] = None
        self._spark: Optional[Any] = None
        self._task_coms: BrickflowTaskComs
        self._current_task: Optional[str] = None
        self._configure()
        self._current_project: Optional[str] = None

    def __new__(cls) -> "Context":
        if not hasattr(cls, "instance"):
            cls.instance = super(Context, cls).__new__(cls)
        return cls.instance  # noqa

    def _configure(self) -> None:
        # testing purposes only
        self._set_spark_session()
        self._configure_dbutils()
        self._task_coms = BrickflowTaskComs(self._dbutils)

    @property
    def current_task(self) -> Optional[str]:
        return self._current_task

    def get_current_timestamp(self) -> int:
        return int(time.time() * 1000)

    def _set_current_task(self, task_key: str) -> None:
        self._current_task = task_key

    def _reset_current_task(self) -> None:
        self._current_task = None

    def get_return_value(self, task_key: Union[str, Callable]) -> Any:
        task_key = task_key.__name__ if callable(task_key) else task_key
        return self.task_coms.get(task_key, RETURN_VALUE_KEY)

    def skip_all_except(self, branch_task: Union[Callable, str]) -> None:
        if self._current_task is None:
            raise RuntimeError("Current task is empty unable to skip...")
        branch_task_key = (
            branch_task.__name__
            if callable(branch_task) and hasattr(branch_task, "__name__") is True
            else branch_task
        )
        self._task_coms.put(self._current_task, BRANCH_SKIP_EXCEPT, branch_task_key)

    def skip_all_following(self) -> None:
        if self._current_task is None:
            raise RuntimeError("Current task is empty unable to skip...")
        self._task_coms.put(self._current_task, BRANCH_SKIP_EXCEPT, SKIP_EXCEPT_HACK)

    @property
    def task_coms(self) -> BrickflowTaskComs:
        return self._task_coms

    @property
    def current_project(self) -> Optional[str]:
        # TODO: not a public api move to internal context or deployment context
        return self._current_project or config(
            BrickflowEnvVars.BRICKFLOW_PROJECT_NAME.value, None
        )

    @staticmethod
    def _ensure_valid_project(project: str) -> None:
        env_project = config(BrickflowEnvVars.BRICKFLOW_PROJECT_NAME.value, None)
        if env_project is None:
            return
        if env_project != project:
            raise RuntimeError(
                f"Project: {project} does not match with env var: {BrickflowEnvVars.BRICKFLOW_PROJECT_NAME.value} "
                f"value: {env_project}"
            )

    def set_current_project(self, project: str) -> None:
        # TODO: not a public api move to internal context or deployment context
        self._ensure_valid_project(project)
        self._current_project = project

    @bind_variable(BrickflowBuiltInTaskVariables.task_key)
    def task_key(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the task_key value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.task_retry_count)
    def task_retry_count(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the task_retry_count value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.run_id)
    def run_id(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the run_id value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.job_id)
    def job_id(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the job_id value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.parent_run_id)
    def parent_run_id(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the parent_run_id value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.start_date)
    def start_date(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the start_date value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @bind_variable(BrickflowBuiltInTaskVariables.start_time)
    def start_time(self, *, debug: Optional[str] = None) -> Any:
        """
        This function fetches the start_time value using the bind_variable decorator.
        The implementation is intentionally empty because the decorator handles the logic.
        """
        pass

    @property
    def log(self) -> logging.Logger:
        return log

    @property
    def dbutils(self) -> "DBUtils":  # type: ignore # noqa: F821
        return self._dbutils

    @property
    def spark(self) -> "SparkSession":  # type: ignore # noqa: F821
        return self._spark

    def is_local(self) -> bool:
        return self.env == BrickflowDefaultEnvs.LOCAL.value

    @property
    def env(self) -> str:
        # reused during deploy time, it uses env variable when deploying or testing locally, and uses
        # dbutils widgets during runtime time in jobs
        return config(
            BrickflowEnvVars.BRICKFLOW_ENV.value,
            self.get_parameter(
                BrickflowInternalVariables.env.value,
                BrickflowDefaultEnvs.LOCAL.value,
            ),
        )

    def get_by_env(
        self,
        purpose: str,
        *,
        default: Optional[T] = None,
        local: Optional[T] = None,
        dev: Optional[T] = None,
        non_prod: Optional[T] = None,
        test: Optional[T] = None,
        qa: Optional[T] = None,
        prod: Optional[T] = None,
        uat: Optional[T] = None,
        **kwargs: Optional[T],
    ) -> Optional[T]:
        # deep copy without modifying kwargs
        def add_if_not_none(
            _d: Dict[str, Optional[T]], _k: str, _v: Optional[T]
        ) -> None:
            if _v is None:
                return
            _d[_k] = _v

        _dict = copy.deepcopy(kwargs)
        add_if_not_none(_dict, "local", local)
        add_if_not_none(_dict, "non_prod", non_prod)
        add_if_not_none(_dict, "dev", dev)
        add_if_not_none(_dict, "test", test)
        add_if_not_none(_dict, "qa", qa)
        add_if_not_none(_dict, "prod", prod)
        add_if_not_none(_dict, "uat", uat)
        _env = self.env
        _ilog.info("Configuring: %s; Using env: '%s' to fetch value...", purpose, _env)
        if _env not in _dict and default is None:
            raise KeyError(
                f"Configuring: {purpose}; Unable to find environment key: {_env}, "
                f"only found env definitions: {list(_dict.keys())}"
            )
        if _env not in _dict and default is not None:
            _ilog.info(
                "Configuring: %s; Found no value configured with env: '%s' using default value...",
                purpose,
                _env,
            )
        res = _dict.get(_env, default)
        return res

    @deprecated
    def dbutils_widget_get_or_else(
        self, key: str, debug: Optional[str]
    ) -> Optional[str]:
        try:
            return self.dbutils.widgets.get(key)
        except Exception:
            # todo: log error
            return debug

    def get_parameter(self, key: str, debug: Optional[str] = None) -> Optional[str]:
        try:
            return self.dbutils.widgets.get(key)
        except Exception:
            # todo: log error
            _ilog.debug("Unable to get parameter: %s from dbutils", key)
            return debug

    def get_project_parameter(
        self, key: str, debug: Optional[str] = None
    ) -> Optional[str]:
        project_params = str(
            self.get_parameter(
                BrickflowEnvVars.BRICKFLOW_PROJECT_PARAMS.value.lower(), debug=debug
            )
        )
        if project_params == debug:
            return debug
        try:
            pairs = project_params.split(",")
            kv_dict = {pair.split("=")[0]: pair.split("=")[1] for pair in pairs}
            value = kv_dict.get(key)
            if value is None:
                _ilog.debug(
                    "Could not find the key in %s project params", project_params
                )
                return debug
            return value
        except (KeyError, IndexError):
            # todo: log error
            _ilog.debug("Could not find the key in %s project params", project_params)
            return debug

    def _try_import_chaining(self, callables: List[Callable]) -> Optional[Any]:
        for c in callables:
            try:
                return c()
            except (ImportError, AttributeError, KeyError, RuntimeError):
                if hasattr(c, "__name__"):
                    _ilog.info("Skipping execution of function: %s", c.__name__)
        return None

    def _set_spark_session(self) -> None:
        def __try_spark_from_ipython_notebook() -> None:
            import IPython  # noqa # pylint: disable=import-error

            self._spark = IPython.get_ipython().user_ns.get("spark", None)
            if self._spark is None:
                raise AttributeError("spark is not set")

        def __try_spark_from_spark_session() -> None:
            from pyspark.sql import (  # noqa # pylint: disable=import-error
                SparkSession,  # noqa
            )

            self._spark = SparkSession.getActiveSession()

        self._try_import_chaining(
            [__try_spark_from_ipython_notebook, __try_spark_from_spark_session]
        )
        _ilog.info("Spark Session object: ctx.spark is set to: %s", self.spark)

    def _configure_dbutils(self) -> ContextMode:
        def __try_dbutils_from_ipython_notebook() -> ContextMode:
            import IPython  # noqa # pylint: disable=import-error

            self._dbutils = IPython.get_ipython().user_ns.get("dbutils")
            if self._dbutils is None:
                raise AttributeError("dbutils is not set")
            return ContextMode.databricks

        def __try_dbutils_from_db_connect_jar() -> None:
            from pyspark.dbutils import (  # noqa # pylint: disable=import-error
                DBUtils,  # noqa
            )

            self._dbutils = DBUtils(self.spark)
            # cant gaurantee databricks

        resp = self._try_import_chaining(
            [__try_dbutils_from_ipython_notebook, __try_dbutils_from_db_connect_jar]
        )

        _ilog.info("DBUtils object: ctx.dbutils is set to: %s", self.dbutils)

        if resp is not None:
            return ContextMode.databricks

        return ContextMode.not_databricks


ctx = Context()
