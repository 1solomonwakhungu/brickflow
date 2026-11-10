# Task value transport

Brickflow passes task values (task return values, branch/skip markers, and anything written with
`ctx.task_coms.put`) between tasks through Databricks task values (`dbutils.jobs.taskValues`). This page
describes how those values are encoded, what changed from the earlier pickle format, and how to migrate.

## Default format: versioned, typed JSON

By default `ctx.task_coms.put(task_id, key, value)` stores a JSON string of the form:

```json
{"__brickflow_task_value__":1,"value":<encoded value>}
```

`ctx.task_coms.get(...)`, `ctx.get_return_value(...)` and branch handling decode it again. Decoding parses
JSON only and never imports or runs code.

Supported value types, which round-trip with their exact type:

| Type | Encoding |
|---|---|
| `None`, `bool`, `int`, finite `float`, `str` | plain JSON |
| `list` | JSON array |
| `dict` with only `str` keys | JSON object |
| `float('nan')`, `float('inf')`, `float('-inf')` | `{"$bf":"float","v":"nan"}` |
| `tuple`, `set`, `frozenset` | `{"$bf":"tuple","v":[...]}` |
| `dict` with non-`str` keys, or a key named `$bf` | `{"$bf":"dict","v":[[key, value], ...]}` |
| `bytes` | `{"$bf":"bytes","v":"<base64>"}` |
| `datetime.datetime`, `datetime.date`, `datetime.time` | ISO 8601 string, tagged |
| `datetime.timedelta` | `[days, seconds, microseconds]`, tagged |
| `decimal.Decimal`, `uuid.UUID` | string, tagged |

Types are matched exactly. Subclasses (for example `OrderedDict`, named tuples, `str`/`int` enums) and any
other object raise `TaskValueSerializationError` when the value is **put**, so the producing task fails
immediately with the task and key in the message instead of the consumer failing later. Convert such values
to a supported type, for example `dict(ordered)`, `tuple(named)` or `member.value`.

### Limits

Encoding and decoding enforce `TaskValueLimits` (`brickflow.context.context`):

| Limit | Default |
|---|---|
| `max_encoded_chars` | 1 MiB of encoded text |
| `max_depth` | 64 levels of container nesting |
| `max_items` | 100,000 values in total |
| `max_int_digits` | 4,300 digits per integer |

Values over a limit raise `TaskValueSerializationError`. Databricks applies its own, smaller size limit to task
values; Brickflow's limits are a decoder safety bound, not a replacement for that limit. A custom
`BrickflowTaskComs(dbutils, limits=TaskValueLimits(...))` can tighten them.

Decoding also rejects malformed envelopes: unknown envelope versions, unknown `$bf` tags, duplicate keys,
`NaN`/`Infinity` literals and invalid tagged payloads.

## `string_serialization=True` is unchanged

`put(..., string_serialization=True)` stores the value as-is and `get(..., string_serialization=True)`
returns it as-is. Databricks requires such values to be JSON serializable. This is the right choice when
non-Brickflow consumers (for example `{{tasks.<task>.values.<key>}}` references or another tool) read the
value.

As before, a default `get` of a value that is not a Brickflow envelope (for example a plain string written with
`string_serialization=True`, or the `"debug"` value returned outside a job run) returns that value
unchanged. The exception is a value with the shape of a legacy pickle payload, described below.

## Legacy pickle values are refused by default

Earlier versions wrote task values as base64-encoded `pickle` data and unpickled whatever a task value
contained. Unpickling can execute arbitrary Python code, so a crafted task value ran code in the consuming
task. This version never unpickles by default: a value that decodes as base64 pickle data raises
`LegacyPickleTaskValueError` (a `ValueError`) and nothing is executed.

This is a hardening change. A producer task that can set a task value usually already runs code under the job's
identity, so the old format did not by itself grant new privileges. The risk is higher when producer and
consumer tasks run with different clusters, identities, secret scopes or library trust.

### Explicit legacy opt-in (trusted producers only)

Set `BRICKFLOW_TASK_VALUES_LEGACY_PICKLE` on the consuming task's cluster or environment, or pass
`legacy_pickle=` to `BrickflowTaskComs(...)` / `BrickflowTaskComsObject.from_encoded_value(...)`:

| Value | Writes | Reads legacy pickle |
|---|---|---|
| unset, `disabled`, `false`, `no`, `off`, `0` (default) | JSON | refused |
| `read` | JSON | unpickled, with a warning |
| `read_write` | legacy pickle | unpickled, with a warning |

Other settings raise `ValueError` when encoding or reading recognized legacy data.
Each legacy operation first emits `LegacyPickleTaskValueWarning`, then logs a warning.
A warnings-as-errors policy stops the operation before the log or pickle operation. Only enable it while every task that can write the value is
trusted to run code in the consumer, and remove it after migration.

## Migration

Within a single job run, all tasks normally use the same Brickflow version, so producers and consumers switch
to JSON together and no action is needed.

Action is needed when versions are mixed:

- **New consumer, old producer** (for example a repaired run that reads values written before the upgrade, or
  tasks pinned to different Brickflow versions): the consumer raises `LegacyPickleTaskValueError`. Re-run the
  producer on the new version, or set `BRICKFLOW_TASK_VALUES_LEGACY_PICKLE=read` on the consumer while the
  producer is trusted.
- **New producer, old consumer**: the old consumer does not understand the JSON envelope. Upgrade consumers
  first, or set `BRICKFLOW_TASK_VALUES_LEGACY_PICKLE=read_write` on the producer during the rollout.
- **Values of unsupported types**: tasks that returned arbitrary objects (task return values are pushed by
  default) now fail at `put`. Return a supported type. Explicit `put`/`get` callers may use
  `string_serialization=True` with a JSON-compatible value on both sides; this does not change automatic returns.

## Compatibility notes

- `BrickflowTaskComsObject(value).to_encoded_value` now returns the JSON envelope, not base64 pickle.
- `BrickflowTaskComsObject.from_encoded_value` accepts `str`, UTF-8 `bytes` and other JSON values; non-string
  values are returned unchanged.
- A plain string written with `string_serialization=True` that starts with `{"__brickflow_task_value__":` is
  treated as an envelope by a default `get`. Read such values with `string_serialization=True`.
- Error types live in `brickflow.context.context`: `TaskValueSerializationError`,
  `LegacyPickleTaskValueError`, `LegacyPickleTaskValueWarning`, `TaskValueLegacyPickleMode` and
  `TaskValueLimits`.

## Branch decisions and strict decoding

An absent branch marker retains the existing behavior. A refused legacy marker,
malformed JSON envelope or unsupported envelope version raises a transport error
from branch evaluation, stopping the consumer instead of running an unselected
task. This applies to ALL_SUCCESS and NONE_FAILED. During mixed-version rollouts,
upgrade consumers first and explicitly enable trusted legacy reading where needed;
upgrade producers afterward. Old consumers cannot interpret JSON branch markers.
For repair runs, rerun old producers or temporarily use the documented trusted
legacy mode. Rollback requires compatible producer and consumer formats together.

The JSON parser has a conservative preflight structural-node budget of eight times
`max_items` plus four envelope nodes; the exact logical item limit is enforced
after parsing. Numeric token length is bounded before conversion, and untagged
floating overflow is refused. Size limits count Python characters, not UTF-8 bytes.
Encoding limits constrain accepted output, not arbitrary input-object allocation.
Raw passthrough values are outside the JSON envelope limits.

Datetime ISO strings do not retain `fold` or timezone object identity/rules.
Unsupported subclasses (including named tuples and enums) fail on automatic task
return storage. `string_serialization=True` is a per-put/get opt-out, not a global
switch for automatic returns. Legacy recognition is limited to canonical base64
protocol2–5 pickles with the expected framing; noncanonical or oversized values
may remain raw. Invalid legacy settings are checked when encoding or reading
recognized legacy data, not for raw passthrough or JSON reads. Treat legacy mode
as a temporary trusted-producer migration mechanism, and remove it after rollout.
