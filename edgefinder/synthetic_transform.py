"""Pure, bounded preparation of the fixed synthetic identity fixture format.

No acquisition or storage is executed here. Namespace existence, PLAYER kind,
and synthetic provider membership require the later coordinator's database
checks. Ledger timestamps and historical availability are never inferred.

Limits govern accepted values, not peak memory or execution time. JSON decoding
and canonicalization allocate temporary objects. Frozen results contain only
tuples and scalars; constructing a dataclass is not proof of execution history.
"""

from dataclasses import dataclass, field
from enum import Enum
import json

from .storage import database


_FORMAT = "edgefinder.synthetic.identity.v1"
_MIN_INTEGER = -9223372036854775808
_MAX_INTEGER = 9223372036854775807
_MAX_BODY_BYTES = 1048576
_MAX_TOTAL_BYTES = 8388608
_MAX_OCCURRENCES = 4096
_MAX_ROWS = 4096
_MAX_PARAMETERS_BYTES = 65536

type SyntheticScalar = None | bool | int | str


class SyntheticTransformCode(str, Enum):
    """Stable categories, independent of caller and fixture contents."""

    INVALID_ARGUMENT = "invalid_argument"
    MALFORMED_FIXTURE = "malformed_fixture"
    RESOURCE_LIMIT = "resource_limit"


class SyntheticTransformError(ValueError):
    """Sanitized failure; never carries parser text or a partial result.

    Suppressing displayed chaining does not erase traceback locals from memory.
    """

    def __init__(self, code: SyntheticTransformCode):
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class PreparedIdentityRow:
    """One occurrence; payload contains sorted key/scalar pairs."""

    identifier: str | None
    payload: tuple[tuple[str, SyntheticScalar], ...]


@dataclass(frozen=True, slots=True)
class PreparedSyntheticIdentity:
    """Prepared evidence only; no assertion that a namespace or snapshot exists.

    At a future storage boundary, reconstruct fresh ordinary dictionaries from
    each row's payload pairs. Do not pass tuples to database.canonical().
    """

    namespace_id: int
    loader_scope: str
    occurrence_indices: tuple[int, ...]
    rows: tuple[PreparedIdentityRow, ...]
    canonical_normalized_bytes: int
    format: str = field(default=_FORMAT, init=False)
    transformation_id: str = field(default="edgefinder.synthetic.identity", init=False)
    transformation_version: str = field(default="v1", init=False)
    provider: str = field(default="synthetic", init=False)
    role: str = field(default="IDENTITY", init=False)
    normalization_version: str = field(default=database.NORMALIZATION_VERSION, init=False)
    original_file_sha256: None = field(default=None, init=False)
    retrieved_at: None = field(default=None, init=False)
    publication_at: None = field(default=None, init=False)
    publication_evidence: None = field(default=None, init=False)


def _scalar_string(value: str) -> bool:
    return not any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _integer(token: str) -> int:
    # JSON's grammar supplies decimal digits and an optional minus. Compare
    # lexically BEFORE int(), independently of Python's integer digit limit.
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > len(limit) or (len(digits) == len(limit) and digits > limit):
        raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
    return int(token)


def _reject_number(token: str) -> None:
    raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result or not _scalar_string(key):
            raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
        result[key] = value
    return result


def _decode(body: bytes) -> list[dict[str, object]]:
    if body.startswith(b"\xef\xbb\xbf"):
        raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
    try:
        document = json.loads(body.decode("utf-8", errors="strict"),
                              object_pairs_hook=_object, parse_int=_integer,
                              parse_float=_reject_number, parse_constant=_reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE) from None
    if (type(document) is not dict or set(document) != {"format", "rows"}
            or document["format"] != _FORMAT or type(document["rows"]) is not list):
        raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
    return document["rows"]


def _prepare_rows(rows: list[dict[str, object]], namespace_id: int,
                  byte_budget: int) -> tuple[tuple[PreparedIdentityRow, ...], int]:
    prepared = []
    byte_count = 0
    for row in rows:
        if type(row) is not dict or set(row) != {"identifier", "payload"}:
            raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
        identifier, payload = row["identifier"], row["payload"]
        if ((identifier is not None and
             (type(identifier) is not str or not _scalar_string(identifier)))
                or type(payload) is not dict):
            raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
        for value in payload.values():
            if (value is not None and type(value) not in (bool, int, str)
                    or type(value) is str and not _scalar_string(value)):
                raise SyntheticTransformError(SyntheticTransformCode.MALFORMED_FIXTURE)
        pairs = tuple(sorted(payload.items()))
        # Match add_snapshot's complete logical record, including every NULL
        # field and a fresh payload dict. Reuse its canonicalization unchanged.
        normalized = dict.fromkeys(database.RECORD_FIELDS)
        normalized.update(namespace_id=namespace_id, identifier=identifier, payload=dict(pairs))
        byte_count += len(database.canonical(normalized).encode("utf-8"))
        if byte_count > byte_budget:
            raise SyntheticTransformError(SyntheticTransformCode.RESOURCE_LIMIT)
        prepared.append(PreparedIdentityRow(identifier, pairs))
    return tuple(prepared), byte_count


def transform_synthetic_identity_v1(
    acquisition_bodies: tuple[bytes, ...],
    *,
    occurrence_indices: tuple[int, ...],
    namespace_id: int,
    loader_scope: str,
) -> PreparedSyntheticIdentity:
    """Validate all inputs and concatenate rows in declared occurrence order.

    Validation order is metadata, container/count/type checks, input byte limits,
    references/coverage, expanded bytes, then documents in acquisition order.
    Each document is decoded once; row and byte multiplicities are checked before
    expanding output. Empty documents are allowed; empty combined output is not.
    Expected failures use INVALID_ARGUMENT, MALFORMED_FIXTURE or RESOURCE_LIMIT.
    Control signals and unexpected programming/resource failures propagate.
    """
    code = SyntheticTransformCode
    if (type(namespace_id) is not int or not _MIN_INTEGER <= namespace_id <= _MAX_INTEGER
            or type(loader_scope) is not str or not loader_scope or loader_scope[0] == "\x00"):
        raise SyntheticTransformError(code.INVALID_ARGUMENT)
    # A cheap lower bound avoids canonicalizing arbitrarily large scope text.
    if len(loader_scope) > _MAX_PARAMETERS_BYTES:
        raise SyntheticTransformError(code.RESOURCE_LIMIT)
    if not _scalar_string(loader_scope):
        raise SyntheticTransformError(code.INVALID_ARGUMENT)
    parameters = {"namespace_id": namespace_id, "loader_scope": loader_scope}
    if len(database.canonical(parameters).encode("utf-8")) > _MAX_PARAMETERS_BYTES:
        raise SyntheticTransformError(code.RESOURCE_LIMIT)
    if (type(acquisition_bodies) is not tuple or type(occurrence_indices) is not tuple
            or not acquisition_bodies or not occurrence_indices):
        raise SyntheticTransformError(code.INVALID_ARGUMENT)
    if len(occurrence_indices) > _MAX_OCCURRENCES or len(acquisition_bodies) > _MAX_OCCURRENCES:
        raise SyntheticTransformError(code.RESOURCE_LIMIT)
    if (any(type(body) is not bytes for body in acquisition_bodies)
            or any(type(index) is not int for index in occurrence_indices)):
        raise SyntheticTransformError(code.INVALID_ARGUMENT)
    lengths = tuple(len(body) for body in acquisition_bodies)
    if any(length > _MAX_BODY_BYTES for length in lengths) or sum(lengths) > _MAX_TOTAL_BYTES:
        raise SyntheticTransformError(code.RESOURCE_LIMIT)
    multiplicities = [0] * len(acquisition_bodies)
    for index in occurrence_indices:
        if not 0 <= index < len(acquisition_bodies):
            raise SyntheticTransformError(code.INVALID_ARGUMENT)
        multiplicities[index] += 1
    if 0 in multiplicities:
        raise SyntheticTransformError(code.INVALID_ARGUMENT)
    if sum(length * count for length, count in zip(lengths, multiplicities)) > _MAX_TOTAL_BYTES:
        raise SyntheticTransformError(code.RESOURCE_LIMIT)

    batches = []
    row_count = 0
    byte_count = 0
    for body, count in zip(acquisition_bodies, multiplicities):
        rows = _decode(body)
        row_count += len(rows) * count
        if row_count > _MAX_ROWS:
            raise SyntheticTransformError(code.RESOURCE_LIMIT)
        prepared, batch_bytes = _prepare_rows(rows, namespace_id,
                                              (_MAX_TOTAL_BYTES - byte_count) // count)
        batches.append(prepared)
        byte_count += batch_bytes * count
    if row_count == 0:
        raise SyntheticTransformError(code.MALFORMED_FIXTURE)
    expanded = tuple(row for index in occurrence_indices for row in batches[index])
    return PreparedSyntheticIdentity(namespace_id, loader_scope, occurrence_indices,
                                     expanded, byte_count)
