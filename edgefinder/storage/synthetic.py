"""Narrow target-read-only checks for the supervised synthetic pipeline.

Existing compatibility machinery initializes disposable reference databases and
reads bundled schemas. The supplied target is never installed, repaired, or
written here. Each reader owns one compatible DEFERRED transaction. Callers must
provide exclusive connection use and prevent concurrent external mutation.
"""

from collections import Counter
from dataclasses import dataclass, field
import sqlite3

from edgefinder import synthetic_transform as transform
from edgefinder.acquisition.runner import OfflineSuccess
from . import database, lineage, provenance


MAX_BODY_BYTES = transform._MAX_BODY_BYTES
MAX_TOTAL_BYTES = transform._MAX_TOTAL_BYTES
MAX_OCCURRENCES = transform._MAX_OCCURRENCES
MAX_ROWS = transform._MAX_ROWS
MAX_PARAMETERS_BYTES = transform._MAX_PARAMETERS_BYTES
TRANSFORMATION_ID = transform.PreparedSyntheticIdentity.__dataclass_fields__["transformation_id"].default
TRANSFORMATION_VERSION = transform.PreparedSyntheticIdentity.__dataclass_fields__["transformation_version"].default


class SyntheticEvidenceMismatch(sqlite3.IntegrityError):
    """A conclusively mismatched retained fact, without source contents."""

    def __init__(self):
        super().__init__("synthetic_evidence_mismatch")


@dataclass(frozen=True, slots=True)
class SyntheticObservationMetadata:
    """Explicit nonsensitive descriptors; syntax cannot establish semantic safety."""

    event_key: str
    logical_artifact_id: str
    scope: str
    recorded_at: str
    provider: str = field(default="synthetic", init=False)
    declared_format: str = field(default="json", init=False)

    def persistence_kwargs(self) -> dict[str, str]:
        """Return a fresh ordinary mapping for the existing persistence APIs."""
        return dict(event_key=self.event_key, provider=self.provider,
                    logical_artifact_id=self.logical_artifact_id, scope=self.scope,
                    declared_format=self.declared_format, recorded_at=self.recorded_at)


@dataclass(frozen=True, slots=True)
class VerifiedSyntheticSnapshot:
    snapshot_id: int
    normalized_sha256: str
    row_count: int
    canonical_normalized_bytes: int


def check_synthetic_connection(db: sqlite3.Connection) -> None:
    """Reject caller transactions before any dependency attribute inspection."""
    if type(db) is not sqlite3.Connection:
        raise TypeError("Expected an EdgeFinder SQLite connection")
    if db.in_transaction:
        raise RuntimeError("Active caller transaction")
    if db.autocommit != sqlite3.LEGACY_TRANSACTION_CONTROL:
        raise RuntimeError("Unsupported Python transaction control")
    if db.row_factory is not sqlite3.Row or db.isolation_level is not None:
        raise RuntimeError("Use an EdgeFinder connect() connection")
    if db.execute("PRAGMA query_only").fetchone()[0] != 0:
        raise RuntimeError("A writable connection is required")


def validate_observation_metadata(metadata: SyntheticObservationMetadata) -> None:
    if type(metadata) is not SyntheticObservationMetadata:
        raise TypeError("Expected synthetic observation metadata")
    if metadata.provider != "synthetic" or metadata.declared_format != "json":
        raise ValueError("Fixed synthetic metadata required")
    provenance._metadata(**metadata.persistence_kwargs())


def validate_snapshot_metadata(namespace_id: int, loader_scope: str) -> None:
    lineage._identifier(namespace_id)
    database._validate_metadata("synthetic", "IDENTITY", loader_scope, None, None, None)
    if loader_scope[0] == "\x00":
        raise ValueError("Invalid loader scope")
    if len(loader_scope) > MAX_PARAMETERS_BYTES:
        raise ValueError("Parameter budget exceeded")
    parameters = dict(namespace_id=namespace_id, loader_scope=loader_scope)
    if len(database.canonical(parameters).encode("utf-8")) > MAX_PARAMETERS_BYTES:
        raise ValueError("Parameter budget exceeded")


def _namespace(db, namespace_id):
    row = db.execute("SELECT 1 FROM main.identifier_namespace WHERE id=? "
                     "AND typeof(provider)='text' AND provider='synthetic' "
                     "AND typeof(kind)='text' AND kind='PLAYER'",
                     (namespace_id,)).fetchone()
    if row is None:
        raise ValueError("Expected an existing synthetic PLAYER namespace")


def preflight_synthetic_pipeline(
    db: sqlite3.Connection, *, metadata: tuple[SyntheticObservationMetadata, ...],
    occurrence_indices: tuple[int, ...], input_labels: tuple[str, ...],
    namespace_id: int, loader_scope: str, derivation_recorded_at: str,
) -> None:
    """Check facts and schema without mutating or reserving the target."""
    check_synthetic_connection(db)
    validate_snapshot_metadata(namespace_id, loader_scope)
    lineage._metadata(TRANSFORMATION_ID, TRANSFORMATION_VERSION, derivation_recorded_at)
    if (type(metadata) is not tuple or not 1 <= len(metadata) <= MAX_OCCURRENCES
            or type(occurrence_indices) is not tuple or type(input_labels) is not tuple
            or not 1 <= len(occurrence_indices) <= MAX_OCCURRENCES
            or len(input_labels) != len(occurrence_indices)):
        raise ValueError("Invalid bounded input group")
    for index, label in zip(occurrence_indices, input_labels):
        if type(index) is not int or not 0 <= index < len(metadata):
            raise ValueError("Invalid acquisition reference")
        provenance._text(label, lineage._TOKEN)
    if set(occurrence_indices) != set(range(len(metadata))):
        raise ValueError("Every acquisition must be referenced")
    for item in metadata:
        validate_observation_metadata(item)
    keys = tuple(item.event_key for item in metadata)
    if len(set(keys)) != len(keys):
        raise ValueError("Distinct acquisition event keys required")
    with provenance._compatible_transaction(db, read=True):
        _namespace(db, namespace_id)
        for key in keys:
            if db.execute("SELECT 1 FROM main.acquisition_observation WHERE event_key=?",
                          (key,)).fetchone():
                raise ValueError("Acquisition event key is already used")


def validate_success_for_persistence(
    metadata: SyntheticObservationMetadata, success: OfflineSuccess, *, max_bytes: int,
) -> None:
    """Known pre-call rejection establishes NOT_COMMITTED for this write."""
    validate_observation_metadata(metadata)
    if type(success) is not OfflineSuccess or type(success.body) is not bytes:
        raise TypeError("Expected an offline acquisition success")
    if not 0 <= len(success.body) <= max_bytes <= MAX_BODY_BYTES:
        raise ValueError("Acquisition exceeded its effective cap")
    provenance._digest(success.sha256)
    if database._artifact_sha256(success.body) != success.sha256:
        raise ValueError("Acquisition digest mismatch")


def _check_text_sizes(db, table, key_column, key, expected):
    # All table/column names come from this module's fixed SQL contracts.
    expressions = ",".join(f"typeof({name}),length(CAST({name} AS BLOB))" for name in expected)
    row = db.execute(f"SELECT {expressions} FROM main.{table} WHERE {key_column}=?",
                     (key,)).fetchone()
    if row is None:
        raise SyntheticEvidenceMismatch()
    for offset, text in enumerate(expected.values()):
        if row[2 * offset] != "text" or row[2 * offset + 1] != len(text.encode("utf-8")):
            raise SyntheticEvidenceMismatch()


def read_verified_synthetic_success(
    db: sqlite3.Connection, *, observation_id: int,
    metadata: SyntheticObservationMetadata, success: OfflineSuccess,
) -> bytes:
    """Check observation identity and exact independently hashed bytes together."""
    check_synthetic_connection(db)
    lineage._identifier(observation_id)
    validate_success_for_persistence(metadata, success, max_bytes=MAX_BODY_BYTES)
    expected = dict(metadata.persistence_kwargs(), evidence_kind="SYNTHETIC", outcome="SUCCESS",
                    artifact_sha256=success.sha256)
    with provenance._compatible_transaction(db, read=True):
        _check_text_sizes(db, "acquisition_observation", "id", observation_id, expected)
        flags = db.execute("SELECT failure_code IS NULL,typeof(cleanup_failed),cleanup_failed "
                           "FROM main.acquisition_observation WHERE id=?", (observation_id,)).fetchone()
        if tuple(flags) != (1, "integer", 0):
            raise SyntheticEvidenceMismatch()
        row = db.execute("SELECT * FROM main.acquisition_observation WHERE id=?",
                         (observation_id,)).fetchone()
        if (type(row["id"]) is not int or row["id"] != observation_id
                or row["failure_code"] is not None or type(row["cleanup_failed"]) is not int
                or row["cleanup_failed"] != 0
                or any(type(row[name]) is not str or row[name] != value
                       for name, value in expected.items())):
            raise SyntheticEvidenceMismatch()
        sizes = db.execute("SELECT typeof(body),byte_length,length(body) FROM main.raw_artifact "
                           "WHERE sha256=?", (success.sha256,)).fetchone()
        if (sizes is None or sizes[0] != "blob" or type(sizes[1]) is not int
                or type(sizes[2]) is not int or sizes[1] != sizes[2]
                or not 0 <= sizes[1] <= MAX_BODY_BYTES or sizes[1] != len(success.body)):
            raise SyntheticEvidenceMismatch()
        try:
            body = provenance._retained_artifact(db, success.sha256)
        except (KeyError, sqlite3.IntegrityError):
            raise SyntheticEvidenceMismatch() from None
        if body != success.body:
            raise SyntheticEvidenceMismatch()
    return body


def snapshot_rows(prepared: transform.PreparedSyntheticIdentity) -> tuple[dict, ...]:
    """Fresh complete logical records; preserve order and duplicate occurrences."""
    if type(prepared) is not transform.PreparedSyntheticIdentity:
        raise TypeError("Expected fixed transformer output")
    validate_snapshot_metadata(prepared.namespace_id, prepared.loader_scope)
    if (type(prepared.rows) is not tuple or not 1 <= len(prepared.rows) <= MAX_ROWS
            or prepared.provider != "synthetic" or prepared.role != "IDENTITY"
            or prepared.normalization_version != database.NORMALIZATION_VERSION
            or prepared.transformation_id != TRANSFORMATION_ID
            or prepared.transformation_version != TRANSFORMATION_VERSION
            or any(value is not None for value in (prepared.original_file_sha256,
                       prepared.retrieved_at, prepared.publication_at, prepared.publication_evidence))):
        raise ValueError("Invalid fixed snapshot output")
    rows = []
    byte_count = 0
    for item in prepared.rows:
        if type(item) is not transform.PreparedIdentityRow:
            raise TypeError("Expected prepared identity rows")
        row = dict.fromkeys(database.RECORD_FIELDS)
        row.update(namespace_id=prepared.namespace_id, identifier=item.identifier, payload=dict(item.payload))
        byte_count += len(database.canonical(row).encode("utf-8"))
        if byte_count > MAX_TOTAL_BYTES:
            raise ValueError("Normalized output budget exceeded")
        rows.append(row)
    if type(prepared.canonical_normalized_bytes) is not int or byte_count != prepared.canonical_normalized_bytes:
        raise ValueError("Prepared normalized byte count mismatch")
    return tuple(rows)


def validate_derivation_for_registration(
    *, snapshot_id: int, prepared: transform.PreparedSyntheticIdentity,
    parameters: dict, recorded_at: str, inputs: tuple[tuple[str, int], ...],
) -> None:
    """Pure validation before the independently owned lineage write is invoked."""
    lineage._identifier(snapshot_id)
    if type(prepared) is not transform.PreparedSyntheticIdentity:
        raise TypeError("Expected fixed transformer output")
    if (prepared.transformation_id != TRANSFORMATION_ID
            or prepared.transformation_version != TRANSFORMATION_VERSION
            or type(parameters) is not dict
            or database.canonical(parameters) != database.canonical(dict(
                namespace_id=prepared.namespace_id, loader_scope=prepared.loader_scope))):
        raise ValueError("Unexpected transformation parameters")
    lineage._metadata(prepared.transformation_id, prepared.transformation_version, recorded_at)
    if len(database.canonical(parameters).encode("utf-8")) > MAX_PARAMETERS_BYTES:
        raise ValueError("Parameter budget exceeded")
    if type(inputs) is not tuple or not 1 <= len(inputs) <= MAX_OCCURRENCES:
        raise ValueError("Invalid lineage group")
    for pair in inputs:
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError("Expected label/observation pairs")
        provenance._text(pair[0], lineage._TOKEN)
        lineage._identifier(pair[1])


def verify_synthetic_snapshot(
    db: sqlite3.Connection, *, snapshot_id: int, prepared: transform.PreparedSyntheticIdentity,
) -> VerifiedSyntheticSnapshot:
    """Check retained columns, exact canonical multiset and Python evidence hash.

    Do not decode untrusted canonical JSON or trust target SQL hash/normalization
    callbacks. A matching expected canonical row supplies its known payload; the
    actual stored payload text and every other column are checked independently.
    """
    check_synthetic_connection(db)
    lineage._identifier(snapshot_id)
    expected_rows = snapshot_rows(prepared)
    by_text = {database.canonical(row): row for row in expected_rows}
    expected_texts = tuple(database.canonical(row) for row in expected_rows)
    remaining = Counter(expected_texts)
    expected_digest = database.evidence_hash(expected_texts)
    header = dict(provider="synthetic", role="IDENTITY", loader_scope=prepared.loader_scope,
                  normalization_version=prepared.normalization_version, normalized_sha256=expected_digest)
    with provenance._compatible_transaction(db, read=True):
        try:
            _namespace(db, prepared.namespace_id)
        except ValueError:
            raise SyntheticEvidenceMismatch() from None
        _check_text_sizes(db, "source_snapshot", "id", snapshot_id, header)
        # Inspect forbidden fields as booleans, avoiding unbounded text materialization.
        flags = db.execute("SELECT sealed,typeof(sealed),original_file_sha256 IS NULL,"
                           "retrieved_at IS NULL,publication_at IS NULL,publication_evidence IS NULL "
                           "FROM main.source_snapshot WHERE id=?", (snapshot_id,)).fetchone()
        if flags[0] != 1 or flags[1] != "integer" or tuple(flags)[2:] != (1, 1, 1, 1):
            raise SyntheticEvidenceMismatch()
        retained_header = db.execute("SELECT provider,role,loader_scope,normalization_version,normalized_sha256 "
                                     "FROM main.source_snapshot WHERE id=?", (snapshot_id,)).fetchone()
        if any(type(retained_header[name]) is not str or retained_header[name] != value
               for name, value in header.items()):
            raise SyntheticEvidenceMismatch()
        count = db.execute("SELECT count(*) FROM main.source_record WHERE snapshot_id=?",
                           (snapshot_id,)).fetchone()[0]
        if count != len(expected_rows) or not 1 <= count <= MAX_ROWS:
            raise SyntheticEvidenceMismatch()
        type_columns = (*database.RECORD_FIELDS, "normalized")
        expressions = ",".join(f"typeof({name})" for name in type_columns)
        sizes = db.execute(f"SELECT {expressions},ordinal,typeof(ordinal),"
                           "length(CAST(normalized AS BLOB)),length(CAST(payload AS BLOB)),"
                           "coalesce(length(CAST(identifier AS BLOB)),0) "
                           "FROM main.source_record WHERE snapshot_id=?", (snapshot_id,))
        totals = [0, 0, 0]
        for facts in sizes:
            for offset, name in enumerate(type_columns):
                permitted = (("integer",) if name == "namespace_id" else
                             ("text", "null") if name == "identifier" else
                             ("text",) if name in ("payload", "normalized") else ("null",))
                if facts[offset] not in permitted:
                    raise SyntheticEvidenceMismatch()
            offset = len(type_columns)
            if facts[offset + 1] != "integer" or facts[offset] < 0:
                raise SyntheticEvidenceMismatch()
            for index, size in enumerate(tuple(facts)[-3:]):
                if type(size) is not int or not 0 <= size <= MAX_TOTAL_BYTES:
                    raise SyntheticEvidenceMismatch()
                totals[index] += size
                if totals[index] > MAX_TOTAL_BYTES:
                    raise SyntheticEvidenceMismatch()
        if totals[0] != prepared.canonical_normalized_bytes:
            raise SyntheticEvidenceMismatch()
        actual_texts = []
        columns = ",".join(database.RECORD_FIELDS)
        for row in db.execute(f"SELECT normalized,{columns} FROM main.source_record WHERE snapshot_id=?",
                              (snapshot_id,)):
            text = row["normalized"]
            if type(text) is not str or remaining[text] <= 0:
                raise SyntheticEvidenceMismatch()
            expected = by_text[text]
            actual = {}
            for name in database.RECORD_FIELDS:
                value = row[name]
                if name == "payload":
                    if type(value) is not str or value != database.canonical(expected[name]):
                        raise SyntheticEvidenceMismatch()
                    actual[name] = dict(expected[name])
                else:
                    if type(value) is not type(expected[name]) or value != expected[name]:
                        raise SyntheticEvidenceMismatch()
                    actual[name] = value
            reconstructed = database.canonical(actual)
            if reconstructed != text:
                raise SyntheticEvidenceMismatch()
            remaining[text] -= 1
            actual_texts.append(reconstructed)
        if any(remaining.values()) or database.evidence_hash(actual_texts) != expected_digest:
            raise SyntheticEvidenceMismatch()
    return VerifiedSyntheticSnapshot(snapshot_id, expected_digest, count, totals[0])
