"""Explicit transactions and canonical, normalized source evidence.

Normalization v1 accepts None, bool, int, finite float, str, list, and string-keyed
dicts. Every value has a type tag; integers use decimal strings and floats use
float.hex(). Strings and keys reject surrogate code points, including paired
surrogates; only Unicode scalar values are accepted. Dict keys are sorted without
Unicode normalization. Lists retain
order. Snapshot rows are sorted by canonical text, retaining duplicates; source
row order is not evidence. SHA-256 hashes UTF-8 normalized evidence, never an
original downloaded file. Equal content in a provider/role/scope/version reuses
the first snapshot only when supplied temporal metadata exactly matches its
original temporal assertions. New claims require a future provenance design.

Connections must be made with connect(): schema checks use registered Python
functions. Unsupported external connections fail closed on evidence writes.
Publication evidence is a caller assertion, not independently authenticated.
"""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3


NORMALIZATION_VERSION = "edgefinder.normalized.v1"
RECORD_FIELDS = (
    "namespace_id", "identifier", "game_namespace_id", "game_identifier",
    "team_namespace_id", "team_identifier", "home_namespace_id",
    "home_identifier", "away_namespace_id", "away_identifier",
    "kickoff_local", "kickoff_timezone", "kickoff_utc", "payload",
)


def _scalar_string(value):
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("Unicode surrogate code points are not normalized evidence")
    return value


def _typed(value):
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Non-finite floats are not normalized evidence")
        return ["float", value.hex()]
    if type(value) is str:
        return ["str", _scalar_string(value)]
    if type(value) is list:
        return ["list", [_typed(item) for item in value]]
    if type(value) is dict and all(type(key) is str for key in value):
        return ["dict", [[_scalar_string(key), _typed(value[key])] for key in sorted(value)]]
    raise TypeError("Unsupported evidence type")


def canonical(value):
    """Return deterministic, type-tagged JSON text (not original-file bytes)."""
    return json.dumps(_typed(value), ensure_ascii=True, separators=(",", ":"))


def _untyped(value):
    tag = value[0]
    if tag == "null":
        return None
    if tag == "dict":
        return {key: _untyped(item) for key, item in value[1]}
    if tag == "list":
        return [_untyped(item) for item in value[1]]
    if tag == "int":
        return int(value[1])
    if tag == "float":
        return float.fromhex(value[1])
    if tag in ("str", "bool"):
        return value[1]
    raise ValueError("Unknown normalization tag")


def _valid_canonical(value):
    try:
        return int(canonical(_untyped(json.loads(value))) == value)
    except (ValueError, TypeError, IndexError, KeyError):
        return 0


def evidence_hash(normalized_rows):
    return hashlib.sha256(canonical(sorted(normalized_rows)).encode("utf-8")).hexdigest()


class _EvidenceHash:
    def __init__(self):
        self.rows = []

    def step(self, row):
        self.rows.append(row)

    def finalize(self):
        return evidence_hash(self.rows)


def _record_canonical(*values):
    row = dict(zip(RECORD_FIELDS, values))
    row["payload"] = _untyped(json.loads(row["payload"]))
    return canonical(row)


def connect(path=":memory:"):
    """Open only the explicitly chosen database (default: isolated memory)."""
    db = sqlite3.connect(path, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    # REPLACE must invoke delete guards too, including on immutable parent rows.
    db.execute("PRAGMA recursive_triggers = ON")
    db.create_function("valid_canonical", 1, _valid_canonical, deterministic=True)
    db.create_function("record_canonical", len(RECORD_FIELDS), _record_canonical,
                       deterministic=True)
    db.create_aggregate("evidence_hash", 1, _EvidenceHash)
    return db


@contextmanager
def transaction(db):
    """One explicit atomic unit; nested transactions are deliberately rejected."""
    if db.in_transaction:
        raise RuntimeError("Nested transactions are not supported")
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except BaseException:
        db.rollback()
        raise


def initialize(db):
    """Create the schema atomically in an empty database; no migration support."""
    if db.in_transaction:
        raise RuntimeError("Initialize outside a transaction")
    try:
        db.executescript("BEGIN IMMEDIATE;\n" +
                         Path(__file__).with_name("schema.sql").read_text(encoding="utf-8") +
                         "\nCOMMIT;")
    except BaseException:
        db.rollback()
        raise


def _validate_metadata(provider, role, loader_scope, retrieved_at,
                       publication_at, publication_evidence):
    """Check every caller claim before either reuse or creation of evidence."""
    for name, value in (("provider", provider), ("role", role),
                        ("loader_scope", loader_scope)):
        if type(value) is not str or not value:
            raise sqlite3.IntegrityError(f"{name} must be nonempty text")
        _scalar_string(value)
    if role not in ("IDENTITY", "SCHEDULE", "STATS"):
        raise sqlite3.IntegrityError("Unknown snapshot role")
    for value in (retrieved_at, publication_at):
        if value is None:
            continue
        if type(value) is not str or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
            raise sqlite3.IntegrityError("Timestamp must be a UTC second in YYYY-MM-DDTHH:MM:SSZ form")
        try:
            datetime.fromisoformat(value)
        except ValueError as error:
            raise sqlite3.IntegrityError("Invalid calendar timestamp") from error
    if publication_evidence is not None:
        if type(publication_evidence) is not str or not publication_evidence.strip():
            raise sqlite3.IntegrityError("Publication evidence must be nonempty text")
        _scalar_string(publication_evidence)
    if (publication_at is None) != (publication_evidence is None):
        raise sqlite3.IntegrityError("Publication time and supporting evidence are required together")
    if publication_at is not None and retrieved_at is not None and publication_at > retrieved_at:
        raise sqlite3.IntegrityError("Publication cannot follow retrieval")


def add_snapshot(db, *, provider, role, loader_scope, rows,
                 retrieved_at=None, publication_at=None, publication_evidence=None):
    """Atomically stage and seal normalized rows; preserve duplicate occurrences.

    Each row requires namespace_id; identifier may be null. Optional relation
    columns describe schedule/stats joins, and payload preserves arbitrary raw
    normalized values. Original-file hashes remain NULL in this offline loader.
    Reuse requires exact temporal metadata equality, including NULLs; incompatible
    or newly supplied claims raise ValueError without altering the first snapshot.
    """
    _validate_metadata(provider, role, loader_scope, retrieved_at,
                       publication_at, publication_evidence)
    prepared = []
    for row in rows:
        if set(row) - set(RECORD_FIELDS):
            raise ValueError("Unknown source-record fields; put raw fields in payload")
        normalized = {name: row.get(name) for name in RECORD_FIELDS}
        if type(normalized["namespace_id"]) is not int:
            raise TypeError("namespace_id must be an integer")
        for name, value in normalized.items():
            if name.endswith("namespace_id") and value is not None and type(value) is not int:
                raise TypeError("Namespace references must be integers")
            if (name.endswith("identifier") or name.startswith("kickoff_")) and value is not None and type(value) is not str:
                raise TypeError("Identifiers and kickoff values must be strings or null")
        prepared.append((normalized, canonical(normalized)))
    if not prepared:
        raise ValueError("A snapshot requires at least one source record")
    digest = evidence_hash([text for _, text in prepared])
    with transaction(db):
        existing = db.execute(
            "SELECT id,retrieved_at,publication_at,publication_evidence FROM source_snapshot "
            "WHERE provider=? AND role=? AND loader_scope=? "
            "AND normalization_version=? AND normalized_sha256=? AND sealed=1",
            (provider, role, loader_scope, NORMALIZATION_VERSION, digest)).fetchone()
        if existing:
            if tuple(existing)[1:] != (retrieved_at, publication_at, publication_evidence):
                raise ValueError("Existing snapshot has different temporal metadata; original provenance is immutable")
            return existing[0]
        snapshot = db.execute(
            "INSERT INTO source_snapshot(provider,role,loader_scope,normalization_version,"
            "normalized_sha256,retrieved_at,publication_at,publication_evidence) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (provider, role, loader_scope, NORMALIZATION_VERSION, digest,
             retrieved_at, publication_at, publication_evidence)).lastrowid
        columns = ",".join(RECORD_FIELDS)
        placeholders = ",".join("?" for _ in RECORD_FIELDS)
        for ordinal, (row, normalized) in enumerate(prepared):
            values = [canonical(row[name]) if name == "payload" else row[name]
                      for name in RECORD_FIELDS]
            db.execute(f"INSERT INTO source_record(snapshot_id,ordinal,{columns},normalized) "
                       f"VALUES(?,?,{placeholders},?)", [snapshot, ordinal, *values, normalized])
        db.execute("UPDATE source_snapshot SET sealed=1 WHERE id=?", (snapshot,))
        return snapshot


# Count each alias/observation key once. Window counts retain every occurrence,
# including NULL keys. The identity lookup joins grouped counts rather than
# rescanning all source records for each row (including large duplicate groups).
_QUARANTINE_SQL = """
    WITH identity_counts AS MATERIALIZED (
        SELECT namespace_id,identifier,count(*) AS alias_count
        FROM source_record WHERE snapshot_id=:identity
        GROUP BY namespace_id,identifier
    ), occurrences AS (
        SELECT id,namespace_id,identifier,0 AS is_stats,
            count(*) OVER (PARTITION BY namespace_id,identifier) AS row_count
        FROM source_record WHERE snapshot_id=:identity
        UNION ALL
        SELECT id,namespace_id,identifier,0,
            count(*) OVER (PARTITION BY namespace_id,identifier)
        FROM source_record WHERE snapshot_id=:schedule
        UNION ALL
        SELECT id,namespace_id,identifier,1,
            count(*) OVER (PARTITION BY namespace_id,identifier,game_namespace_id,game_identifier)
        FROM source_record WHERE snapshot_id=:stats
    )
    INSERT INTO quarantine(run_id,source_record_id,reason)
    SELECT :run,r.id,'Unresolved, ambiguous, or duplicate source identity'
    FROM occurrences r LEFT JOIN identity_counts i
        ON i.namespace_id=r.namespace_id AND i.identifier=r.identifier
    WHERE r.identifier IS NULL OR r.identifier='' OR r.row_count>1 OR
        (r.is_stats=1 AND coalesce(i.alias_count,0)<>1)
"""


def create_run(db, *, identity, schedule, stats):
    with transaction(db):
        run = db.execute(
            "INSERT INTO validation_run(identity_snapshot,schedule_snapshot,stats_snapshot) "
            "VALUES(?,?,?)", (identity, schedule, stats)).lastrowid
        # Stage every occurrence, but automatically quarantine missing/ambiguous
        # aliases and duplicate observation keys. Quarantine never deletes evidence.
        db.execute(_QUARANTINE_SQL, {"run": run, "identity": identity,
                                     "schedule": schedule, "stats": stats})
        return run


def seal_run(db, run_id):
    with transaction(db):
        result = db.execute("UPDATE validation_run SET sealed=1 WHERE id=?", (run_id,))
        if result.rowcount != 1:
            raise ValueError(f"Validation run {run_id!r} does not exist")
