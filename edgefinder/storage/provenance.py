"""Bounded synthetic bytes and immutable acquisition observations only.

Callers supply non-sensitive synthetic descriptors, including recorded_at once
per event (and unchanged on retries). Syntax checks cannot prove arbitrary free
text is semantically safe. Never derive metadata from exceptions, URLs, response
text, or acquisition objects. Ledger times confer no historical availability.

Each public call owns its transaction and leaves connection lifetime to the
caller. Writes use database.transaction(); public reads use a DEFERRED snapshot.
Exact installed schema is checked each time, never installed on the target.
The 64 MiB bound is per retained body, not database size or process RSS: SQLite
bindings, SQL hash callbacks, page storage, and returned bytes can make copies.
Digests establish byte integrity, not source authenticity or acquisition history.

Wrong input types raise TypeError; invalid values and changed events raise
ValueError. Unsupported connections/schema raise RuntimeError. Missing artifacts
raise KeyError; corrupt retained evidence raises sqlite3.IntegrityError. Other
SQLite errors propagate after rollback. No errors here include supplied facts.
"""

from contextlib import closing, contextmanager
from datetime import datetime
import hashlib
import re
import sqlite3

from edgefinder.acquisition.runner import OfflineFailureCode
from . import database


_EVENT_COLUMNS = (
    "event_key", "evidence_kind", "provider", "logical_artifact_id", "scope",
    "declared_format", "recorded_at", "outcome", "artifact_sha256",
    "failure_code", "cleanup_failed",
)


def _text(value, pattern):
    if type(value) is not str:
        raise TypeError("Expected exact string metadata")
    if re.fullmatch(pattern, value) is None:
        raise ValueError("Invalid synthetic metadata syntax or length")


def _metadata(event_key, provider, logical_artifact_id, scope, declared_format,
              recorded_at):
    _text(event_key, r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
    _text(provider, r"[a-z0-9][a-z0-9._-]{0,127}")
    _text(logical_artifact_id, r"[a-z0-9][a-z0-9._-]{0,255}")
    _text(scope, r"[ -~]{1,1024}")
    if scope != scope.strip(" "):
        raise ValueError("Scope must not have surrounding spaces")
    _text(declared_format, r"[a-z0-9][a-z0-9._-]{0,63}")
    _text(recorded_at, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
    try:
        # Python 3.14 fromisoformat accepts and normalizes 24:00:00. The
        # constructor instead requires canonical hours and calendar components.
        datetime(int(recorded_at[:4]), int(recorded_at[5:7]), int(recorded_at[8:10]),
                 int(recorded_at[11:13]), int(recorded_at[14:16]), int(recorded_at[17:19]))
    except ValueError:
        raise ValueError("Invalid calendar timestamp") from None
    return (event_key, "SYNTHETIC", provider, logical_artifact_id, scope,
            declared_format, recorded_at)


def _digest(sha256):
    if type(sha256) is not str:
        raise TypeError("Expected an exact SHA-256 string")
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ValueError("Expected a lowercase SHA-256 digest")


@contextmanager
def _read_transaction(db):
    """Mirror transaction() rollback ownership, without reserving the writer."""
    db.execute("BEGIN DEFERRED")
    try:
        yield db
        db.execute("COMMIT")
    except BaseException:
        db.rollback()
        raise


@contextmanager
def _compatible_transaction(db, *, read=False):
    """Check connection outside, and exact target schema inside, one transaction."""
    if type(db) is not sqlite3.Connection:
        raise TypeError("Expected an EdgeFinder SQLite connection")
    if db.in_transaction:
        raise RuntimeError("Nested transactions are not supported")
    database._installation_connection(db)
    if db.execute("PRAGMA ignore_check_constraints").fetchone()[0] != 0:
        raise RuntimeError("CHECK constraints must be enabled")
    owner = _read_transaction if read else database.transaction
    with owner(db):
        if (db.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone() or
                any(row[1] not in ("main", "temp")
                    for row in db.execute("PRAGMA database_list"))):
            raise RuntimeError("Use an isolated main database")
        if db.execute("PRAGMA main.user_version").fetchone()[0] != 1:
            raise RuntimeError("Expected installed B1.3a schema version 1")
        with closing(database.connect()) as reference:
            database.initialize(reference)
            if database._schema_signature(db) != database._schema_signature(reference):
                raise RuntimeError("Incompatible installed B1.3a schema")
        if db.execute("PRAGMA main.foreign_key_check").fetchone():
            raise RuntimeError("Existing foreign-key integrity check failed")
        yield db


def _retained_artifact(db, sha256):
    """Verify independently of SQL hashing; caller already owns a transaction."""
    row = db.execute(
        "SELECT sha256,byte_length,typeof(body),length(body) "
        "FROM main.raw_artifact WHERE sha256=?", (sha256,)).fetchone()
    if row is None:
        raise KeyError("Artifact not found")
    digest, recorded_length, storage_type, actual_length = row
    if (type(digest) is not str or digest != sha256 or
            type(recorded_length) is not int or
            not 0 <= recorded_length <= database.MAX_ARTIFACT_BYTES or
            storage_type != "blob" or type(actual_length) is not int or
            actual_length != recorded_length):
        raise sqlite3.IntegrityError("Invalid retained artifact type or length")
    # Preflight prevents materializing an oversized or wrongly typed BLOB.
    body = db.execute("SELECT body FROM main.raw_artifact WHERE sha256=?",
                      (sha256,)).fetchone()[0]
    if (type(body) is not bytes or len(body) != recorded_length or
            hashlib.sha256(body).hexdigest() != sha256):
        raise sqlite3.IntegrityError("Retained artifact failed independent verification")
    return body


def _existing_event(db, facts):
    row = db.execute(
        "SELECT id," + ",".join(_EVENT_COLUMNS) +
        " FROM main.acquisition_observation WHERE event_key=?", (facts[0],)).fetchone()
    if row is None:
        return None
    retained = tuple(row)[1:]
    if any(type(old) is not type(new) or old != new
           for old, new in zip(retained, facts)):
        raise ValueError("Existing event has different immutable facts")
    return row[0]


def _insert_event(db, facts):
    # Verified on SQLite 3.50.4: omitted NEW.id collides with an existing -1
    # in acquisition_insert. Allocate explicitly while BEGIN IMMEDIATE is held.
    largest = db.execute("SELECT max(id) FROM main.acquisition_observation").fetchone()[0]
    observation_id = max(0, largest if largest is not None else 0) + 1
    if observation_id > 9223372036854775807:
        raise sqlite3.IntegrityError("Positive observation IDs are exhausted")
    db.execute(
        "INSERT INTO main.acquisition_observation(id," + ",".join(_EVENT_COLUMNS) +
        ") VALUES(" + ",".join("?" for _ in range(len(facts) + 1)) + ")",
        (observation_id, *facts))
    return observation_id


def persist_success(
    db: sqlite3.Connection, *, event_key: str, provider: str,
    logical_artifact_id: str, scope: str, declared_format: str, recorded_at: str,
    body: bytes, sha256: str,
) -> int:
    """Commit exact verified bytes and a synthetic success, or reuse exact facts.

    OfflineSuccess construction alone is not byte-integrity validation. Check
    input bytes even for retries; independently verify retained bytes on reuse.
    """
    metadata = _metadata(event_key, provider, logical_artifact_id, scope,
                         declared_format, recorded_at)
    if type(body) is not bytes:
        raise TypeError("Expected exact immutable bytes")
    if len(body) > database.MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact exceeds 64 MiB")
    _digest(sha256)
    if hashlib.sha256(body).hexdigest() != sha256:
        raise ValueError("Supplied digest does not match artifact bytes")
    facts = (*metadata, "SUCCESS", sha256, None, 0)
    with _compatible_transaction(db):
        observation_id = _existing_event(db, facts)
        exists = db.execute("SELECT 1 FROM main.raw_artifact WHERE sha256=?",
                            (sha256,)).fetchone()
        if exists:
            if _retained_artifact(db, sha256) != body:
                raise sqlite3.IntegrityError("Retained artifact differs from supplied bytes")
        else:
            if observation_id is not None:
                raise sqlite3.IntegrityError("Success references a missing artifact")
            db.execute("INSERT INTO main.raw_artifact(sha256,byte_length,body) VALUES(?,?,?)",
                       (sha256, len(body), body))
        if observation_id is None:
            observation_id = _insert_event(db, facts)
    return observation_id


def persist_failure(
    db: sqlite3.Connection, *, event_key: str, provider: str,
    logical_artifact_id: str, scope: str, declared_format: str, recorded_at: str,
    failure_code: OfflineFailureCode, cleanup_failed: bool,
) -> int:
    """Commit stable failure facts only, with no exception or partial payload.

    A primary cleanup_failure may have cleanup_failed=False; the flag is an
    independent fact. Caller-supplied metadata must be non-sensitive synthetic
    descriptors, never derived from exceptions or acquisition objects.
    """
    metadata = _metadata(event_key, provider, logical_artifact_id, scope,
                         declared_format, recorded_at)
    if type(failure_code) is not OfflineFailureCode:
        raise TypeError("Expected an OfflineFailureCode")
    if type(cleanup_failed) is not bool:
        raise TypeError("Expected an exact Boolean cleanup flag")
    facts = (*metadata, "FAILURE", None, failure_code.value, int(cleanup_failed))
    with _compatible_transaction(db):
        observation_id = _existing_event(db, facts)
        if observation_id is None:
            observation_id = _insert_event(db, facts)
    return observation_id


def get_artifact(db: sqlite3.Connection, *, sha256: str) -> bytes:
    """Return independently verified retained bytes in a DEFERRED read snapshot."""
    _digest(sha256)
    with _compatible_transaction(db, read=True):
        body = _retained_artifact(db, sha256)
    return body
