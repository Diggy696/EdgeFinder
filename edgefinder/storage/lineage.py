"""Atomic synthetic lineage assertions for existing sealed snapshots.

Lineage records caller assertions, not proof that a transformation executed.
recorded_at is ledger time and grants no historical availability. Every successful
registration creates a new assertion, even for identical facts (Option A).
Retrying after an uncertain commit outcome may create an additional assertion.
B1.3d must revisit durable execution identity before unattended retries.

Each call owns its transaction: active caller transactions are rejected without
commit, rollback, or mutation. Registration uses BEGIN IMMEDIATE; reads use one
DEFERRED snapshot, including compatibility and relationship checks. Connections
remain caller-owned. No schema is installed or repaired on the target database.

Registration and default retrieval check metadata and relationships, including
retained artifact types and lengths. get_derivation(verify_artifacts=True) also
independently hashes each distinct retained artifact with Python SHA-256. Neither
mode authenticates a source or establishes execution history.

Wrong argument types raise TypeError; invalid argument values raise ValueError.
Unsupported connections/schema, existing foreign-key violations, and active
transactions raise RuntimeError.
Missing derivations raise KeyError; invalid stored facts, ineligible snapshots,
and broken relationships raise sqlite3.IntegrityError. SQLite failures propagate
after rollback of this call's work. Errors do not include supplied metadata.
"""

from dataclasses import dataclass
from datetime import datetime
import sqlite3

from . import database, provenance


_TOKEN = r"[a-z0-9][a-z0-9._-]{0,127}"
_MAX_PARAMETERS = 65536
_MIN_ID = -9223372036854775808
_MAX_ID = 9223372036854775807


@dataclass(frozen=True, slots=True)
class DerivationInput:
    """One declared occurrence; ordinal is zero-based and duplicates are kept."""

    ordinal: int
    input_label: str
    observation_id: int
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class Derivation:
    """Verified sealed assertion; parameters contains canonical text."""

    derivation_id: int
    snapshot_id: int
    transformation_id: str
    transformation_version: str
    parameters: str
    recorded_at: str
    expected_input_count: int
    evidence_kind: str
    sealed: bool
    inputs: tuple[DerivationInput, ...]


def _ownership(db):
    if type(db) is not sqlite3.Connection:
        raise TypeError("Expected an EdgeFinder SQLite connection")
    if db.in_transaction:
        raise RuntimeError("Active caller transaction: nested transactions are not supported")


def _identifier(value):
    # The schema permits signed IDs, including zero and negative existing IDs.
    if type(value) is not int:
        raise TypeError("Expected an exact integer identifier")
    if not _MIN_ID <= value <= _MAX_ID:
        raise ValueError("Identifier is outside SQLite's signed integer range")


def _metadata(transformation_id, transformation_version, recorded_at):
    provenance._text(transformation_id, _TOKEN)
    provenance._text(transformation_version, _TOKEN)
    provenance._text(recorded_at,
                     r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
    try:
        # Match provenance's strict calendar check, including rejecting 24:00.
        datetime(int(recorded_at[:4]), int(recorded_at[5:7]), int(recorded_at[8:10]),
                 int(recorded_at[11:13]), int(recorded_at[14:16]), int(recorded_at[17:19]))
    except ValueError:
        raise ValueError("Invalid calendar timestamp") from None


def _snapshot(db, snapshot_id):
    row = db.execute(
        "SELECT id,sealed,original_file_sha256,retrieved_at,publication_at,publication_evidence "
        "FROM main.source_snapshot WHERE id=?", (snapshot_id,)).fetchone()
    if (row is None or type(row[0]) is not int or row[0] != snapshot_id or
            type(row[1]) is not int or row[1] != 1 or
            any(value is not None for value in tuple(row)[2:])):
        raise sqlite3.IntegrityError(
            "Synthetic lineage requires an existing sealed snapshot without historical evidence")


def _artifact(db, digest, *, verify):
    provenance._digest(digest)
    row = db.execute(
        "SELECT sha256,byte_length,typeof(body),length(body) FROM main.raw_artifact "
        "WHERE sha256=?", (digest,)).fetchone()
    if (row is None or type(row[0]) is not str or row[0] != digest or
            type(row[1]) is not int or not 0 <= row[1] <= database.MAX_ARTIFACT_BYTES or
            row[2] != "blob" or type(row[3]) is not int or row[3] != row[1]):
        raise sqlite3.IntegrityError("Invalid or missing retained artifact metadata")
    if verify:
        # Already inside the public read transaction; do not nest get_artifact().
        provenance._retained_artifact(db, digest)


def _observation(db, observation_id, artifacts, *, verify):
    row = db.execute("SELECT * FROM main.acquisition_observation WHERE id=?",
                     (observation_id,)).fetchone()
    if row is None:
        raise sqlite3.IntegrityError("Missing derivation input observation")
    try:
        _identifier(row["id"])
        if row["id"] != observation_id:
            raise ValueError("Inconsistent observation identifier")
        provenance._metadata(row["event_key"], row["provider"], row["logical_artifact_id"],
                             row["scope"], row["declared_format"], row["recorded_at"])
        if (row["evidence_kind"] != "SYNTHETIC" or row["outcome"] != "SUCCESS" or
                row["failure_code"] is not None or type(row["cleanup_failed"]) is not int or
                row["cleanup_failed"] != 0):
            raise ValueError("Observation is not a synthetic success")
        digest = row["artifact_sha256"]
        if digest not in artifacts:
            _artifact(db, digest, verify=verify)
            artifacts.add(digest)
    except (TypeError, ValueError):
        raise sqlite3.IntegrityError("Malformed synthetic input observation or artifact") from None
    return digest


def _occurrences(db, inputs, *, verify=False):
    observations = {}
    artifacts = set()
    result = []
    for ordinal, (label, observation_id) in enumerate(inputs):
        if observation_id not in observations:
            observations[observation_id] = _observation(
                db, observation_id, artifacts, verify=verify)
        result.append(DerivationInput(ordinal, label, observation_id,
                                      observations[observation_id]))
    return tuple(result)


def _insert_header(db, snapshot_id, transformation_id, transformation_version,
                   parameters, recorded_at, count):
    # Reproduced in test_lineage: omitted NEW.id collides with an existing -1 in
    # derivation_insert. Allocate explicitly while BEGIN IMMEDIATE is held, as
    # provenance does for acquisition observations. Never change negative rows.
    largest = db.execute("SELECT max(id) FROM main.snapshot_derivation").fetchone()[0]
    identifier = max(0, largest if largest is not None else 0) + 1
    if identifier > _MAX_ID:
        raise sqlite3.IntegrityError("Positive derivation IDs are exhausted")
    db.execute(
        "INSERT INTO main.snapshot_derivation(id,snapshot_id,transformation_id,"
        "transformation_version,parameters,recorded_at,expected_input_count,evidence_kind) "
        "VALUES(?,?,?,?,?,?,?,'SYNTHETIC')",
        (identifier, snapshot_id, transformation_id, transformation_version,
         parameters, recorded_at, count))
    return identifier


def register_derivation(
    db: sqlite3.Connection, *, snapshot_id: int, transformation_id: str,
    transformation_version: str, parameters: object, recorded_at: str,
    inputs: tuple[tuple[str, int], ...],
) -> int:
    """Commit a distinct sealed assertion; identical retries create new IDs.

    parameters is a Python value accepted by database.canonical(), never an
    alternate pre-canonicalized-text argument. Strings are ordinary values.
    No artifact bodies are hashed during registration.
    """
    _ownership(db)
    _identifier(snapshot_id)
    _metadata(transformation_id, transformation_version, recorded_at)
    if type(inputs) is not tuple:
        raise TypeError("Inputs must be an ordered tuple of label/observation pairs")
    if not 1 <= len(inputs) <= 4096:
        raise ValueError("A derivation requires 1 through 4096 input occurrences")
    for pair in inputs:
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError("Each input occurrence must be a label/observation tuple")
        provenance._text(pair[0], _TOKEN)
        _identifier(pair[1])
    text = database.canonical(parameters)
    if len(text.encode("utf-8")) > _MAX_PARAMETERS:
        raise ValueError("Canonical parameters exceed 65536 encoded bytes")
    with provenance._compatible_transaction(db):
        _snapshot(db, snapshot_id)
        _occurrences(db, inputs)
        identifier = _insert_header(db, snapshot_id, transformation_id,
                                    transformation_version, text, recorded_at, len(inputs))
        db.executemany(
            "INSERT INTO main.derivation_input(derivation_id,ordinal,input_label,observation_id) "
            "VALUES(?,?,?,?)",
            ((identifier, ordinal, label, observation_id)
             for ordinal, (label, observation_id) in enumerate(inputs)))
        sealed = db.execute(
            "UPDATE main.snapshot_derivation SET sealed=1 WHERE id=? AND sealed=0", (identifier,))
        if (sealed.rowcount != 1 or db.execute(
                "SELECT sealed FROM main.snapshot_derivation WHERE id=?",
                (identifier,)).fetchone()[0] != 1):
            raise sqlite3.IntegrityError("Derivation sealing failed")
    return identifier


def get_derivation(
    db: sqlite3.Connection, *, derivation_id: int, verify_artifacts: bool = False,
) -> Derivation:
    """Return a verified immutable assertion in one consistent read snapshot."""
    _ownership(db)
    _identifier(derivation_id)
    if type(verify_artifacts) is not bool:
        raise TypeError("verify_artifacts must be an exact Boolean")
    with provenance._compatible_transaction(db, read=True):
        row = db.execute("SELECT * FROM main.snapshot_derivation WHERE id=?",
                         (derivation_id,)).fetchone()
        if row is None:
            raise KeyError("Derivation not found")
        try:
            _identifier(row["id"])
            _identifier(row["snapshot_id"])
            _metadata(row["transformation_id"], row["transformation_version"], row["recorded_at"])
            if (row["id"] != derivation_id or type(row["sealed"]) is not int or
                    row["sealed"] != 1 or row["evidence_kind"] != "SYNTHETIC" or
                    type(row["expected_input_count"]) is not int or
                    not 1 <= row["expected_input_count"] <= 4096):
                raise ValueError("Invalid derivation header")
            text = row["parameters"]
            if (type(text) is not str or len(text.encode("utf-8")) > _MAX_PARAMETERS or
                    database._valid_canonical(text) != 1):
                raise ValueError("Invalid canonical parameters")
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise sqlite3.IntegrityError("Malformed or unsealed derivation") from None
        _snapshot(db, row["snapshot_id"])
        retained = db.execute(
            "SELECT ordinal,input_label,observation_id FROM main.derivation_input "
            "WHERE derivation_id=? ORDER BY ordinal", (derivation_id,)).fetchall()
        if len(retained) != row["expected_input_count"]:
            raise sqlite3.IntegrityError("Incomplete derivation input count")
        try:
            for ordinal, occurrence in enumerate(retained):
                if type(occurrence[0]) is not int or occurrence[0] != ordinal:
                    raise ValueError("Noncontiguous input positions")
                provenance._text(occurrence[1], _TOKEN)
                _identifier(occurrence[2])
        except (TypeError, ValueError):
            raise sqlite3.IntegrityError("Malformed derivation input occurrences") from None
        inputs = _occurrences(db, tuple((r[1], r[2]) for r in retained), verify=verify_artifacts)
        result = Derivation(row["id"], row["snapshot_id"], row["transformation_id"],
                            row["transformation_version"], text, row["recorded_at"],
                            row["expected_input_count"], row["evidence_kind"], True, inputs)
    return result


def list_derivation_ids(db: sqlite3.Connection, *, snapshot_id: int) -> tuple[int, ...]:
    """List sealed assertion IDs in ascending numeric order.

    Open staging groups are excluded. No matches, including a missing snapshot,
    return (). Use get_derivation() to validate an individual assertion's facts.
    """
    _ownership(db)
    _identifier(snapshot_id)
    with provenance._compatible_transaction(db, read=True):
        result = tuple(row[0] for row in db.execute(
            "SELECT id FROM main.snapshot_derivation WHERE snapshot_id=? AND sealed=1 ORDER BY id",
            (snapshot_id,)))
    return result
