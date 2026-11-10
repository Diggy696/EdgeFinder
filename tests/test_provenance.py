"""Offline persistence checks; isolated databases and no acquisition callbacks."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import patch

from edgefinder.acquisition.contracts import (
    AddressRules, ValidatedConnectionPlan, ValidatedURL,
)
from edgefinder.acquisition.runner import OfflineFailureCode, OfflineSuccess
from edgefinder.storage import database, provenance
from edgefinder.storage.provenance import get_artifact, persist_failure, persist_success
from tests.test_storage_migrations import database_state, legacy_schema, populate_research


METADATA = dict(event_key="event-1", provider="synthetic", logical_artifact_id="fixture",
                scope="invented fixture", declared_format="opaque",
                recorded_at="2030-10-03T00:00:00Z")
BODY = b"\x00\xffsynthetic\xfe\x80\x00"
DIGEST = hashlib.sha256(BODY).hexdigest()


class BytesSubclass(bytes):
    pass


class StringSubclass(str):
    pass


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.db = database.connect()
        self.addCleanup(self.db.close)
        database.initialize(self.db)

    def success(self, db=None, **changes):
        values = dict(METADATA, body=BODY, sha256=DIGEST)
        values.update(changes)
        return persist_success(self.db if db is None else db, **values)

    def failure(self, db=None, **changes):
        values = dict(METADATA, failure_code=OfflineFailureCode.STREAM_FAILURE,
                      cleanup_failed=False)
        values.update(changes)
        return persist_failure(self.db if db is None else db, **values)

    def operations(self, db):
        return (lambda: persist_success(db, **METADATA, body=BODY, sha256=DIGEST),
                lambda: persist_failure(db, **METADATA,
                                        failure_code=OfflineFailureCode.STREAM_FAILURE,
                                        cleanup_failed=False),
                lambda: get_artifact(db, sha256=DIGEST))

    def assert_rejected_unchanged(self, db, operation, error=RuntimeError):
        before = database_state(db)
        with self.assertRaises(error):
            operation()
        self.assertEqual(database_state(db), before)
        self.assertFalse(db.in_transaction)

    def corrupt_artifact(self, sql, parameters):
        """Damage only this memory fixture, restoring the exact original guard."""
        guard = self.db.execute(
            "SELECT sql FROM main.sqlite_schema WHERE name='artifact_update'").fetchone()[0]
        self.db.execute("DROP TRIGGER artifact_update")
        self.db.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self.db.execute(sql, parameters)
        finally:
            self.db.execute("PRAGMA ignore_check_constraints=OFF")
            self.db.execute(guard)

    def test_exact_empty_nul_and_arbitrary_binary_round_trips(self):
        for index, body in enumerate((b"", b"\x00", bytes(range(256)), BODY)):
            with self.subTest(length=len(body)):
                digest = hashlib.sha256(body).hexdigest()
                observation = self.success(event_key=f"binary-{index}", body=body, sha256=digest)
                retained = get_artifact(self.db, sha256=digest)
                self.assertIs(type(retained), bytes)
                self.assertEqual(retained, body)
                row = self.db.execute(
                    "SELECT evidence_kind,outcome,artifact_sha256,failure_code,cleanup_failed "
                    "FROM acquisition_observation WHERE id=?", (observation,)).fetchone()
                self.assertEqual(tuple(row), ("SYNTHETIC", "SUCCESS", digest, None, 0))

    def test_body_requires_exact_immutable_bytes(self):
        for body in (None, "text", 0, bytearray(BODY), memoryview(BODY), BytesSubclass(BODY)):
            with self.subTest(type=type(body).__name__):
                self.assert_rejected_unchanged(
                    self.db, lambda: self.success(body=body), TypeError)

    def test_digest_spelling_and_exact_type_required_for_write_and_read(self):
        for digest in ("", "a" * 63, "a" * 65, DIGEST.upper(), "g" * 64,
                       DIGEST + "\x00", " " + DIGEST, DIGEST + "\n"):
            for operation in (lambda: self.success(sha256=digest),
                              lambda: get_artifact(self.db, sha256=digest)):
                with self.subTest(digest=repr(digest)):
                    self.assert_rejected_unchanged(self.db, operation, ValueError)
        for digest in (None, 1, DIGEST.encode(), StringSubclass(DIGEST)):
            for operation in (lambda: self.success(sha256=digest),
                              lambda: get_artifact(self.db, sha256=digest)):
                with self.subTest(type=type(digest).__name__):
                    self.assert_rejected_unchanged(self.db, operation, TypeError)

    def test_forged_digest_rejected_before_database_access_even_on_retry(self):
        self.success()
        with patch.object(provenance, "_compatible_transaction") as transaction:
            with self.assertRaisesRegex(ValueError, "does not match"):
                self.success(body=b"changed", sha256=DIGEST)
            transaction.assert_not_called()

    def test_offline_success_constructor_is_not_integrity_proof(self):
        plan = ValidatedConnectionPlan(ValidatedURL("synthetic.example", "/fixture"),
                                       ("8.8.8.8",), AddressRules())
        result = OfflineSuccess((plan,), BODY, "0" * 64)
        self.assert_rejected_unchanged(
            self.db, lambda: self.success(body=result.body, sha256=result.sha256), ValueError)

    def test_exact_64_mib_is_accepted_and_independently_retrieved(self):
        body = b"x" * database.MAX_ARTIFACT_BYTES
        digest = hashlib.sha256(body).hexdigest()
        self.success(body=body, sha256=digest)
        self.assertEqual(get_artifact(self.db, sha256=digest), body)
        self.assertEqual(self.db.execute("SELECT byte_length FROM raw_artifact").fetchone()[0],
                         67108864)
        del body
        # Reuse this large fixture rather than allocating a second large Python
        # body. An oversized retained BLOB must fail preflight on retrieval.
        oversized = database.MAX_ARTIFACT_BYTES + 1
        self.corrupt_artifact("UPDATE raw_artifact SET body=zeroblob(?),byte_length=?",
                              (oversized, oversized))
        with self.assertRaises(sqlite3.IntegrityError):
            get_artifact(self.db, sha256=digest)

    def test_64_mib_plus_one_rejected_before_hash_or_database_access(self):
        body = b"x" * (database.MAX_ARTIFACT_BYTES + 1)
        with (patch.object(provenance.hashlib, "sha256") as hashing,
              patch.object(provenance, "_compatible_transaction") as transaction):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                self.success(body=body)
            hashing.assert_not_called()
            transaction.assert_not_called()

    def test_deduplication_distinct_events_and_exact_success_retry(self):
        first = self.success()
        before = database_state(self.db)
        changes = self.db.total_changes
        self.assertEqual(self.success(), first)
        self.assertEqual(database_state(self.db), before)
        self.assertEqual(self.db.total_changes, changes)
        second = self.success(event_key="event-2")
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.execute("SELECT count(*) FROM raw_artifact").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM acquisition_observation").fetchone()[0], 2)

    def test_unreferenced_existing_artifact_is_reused_without_overwrite(self):
        self.db.execute("INSERT INTO raw_artifact VALUES(?,?,?)", (DIGEST, len(BODY), BODY))
        before = tuple(self.db.execute("SELECT * FROM raw_artifact").fetchone())
        changes = self.db.total_changes
        self.success()
        self.assertEqual(self.db.total_changes - changes, 1)
        self.assertEqual(tuple(self.db.execute("SELECT * FROM raw_artifact").fetchone()), before)

    def test_each_metadata_and_timestamp_change_conflicts_for_both_outcomes(self):
        changes = dict(provider="other", logical_artifact_id="other", scope="other scope",
                       declared_format="binary", recorded_at="2030-10-03T00:00:01Z")
        self.success()
        self.failure(event_key="failed-event")
        for field, value in changes.items():
            for operation in (lambda: self.success(**{field: value}),
                              lambda: self.failure(event_key="failed-event", **{field: value})):
                with self.subTest(field=field):
                    self.assert_rejected_unchanged(self.db, operation, ValueError)

    def test_changed_bytes_and_outcome_conflicts_never_leave_orphan_artifacts(self):
        self.failure()
        self.assert_rejected_unchanged(self.db, self.success, ValueError)
        self.success(event_key="successful")
        changed = b"previously unseen bytes"
        self.assert_rejected_unchanged(
            self.db, lambda: self.success(event_key="successful", body=changed,
                                           sha256=hashlib.sha256(changed).hexdigest()), ValueError)
        self.assert_rejected_unchanged(
            self.db, lambda: self.failure(event_key="successful"), ValueError)

    def test_metadata_rejects_wrong_types_without_coercion(self):
        for field in METADATA:
            for value in (None, 1, b"fixture", StringSubclass(METADATA[field])):
                for operation in (self.success, self.failure):
                    with self.subTest(field=field, type=type(value).__name__, path=operation.__name__):
                        with self.assertRaises(TypeError):
                            operation(**{field: value})
        self.assertEqual(self.db.total_changes, 0)

    def test_metadata_schema_syntax_and_bounds_apply_to_both_paths(self):
        invalid = {
            "event_key": ("", "a" * 129, ".bad", "-bad", "a/b", "a\x00x"),
            "provider": ("", "a" * 129, "NFLVERSE", ".bad", "a:b", "a\n", "\u00e9"),
            "logical_artifact_id": ("", "a" * 257, "_bad", "a/b", "a\x00x"),
            "scope": ("", " ", " leading", "trailing ", "a" * 1025, "a\t", "a\n",
                      "a\x00", "\u007f", "\u00e9", "\ud800"),
            "declared_format": ("", "a" * 65, "-bad", "a/b", "a\x00x"),
        }
        for field, values in invalid.items():
            for value in values:
                for operation in (self.success, self.failure):
                    with self.subTest(field=field, value=repr(value), path=operation.__name__):
                        with self.assertRaises(ValueError):
                            operation(**{field: value})
        self.assertEqual(self.db.total_changes, 0)

    def test_maximum_metadata_lengths_and_canonical_extreme_dates(self):
        self.success(event_key="A" * 128, provider="a" * 128,
                     logical_artifact_id="a" * 256, scope="~" * 1024,
                     declared_format="a" * 64, recorded_at="0001-01-01T00:00:00Z")
        self.failure(event_key="Z:._-0", provider="0", logical_artifact_id="0",
                     scope="!", declared_format="0", recorded_at="9999-12-31T23:59:59Z")
        self.failure(event_key="leap", recorded_at="2032-02-29T23:59:59Z")

    def test_timestamp_spelling_and_calendar_validation(self):
        for value in ("", "0000-01-01T00:00:00Z", "2030-02-29T00:00:00Z",
                      "2030-02-30T00:00:00Z", "2030-13-01T00:00:00Z",
                      "2030-10-03T24:00:00Z", "2030-10-03T00:00:60Z",
                      "2030-10-03 00:00:00Z", "2030-10-03T00:00:00+00:00",
                      "2030-10-03T00:00:00.000Z", "2030-10-03T00:00:00z",
                      METADATA["recorded_at"] + "\n", METADATA["recorded_at"] + "\x00"):
            for operation in (self.success, self.failure):
                with self.subTest(value=repr(value), path=operation.__name__):
                    with self.assertRaises(ValueError):
                        operation(recorded_at=value)
        self.assertEqual(self.db.total_changes, 0)

    def test_failure_codes_flags_and_exact_idempotency(self):
        for code in OfflineFailureCode:
            for flag in (False, True):
                key = f"failure-{code.value}-{int(flag)}"
                observation = self.failure(event_key=key, failure_code=code, cleanup_failed=flag)
                changes = self.db.total_changes
                self.assertEqual(self.failure(event_key=key, failure_code=code,
                                               cleanup_failed=flag), observation)
                self.assertEqual(self.db.total_changes, changes)
                row = self.db.execute(
                    "SELECT evidence_kind,outcome,artifact_sha256,failure_code,cleanup_failed "
                    "FROM acquisition_observation WHERE id=?", (observation,)).fetchone()
                self.assertEqual(tuple(row), ("SYNTHETIC", "FAILURE", None, code.value, int(flag)))
        self.assertEqual(self.db.execute("SELECT count(*) FROM raw_artifact").fetchone()[0], 0)

    def test_failure_code_and_cleanup_flag_require_exact_types(self):
        for code in (None, "stream_failure", "arbitrary private message", 1,
                     RuntimeError("private response text")):
            self.assert_rejected_unchanged(
                self.db, lambda: self.failure(failure_code=code), TypeError)
        for flag in (None, 0, 1, "false", b"true"):
            self.assert_rejected_unchanged(
                self.db, lambda: self.failure(cleanup_failed=flag), TypeError)

    def test_changed_failure_code_or_cleanup_flag_conflicts(self):
        self.failure()
        self.assert_rejected_unchanged(
            self.db, lambda: self.failure(failure_code=OfflineFailureCode.CLEANUP_FAILURE), ValueError)
        self.assert_rejected_unchanged(
            self.db, lambda: self.failure(cleanup_failed=True), ValueError)

    def test_failure_api_excludes_exception_url_plan_and_partial_body_fields(self):
        for field, value in (("exception", RuntimeError("private message")),
                             ("url", "https://synthetic.example/private"),
                             ("request_plans", ()), ("body", b"partial")):
            self.assert_rejected_unchanged(
                self.db, lambda: self.failure(**{field: value}), TypeError)
        self.failure()
        row = tuple(self.db.execute("SELECT * FROM acquisition_observation").fetchone())
        self.assertNotIn("private message", row)
        self.assertNotIn(b"partial", row)

    def test_observation_insert_failure_rolls_back_already_inserted_artifact(self):
        before = database_state(self.db)
        inserted = []

        def deny_observation(action, first, second, schema, source):
            if action == sqlite3.SQLITE_INSERT and first == "acquisition_observation":
                inserted.append(self.db.execute("SELECT count(*) FROM raw_artifact").fetchone()[0])
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(deny_observation)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.success()
        finally:
            self.db.set_authorizer(None)
        self.assertEqual(inserted, [1], "failure must occur after artifact insertion")
        self.assertEqual(database_state(self.db), before)
        self.assertFalse(self.db.in_transaction)

    def test_commit_failure_rolls_back_both_success_and_failure(self):
        def deny_commit(action, first, second, schema, source):
            if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        for operation in (self.success, self.failure):
            before = database_state(self.db)
            self.db.set_authorizer(deny_commit)
            try:
                with self.assertRaises(sqlite3.DatabaseError):
                    operation()
            finally:
                self.db.set_authorizer(None)
            self.assertEqual(database_state(self.db), before)
            self.assertFalse(self.db.in_transaction)

    def test_control_signal_after_artifact_insertion_rolls_back(self):
        with patch.object(provenance, "_insert_event", side_effect=KeyboardInterrupt):
            self.assert_rejected_unchanged(self.db, self.success, KeyboardInterrupt)

    def test_get_missing_artifact_raises_controlled_key_error(self):
        self.assert_rejected_unchanged(
            self.db, lambda: get_artifact(self.db, sha256=DIGEST), KeyError)

    def test_corrupted_retained_length_is_rejected_on_read_and_reuse(self):
        self.success()
        self.corrupt_artifact("UPDATE raw_artifact SET byte_length=byte_length+1", ())
        for operation in (lambda: get_artifact(self.db, sha256=DIGEST), self.success,
                          lambda: self.success(event_key="other")):
            self.assert_rejected_unchanged(self.db, operation, sqlite3.IntegrityError)

    def test_same_length_corruption_rejected_independently_of_sql_digest(self):
        self.success()
        self.corrupt_artifact("UPDATE raw_artifact SET body=?", (b"x" * len(BODY),))
        original_hash = database._artifact_sha256
        self.db.create_function("artifact_sha256", 1,
                                lambda body: original_hash(body) if body == b"" else DIGEST,
                                deterministic=True)
        self.assertEqual(self.db.execute("SELECT artifact_sha256(body) FROM raw_artifact").fetchone()[0],
                         DIGEST)
        for operation in (lambda: get_artifact(self.db, sha256=DIGEST), self.success,
                          lambda: self.success(event_key="other")):
            self.assert_rejected_unchanged(self.db, operation, sqlite3.IntegrityError)

    def test_corrupted_sql_length_preflight_avoids_python_hashing(self):
        self.success()
        self.corrupt_artifact("UPDATE raw_artifact SET byte_length=-1", ())
        real_hash = hashlib.sha256
        hashed = []

        def track_hash(body):
            hashed.append(body)
            return real_hash(body)

        with patch.object(provenance.hashlib, "sha256", side_effect=track_hash):
            with self.assertRaises(sqlite3.IntegrityError):
                get_artifact(self.db, sha256=DIGEST)
        self.assertNotIn(BODY, hashed)

    def test_python_length_verification_is_independent_of_sql_length(self):
        self.success()
        self.corrupt_artifact("UPDATE raw_artifact SET body=?", (b"x",))
        self.db.create_function("length", 1, lambda value: len(BODY))
        self.assert_rejected_unchanged(
            self.db, lambda: get_artifact(self.db, sha256=DIGEST), sqlite3.IntegrityError)

    def test_read_transaction_rolls_back_on_commit_failure_and_control_signal(self):
        self.success()

        def deny_commit(action, first, second, schema, source):
            if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        before = database_state(self.db)
        self.db.set_authorizer(deny_commit)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                get_artifact(self.db, sha256=DIGEST)
        finally:
            self.db.set_authorizer(None)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(database_state(self.db), before)
        with patch.object(provenance, "_retained_artifact", side_effect=KeyboardInterrupt):
            self.assert_rejected_unchanged(
                self.db, lambda: get_artifact(self.db, sha256=DIGEST), KeyboardInterrupt)

    def test_wrong_storage_type_is_rejected_before_fetching_body(self):
        # STRICT storage prevents constructing a wrong type normally. Simulate
        # the observed type using a SQL function in this isolated connection,
        # leaving the inspected schema unchanged.
        self.success()
        self.db.create_function("typeof", 1, lambda value: "text")
        self.assert_rejected_unchanged(
            self.db, lambda: get_artifact(self.db, sha256=DIGEST), sqlite3.IntegrityError)

    def test_exact_bytes_comparison_protects_digest_reuse(self):
        self.success()
        # Simulate a hash collision at the verified-loader boundary; equality
        # with supplied bytes must still fail, without a new observation.
        with patch.object(provenance, "_retained_artifact", return_value=b"different"):
            self.assert_rejected_unchanged(
                self.db, lambda: self.success(event_key="other"), sqlite3.IntegrityError)

    def test_missing_and_legacy_schemas_are_rejected_without_installation(self):
        for legacy in (False, True):
            with closing(database.connect()) as db:
                if legacy:
                    legacy_schema(db)
                for operation in self.operations(db):
                    self.assert_rejected_unchanged(db, operation)

    def test_schema_changes_and_wrong_version_rejected_without_repair(self):
        alterations = (
            "PRAGMA user_version=0", "PRAGMA user_version=2",
            "DROP TRIGGER artifact_update", "DROP INDEX observation_artifact",
            "ALTER TABLE raw_artifact ADD COLUMN extra TEXT",
            "CREATE TABLE extra(x TEXT) STRICT",
            "DROP TRIGGER acquisition_insert; CREATE TRIGGER acquisition_insert "
            "BEFORE INSERT ON acquisition_observation BEGIN SELECT 1; END",
        )
        for sql in alterations:
            with self.subTest(sql=sql), closing(database.connect()) as db:
                database.initialize(db)
                db.executescript(sql)
                for operation in self.operations(db):
                    self.assert_rejected_unchanged(db, operation)

    def test_schema_acceptance_is_not_cached(self):
        self.success()
        self.db.execute("DROP TRIGGER artifact_delete")
        for operation in self.operations(self.db):
            self.assert_rejected_unchanged(self.db, operation)

    def test_unsupported_connection_contracts_are_rejected(self):
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as raw:
            raw.row_factory = sqlite3.Row
            raw.execute("PRAGMA foreign_keys=ON")
            raw.execute("PRAGMA recursive_triggers=ON")
            for operation in self.operations(raw):
                self.assert_rejected_unchanged(raw, operation)
        for attribute, value in (("row_factory", None), ("isolation_level", "DEFERRED")):
            original = getattr(self.db, attribute)
            setattr(self.db, attribute, value)
            try:
                for operation in self.operations(self.db):
                    with self.assertRaises(RuntimeError):
                        operation()
                    self.assertFalse(self.db.in_transaction)
            finally:
                setattr(self.db, attribute, original)
        for operation in self.operations(None):
            with self.assertRaises(TypeError):
                operation()

    def test_disabled_constraints_and_missing_sql_function_rejected(self):
        for pragma, invalid, restored in (("foreign_keys", 0, 1),
                                          ("recursive_triggers", 0, 1),
                                          ("ignore_check_constraints", 1, 0)):
            self.db.execute(f"PRAGMA {pragma}={invalid}")
            try:
                for operation in self.operations(self.db):
                    self.assert_rejected_unchanged(self.db, operation)
            finally:
                self.db.execute(f"PRAGMA {pragma}={restored}")
        self.db.create_function("artifact_sha256", 1, None)
        for operation in self.operations(self.db):
            self.assert_rejected_unchanged(self.db, operation)

    def test_temp_objects_and_attached_databases_rejected(self):
        for sql in ("CREATE TEMP TABLE raw_artifact(x)",
                    "ATTACH DATABASE ':memory:' AS other"):
            with self.subTest(sql=sql), closing(database.connect()) as db:
                database.initialize(db)
                db.execute(sql)
                for operation in self.operations(db):
                    self.assert_rejected_unchanged(db, operation)

    def test_foreign_key_violation_rejected_without_repair(self):
        guard = self.db.execute(
            "SELECT sql FROM sqlite_schema WHERE name='quarantine_insert'").fetchone()[0]
        self.db.execute("PRAGMA foreign_keys=OFF")
        self.db.execute("DROP TRIGGER quarantine_insert")
        try:
            self.db.execute("INSERT INTO quarantine VALUES(999,999,'synthetic broken fixture')")
        finally:
            self.db.execute(guard)
            self.db.execute("PRAGMA foreign_keys=ON")
        for operation in self.operations(self.db):
            self.assert_rejected_unchanged(self.db, operation)

    def test_nested_transactions_remain_owned_by_caller(self):
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO entity(kind,label) VALUES('TEAM','caller fixture')")
        before = database_state(self.db)
        try:
            for operation in self.operations(self.db):
                with self.assertRaisesRegex(RuntimeError, "Nested"):
                    operation()
                self.assertTrue(self.db.in_transaction)
                self.assertEqual(database_state(self.db), before)
        finally:
            self.db.rollback()
        self.assertEqual(self.db.execute("SELECT count(*) FROM entity").fetchone()[0], 0)

    def test_write_and_read_transaction_modes_and_schema_inspection_order(self):
        for operation, begin in ((self.success, "BEGIN IMMEDIATE"),
                                 (lambda: self.failure(event_key="failure"), "BEGIN IMMEDIATE"),
                                 (lambda: get_artifact(self.db, sha256=DIGEST), "BEGIN DEFERRED")):
            statements = []
            self.db.set_trace_callback(statements.append)
            try:
                operation()
            finally:
                self.db.set_trace_callback(None)
            index = statements.index(begin)
            inspection = next(i for i, sql in enumerate(statements) if "main.sqlite_schema" in sql)
            self.assertLess(index, inspection)
            self.assertEqual(statements[-1], "COMMIT")
            self.assertEqual(sum(sql.startswith("BEGIN") for sql in statements), 1)

    def insert_failure_id(self, observation_id, event_key):
        self.db.execute(
            "INSERT INTO acquisition_observation(id,event_key,evidence_kind,provider,"
            "logical_artifact_id,scope,declared_format,recorded_at,outcome,failure_code,cleanup_failed) "
            "VALUES(?,?,'SYNTHETIC',?,?,?,?,?,'FAILURE','stream_failure',0)",
            (observation_id, event_key, METADATA["provider"], METADATA["logical_artifact_id"],
             METADATA["scope"], METADATA["declared_format"], METADATA["recorded_at"]))

    def test_negative_id_trigger_experiment_and_explicit_positive_allocation(self):
        self.insert_failure_id(-1, "negative-one")
        self.insert_failure_id(-7, "negative-seven")
        before = database_state(self.db)
        # Targeted reproduction of the actual baseline trigger/SQLite behavior.
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be replaced"):
            self.db.execute(
                "INSERT INTO acquisition_observation(event_key,evidence_kind,provider,"
                "logical_artifact_id,scope,declared_format,recorded_at,outcome,failure_code,cleanup_failed) "
                "SELECT 'automatic','SYNTHETIC',provider,logical_artifact_id,scope,declared_format,"
                "recorded_at,outcome,failure_code,cleanup_failed FROM acquisition_observation WHERE id=-1")
        self.assertEqual(database_state(self.db), before)
        self.assertEqual(self.failure(event_key="negative-one"), -1)
        self.assertEqual(self.failure(event_key="negative-seven"), -7)
        self.assertEqual(self.success(), 1)
        self.assertEqual(self.failure(event_key="new-failure"), 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM acquisition_observation WHERE id<0").fetchone()[0], 2)

    def test_positive_id_exhaustion_rolls_back_artifact_and_allows_retry(self):
        maximum = 9223372036854775807
        self.insert_failure_id(maximum, METADATA["event_key"])
        self.assertEqual(self.failure(), maximum)
        self.assert_rejected_unchanged(
            self.db, lambda: self.success(event_key="new"), sqlite3.IntegrityError)
        self.assert_rejected_unchanged(
            self.db, lambda: self.failure(event_key="new"), sqlite3.IntegrityError)

    def test_historical_rows_seals_and_research_selection_behavior_preserved(self):
        historical_run, snapshots = populate_research(
            self.db, retrieved_at="2030-10-03T00:00:00Z",
            publication_at="2030-10-02T00:00:00Z", publication_evidence="Synthetic assertion")
        before = database_state(self.db)
        self.success()
        self.failure(event_key="failure")
        get_artifact(self.db, sha256=DIGEST)
        after = database_state(self.db)
        self.assertEqual(after[:2], before[:2])
        unaffected = {name: rows for name, rows in before[2]
                      if name not in ("raw_artifact", "acquisition_observation")}
        self.assertEqual({name: rows for name, rows in after[2] if name in unaffected}, unaffected)
        for mode, cutoff in (("OBSERVED_BY_EDGEFINDER", "2030-10-02T23:59:59Z"),
                             ("VERIFIED_PUBLICATION", "2030-10-01T23:59:59Z")):
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                                (historical_run, mode, cutoff))
        for snapshot in snapshots:
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("UPDATE source_snapshot SET retrieved_at=NULL WHERE id=?", (snapshot,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE validation_run SET sealed=0 WHERE id=?", (historical_run,))


class ProvenanceConcurrencyTests(unittest.TestCase):
    def success(self, db, **changes):
        values = dict(METADATA, body=BODY, sha256=DIGEST)
        values.update(changes)
        return persist_success(db, **values)

    def test_deferred_retrieval_does_not_reserve_writer_and_lock_failure_is_atomic(self):
        with TemporaryDirectory(prefix="edgefinder-provenance-") as folder:
            path = Path(folder) / "isolated.sqlite"
            with closing(database.connect(path)) as first, closing(database.connect(path)) as second:
                database.initialize(first)
                self.success(first)
                second.execute("PRAGMA busy_timeout=0")
                with database.transaction(first):
                    second.execute("PRAGMA query_only=ON")
                    self.assertEqual(get_artifact(second, sha256=DIGEST), BODY)
                    second.execute("PRAGMA query_only=OFF")
                    with self.assertRaises(sqlite3.OperationalError):
                        self.success(second, event_key="other")
                    self.assertFalse(second.in_transaction)
                    self.assertTrue(first.in_transaction)
                self.success(second, event_key="other")
                self.assertEqual(first.execute("SELECT count(*) FROM raw_artifact").fetchone()[0], 1)
                self.assertEqual(first.execute("SELECT count(*) FROM acquisition_observation").fetchone()[0], 2)

    def test_concurrent_identical_and_conflicting_events_serialize(self):
        with TemporaryDirectory(prefix="edgefinder-provenance-") as folder:
            path = Path(folder) / "isolated.sqlite"
            with closing(database.connect(path)) as db:
                database.initialize(db)
            for same in (True, False):
                barrier = Barrier(2)

                def worker(index):
                    with closing(database.connect(path)) as db:
                        barrier.wait(timeout=10)
                        try:
                            return self.success(db, event_key=f"concurrent-{same}",
                                                scope="same scope" if same else f"scope {index}")
                        except ValueError:
                            self.assertFalse(db.in_transaction)
                            return "conflict"

                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(worker, (0, 1)))
                if same:
                    self.assertIs(type(results[0]), int)
                    self.assertEqual(results[0], results[1])
                else:
                    self.assertEqual(results.count("conflict"), 1)
                    self.assertEqual(sum(type(result) is int for result in results), 1)
            with closing(database.connect(path)) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM raw_artifact").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT count(*) FROM acquisition_observation").fetchone()[0], 2)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
