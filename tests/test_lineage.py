"""Offline grouped lineage checks using isolated synthetic SQLite fixtures."""

from contextlib import closing
from dataclasses import FrozenInstanceError
import hashlib
import sqlite3
import unittest
from unittest.mock import patch

from edgefinder.acquisition.runner import OfflineFailureCode
from edgefinder.storage import database, lineage, provenance
from edgefinder.storage.lineage import (
    Derivation, DerivationInput, get_derivation, list_derivation_ids, register_derivation,
)
from tests.test_storage_migrations import database_state, legacy_schema, populate_research


RECORDED_AT = "2030-10-03T00:00:00Z"
BODY = b"\x00\xffsynthetic lineage\x80"
DIGEST = hashlib.sha256(BODY).hexdigest()
METADATA = dict(event_key="lineage-event", provider="synthetic", logical_artifact_id="fixture",
                scope="invented fixture", declared_format="opaque", recorded_at=RECORDED_AT)


class LineageTests(unittest.TestCase):
    def setUp(self):
        self.db = database.connect()
        self.addCleanup(self.db.close)
        database.initialize(self.db)
        self.run, self.snapshots = populate_research(self.db)
        self.observation = provenance.persist_success(self.db, **METADATA, body=BODY, sha256=DIGEST)

    def register(self, db=None, **changes):
        values = dict(snapshot_id=self.snapshots[0], transformation_id="fixture.transform",
                      transformation_version="v1", parameters={"selection": [1, True, None]},
                      recorded_at=RECORDED_AT, inputs=(("players", self.observation),))
        values.update(changes)
        return register_derivation(self.db if db is None else db, **values)

    def operations(self, db):
        return (lambda: self.register(db=db),
                lambda: get_derivation(db, derivation_id=1),
                lambda: list_derivation_ids(db, snapshot_id=self.snapshots[0]))

    def assert_rejected_unchanged(self, operation, error, db=None):
        db = self.db if db is None else db
        before = database_state(db)
        with self.assertRaises(error):
            operation()
        self.assertEqual(database_state(db), before)
        self.assertFalse(db.in_transaction)

    def corrupt(self, sql, parameters=(), *, guards):
        """Damage memory fixtures only; restore exact schema before API calls."""
        definitions = [self.db.execute(
            "SELECT sql FROM main.sqlite_schema WHERE name=?", (name,)).fetchone()[0]
                       for name in guards]
        self.db.execute("PRAGMA foreign_keys=OFF")
        self.db.execute("PRAGMA ignore_check_constraints=ON")
        try:
            for name in guards:
                self.db.execute(f'DROP TRIGGER "{name}"')
            self.db.execute(sql, parameters)
        finally:
            for definition in definitions:
                self.db.execute(definition)
            self.db.execute("PRAGMA ignore_check_constraints=OFF")
            self.db.execute("PRAGMA foreign_keys=ON")

    def header(self, *, identifier=None, **changes):
        values = dict(snapshot_id=self.snapshots[0], transformation_id="fixture.transform",
                      transformation_version="v1", parameters=database.canonical(None),
                      recorded_at=RECORDED_AT, expected_input_count=1, evidence_kind="SYNTHETIC")
        if identifier is not None:
            values["id"] = identifier
        values.update(changes)
        return self.db.execute(
            f"INSERT INTO snapshot_derivation({','.join(values)}) "
            f"VALUES({','.join('?' for _ in values)})", tuple(values.values())).lastrowid

    def test_round_trip_and_exact_immutable_dataclass_contract(self):
        identifier = self.register()
        result = get_derivation(self.db, derivation_id=identifier, verify_artifacts=True)
        self.assertIs(type(identifier), int)
        self.assertEqual(result, Derivation(
            identifier, self.snapshots[0], "fixture.transform", "v1",
            database.canonical({"selection": [1, True, None]}), RECORDED_AT, 1,
            "SYNTHETIC", True, (DerivationInput(0, "players", self.observation, DIGEST),)))
        self.assertIs(type(result.inputs), tuple)
        self.assertIs(type(result.sealed), bool)
        for target, name, value in ((result, "snapshot_id", 7),
                                    (result.inputs[0], "input_label", "changed")):
            with self.assertRaises(FrozenInstanceError):
                setattr(target, name, value)
        self.assertIsInstance(hash(result), int)

    def test_option_a_identical_retries_create_distinct_immutable_assertions(self):
        first = self.register()
        old = get_derivation(self.db, derivation_id=first)
        changes = self.db.total_changes
        second = self.register()
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.total_changes - changes, 3)
        self.assertEqual(get_derivation(self.db, derivation_id=first), old)
        self.assertEqual(list_derivation_ids(self.db, snapshot_id=self.snapshots[0]),
                         (first, second))

    def test_multiple_derivations_keep_alternative_groups_separate(self):
        first = self.register()
        second = self.register(parameters={"selection": "other"}, inputs=(("teams", self.observation),))
        self.assertEqual(get_derivation(self.db, derivation_id=first).inputs[0].input_label, "players")
        self.assertEqual(get_derivation(self.db, derivation_id=second).inputs[0].input_label, "teams")
        other = self.register(snapshot_id=self.snapshots[1])
        self.assertEqual(list_derivation_ids(self.db, snapshot_id=self.snapshots[1]), (other,))

    def test_repeated_labels_observations_and_shared_artifacts_preserve_order(self):
        another = provenance.persist_success(self.db, **dict(METADATA, event_key="another"),
                                              body=BODY, sha256=DIGEST)
        inputs = (("z", another), ("a", self.observation), ("z", self.observation),
                  ("z", another), ("a", self.observation))
        identifier = self.register(inputs=inputs)
        with patch.object(provenance, "_retained_artifact", wraps=provenance._retained_artifact) as verify:
            result = get_derivation(self.db, derivation_id=identifier, verify_artifacts=True)
        self.assertEqual(tuple((i.input_label, i.observation_id) for i in result.inputs), inputs)
        self.assertEqual(tuple(i.ordinal for i in result.inputs), tuple(range(len(inputs))))
        verify.assert_called_once_with(self.db, DIGEST)

    def test_out_of_order_sql_insertion_is_read_in_declared_ordinal_order(self):
        identifier = self.header(expected_input_count=3)
        for ordinal, label in ((2, "z"), (0, "a"), (1, "b")):
            self.db.execute("INSERT INTO derivation_input VALUES(?,?,?,?)",
                            (identifier, ordinal, label, self.observation))
        self.db.execute("UPDATE snapshot_derivation SET sealed=1 WHERE id=?", (identifier,))
        self.assertEqual(tuple(i.input_label for i in get_derivation(
            self.db, derivation_id=identifier).inputs), ("a", "b", "z"))

    def test_list_is_sorted_immutable_excludes_open_groups_and_returns_empty(self):
        self.assertEqual(list_derivation_ids(self.db, snapshot_id=99999), ())
        self.assertEqual(list_derivation_ids(self.db, snapshot_id=self.snapshots[0]), ())
        self.header(identifier=10)
        for identifier in (7, -3, 2):
            self.header(identifier=identifier)
            self.db.execute("INSERT INTO derivation_input VALUES(?,0,'fixture',?)",
                            (identifier, self.observation))
            self.db.execute("UPDATE snapshot_derivation SET sealed=1 WHERE id=?", (identifier,))
        result = list_derivation_ids(self.db, snapshot_id=self.snapshots[0])
        self.assertIs(type(result), tuple)
        self.assertEqual(result, (-3, 2, 7))
        self.assertEqual(get_derivation(self.db, derivation_id=-3).derivation_id, -3)

    def test_input_count_zero_and_4097_rejected_4096_preserved(self):
        for inputs in ((), (("fixture", self.observation),) * 4097):
            self.assert_rejected_unchanged(lambda: self.register(inputs=inputs), ValueError)
        inputs = (("fixture", self.observation),) * 4096
        identifier = self.register(inputs=inputs)
        result = get_derivation(self.db, derivation_id=identifier)
        self.assertEqual(result.expected_input_count, 4096)
        self.assertEqual(tuple((i.input_label, i.observation_id) for i in result.inputs), inputs)

    def test_inputs_require_exact_tuples_and_pairs(self):
        for inputs in (None, [], [("fixture", self.observation)],
                       (["fixture", self.observation],), (("fixture",),),
                       (("fixture", self.observation, 7),), ("fixture",)):
            with self.subTest(inputs=inputs):
                self.assert_rejected_unchanged(lambda: self.register(inputs=inputs), TypeError)

    def test_identifier_types_and_sqlite_bounds(self):
        for value, error in ((None, TypeError), (True, TypeError), (1.0, TypeError),
                             ("1", TypeError), (2 ** 63, ValueError), (-2 ** 63 - 1, ValueError)):
            for operation in (lambda: self.register(snapshot_id=value),
                              lambda: self.register(inputs=(("fixture", value),)),
                              lambda: get_derivation(self.db, derivation_id=value),
                              lambda: list_derivation_ids(self.db, snapshot_id=value)):
                with self.subTest(value=value):
                    self.assert_rejected_unchanged(operation, error)

    def test_missing_unsealed_and_historical_snapshots_rejected(self):
        unsealed = self.db.execute(
            "INSERT INTO source_snapshot(provider,role,loader_scope,normalization_version,normalized_sha256) "
            "VALUES('synthetic','IDENTITY','unsealed','edgefinder.normalized.v1',?)", ("0" * 64,)).lastrowid
        snapshots = [99999, unsealed]
        for times in (dict(retrieved_at=RECORDED_AT),
                      dict(publication_at=RECORDED_AT, publication_evidence="Synthetic assertion")):
            snapshots.append(database.add_snapshot(
                self.db, provider="synthetic", role="IDENTITY", loader_scope="historical",
                rows=[dict(namespace_id=1, payload=times)], **times))
        for snapshot_id in snapshots:
            with self.subTest(snapshot=snapshot_id):
                self.assert_rejected_unchanged(lambda: self.register(snapshot_id=snapshot_id),
                                               sqlite3.IntegrityError)

    def test_every_output_evidence_field_is_rechecked_on_register_and_retrieval(self):
        identifier = self.register()
        for field, value in (("retrieved_at", RECORDED_AT), ("publication_at", RECORDED_AT),
                             ("publication_evidence", "synthetic"), ("original_file_sha256", "a" * 64),
                             ("sealed", 0)):
            old = self.db.execute(f"SELECT {field} FROM source_snapshot WHERE id=?",
                                  (self.snapshots[0],)).fetchone()[0]
            self.corrupt(f"UPDATE source_snapshot SET {field}=? WHERE id=?",
                         (value, self.snapshots[0]), guards=("snapshot_seal",))
            try:
                for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
                    with self.subTest(field=field):
                        self.assert_rejected_unchanged(operation, sqlite3.IntegrityError)
            finally:
                self.corrupt(f"UPDATE source_snapshot SET {field}=? WHERE id=?",
                             (old, self.snapshots[0]), guards=("snapshot_seal",))

    def test_missing_and_failed_observations_are_rejected(self):
        failed = provenance.persist_failure(
            self.db, **dict(METADATA, event_key="failed"),
            failure_code=OfflineFailureCode.STREAM_FAILURE, cleanup_failed=False)
        for observation in (99999, failed):
            self.assert_rejected_unchanged(
                lambda: self.register(inputs=(("fixture", observation),)), sqlite3.IntegrityError)

    def test_malformed_observation_metadata_and_success_facts_rejected_on_both_paths(self):
        identifier = self.register()
        changes = (("event_key", "invalid/key"), ("provider", "INVALID"),
                   ("logical_artifact_id", ""), ("scope", " leading"),
                   ("declared_format", "invalid/format"), ("recorded_at", "2030-02-30T00:00:00Z"),
                   ("evidence_kind", "OTHER"), ("outcome", "FAILURE"),
                   ("failure_code", "stream_failure"), ("cleanup_failed", 1),
                   ("artifact_sha256", None))
        for field, value in changes:
            old = self.db.execute(f"SELECT {field} FROM acquisition_observation WHERE id=?",
                                  (self.observation,)).fetchone()[0]
            self.corrupt(f"UPDATE acquisition_observation SET {field}=? WHERE id=?",
                         (value, self.observation), guards=("acquisition_update",))
            try:
                for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
                    with self.subTest(field=field):
                        self.assert_rejected_unchanged(operation, sqlite3.IntegrityError)
            finally:
                self.corrupt(f"UPDATE acquisition_observation SET {field}=? WHERE id=?",
                             (old, self.observation), guards=("acquisition_update",))

    def test_artifact_lengths_and_storage_type_checked_without_hashing_bodies(self):
        identifier = self.register()
        for length in (-1, len(BODY) + 1, database.MAX_ARTIFACT_BYTES + 1):
            self.corrupt("UPDATE raw_artifact SET byte_length=? WHERE sha256=?",
                         (length, DIGEST), guards=("artifact_update",))
            try:
                for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
                    self.assert_rejected_unchanged(operation, sqlite3.IntegrityError)
            finally:
                self.corrupt("UPDATE raw_artifact SET byte_length=? WHERE sha256=?",
                             (len(BODY), DIGEST), guards=("artifact_update",))
        self.db.create_function("typeof", 1, lambda body: "text")
        for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
            self.assert_rejected_unchanged(operation, sqlite3.IntegrityError)

    def test_missing_artifact_rejected_as_existing_foreign_key_corruption(self):
        identifier = self.register()
        self.corrupt("DELETE FROM raw_artifact WHERE sha256=?", (DIGEST,), guards=("artifact_delete",))
        for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
            self.assert_rejected_unchanged(operation, RuntimeError)

    def test_inconsistent_artifact_reference_rejected_without_repair(self):
        identifier = self.register()
        self.corrupt("UPDATE acquisition_observation SET artifact_sha256=? WHERE id=?",
                     ("0" * 64, self.observation), guards=("acquisition_update",))
        for operation in (self.register, lambda: get_derivation(self.db, derivation_id=identifier)):
            self.assert_rejected_unchanged(operation, RuntimeError)

    def test_python_parameter_canonicalization_including_typed_values(self):
        values = {"z": [None, True, 1, 1.0, -0.0, "\u00e9"], "a": {"x": []}}
        identifier = self.register(parameters=values)
        values["z"].append("caller mutation")
        result = get_derivation(self.db, derivation_id=identifier)
        self.assertEqual(result.parameters, database.canonical(
            {"a": {"x": []}, "z": [None, True, 1, 1.0, -0.0, "\u00e9"]}))
        for value in (None, True, 1, 1.0, "text", [1], {"x": 1}):
            identifier = self.register(parameters=value)
            self.assertEqual(get_derivation(self.db, derivation_id=identifier).parameters,
                             database.canonical(value))

    def test_canonical_json_text_is_an_ordinary_string_not_alternate_input(self):
        text = database.canonical({"x": 1})
        identifier = self.register(parameters=text)
        self.assertEqual(get_derivation(self.db, derivation_id=identifier).parameters,
                         database.canonical(text))
        self.assert_rejected_unchanged(lambda: self.register(parameters_json=text), TypeError)

    def test_parameter_byte_size_boundary_65536_and_65537(self):
        overhead = len(database.canonical("").encode("utf-8"))
        accepted = "x" * (65536 - overhead)
        self.assertEqual(len(database.canonical(accepted).encode("utf-8")), 65536)
        identifier = self.register(parameters=accepted)
        self.assertEqual(len(get_derivation(self.db, derivation_id=identifier).parameters.encode("utf-8")), 65536)
        self.assert_rejected_unchanged(lambda: self.register(parameters=accepted + "x"), ValueError)
        # ASCII escaping makes code-point count an invalid substitute for bytes.
        unicode_value = "\u00e9" * ((65536 - overhead) // 6 + 1)
        self.assertLess(len(unicode_value), 65536)
        self.assert_rejected_unchanged(lambda: self.register(parameters=unicode_value), ValueError)

    def test_invalid_python_parameters_rejected_without_writes(self):
        for value, error in ((float("nan"), ValueError), (float("inf"), ValueError),
                             ("\ud800", ValueError), ({"\udfff": 1}, ValueError),
                             ((1,), TypeError), ({1: "x"}, TypeError), (b"x", TypeError)):
            self.assert_rejected_unchanged(lambda: self.register(parameters=value), error)

    def test_transformation_metadata_and_input_label_syntax_and_types(self):
        for field in ("transformation_id", "transformation_version"):
            for value in ("", "a" * 129, "INVALID", "-leading", "a/b", "a\x00", "a\n", "\u00e9"):
                with self.subTest(field=field, value=repr(value)):
                    self.assert_rejected_unchanged(lambda: self.register(**{field: value}), ValueError)
            for value in (None, 1, b"fixture"):
                self.assert_rejected_unchanged(lambda: self.register(**{field: value}), TypeError)
        for value, error in (("", ValueError), ("a" * 129, ValueError), ("a/b", ValueError),
                             ("a\x00", ValueError), (None, TypeError), (1, TypeError)):
            self.assert_rejected_unchanged(
                lambda: self.register(inputs=((value, self.observation),)), error)
        self.register(transformation_id="a" * 128, transformation_version="0._-v1",
                      inputs=(("a" * 128, self.observation),))

    def test_recorded_at_requires_valid_canonical_utc_seconds(self):
        for value in ("", "0000-01-01T00:00:00Z", "2030-02-29T00:00:00Z",
                      "2030-02-30T00:00:00Z", "2030-10-03T24:00:00Z",
                      "2030-10-03T00:00:60Z", "2030-10-03T00:00:00+00:00",
                      "2030-10-03T00:00:00.000Z", RECORDED_AT + "\n"):
            self.assert_rejected_unchanged(lambda: self.register(recorded_at=value), ValueError)
        for value in (None, 1):
            self.assert_rejected_unchanged(lambda: self.register(recorded_at=value), TypeError)
        for value in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "2032-02-29T00:00:00Z"):
            self.register(recorded_at=value)

    def test_input_insertion_failure_rolls_back_staged_header(self):
        counts = []

        # Deny input preparation after the header has been written.
        def deny_input(action, first, second, schema, source):
            if action == sqlite3.SQLITE_INSERT and first == "derivation_input":
                counts.append(self.db.execute("SELECT count(*) FROM snapshot_derivation").fetchone()[0])
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(deny_input)
        try:
            self.assert_rejected_unchanged(self.register, sqlite3.DatabaseError)
        finally:
            self.db.set_authorizer(None)
        self.assertEqual(counts, [1], "insertion failure must follow header insertion")

    def test_mid_group_sqlite_interrupt_rolls_back_already_inserted_input(self):
        before = database_state(self.db)
        # Inject after the first input statement using SQLite's progress callback.
        seen_partial = []

        def interrupt():
            if seen_partial:
                return 0
            count = self.db.execute("SELECT count(*) FROM derivation_input").fetchone()[0]
            if count:
                seen_partial.append(count)
                return 1
            return 0

        # Install only after validation and header insertion to avoid recursive
        # inspection during schema validation. Reentrant inspection is disabled.
        insert = lineage._insert_header

        def insert_then_watch(*args):
            identifier = insert(*args)

            def progress():
                self.db.set_progress_handler(None, 0)
                result = interrupt()
                if not result:
                    self.db.set_progress_handler(progress, 1)
                return result

            self.db.set_progress_handler(progress, 1)
            return identifier

        try:
            with patch.object(lineage, "_insert_header", side_effect=insert_then_watch):
                with self.assertRaises(sqlite3.OperationalError):
                    self.register(inputs=(("a", self.observation), ("b", self.observation)))
        finally:
            self.db.set_progress_handler(None, 0)
        self.assertEqual(seen_partial, [1])
        self.assertEqual(database_state(self.db), before)
        self.assertFalse(self.db.in_transaction)

    def test_failed_sealing_rolls_back_complete_staged_group(self):
        counts = []

        def deny_seal(action, first, second, schema, source):
            if action == sqlite3.SQLITE_UPDATE and first == "snapshot_derivation":
                counts.append(self.db.execute("SELECT count(*) FROM derivation_input").fetchone()[0])
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(deny_seal)
        try:
            self.assert_rejected_unchanged(self.register, sqlite3.DatabaseError)
        finally:
            self.db.set_authorizer(None)
        self.assertEqual(counts, [1], "sealing failure must follow all input inserts")

    def test_silently_ignored_sealing_does_not_commit_open_group(self):
        def ignore_seal(action, first, second, schema, source):
            if action == sqlite3.SQLITE_UPDATE and first == "snapshot_derivation":
                return sqlite3.SQLITE_IGNORE
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(ignore_seal)
        try:
            self.assert_rejected_unchanged(self.register, sqlite3.IntegrityError)
        finally:
            self.db.set_authorizer(None)

    def test_commit_failure_and_baseexception_roll_back_owned_work(self):
        def deny_commit(action, first, second, schema, source):
            if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(deny_commit)
        try:
            self.assert_rejected_unchanged(self.register, sqlite3.DatabaseError)
        finally:
            self.db.set_authorizer(None)
        original = lineage._insert_header

        def insert_then_interrupt(*args):
            original(*args)
            raise KeyboardInterrupt

        with patch.object(lineage, "_insert_header", side_effect=insert_then_interrupt):
            self.assert_rejected_unchanged(self.register, KeyboardInterrupt)

    def test_active_caller_work_remains_uncommitted_and_owned_by_caller(self):
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO entity(kind,label) VALUES('TEAM','caller fixture')")
        before = database_state(self.db)
        statements = []
        self.db.set_trace_callback(statements.append)
        try:
            for operation in self.operations(self.db):
                with self.assertRaisesRegex(RuntimeError, "Active caller transaction"):
                    operation()
                self.assertTrue(self.db.in_transaction)
                self.assertEqual(database_state(self.db), before)
            # Active ownership takes precedence even over malformed arguments.
            with self.assertRaisesRegex(RuntimeError, "Active caller transaction"):
                self.register(parameters=object(), inputs=())
            self.assertFalse(any(sql in ("COMMIT", "ROLLBACK") for sql in statements))
        finally:
            self.db.set_trace_callback(None)
            self.db.rollback()
        self.assertEqual(self.db.execute("SELECT count(*) FROM entity WHERE label='caller fixture'").fetchone()[0], 0)

    def test_negative_derivation_ids_preserved_and_positive_allocation_succeeds(self):
        self.header(identifier=-1)
        self.header(identifier=-7)
        before = tuple(tuple(r) for r in self.db.execute("SELECT * FROM snapshot_derivation WHERE id<0 ORDER BY id"))
        self.assertEqual(self.register(), 1)
        self.assertEqual(self.register(), 2)
        self.assertEqual(tuple(tuple(r) for r in self.db.execute(
            "SELECT * FROM snapshot_derivation WHERE id<0 ORDER BY id")), before)

    def test_negative_observation_and_snapshot_identifiers_are_valid_references(self):
        snapshot = -8
        self.db.execute(
            "INSERT INTO source_snapshot(id,provider,role,loader_scope,normalization_version,normalized_sha256) "
            "SELECT ?,provider,role,'negative',normalization_version,normalized_sha256 FROM source_snapshot WHERE id=?",
            (snapshot, self.snapshots[0]))
        self.db.execute(
            "INSERT INTO source_record(snapshot_id,ordinal," + ",".join(database.RECORD_FIELDS) + ",normalized) "
            "SELECT ?,ordinal," + ",".join(database.RECORD_FIELDS) + ",normalized FROM source_record WHERE snapshot_id=?",
            (snapshot, self.snapshots[0]))
        self.db.execute("UPDATE source_snapshot SET sealed=1 WHERE id=?", (snapshot,))
        self.db.execute(
            "INSERT INTO acquisition_observation(id," + ",".join(provenance._EVENT_COLUMNS) + ") "
            "SELECT -9,'negative-event',evidence_kind,provider,logical_artifact_id,scope,declared_format,"
            "recorded_at,outcome,artifact_sha256,failure_code,cleanup_failed FROM acquisition_observation WHERE id=?",
            (self.observation,))
        identifier = self.register(snapshot_id=snapshot, inputs=(("negative", -9),))
        result = get_derivation(self.db, derivation_id=identifier)
        self.assertEqual((result.snapshot_id, result.inputs[0].observation_id), (-8, -9))

    def test_positive_derivation_id_exhaustion_rolls_back(self):
        self.header(identifier=9223372036854775807)
        self.assert_rejected_unchanged(self.register, sqlite3.IntegrityError)

    def test_missing_and_unsealed_derivations_rejected(self):
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=99999), KeyError)
        identifier = self.header()
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                       sqlite3.IntegrityError)
        self.db.execute("INSERT INTO derivation_input VALUES(?,0,'fixture',?)", (identifier, self.observation))
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                       sqlite3.IntegrityError)

    def test_incomplete_counts_and_noncontiguous_positions_rejected(self):
        identifier = self.register(inputs=(("a", self.observation), ("b", self.observation)))
        self.corrupt("DELETE FROM derivation_input WHERE derivation_id=? AND ordinal=1",
                     (identifier,), guards=("input_delete",))
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                       sqlite3.IntegrityError)
        self.corrupt("UPDATE derivation_input SET ordinal=1 WHERE derivation_id=?", (identifier,),
                     guards=("input_update",))
        self.corrupt("UPDATE snapshot_derivation SET expected_input_count=1 WHERE id=?", (identifier,),
                     guards=("derivation_seal",))
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                       sqlite3.IntegrityError)

    def test_malformed_derivation_header_rejected(self):
        identifier = self.register()
        for field, value in (("sealed", 2), ("evidence_kind", "OTHER"), ("expected_input_count", 0),
                             ("expected_input_count", 4097), ("transformation_id", "bad/id"),
                             ("transformation_version", "BAD"), ("recorded_at", "2030-02-30T00:00:00Z"),
                             ("parameters", "{}"), ("parameters", '["bool",1]'),
                             ("parameters", database.canonical("x" * 65536))):
            old = self.db.execute(f"SELECT {field} FROM snapshot_derivation WHERE id=?", (identifier,)).fetchone()[0]
            self.corrupt(f"UPDATE snapshot_derivation SET {field}=? WHERE id=?", (value, identifier),
                         guards=("derivation_seal",))
            try:
                with self.subTest(field=field, value=repr(value)[:60]):
                    self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                                   sqlite3.IntegrityError)
            finally:
                self.corrupt(f"UPDATE snapshot_derivation SET {field}=? WHERE id=?", (old, identifier),
                             guards=("derivation_seal",))

    def test_malformed_input_label_rejected_on_retrieval(self):
        identifier = self.register()
        self.corrupt("UPDATE derivation_input SET input_label='bad/label' WHERE derivation_id=?",
                     (identifier,), guards=("input_update",))
        self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier),
                                       sqlite3.IntegrityError)

    def test_missing_input_observation_and_output_snapshot_relationships_rejected(self):
        identifier = self.register()
        for table, field, guard in (("derivation_input", "observation_id", "input_update"),
                                    ("snapshot_derivation", "snapshot_id", "derivation_seal")):
            key = "derivation_id" if table == "derivation_input" else "id"
            old = self.db.execute(f"SELECT {field} FROM {table} WHERE {key}=?", (identifier,)).fetchone()[0]
            self.corrupt(f"UPDATE {table} SET {field}=99999 WHERE {key}=?", (identifier,), guards=(guard,))
            try:
                self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier), RuntimeError)
            finally:
                self.corrupt(f"UPDATE {table} SET {field}=? WHERE {key}=?", (old, identifier), guards=(guard,))

    def test_same_length_artifact_tampering_requires_full_sha256_verification(self):
        identifier = self.register()
        self.corrupt("UPDATE raw_artifact SET body=? WHERE sha256=?",
                     (b"x" * len(BODY), DIGEST), guards=("artifact_update",))
        original = database._artifact_sha256
        self.db.create_function("artifact_sha256", 1,
                                lambda body: original(body) if body == b"" else DIGEST,
                                deterministic=True)
        before = database_state(self.db)
        self.assertEqual(get_derivation(self.db, derivation_id=identifier).inputs[0].artifact_sha256, DIGEST)
        self.assert_rejected_unchanged(
            lambda: get_derivation(self.db, derivation_id=identifier, verify_artifacts=True), sqlite3.IntegrityError)
        self.assertEqual(database_state(self.db), before)

    def test_default_metadata_mode_does_not_materialize_artifact_bytes(self):
        with patch.object(provenance, "_retained_artifact", side_effect=AssertionError("unexpected body read")):
            identifier = self.register()
            get_derivation(self.db, derivation_id=identifier)

    def test_verify_artifacts_requires_exact_boolean(self):
        identifier = self.register()
        for value in (None, 0, 1, "true"):
            self.assert_rejected_unchanged(
                lambda: get_derivation(self.db, derivation_id=identifier, verify_artifacts=value), TypeError)

    def test_incompatible_schemas_rejected_without_installation_or_repairs(self):
        alterations = ("PRAGMA user_version=0", "PRAGMA user_version=2",
                       "DROP TRIGGER derivation_seal", "DROP INDEX derivation_snapshot",
                       "ALTER TABLE snapshot_derivation ADD COLUMN extra TEXT",
                       "CREATE TABLE extra(x TEXT) STRICT")
        for alteration in (None, "legacy", *alterations):
            with self.subTest(alteration=alteration), closing(database.connect()) as db:
                if alteration == "legacy":
                    legacy_schema(db)
                elif alteration is not None:
                    database.initialize(db)
                    db.execute(alteration)
                for operation in self.operations(db):
                    self.assert_rejected_unchanged(operation, RuntimeError, db=db)

    def test_compatibility_checked_on_each_call(self):
        identifier = self.register()
        get_derivation(self.db, derivation_id=identifier)
        list_derivation_ids(self.db, snapshot_id=self.snapshots[0])
        self.db.execute("DROP TRIGGER input_delete")
        for operation in self.operations(self.db):
            self.assert_rejected_unchanged(operation, RuntimeError)

    def test_connection_contracts_constraints_and_callbacks_checked(self):
        with self.assertRaises(TypeError):
            register_derivation(None, snapshot_id=1, transformation_id="x", transformation_version="v1",
                                parameters=None, recorded_at=RECORDED_AT, inputs=(("x", 1),))
        for operation in (lambda: get_derivation(None, derivation_id=1),
                          lambda: list_derivation_ids(None, snapshot_id=1)):
            with self.assertRaises(TypeError):
                operation()
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
        for pragma, value, restore in (("foreign_keys", 0, 1), ("recursive_triggers", 0, 1),
                                       ("ignore_check_constraints", 1, 0)):
            self.db.execute(f"PRAGMA {pragma}={value}")
            try:
                for operation in self.operations(self.db):
                    self.assert_rejected_unchanged(operation, RuntimeError)
            finally:
                self.db.execute(f"PRAGMA {pragma}={restore}")
        self.db.create_function("artifact_sha256", 1, None)
        for operation in self.operations(self.db):
            self.assert_rejected_unchanged(operation, RuntimeError)

    def test_temp_shadowing_and_attached_databases_rejected(self):
        for sql in ("CREATE TEMP TABLE snapshot_derivation(x)", "ATTACH DATABASE ':memory:' AS other"):
            with self.subTest(sql=sql), closing(database.connect()) as db:
                database.initialize(db)
                db.execute(sql)
                for operation in self.operations(db):
                    self.assert_rejected_unchanged(operation, RuntimeError, db=db)

    def test_write_read_modes_and_schema_inspection_share_one_transaction(self):
        identifier = self.register()
        for operation, begin in ((self.register, "BEGIN IMMEDIATE"),
                                 (lambda: get_derivation(self.db, derivation_id=identifier,
                                                         verify_artifacts=True), "BEGIN DEFERRED"),
                                 (lambda: list_derivation_ids(self.db, snapshot_id=self.snapshots[0]),
                                  "BEGIN DEFERRED")):
            statements = []
            self.db.set_trace_callback(statements.append)
            try:
                operation()
            finally:
                self.db.set_trace_callback(None)
            index = statements.index(begin)
            schema = next(i for i, sql in enumerate(statements) if "main.sqlite_schema" in sql)
            self.assertLess(index, schema)
            self.assertEqual(sum(sql.startswith("BEGIN") for sql in statements), 1)
            self.assertEqual(statements[-1], "COMMIT")
            self.assertFalse(self.db.in_transaction)

    def test_read_failures_and_control_signals_release_only_owned_transactions(self):
        identifier = self.register()
        with patch.object(lineage, "_occurrences", side_effect=KeyboardInterrupt):
            self.assert_rejected_unchanged(lambda: get_derivation(self.db, derivation_id=identifier), KeyboardInterrupt)

        def deny_commit(action, first, second, schema, source):
            if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.db.set_authorizer(deny_commit)
        try:
            for operation in self.operations(self.db)[1:]:
                self.assert_rejected_unchanged(operation, sqlite3.DatabaseError)
        finally:
            self.db.set_authorizer(None)

    def test_existing_snapshot_run_and_research_selection_state_never_changes(self):
        before = database_state(self.db)
        identifier = self.register()
        get_derivation(self.db, derivation_id=identifier, verify_artifacts=True)
        list_derivation_ids(self.db, snapshot_id=self.snapshots[0])
        after = database_state(self.db)
        self.assertEqual(after[:2], before[:2])
        protected = {name: rows for name, rows in before[2]
                     if name not in ("snapshot_derivation", "derivation_input")}
        self.assertEqual({name: rows for name, rows in after[2] if name in protected}, protected)
        for mode in ("OBSERVED_BY_EDGEFINDER", "VERIFIED_PUBLICATION"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                                (self.run, mode, "9999-12-31T23:59:59Z"))

    def test_existing_historical_evidence_and_selections_remain_unchanged(self):
        with closing(database.connect()) as db:
            database.initialize(db)
            _, historical = populate_research(
                db, retrieved_at=RECORDED_AT, publication_at="2030-10-02T00:00:00Z",
                publication_evidence="Synthetic historical assertion")
            synthetic = database.add_snapshot(
                db, provider="synthetic", role="IDENTITY", loader_scope="lineage-only",
                rows=[dict(namespace_id=1, identifier="synthetic-player")])
            observation = provenance.persist_success(db, **METADATA, body=BODY, sha256=DIGEST)
            before = database_state(db)
            identifier = self.register(db=db, snapshot_id=synthetic, inputs=(("fixture", observation),))
            get_derivation(db, derivation_id=identifier, verify_artifacts=True)
            list_derivation_ids(db, snapshot_id=synthetic)
            for snapshot in historical:
                self.assert_rejected_unchanged(
                    lambda: self.register(db=db, snapshot_id=snapshot, inputs=(("fixture", observation),)),
                    sqlite3.IntegrityError, db=db)
            after = database_state(db)
            self.assertEqual(after[:2], before[:2])
            protected = {name: rows for name, rows in before[2]
                         if name not in ("snapshot_derivation", "derivation_input")}
            self.assertEqual({name: rows for name, rows in after[2] if name in protected}, protected)


class NegativeDerivationIdTests(unittest.TestCase):
    def test_omitted_id_collides_with_negative_one_in_existing_trigger(self):
        """Reproduce allocation behavior before choosing an API workaround."""
        with closing(database.connect()) as db:
            database.initialize(db)
            _, snapshots = populate_research(db)
            facts = (snapshots[0], "fixture.transform", "v1", database.canonical(None),
                     RECORDED_AT, 1, "SYNTHETIC")
            columns = ("snapshot_id,transformation_id,transformation_version,parameters,"
                       "recorded_at,expected_input_count,evidence_kind")
            for identifier in (-1, -7):
                db.execute(f"INSERT INTO snapshot_derivation(id,{columns}) "
                           "VALUES(?,?,?,?,?,?,?,?)", (identifier, *facts))
            before = database_state(db)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be replaced"):
                db.execute(f"INSERT INTO snapshot_derivation({columns}) "
                           "VALUES(?,?,?,?,?,?,?)", facts)
            self.assertEqual(database_state(db), before)
            self.assertFalse(db.in_transaction)


if __name__ == "__main__":
    unittest.main()
