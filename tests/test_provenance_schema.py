"""Direct synthetic SQL fixtures only; no provenance persistence APIs or I/O."""

import hashlib
import sqlite3
import unittest

from edgefinder.acquisition.runner import OfflineFailureCode
from edgefinder.storage.database import (
    MAX_ARTIFACT_BYTES, _artifact_sha256, add_snapshot, canonical, connect, initialize,
)
from tests.test_storage_migrations import populate_research


RECORDED_AT = "2030-10-03T00:00:00Z"


class ProvenanceSchemaTests(unittest.TestCase):
    def setUp(self):
        self.db = connect()
        self.addCleanup(self.db.close)
        initialize(self.db)
        self.run, self.snapshots = populate_research(self.db)
        self.sequence = 0

    def artifact(self, body=b"\x00\xffsynthetic\x80"):
        digest = hashlib.sha256(body).hexdigest()
        self.db.execute("INSERT INTO raw_artifact(sha256,byte_length,body) VALUES(?,?,?)",
                        (digest, len(body), body))
        return digest

    def observation(self, **changes):
        self.sequence += 1
        values = dict(event_key=f"event-{self.sequence}", evidence_kind="SYNTHETIC",
                      provider="synthetic", logical_artifact_id="fixture",
                      scope="invented fixture", declared_format="opaque", recorded_at=RECORDED_AT,
                      outcome="FAILURE", artifact_sha256=None, failure_code="stream_failure",
                      cleanup_failed=0)
        values.update(changes)
        return self.db.execute(
            f"INSERT INTO acquisition_observation({','.join(values)}) "
            f"VALUES({','.join('?' for _ in values)})", tuple(values.values())).lastrowid

    def success(self, **changes):
        body = f"artifact-{self.sequence}".encode()
        digest = self.artifact(body)
        return self.observation(outcome="SUCCESS", artifact_sha256=digest,
                                failure_code=None, **changes)

    def derivation(self, **changes):
        values = dict(snapshot_id=self.snapshots[0], transformation_id="fixture.transform",
                      transformation_version="v1", parameters=canonical({"selection": []}),
                      recorded_at=RECORDED_AT, expected_input_count=1,
                      evidence_kind="SYNTHETIC", sealed=0)
        values.update(changes)
        return self.db.execute(
            f"INSERT INTO snapshot_derivation({','.join(values)}) "
            f"VALUES({','.join('?' for _ in values)})", tuple(values.values())).lastrowid

    def input(self, derivation, observation, ordinal=0, label="fixture"):
        self.db.execute("INSERT INTO derivation_input VALUES(?,?,?,?)",
                        (derivation, ordinal, label, observation))

    def seal(self, derivation):
        self.db.execute("UPDATE snapshot_derivation SET sealed=1 WHERE id=?", (derivation,))

    def complete(self):
        derivation = self.derivation()
        self.input(derivation, self.success())
        self.seal(derivation)
        return derivation

    def without_insert_guard(self, name, operation):
        """Damage only an isolated fixture to exercise seal-time rechecks."""
        sql = self.db.execute("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
                              (name,)).fetchone()[0]
        self.db.execute(f'DROP TRIGGER "{name}"')
        try:
            return operation()
        finally:
            self.db.execute(sql)

    def test_empty_and_arbitrary_binary_artifacts_retain_exact_bytes(self):
        for body in (b"", bytes(range(256)), b"\x00\xff\xfe\x80\x00"):
            with self.subTest(length=len(body)):
                digest = self.artifact(body)
                row = self.db.execute("SELECT * FROM raw_artifact WHERE sha256=?", (digest,)).fetchone()
                self.assertEqual(tuple(row), (hashlib.sha256(body).hexdigest(), len(body), body))

    def test_digest_length_type_and_null_invariants(self):
        body = b"fixture"
        digest = hashlib.sha256(body).hexdigest()
        for values in (("0" * 64, len(body), body), (digest, 0, body), (digest, -1, body),
                       (digest.upper(), len(body), body), (digest[:-1], len(body), body),
                       (digest + "\x00x", len(body), body), (None, len(body), body),
                       (digest, None, body), (digest, len(body), "fixture"),
                       (digest, len(body), None), (digest, len(body), 123),
                       (digest, "not-an-integer", body)):
            with self.subTest(values=values[:2]), self.assertRaises(sqlite3.Error):
                self.db.execute("INSERT INTO raw_artifact VALUES(?,?,?)", values)
        self.assertEqual(self.db.execute("SELECT count(*) FROM raw_artifact").fetchone()[0], 0)

    def test_artifact_cap_inclusive_and_database_boundary_rejects_overflow(self):
        body = b"x" * MAX_ARTIFACT_BYTES
        digest = self.artifact(body)
        self.assertEqual(self.db.execute("SELECT byte_length,length(body) FROM raw_artifact WHERE sha256=?",
                                         (digest,)).fetchone()[:], (67108864, 67108864))
        del body
        with self.assertRaises(sqlite3.Error):
            self.db.execute("INSERT INTO raw_artifact VALUES(?,?,zeroblob(?))",
                            ("0" * 64, MAX_ARTIFACT_BYTES + 1, MAX_ARTIFACT_BYTES + 1))

    def test_hash_function_is_bounded_and_rejects_nonbytes(self):
        for value in (None, "text", 1, 0.0, bytearray(b"x"), memoryview(b"x")):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                _artifact_sha256(value)
        oversized = b"x" * (MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(ValueError):
            _artifact_sha256(oversized)
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("SELECT artifact_sha256(?)", (oversized,))
        for value in (None, "text", 1, 0.0):
            with self.subTest(sql_type=type(value).__name__), self.assertRaises(sqlite3.OperationalError):
                self.db.execute("SELECT artifact_sha256(?)", (value,))

    def test_artifact_update_delete_replace_and_upsert_are_rejected(self):
        digest = self.artifact()
        before = tuple(self.db.execute("SELECT * FROM raw_artifact").fetchone())
        statements = (
            ("UPDATE raw_artifact SET body=body WHERE sha256=?", (digest,)),
            ("DELETE FROM raw_artifact WHERE sha256=?", (digest,)),
            ("INSERT OR REPLACE INTO raw_artifact SELECT * FROM raw_artifact WHERE sha256=?", (digest,)),
            ("INSERT INTO raw_artifact SELECT * FROM raw_artifact WHERE sha256=? "
             "ON CONFLICT(sha256) DO UPDATE SET body=excluded.body", (digest,)),
        )
        for sql, args in statements:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, args)
        self.assertEqual(tuple(self.db.execute("SELECT * FROM raw_artifact").fetchone()), before)

    def test_artifact_has_no_writable_incremental_blob_path(self):
        digest = self.artifact()
        table = next(r for r in self.db.execute("PRAGMA table_list") if r["name"] == "raw_artifact")
        self.assertEqual(table["wr"], 1)
        with self.assertRaises(sqlite3.OperationalError):
            self.db.blobopen("raw_artifact", "body", 1)
        self.assertEqual(self.db.execute("SELECT sha256=artifact_sha256(body) FROM raw_artifact "
                                         "WHERE sha256=?", (digest,)).fetchone()[0], 1)

    def test_replacement_guards_also_reject_unreferenced_rows_with_recursive_triggers_off(self):
        self.artifact()
        self.observation()
        self.derivation()
        self.db.execute("PRAGMA recursive_triggers=OFF")
        try:
            for table in ("raw_artifact", "acquisition_observation", "snapshot_derivation"):
                with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                    self.db.execute(f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}")
        finally:
            self.db.execute("PRAGMA recursive_triggers=ON")

    def test_success_failure_and_secondary_cleanup_indicator(self):
        success = self.success()
        for code in OfflineFailureCode:
            for cleanup in (0, 1):
                failure = self.observation(failure_code=code.value, cleanup_failed=cleanup)
                row = self.db.execute("SELECT outcome,artifact_sha256,failure_code,cleanup_failed "
                                      "FROM acquisition_observation WHERE id=?", (failure,)).fetchone()
                self.assertEqual(tuple(row), ("FAILURE", None, code.value, cleanup))
        self.assertIsNotNone(self.db.execute("SELECT artifact_sha256 FROM acquisition_observation WHERE id=?",
                                             (success,)).fetchone()[0])

    def test_observation_outcome_invariants_fail_closed_including_nulls(self):
        digest = self.artifact()
        for changes in (
                {"outcome": "SUCCESS"},
                {"outcome": "SUCCESS", "artifact_sha256": digest},
                {"outcome": "SUCCESS", "artifact_sha256": digest, "failure_code": None, "cleanup_failed": 1},
                {"outcome": "SUCCESS", "artifact_sha256": "f" * 64, "failure_code": None},
                {"artifact_sha256": digest}, {"failure_code": None},
                {"failure_code": "arbitrary exception text"}, {"outcome": "PENDING"},
                {"outcome": None}, {"cleanup_failed": None}, {"cleanup_failed": 2}):
            with self.subTest(changes=changes), self.assertRaises(sqlite3.Error):
                self.observation(**changes)

    def test_observations_are_unique_immutable_and_cannot_be_reclassified(self):
        observation = self.observation(event_key="one-attempt")
        before = tuple(self.db.execute("SELECT * FROM acquisition_observation").fetchone())
        with self.assertRaises(sqlite3.IntegrityError):
            self.observation(event_key="one-attempt")
        for sql in (
                "UPDATE acquisition_observation SET provider=provider WHERE id=?",
                "UPDATE acquisition_observation SET evidence_kind='SOURCE_ACQUISITION' WHERE id=?",
                "DELETE FROM acquisition_observation WHERE id=?",
                "INSERT OR REPLACE INTO acquisition_observation SELECT * FROM acquisition_observation WHERE id=?"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, (observation,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.observation(id=observation, event_key="different-event")
        self.assertEqual(tuple(self.db.execute("SELECT * FROM acquisition_observation").fetchone()), before)

    def test_observation_metadata_bounds_and_explicit_classification(self):
        for field, bad_values in {
                "event_key": (None, "", " x", "x\x00hidden", "x" * 129, "x/y"),
                "provider": (None, "", "NFLVERSE", "x\n", "x\x00hidden", "x" * 129, "é"),
                "logical_artifact_id": ("", "x" * 257, "x/y", "x\x00hidden"),
                "scope": ("", " ", " x", "x ", "x\n", "x\t", "é", "x\x00hidden", "x" * 1025),
                "declared_format": ("", "x/y", "x" * 65, "x\x00hidden"),
                "evidence_kind": (None, "", "SOURCE_ACQUISITION", "synthetic"),
        }.items():
            for value in bad_values:
                with self.subTest(field=field, value=repr(value)), self.assertRaises(sqlite3.Error):
                    self.observation(**{field: value})
        self.observation(event_key="a" * 128, provider="a" * 128,
                         logical_artifact_id="a" * 256, scope="x" * 1024,
                         declared_format="a" * 64)

    def test_recording_times_require_canonical_valid_utc_seconds(self):
        for value in (None, "", "2030-02-30T00:00:00Z", "0000-01-01T00:00:00Z",
                      "2030-10-03 00:00:00", "2030-10-03T00:00:00+00:00",
                      "2030-10-03T00:00:00.000Z", "2030-10-03T00:00:60Z", RECORDED_AT + "\x00"):
            for insert in (self.observation, self.derivation):
                with self.subTest(value=value, table=insert.__name__), self.assertRaises(sqlite3.Error):
                    insert(recorded_at=value)
        self.observation(recorded_at="2032-02-29T23:59:59Z")
        self.derivation(recorded_at="2032-02-29T23:59:59Z")

    def test_no_source_availability_columns_or_dormant_live_mode(self):
        for table in ("acquisition_observation", "snapshot_derivation"):
            names = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
            self.assertTrue({"retrieved_at", "publication_at", "publication_evidence"}.isdisjoint(names))
        with self.assertRaises(sqlite3.IntegrityError):
            self.derivation(evidence_kind="SOURCE_ACQUISITION")

    def test_complete_group_seals_and_preserves_order_labels_and_repeated_inputs(self):
        observation = self.success()
        derivation = self.derivation(expected_input_count=3)
        for ordinal, label in ((2, "stats"), (0, "players"), (1, "teams")):
            self.input(derivation, observation, ordinal, label)
        self.seal(derivation)
        rows = self.db.execute("SELECT ordinal,input_label,observation_id FROM derivation_input "
                               "WHERE derivation_id=? ORDER BY ordinal", (derivation,)).fetchall()
        self.assertEqual([tuple(r) for r in rows],
                         [(0, "players", observation), (1, "teams", observation), (2, "stats", observation)])
        self.assertEqual(self.db.execute("SELECT sealed FROM snapshot_derivation WHERE id=?", (derivation,)).fetchone()[0], 1)

    def test_multiple_derivations_keep_alternative_input_groups_separate(self):
        first, second = self.complete(), self.complete()
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.execute("SELECT count(DISTINCT snapshot_id) FROM snapshot_derivation").fetchone()[0], 1)
        rows = self.db.execute("SELECT derivation_id,observation_id FROM derivation_input ORDER BY derivation_id").fetchall()
        self.assertEqual([r[0] for r in rows], [first, second])
        self.assertNotEqual(rows[0][1], rows[1][1])

    def test_missing_and_gapped_input_sets_cannot_seal(self):
        observation = self.success()
        empty = self.derivation()
        gap = self.derivation(expected_input_count=3)
        self.input(gap, observation, 0)
        self.input(gap, observation, 2)
        for derivation in (empty, gap):
            with self.subTest(derivation=derivation), self.assertRaises(sqlite3.IntegrityError):
                self.seal(derivation)
            self.assertEqual(self.db.execute("SELECT sealed FROM snapshot_derivation WHERE id=?", (derivation,)).fetchone()[0], 0)
        self.input(gap, observation, 1)
        self.seal(gap)

    def test_input_foreign_keys_failed_inputs_and_ordinal_bounds(self):
        derivation = self.derivation(expected_input_count=2)
        observation = self.success()
        failure = self.observation()
        for group, obs, ordinal in ((9999, observation, 0), (derivation, 9999, 0),
                                    (derivation, failure, 0), (derivation, observation, -1),
                                    (derivation, observation, 2)):
            with self.subTest(group=group, obs=obs, ordinal=ordinal), self.assertRaises(sqlite3.IntegrityError):
                self.input(group, obs, ordinal)
        self.input(derivation, observation)
        with self.assertRaises(sqlite3.IntegrityError):
            self.input(derivation, observation)
        for label in ("", "x\x00hidden", "x" * 129, "x/y"):
            with self.subTest(label=repr(label)), self.assertRaises(sqlite3.IntegrityError):
                self.input(derivation, observation, 1, label)

    def test_mismatched_evidence_classification_is_rejected_by_input_guard(self):
        self.db.execute("PRAGMA ignore_check_constraints=ON")
        try:
            observation = self.success(evidence_kind="SOURCE_ACQUISITION")
        finally:
            self.db.execute("PRAGMA ignore_check_constraints=OFF")
        derivation = self.derivation()
        with self.assertRaises(sqlite3.IntegrityError):
            self.input(derivation, observation)

    def test_sealing_independently_rechecks_input_success_and_contiguity(self):
        failed_input = self.derivation()
        failure = self.observation()
        self.without_insert_guard("input_insert", lambda: self.input(failed_input, failure))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "successful synthetic"):
            self.seal(failed_input)
        gap = self.derivation(expected_input_count=2)
        observation = self.success()
        self.input(gap, observation, 0)
        self.without_insert_guard("input_insert", lambda: self.input(gap, observation, 2))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "contiguous"):
            self.seal(gap)

    def test_timestamped_and_unsealed_or_missing_outputs_are_rejected(self):
        for times in ({"retrieved_at": RECORDED_AT},
                      {"publication_at": RECORDED_AT, "publication_evidence": "Synthetic assertion"}):
            snapshot = add_snapshot(self.db, provider="synthetic", role="IDENTITY", loader_scope="timed",
                                    rows=[dict(namespace_id=1, identifier="p1", payload=times)], **times)
            with self.subTest(times=times), self.assertRaises(sqlite3.IntegrityError):
                self.derivation(snapshot_id=snapshot)
        unsealed = self.db.execute("INSERT INTO source_snapshot(provider,role,loader_scope,normalization_version,normalized_sha256) "
                                   "VALUES('synthetic','IDENTITY','unsealed','edgefinder.normalized.v1',?)",
                                   ("0" * 64,)).lastrowid
        for snapshot in (unsealed, 9999):
            with self.subTest(snapshot=snapshot), self.assertRaises(sqlite3.IntegrityError):
                self.derivation(snapshot_id=snapshot)

    def test_sealing_rechecks_output_historical_eligibility(self):
        snapshot = add_snapshot(self.db, provider="synthetic", role="IDENTITY", loader_scope="timed",
                                rows=[dict(namespace_id=1, identifier="p1")], retrieved_at=RECORDED_AT)
        derivation = self.without_insert_guard("derivation_insert", lambda: self.derivation(snapshot_id=snapshot))
        self.input(derivation, self.success())
        with self.assertRaisesRegex(sqlite3.IntegrityError, "output is not eligible"):
            self.seal(derivation)

    def test_derivation_starts_open_and_header_changes_are_always_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.derivation(sealed=1)
        derivation = self.derivation()
        for column, value in (("id", 9999), ("snapshot_id", self.snapshots[1]),
                              ("transformation_id", "other"), ("transformation_version", "v2"),
                              ("parameters", canonical({"different": True})),
                              ("recorded_at", "2030-10-04T00:00:00Z"), ("expected_input_count", 2),
                              ("evidence_kind", "SOURCE_ACQUISITION")):
            with self.subTest(column=column), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f"UPDATE snapshot_derivation SET {column}=?,sealed=1 WHERE id=?", (value, derivation))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE snapshot_derivation SET sealed=0 WHERE id=?", (derivation,))

    def test_derivation_metadata_and_parameter_bounds(self):
        for changes in ({"transformation_id": ""}, {"transformation_id": "x" * 129},
                        {"transformation_version": "x/y"}, {"transformation_version": "x\x00hidden"},
                        {"parameters": "{}"}, {"parameters": canonical("x" * 65536)},
                        {"parameters": None}, {"expected_input_count": 0},
                        {"expected_input_count": 4097}, {"expected_input_count": None},
                        {"evidence_kind": None}):
            with self.subTest(changes=list(changes)), self.assertRaises(sqlite3.Error):
                self.derivation(**changes)
        self.derivation(expected_input_count=4096)

    def test_open_inputs_can_be_corrected_by_delete_insert_without_changing_header(self):
        derivation = self.derivation()
        first = self.success()
        self.input(derivation, first)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE derivation_input SET input_label='other' WHERE derivation_id=?", (derivation,))
        self.db.execute("DELETE FROM derivation_input WHERE derivation_id=?", (derivation,))
        replacement = self.success()
        self.input(derivation, replacement)
        self.seal(derivation)

    def test_sealed_derivation_and_inputs_reject_all_mutations_and_replacement(self):
        derivation = self.complete()
        for sql in (
                "UPDATE snapshot_derivation SET sealed=0 WHERE id=?",
                "UPDATE snapshot_derivation SET sealed=1 WHERE id=?",
                "DELETE FROM snapshot_derivation WHERE id=?",
                "INSERT OR REPLACE INTO snapshot_derivation SELECT * FROM snapshot_derivation WHERE id=?",
                "UPDATE derivation_input SET input_label=input_label WHERE derivation_id=?",
                "DELETE FROM derivation_input WHERE derivation_id=?",
                "INSERT OR REPLACE INTO derivation_input SELECT * FROM derivation_input WHERE derivation_id=?"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, (derivation,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.input(derivation, self.success(), 1)
        other = self.derivation()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE derivation_input SET derivation_id=? WHERE derivation_id=?", (other, derivation))

    def test_unsealed_derivation_cannot_be_deleted_or_replaced(self):
        derivation = self.derivation()
        for sql in ("DELETE FROM snapshot_derivation WHERE id=?",
                    "INSERT OR REPLACE INTO snapshot_derivation SELECT * FROM snapshot_derivation WHERE id=?"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, (derivation,))

    def test_explicit_foreign_keys_are_restrictive_and_integrity_remains_valid(self):
        expected = {"acquisition_observation": {"artifact_sha256"},
                    "snapshot_derivation": {"snapshot_id"},
                    "derivation_input": {"derivation_id", "observation_id"}}
        for table, columns in expected.items():
            keys = self.db.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            self.assertEqual({r["from"] for r in keys}, columns)
            self.assertTrue(all(r["on_delete"] == "RESTRICT" for r in keys))
        self.complete()
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_synthetic_lineage_cannot_grant_historical_eligibility_or_modify_baseline(self):
        baseline = tuple(tuple(r) for r in self.db.execute(
            "SELECT type,name,sql FROM sqlite_schema WHERE tbl_name IN ('source_snapshot','research_selection') ORDER BY type,name"))
        snapshots = tuple(tuple(r) for r in self.db.execute("SELECT * FROM source_snapshot ORDER BY id"))
        selections = tuple(tuple(r) for r in self.db.execute("SELECT * FROM research_selection ORDER BY id"))
        for snapshot in self.snapshots:
            derivation = self.derivation(snapshot_id=snapshot)
            self.input(derivation, self.success())
            self.seal(derivation)
        for mode in ("OBSERVED_BY_EDGEFINDER", "VERIFIED_PUBLICATION"):
            with self.subTest(mode=mode), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                                (self.run, mode, "9999-12-31T23:59:59Z"))
        self.assertEqual(tuple(tuple(r) for r in self.db.execute("SELECT * FROM source_snapshot ORDER BY id")), snapshots)
        self.assertEqual(tuple(tuple(r) for r in self.db.execute("SELECT * FROM research_selection ORDER BY id")), selections)
        self.assertEqual(tuple(tuple(r) for r in self.db.execute(
            "SELECT type,name,sql FROM sqlite_schema WHERE tbl_name IN ('source_snapshot','research_selection') ORDER BY type,name")), baseline)
        self.db.execute("INSERT INTO research_selection(run_id,mode) VALUES(?,'RETROSPECTIVE')", (self.run,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO source_snapshot(provider,role,loader_scope,normalization_version,normalized_sha256,original_file_sha256) "
                            "VALUES('synthetic','IDENTITY','bad-original','edgefinder.normalized.v1',?,?)", ("0" * 64, "1" * 64))


if __name__ == "__main__":
    unittest.main()
