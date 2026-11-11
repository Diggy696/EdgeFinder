"""Real synthetic pipeline integration using isolated in-memory databases only."""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

from edgefinder.acquisition import runner
from edgefinder.acquisition.contracts import AddressRules, URLRule, URLRules
from edgefinder import synthetic_transform as transform
from edgefinder.storage import database, lineage, provenance, synthetic as storage
from edgefinder.synthetic_pipeline import (
    CommitKnowledge as C, PipelineFailureCode as F, PipelineStage as S,
    PipelineStatus as Status, StageOutcome as O, SyntheticAcquisitionSpec,
    SyntheticInputOccurrence as Occurrence, SyntheticObservationMetadata as Metadata,
    run_synthetic_pipeline,
)
from tests.test_acquisition_runner import FakeClock, FakeResolver, FakeStream, FakeTransport
from tests.test_storage_migrations import database_state, populate_research


TIME = "2030-10-03T00:00:00Z"
URL = "https://fixtures.example.test/identity"
RULES = URLRules((URLRule("fixtures.example.test", "/identity"),))
MIB = 1048576
TOTAL = 8 * MIB


def fixture(rows=None):
    return json.dumps(dict(format="edgefinder.synthetic.identity.v1",
                           rows=[dict(identifier="p1", payload={"sample": 7})] if rows is None else rows),
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class MemoryStream:
    status = 200
    locations = ()

    def __init__(self, body):
        self.body = body
        self.offset = 0
        self.reads = []
        self.closes = 0

    def read(self, max_bytes, *, deadline):
        self.reads.append(max_bytes)
        chunk = self.body[self.offset:self.offset + max_bytes]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closes += 1


def specification(key="event-1", body=None, **changes):
    values = dict(observation=Metadata(key, "identity-fixture", "invented synthetic input", TIME),
                  initial_url=URL, url_rules=RULES, address_rules=AddressRules(),
                  resolver=FakeResolver(), transport=FakeTransport(MemoryStream(fixture() if body is None else body)),
                  clock=FakeClock(), timeout_seconds=10)
    values.update(changes)
    return SyntheticAcquisitionSpec(**values)


def stage(result, name, index=None):
    return next(item for item in result.stages if item.stage is name and item.acquisition_index == index)


class SyntheticPipelineTests(unittest.TestCase):
    def setUp(self):
        self.new_database()

    def new_database(self):
        self.db = database.connect()
        self.addCleanup(self.db.close)
        database.initialize(self.db)
        self.namespace = self.db.execute(
            "INSERT INTO identifier_namespace(provider,kind,name) VALUES('synthetic','PLAYER','pipeline-player')"
        ).lastrowid

    def run_pipeline(self, acquisitions=None, occurrences=None, **changes):
        values = dict(acquisitions=(specification(),) if acquisitions is None else acquisitions,
                      occurrences=(Occurrence(0, "players"),) if occurrences is None else occurrences,
                      namespace_id=self.namespace, loader_scope="pipeline-fixture",
                      derivation_recorded_at=TIME)
        values.update(changes)
        return run_synthetic_pipeline(self.db, **values)

    def count(self, table):
        return self.db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]

    def assert_rejected(self, *, acquisitions=None, occurrences=None, **changes):
        specs = (specification(),) if acquisitions is None else acquisitions
        before = database_state(self.db)
        result = self.run_pipeline(specs, occurrences, **changes)
        self.assertIs(result.status, Status.REJECTED)
        self.assertIs(result.failure.code, F.PREFLIGHT_REJECTED)
        self.assertEqual(database_state(self.db), before)
        for spec in specs:
            if type(spec) is SyntheticAcquisitionSpec:
                self.assertEqual(spec.resolver.calls, [])
                self.assertEqual(spec.transport.calls, [])
                self.assertEqual(spec.clock.calls, 0)
        self.assertIsNone(result.snapshot_id)
        self.assertIsNone(result.derivation_id)
        return result

    def corrupt(self, sql, parameters=(), *, guards):
        definitions = [self.db.execute("SELECT sql FROM main.sqlite_schema WHERE name=?",
                                       (name,)).fetchone()[0] for name in guards]
        self.db.execute("PRAGMA ignore_check_constraints=ON")
        try:
            for name in guards:
                self.db.execute(f'DROP TRIGGER "{name}"')
            self.db.execute(sql, parameters)
        finally:
            for definition in definitions:
                self.db.execute(definition)
            self.db.execute("PRAGMA ignore_check_constraints=OFF")

    def test_one_input_complete_real_components_and_full_verification(self):
        spec = specification()
        with patch.object(lineage, "get_derivation", wraps=lineage.get_derivation) as get:
            result = self.run_pipeline((spec,))
        self.assertIs(result.status, Status.COMPLETE)
        self.assertIsNone(result.failure)
        self.assertIsNone(result.secondary_failure)
        self.assertTrue(all(report.outcome is O.SUCCEEDED for report in result.stages))
        self.assertEqual(result.output_row_count, 1)
        self.assertEqual(result.acquired_bytes, len(fixture()))
        self.assertEqual(result.occurrence_expanded_bytes, len(fixture()))
        self.assertEqual(result.acquisitions[0].effective_max_bytes, MIB)
        self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
        self.assertEqual(result.inputs[0].observation_id, result.acquisitions[0].observation_id)
        get.assert_called_once_with(self.db, derivation_id=result.derivation_id, verify_artifacts=True)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(len(spec.transport.calls), 1)
        self.assertEqual(len(spec.resolver.calls), 1)

    def test_grouped_order_labels_references_and_duplicate_rows(self):
        a = fixture([dict(identifier="a", payload={}), dict(identifier="a", payload={})])
        b = fixture([dict(identifier="b", payload={})])
        specs = (specification("a", a), specification("b", b))
        occurrences = (Occurrence(1, "same"), Occurrence(0, "same"), Occurrence(1, "same"))
        result = self.run_pipeline(specs, occurrences)
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(result.output_row_count, 4)
        self.assertEqual(result.occurrence_expanded_bytes, len(a) + 2 * len(b))
        retained = lineage.get_derivation(self.db, derivation_id=result.derivation_id, verify_artifacts=True)
        self.assertEqual(tuple((item.ordinal, item.input_label, item.observation_id) for item in retained.inputs),
                         tuple((index, "same", result.acquisitions[item.acquisition_index].observation_id)
                               for index, item in enumerate(occurrences)))
        rows = self.db.execute("SELECT identifier FROM source_record WHERE snapshot_id=? ORDER BY ordinal",
                               (result.snapshot_id,)).fetchall()
        self.assertEqual(tuple(row[0] for row in rows), ("b", "a", "a", "b"))
        self.assertTrue(all(len(spec.transport.calls) == 1 for spec in specs))

    def test_equal_bodies_are_distinct_events_with_one_artifact(self):
        result = self.run_pipeline((specification("a"), specification("b")),
                                   (Occurrence(1, "players"), Occurrence(0, "players")))
        self.assertIs(result.status, Status.COMPLETE)
        self.assertNotEqual(result.acquisitions[0].observation_id, result.acquisitions[1].observation_id)
        self.assertEqual(result.acquisitions[0].sha256, result.acquisitions[1].sha256)
        self.assertEqual(self.count("raw_artifact"), 1)
        self.assertEqual(self.count("acquisition_observation"), 2)
        self.assertEqual(result.acquired_bytes, 2 * len(fixture()))

    def test_reordered_occurrences_reuse_snapshot_but_create_new_assertion(self):
        a = fixture([dict(identifier="a", payload={})])
        b = fixture([dict(identifier="b", payload={})])
        first = self.run_pipeline((specification("a1", a), specification("b1", b)),
                                  (Occurrence(0, "a"), Occurrence(1, "b")))
        second = self.run_pipeline((specification("a2", a), specification("b2", b)),
                                   (Occurrence(1, "b"), Occurrence(0, "a")))
        self.assertIs(second.status, Status.COMPLETE)
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        self.assertNotEqual(first.derivation_id, second.derivation_id)
        self.assertEqual(self.count("source_snapshot"), 1)
        self.assertEqual(self.count("snapshot_derivation"), 2)
        self.assertFalse(hasattr(second, "created"))
        stored = self.db.execute("SELECT identifier FROM source_record WHERE snapshot_id=? ORDER BY ordinal",
                                 (second.snapshot_id,)).fetchall()
        self.assertEqual(tuple(row[0] for row in stored), ("a", "b"))

    def test_empty_document_can_contribute_no_rows(self):
        result = self.run_pipeline((specification("empty", fixture([])), specification("full")),
                                   (Occurrence(0, "empty"), Occurrence(1, "full"), Occurrence(0, "empty")))
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(result.output_row_count, 1)
        self.assertEqual(len(result.inputs), 3)

    def test_frozen_specs_metadata_and_deeply_immutable_reports(self):
        spec = specification()
        result = self.run_pipeline((spec,))
        for target, attribute, value in ((spec, "initial_url", "changed"),
                                         (spec.observation, "provider", "changed"),
                                         (result, "status", Status.INCOMPLETE),
                                         (result.acquisitions[0], "observation_id", 99),
                                         (result.stages[0], "outcome", O.FAILED),
                                         (result.inputs[0], "input_label", "changed")):
            with self.subTest(attribute=attribute), self.assertRaises(FrozenInstanceError):
                setattr(target, attribute, value)
        self.assertIs(type(result.acquisitions), tuple)
        self.assertIs(type(result.stages), tuple)
        self.assertIs(type(result.inputs), tuple)
        self.assertIsInstance(hash(result), int)
        fresh = spec.observation.persistence_kwargs()
        fresh["provider"] = "changed"
        self.assertEqual(spec.observation.provider, "synthetic")
        self.assertNotIn("fixture-player", repr(result))
        self.assertNotIn(URL, repr(result))

    def test_preflight_owns_only_read_transaction_and_no_target_changes(self):
        spec = specification()
        before = database_state(self.db)
        statements = []
        self.db.set_trace_callback(statements.append)
        try:
            storage.preflight_synthetic_pipeline(
                self.db, metadata=(spec.observation,), occurrence_indices=(0,), input_labels=("players",),
                namespace_id=self.namespace, loader_scope="pipeline-fixture", derivation_recorded_at=TIME)
        finally:
            self.db.set_trace_callback(None)
        self.assertEqual(database_state(self.db), before)
        self.assertEqual(sum(statement == "BEGIN DEFERRED" for statement in statements), 1)
        self.assertFalse(any(statement.startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "BEGIN IMMEDIATE"))
                             for statement in statements))

    def test_active_transaction_is_rejected_and_remains_owned_by_caller(self):
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO entity(kind,label) VALUES('PLAYER','caller work')")
        statements = []
        self.db.set_trace_callback(statements.append)
        try:
            self.assert_rejected()
            self.assertTrue(self.db.in_transaction)
            self.assertFalse(any(statement in ("COMMIT", "ROLLBACK") for statement in statements))
        finally:
            self.db.set_trace_callback(None)
            self.db.rollback()

    def test_namespace_existence_provider_kind_and_integer_range(self):
        wrong_provider = self.db.execute("INSERT INTO identifier_namespace(provider,kind,name) "
                                         "VALUES('other','PLAYER','other')").lastrowid
        wrong_kind = self.db.execute("INSERT INTO identifier_namespace(provider,kind,name) "
                                     "VALUES('synthetic','TEAM','teams')").lastrowid
        for identifier in (wrong_provider, wrong_kind, 999, True, "1", 2 ** 63):
            with self.subTest(identifier=identifier):
                self.assert_rejected(namespace_id=identifier)

    def test_zero_and_negative_existing_namespaces_are_supported(self):
        for identifier in (0, -5):
            self.db.execute("INSERT INTO identifier_namespace(id,provider,kind,name) VALUES(?,'synthetic','PLAYER',?)",
                            (identifier, f"namespace-{identifier}"))
            result = self.run_pipeline((specification(f"event-{identifier}"),), namespace_id=identifier)
            self.assertIs(result.status, Status.COMPLETE)

    def test_duplicate_and_reused_event_keys_rejected_before_callbacks(self):
        self.assert_rejected(acquisitions=(specification("same"), specification("same")),
                             occurrences=(Occurrence(0, "a"), Occurrence(1, "b")))
        first = self.run_pipeline()
        self.assertIs(first.status, Status.COMPLETE)
        self.assert_rejected()

    def test_metadata_syntax_bounds_and_calendar_rejected(self):
        base = specification()
        changes = (dict(event_key="bad key"), dict(event_key="x" * 129),
                   dict(logical_artifact_id="UPPER"), dict(logical_artifact_id="x" * 257),
                   dict(scope=" leading"), dict(scope="nonascii \u00e9"), dict(scope="x" * 1025),
                   dict(recorded_at="2030-02-30T00:00:00Z"), dict(recorded_at="2030-10-03T24:00:00Z"))
        for change in changes:
            with self.subTest(change=list(change)):
                self.assert_rejected(acquisitions=(replace(base, observation=replace(base.observation, **change)),))

    def test_occurrence_indices_coverage_labels_and_container_types(self):
        cases = ((), (Occurrence(True, "a"),), (Occurrence(-1, "a"),), (Occurrence(1, "a"),),
                 (Occurrence(0, "Upper"),), (Occurrence(0, "a" * 129),), (Occurrence(0, ""),),
                 [Occurrence(0, "a")], ((0, "a"),), (Occurrence(0, "a"),) * 4097)
        for occurrences in cases:
            with self.subTest(container=type(occurrences).__name__, count=len(occurrences)):
                self.assert_rejected(occurrences=occurrences)
        self.assert_rejected(acquisitions=(specification("a"), specification("b")))
        for acquisitions in ((), [specification()], (object(),)):
            with self.subTest(container=type(acquisitions).__name__):
                self.assert_rejected(acquisitions=acquisitions)

    def test_runner_configuration_rejections_before_callbacks(self):
        for changes in (dict(initial_url=None), dict(initial_url="x" * 4097), dict(url_rules=None),
                        dict(address_rules=None), dict(timeout_seconds=True), dict(timeout_seconds=0),
                        dict(timeout_seconds=float("inf"))):
            with self.subTest(change=list(changes)):
                self.assert_rejected(acquisitions=(specification(**changes),))

    def test_scope_parameters_and_derivation_timestamp_rejected(self):
        for changes in (dict(loader_scope=""), dict(loader_scope="\x00scope"),
                        dict(loader_scope="\ud800"), dict(loader_scope="x" * 65536),
                        dict(derivation_recorded_at="2030-02-30T00:00:00Z")):
            with self.subTest(change=list(changes)):
                self.assert_rejected(**changes)

    def test_query_only_and_transaction_modes_rejected_without_repair(self):
        self.db.execute("PRAGMA query_only=ON")
        self.assert_rejected()
        self.assertEqual(self.db.execute("PRAGMA query_only").fetchone()[0], 1)
        self.db.execute("PRAGMA query_only=OFF")
        for mode in (True, False):
            with self.subTest(mode=mode):
                self.db.autocommit = mode
                self.assert_rejected()
                self.assertIs(self.db.autocommit, mode)
                self.db.autocommit = sqlite3.LEGACY_TRANSACTION_CONTROL

    def test_connection_configuration_rejected_without_executing_custom_row_factory(self):
        spec = specification()

        def unexpected_factory(cursor, row):
            raise AssertionError("Unsupported row factory must not execute")

        self.db.row_factory = unexpected_factory
        try:
            result = self.run_pipeline((spec,))
        finally:
            self.db.row_factory = sqlite3.Row
        self.assertIs(result.status, Status.REJECTED)
        self.assertEqual(spec.resolver.calls, [])
        self.assertEqual(spec.transport.calls, [])
        self.assertEqual(spec.clock.calls, 0)
        self.db.isolation_level = "DEFERRED"
        try:
            self.assert_rejected()
        finally:
            self.db.isolation_level = None

    def test_schema_changes_and_wrong_version_rejected_without_installation(self):
        for alteration in ("PRAGMA user_version=0", "DROP TRIGGER artifact_update",
                           "CREATE TABLE unrelated(x TEXT) STRICT"):
            with self.subTest(alteration=alteration):
                self.new_database()
                self.db.execute(alteration)
                self.assert_rejected()

    def test_missing_schema_rejected(self):
        self.db = database.connect()
        self.addCleanup(self.db.close)
        self.assert_rejected()

    def test_required_constraints_and_sql_functions_checked(self):
        for pragma in ("foreign_keys", "recursive_triggers", "ignore_check_constraints"):
            with self.subTest(pragma=pragma):
                value = 1 if pragma == "ignore_check_constraints" else 0
                self.db.execute(f"PRAGMA {pragma}={value}")
                self.assert_rejected()
                self.db.execute(f"PRAGMA {pragma}={1 - value}")
        self.db.create_function("artifact_sha256", 1, None)
        self.assert_rejected()

    def test_temp_objects_and_attached_databases_rejected(self):
        self.db.execute("CREATE TEMP TABLE source_snapshot(x TEXT)")
        self.assert_rejected()
        self.db.execute("DROP TABLE temp.source_snapshot")
        self.db.execute("ATTACH DATABASE ':memory:' AS extra")
        self.assert_rejected()

    def test_no_acquisition_callbacks_within_a_database_transaction(self):
        spec = specification()
        original = runner.run_offline

        def checked(*args, **kwargs):
            self.assertFalse(self.db.in_transaction)
            return original(*args, **kwargs)

        with patch.object(runner, "run_offline", side_effect=checked) as acquire:
            result = self.run_pipeline((spec,))
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(acquire.call_count, 1)

    def test_url_and_address_failures_record_actual_failure_facts(self):
        for changes, expected in ((dict(url_rules=URLRules()), runner.OfflineFailureCode.URL_POLICY),
                                  (dict(resolver=FakeResolver([("127.0.0.1",)])),
                                   runner.OfflineFailureCode.ADDRESS_POLICY)):
            with self.subTest(code=expected):
                key = "failure-" + expected.value
                spec = specification(key, **changes)
                result = self.run_pipeline((spec,))
                self.assertIs(result.status, Status.INCOMPLETE)
                self.assertIs(result.acquisitions[0].failure_code, expected)
                self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
                self.assertEqual(spec.transport.calls, [])
                row = self.db.execute("SELECT outcome,failure_code,cleanup_failed,artifact_sha256 "
                                      "FROM acquisition_observation WHERE id=?",
                                      (result.acquisitions[0].observation_id,)).fetchone()
                self.assertEqual(tuple(row), ("FAILURE", expected.value, 0, None))
        self.assertEqual(self.count("raw_artifact"), 0)

    def test_transport_stream_deadline_and_cleanup_failures_stop_pipeline(self):
        cases = (
            (dict(transport=FakeTransport(ValueError("transport-marker"))), runner.OfflineFailureCode.TRANSPORT_FAILURE),
            (dict(transport=FakeTransport(FakeStream([b"partial", ValueError("stream-marker")]))),
             runner.OfflineFailureCode.STREAM_FAILURE),
            (dict(clock=FakeClock(readings=(0, 10))), runner.OfflineFailureCode.DEADLINE_EXCEEDED),
            (dict(transport=FakeTransport(FakeStream([fixture()], on_close=ValueError("cleanup-marker")))),
             runner.OfflineFailureCode.CLEANUP_FAILURE),
        )
        for index, (changes, expected) in enumerate(cases):
            with self.subTest(code=expected):
                spec = specification(f"failure-{index}", **changes)
                result = self.run_pipeline((spec,))
                self.assertIs(result.status, Status.INCOMPLETE)
                self.assertIs(result.acquisitions[0].outcome, O.FAILED)
                self.assertIs(result.acquisitions[0].failure_code, expected)
                self.assertIsNone(result.acquisitions[0].sha256)
                self.assertIsNone(result.acquisitions[0].byte_count)
                self.assertIsNone(result.snapshot_id)
                self.assertIs(stage(result, S.TRANSFORMATION).outcome, O.NOT_ATTEMPTED)
                self.assertNotIn("marker", repr(result))
        self.assertEqual(self.count("raw_artifact"), 0)

    def test_secondary_cleanup_flag_preserves_primary_stream_failure(self):
        stream = FakeStream([ValueError("stream-marker")], on_close=ValueError("cleanup-marker"))
        result = self.run_pipeline((specification(transport=FakeTransport(stream)),))
        self.assertIs(result.acquisitions[0].failure_code, runner.OfflineFailureCode.STREAM_FAILURE)
        self.assertIs(result.acquisitions[0].cleanup_failed, True)
        row = self.db.execute("SELECT failure_code,cleanup_failed FROM acquisition_observation").fetchone()
        self.assertEqual(tuple(row), ("stream_failure", 1))
        self.assertEqual(stream.closes, 1)

    def test_failure_halfway_retains_prior_success_and_marks_later_unattempted(self):
        specs = (specification("success"), specification("failure", url_rules=URLRules()), specification("later"))
        result = self.run_pipeline(specs, tuple(Occurrence(index, "players") for index in range(3)))
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.acquisitions[0].outcome, O.SUCCEEDED)
        self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
        self.assertIsNotNone(result.acquisitions[0].observation_id)
        self.assertIsNotNone(result.acquisitions[1].observation_id)
        self.assertIs(result.acquisitions[2].outcome, O.NOT_ATTEMPTED)
        self.assertEqual(specs[2].clock.calls, 0)
        self.assertEqual(specs[2].transport.calls, [])
        self.assertEqual(self.count("acquisition_observation"), 2)
        self.assertEqual(self.count("raw_artifact"), 1)

    def test_failure_observation_recording_error_is_secondary_unknown(self):
        with patch.object(provenance, "persist_failure", side_effect=sqlite3.OperationalError("database-marker")) as persist:
            result = self.run_pipeline((specification(url_rules=URLRules()),))
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIs(result.failure.code, F.ACQUISITION_FAILED)
        self.assertIs(result.secondary_failure.code, F.FAILURE_PERSISTENCE_FAILED)
        self.assertIs(result.acquisitions[0].failure_code, runner.OfflineFailureCode.URL_POLICY)
        self.assertIs(result.acquisitions[0].observation_commit, C.UNKNOWN)
        self.assertEqual(persist.call_count, 1)
        self.assertNotIn("database-marker", repr(result))

    def test_failure_recording_exception_after_real_commit_is_not_retried(self):
        original = provenance.persist_failure

        def committed_then_lost(*args, **kwargs):
            original(*args, **kwargs)
            raise sqlite3.OperationalError("lost failure receipt")

        with patch.object(provenance, "persist_failure", side_effect=committed_then_lost) as persist:
            result = self.run_pipeline((specification(url_rules=URLRules()),))
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIsNone(result.acquisitions[0].observation_id)
        self.assertEqual(self.count("acquisition_observation"), 1)
        self.assertEqual(persist.call_count, 1)

    def test_individual_body_limit_exact_and_one_over(self):
        body = fixture()
        body += b" " * (MIB - len(body))
        accepted = self.run_pipeline((specification("exact", body),))
        self.assertIs(accepted.status, Status.COMPLETE)
        rejected = self.run_pipeline((specification("over", body + b" "),))
        self.assertIs(rejected.status, Status.INCOMPLETE)
        self.assertIs(rejected.acquisitions[0].failure_code, runner.OfflineFailureCode.BYTE_LIMIT)
        self.assertEqual(self.count("raw_artifact"), 1)

    def test_aggregate_limit_enforced_during_ninth_acquisition(self):
        body = fixture()
        body += b" " * (MIB - len(body))
        specs = tuple(specification(f"aggregate-{index}", body if index < 8 else fixture()) for index in range(9))
        result = self.run_pipeline(specs, tuple(Occurrence(index, "players") for index in range(9)))
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertEqual(result.acquired_bytes, TOTAL)
        self.assertEqual(result.occurrence_expanded_bytes, TOTAL)
        self.assertEqual(result.acquisitions[-1].effective_max_bytes, 0)
        self.assertIs(result.acquisitions[-1].failure_code, runner.OfflineFailureCode.BYTE_LIMIT)
        self.assertEqual(self.count("acquisition_observation"), 9)
        self.assertEqual(self.count("raw_artifact"), 1)
        self.assertEqual(self.count("source_snapshot"), 0)

    def test_exact_aggregate_limit_success(self):
        body = fixture()
        body += b" " * (MIB - len(body))
        specs = tuple(specification(f"aggregate-{index}", body) for index in range(8))
        result = self.run_pipeline(specs, tuple(Occurrence(index, "players") for index in range(8)))
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(result.acquired_bytes, TOTAL)

    def test_occurrence_weighted_limit_controls_effective_runner_cap(self):
        body = fixture()
        body += b" " * (MIB - len(body))
        with patch.object(runner, "run_offline", wraps=runner.run_offline) as acquire:
            result = self.run_pipeline((specification(body=body),), (Occurrence(0, "players"),) * 9)
        self.assertEqual(result.acquisitions[0].effective_max_bytes, TOTAL // 9)
        self.assertEqual(acquire.call_args.kwargs["limits"].max_bytes, TOTAL // 9)
        self.assertIs(result.acquisitions[0].failure_code, runner.OfflineFailureCode.BYTE_LIMIT)
        self.assertEqual(result.acquired_bytes, 0)
        self.assertEqual(result.occurrence_expanded_bytes, 0)
        self.assertEqual(self.count("raw_artifact"), 0)

    def test_exact_expanded_limit_success_and_remaining_weighted_cap(self):
        body = fixture()
        body += b" " * (MIB - len(body))
        result = self.run_pipeline((specification(body=body),), (Occurrence(0, "players"),) * 8)
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(result.acquired_bytes, MIB)
        self.assertEqual(result.occurrence_expanded_bytes, TOTAL)

    def test_remaining_expanded_budget_uses_prior_occurrence_multiplicities(self):
        specs = (specification("first"), specification("second"))
        occurrences = (Occurrence(0, "first"),) * 3 + (Occurrence(1, "second"),) * 8
        with patch.object(runner, "run_offline", wraps=runner.run_offline) as acquire:
            result = self.run_pipeline(specs, occurrences)
        self.assertIs(result.status, Status.COMPLETE)
        expected_cap = (TOTAL - 3 * len(fixture())) // 8
        self.assertLess(expected_cap, MIB)
        self.assertEqual(result.acquisitions[1].effective_max_bytes, expected_cap)
        self.assertEqual(acquire.call_args_list[1].kwargs["limits"].max_bytes, expected_cap)

    def test_forged_runner_success_is_known_precall_noncommit(self):
        actual = runner.run_offline(URL, url_rules=RULES, address_rules=AddressRules(),
                                    resolver=FakeResolver(), transport=FakeTransport(MemoryStream(fixture())),
                                    clock=FakeClock(), limits=runner.OfflineLimits(10, MIB))
        forged = replace(actual, sha256="0" * 64)
        with patch.object(runner, "run_offline", return_value=forged):
            with patch.object(provenance, "persist_success", wraps=provenance.persist_success) as persist:
                result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.acquisitions[0].outcome, O.SUCCEEDED)
        self.assertIs(result.acquisitions[0].observation_commit, C.NOT_COMMITTED)
        self.assertIs(result.failure.code, F.SUCCESS_INPUT_INVALID)
        persist.assert_not_called()

    def test_success_observation_insert_failure_is_conservatively_unknown(self):
        def deny(action, first, second, schema, source):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and first == "acquisition_observation" else sqlite3.SQLITE_OK

        self.db.set_authorizer(deny)
        try:
            result = self.run_pipeline()
        finally:
            self.db.set_authorizer(None)
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIs(result.acquisitions[0].outcome, O.SUCCEEDED)
        self.assertIs(result.acquisitions[0].observation_commit, C.UNKNOWN)
        self.assertEqual(self.count("raw_artifact"), 0)  # Actual rollback is not a public receipt.
        self.assertEqual(self.count("acquisition_observation"), 0)
        self.assertFalse(self.db.in_transaction)

    def test_commit_denial_at_each_write_keeps_prior_confirmed_ids(self):
        operations = ((provenance, "persist_success", S.OBSERVATION_PERSISTENCE),
                      (database, "add_snapshot", S.SNAPSHOT_PERSISTENCE),
                      (lineage, "register_derivation", S.LINEAGE_REGISTRATION))
        for module, name, failed_stage in operations:
            with self.subTest(stage=failed_stage):
                self.new_database()
                original = getattr(module, name)

                def deny_commit(action, first, second, schema, source):
                    return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT" else sqlite3.SQLITE_OK

                def failed_commit(*args, **kwargs):
                    self.db.set_authorizer(deny_commit)
                    try:
                        return original(*args, **kwargs)
                    finally:
                        self.db.set_authorizer(None)

                with patch.object(module, name, side_effect=failed_commit) as write:
                    result = self.run_pipeline()
                self.assertIs(result.status, Status.INDETERMINATE)
                index = 0 if failed_stage is S.OBSERVATION_PERSISTENCE else None
                self.assertIs(stage(result, failed_stage, index).commit_knowledge, C.UNKNOWN)
                self.assertEqual(write.call_count, 1)
                if failed_stage is not S.OBSERVATION_PERSISTENCE:
                    self.assertIsNotNone(result.acquisitions[0].observation_id)
                if failed_stage is S.LINEAGE_REGISTRATION:
                    self.assertIsNotNone(result.snapshot_id)
                self.assertFalse(self.db.in_transaction)

    def test_exceptions_after_real_commits_leave_uncertainty_and_no_retries(self):
        operations = ((provenance, "persist_success", S.OBSERVATION_PERSISTENCE, "acquisition_observation"),
                      (database, "add_snapshot", S.SNAPSHOT_PERSISTENCE, "source_snapshot"),
                      (lineage, "register_derivation", S.LINEAGE_REGISTRATION, "snapshot_derivation"))
        for module, name, failed_stage, table in operations:
            with self.subTest(stage=failed_stage):
                self.new_database()
                original = getattr(module, name)

                def committed_then_lost(*args, **kwargs):
                    original(*args, **kwargs)
                    raise sqlite3.OperationalError("lost receipt fixture-marker")

                with patch.object(module, name, side_effect=committed_then_lost) as write:
                    result = self.run_pipeline()
                self.assertIs(result.status, Status.INDETERMINATE)
                index = 0 if failed_stage is S.OBSERVATION_PERSISTENCE else None
                self.assertIs(stage(result, failed_stage, index).commit_knowledge, C.UNKNOWN)
                self.assertEqual(self.count(table), 1)
                self.assertEqual(write.call_count, 1)
                self.assertNotIn("fixture-marker", repr(result))
                if failed_stage is S.LINEAGE_REGISTRATION:
                    self.assertIsNotNone(result.snapshot_id)
                    self.assertIsNone(result.derivation_id)

    def test_malformed_fixture_preserves_successful_raw_evidence(self):
        body = b"invalid synthetic JSON"
        result = self.run_pipeline((specification(body=body),))
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.TRANSFORMATION_FAILED)
        self.assertEqual(result.failure.detail_code, "malformed_fixture")
        self.assertIs(result.acquisitions[0].outcome, O.SUCCEEDED)
        self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
        self.assertEqual(provenance.get_artifact(self.db, sha256=result.acquisitions[0].sha256), body)
        self.assertEqual(self.count("source_snapshot"), 0)
        row = self.db.execute("SELECT outcome,failure_code FROM acquisition_observation").fetchone()
        self.assertEqual(tuple(row), ("SUCCESS", None))

    def test_transformation_row_and_canonical_byte_bounds(self):
        rows = [dict(identifier="p", payload={})] * 2049
        row = dict.fromkeys(database.RECORD_FIELDS)
        row.update(namespace_id=self.namespace, identifier="p", payload={"x": ""})
        overhead = len(database.canonical(row).encode("utf-8"))
        oversized = dict(identifier="p", payload={"x": "x" * (TOTAL // 16 - overhead + 1)})
        for index, (body, multiplicity) in enumerate(((fixture(rows), 2), (fixture([oversized]), 16))):
            with self.subTest(case=index):
                result = self.run_pipeline((specification(f"bound-{index}", body),),
                                           (Occurrence(0, "players"),) * multiplicity)
                self.assertIs(result.status, Status.INCOMPLETE)
                self.assertEqual(result.failure.detail_code, "resource_limit")
                self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
                self.assertIs(stage(result, S.SNAPSHOT_PERSISTENCE).commit_knowledge, C.NOT_ATTEMPTED)

    def test_snapshot_receives_fresh_complete_ordinary_rows_and_no_time_claims(self):
        original = database.add_snapshot

        def checked(db, **kwargs):
            self.assertEqual(set(kwargs), {"provider", "role", "loader_scope", "rows"})
            self.assertEqual(kwargs["provider"], "synthetic")
            self.assertEqual(kwargs["role"], "IDENTITY")
            first, second = kwargs["rows"]
            self.assertIs(type(first), dict)
            self.assertIs(type(first["payload"]), dict)
            self.assertIsNot(first, second)
            self.assertIsNot(first["payload"], second["payload"])
            self.assertEqual(set(first), set(database.RECORD_FIELDS))
            self.assertTrue(all(value is None for name, value in first.items()
                                if name not in ("namespace_id", "identifier", "payload")))
            return original(db, **kwargs)

        with patch.object(database, "add_snapshot", side_effect=checked):
            result = self.run_pipeline(occurrences=(Occurrence(0, "players"),) * 2)
        self.assertIs(result.status, Status.COMPLETE)

    def test_artifact_corruption_detected_independently_of_sql_hash_callback(self):
        original = storage.read_verified_synthetic_success

        def damaged(db, **kwargs):
            digest = kwargs["success"].sha256
            self.corrupt("UPDATE raw_artifact SET body=? WHERE sha256=?",
                         (b"x" * len(fixture()), digest), guards=("artifact_update",))
            real_hash = database._artifact_sha256
            self.db.create_function("artifact_sha256", 1,
                                    lambda body: real_hash(body) if body == b"" else digest,
                                    deterministic=True)
            return original(db, **kwargs)

        with patch.object(storage, "read_verified_synthetic_success", side_effect=damaged):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.ARTIFACT_MISMATCH)
        self.assertIsNotNone(result.acquisitions[0].observation_id)
        self.assertIs(stage(result, S.TRANSFORMATION).outcome, O.NOT_ATTEMPTED)

    def test_observation_relationship_metadata_mismatch_detected(self):
        original = storage.read_verified_synthetic_success

        def damaged(db, **kwargs):
            self.corrupt("UPDATE acquisition_observation SET logical_artifact_id='other-fixture' WHERE id=?",
                         (kwargs["observation_id"],), guards=("acquisition_update",))
            return original(db, **kwargs)

        with patch.object(storage, "read_verified_synthetic_success", side_effect=damaged):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.ARTIFACT_MISMATCH)

    def test_artifact_read_failure_is_uncertain_and_preserves_observation(self):
        with patch.object(storage, "read_verified_synthetic_success", side_effect=sqlite3.OperationalError("read-marker")):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIs(result.failure.code, F.ARTIFACT_VERIFICATION_FAILED)
        self.assertIs(result.acquisitions[0].observation_commit, C.CONFIRMED)
        self.assertIsNotNone(result.acquisitions[0].observation_id)
        self.assertNotIn("read-marker", repr(result))

    def test_oversized_artifact_rejected_before_materializing_body(self):
        original = storage.read_verified_synthetic_success
        read_bodies = []

        def damaged(db, **kwargs):
            self.corrupt("UPDATE raw_artifact SET body=?,byte_length=? WHERE sha256=?",
                         (b"x" * (MIB + 1), MIB + 1, kwargs["success"].sha256), guards=("artifact_update",))
            self.db.set_trace_callback(lambda sql: read_bodies.append(sql) if sql.startswith("SELECT body FROM") else None)
            try:
                return original(db, **kwargs)
            finally:
                self.db.set_trace_callback(None)

        with patch.object(storage, "read_verified_synthetic_success", side_effect=damaged):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertEqual(read_bodies, [])

    def test_forbidden_failure_metadata_rejected_before_materializing_observation(self):
        original = storage.read_verified_synthetic_success
        read_observations = []

        def damaged(db, **kwargs):
            self.corrupt("UPDATE acquisition_observation SET failure_code=? WHERE id=?",
                         ("x" * (TOTAL + 1), kwargs["observation_id"]), guards=("acquisition_update",))
            self.db.set_trace_callback(lambda sql: read_observations.append(sql)
                                      if sql.startswith("SELECT * FROM main.acquisition_observation") else None)
            try:
                return original(db, **kwargs)
            finally:
                self.db.set_trace_callback(None)

        with patch.object(storage, "read_verified_synthetic_success", side_effect=damaged):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.ARTIFACT_MISMATCH)
        self.assertEqual(read_observations, [])

    def test_corrupt_snapshot_actual_columns_normalized_text_and_digest(self):
        changes = (
            ("UPDATE source_record SET payload=? WHERE snapshot_id=?", database.canonical({"sample": 8}), "record_update"),
            ("UPDATE source_record SET identifier=? WHERE snapshot_id=?", "p2", "record_update"),
            ("UPDATE source_record SET normalized=replace(normalized,'sample','zample') WHERE snapshot_id=?", None, "record_update"),
            ("UPDATE source_snapshot SET normalized_sha256=? WHERE id=?", "0" * 64, "snapshot_seal"),
        )
        for sql, value, guard in changes:
            with self.subTest(sql=sql):
                self.new_database()
                original = database.add_snapshot

                def damaged(*args, **kwargs):
                    identifier = original(*args, **kwargs)
                    parameters = (identifier,) if value is None else (value, identifier)
                    self.corrupt(sql, parameters, guards=(guard,))
                    return identifier

                with patch.object(database, "add_snapshot", side_effect=damaged):
                    with patch.object(lineage, "register_derivation", wraps=lineage.register_derivation) as register:
                        result = self.run_pipeline()
                self.assertIs(result.status, Status.INCOMPLETE)
                self.assertIs(result.failure.code, F.SNAPSHOT_MISMATCH)
                self.assertIsNotNone(result.snapshot_id)
                self.assertIs(stage(result, S.SNAPSHOT_PERSISTENCE).commit_knowledge, C.CONFIRMED)
                register.assert_not_called()

    def test_snapshot_sql_types_and_unexpected_relationship_columns_rejected(self):
        original = database.add_snapshot

        def damaged(*args, **kwargs):
            identifier = original(*args, **kwargs)
            team = self.db.execute("INSERT INTO identifier_namespace(provider,kind,name) "
                                   "VALUES('synthetic','TEAM','unexpected')").lastrowid
            self.corrupt("UPDATE source_record SET team_namespace_id=? WHERE snapshot_id=?",
                         (team, identifier), guards=("record_update",))
            return identifier

        with patch.object(database, "add_snapshot", side_effect=damaged):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.SNAPSHOT_MISMATCH)

    def test_oversized_snapshot_text_rejected_before_loading_rows(self):
        original = database.add_snapshot
        read_rows = []

        def damaged(*args, **kwargs):
            identifier = original(*args, **kwargs)
            self.corrupt("UPDATE source_record SET payload=? WHERE snapshot_id=?",
                         ("x" * (TOTAL + 1), identifier), guards=("record_update",))
            self.db.set_trace_callback(lambda sql: read_rows.append(sql) if sql.startswith("SELECT normalized,") else None)
            return identifier

        try:
            with patch.object(database, "add_snapshot", side_effect=damaged):
                result = self.run_pipeline()
        finally:
            self.db.set_trace_callback(None)
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertEqual(read_rows, [])

    def test_snapshot_verification_error_is_uncertain_after_confirmed_commit(self):
        with patch.object(storage, "verify_synthetic_snapshot", side_effect=sqlite3.OperationalError("read-marker")):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIsNotNone(result.snapshot_id)
        self.assertIs(stage(result, S.SNAPSHOT_PERSISTENCE).commit_knowledge, C.CONFIRMED)
        self.assertIsNone(result.derivation_id)

    def test_snapshot_reuse_historical_conflict_never_invents_retrieval_evidence(self):
        prepared = transform.transform_synthetic_identity_v1((fixture(),), occurrence_indices=(0,),
                                                             namespace_id=self.namespace, loader_scope="pipeline-fixture")
        identifier = database.add_snapshot(self.db, provider="synthetic", role="IDENTITY", loader_scope="pipeline-fixture",
                                           rows=storage.snapshot_rows(prepared), retrieved_at=TIME)
        result = self.run_pipeline()
        self.assertIs(result.status, Status.INDETERMINATE)  # Raised write API supplies no commit receipt.
        self.assertIs(stage(result, S.SNAPSHOT_PERSISTENCE).commit_knowledge, C.UNKNOWN)
        self.assertIsNone(result.snapshot_id)
        self.assertEqual(self.db.execute("SELECT retrieved_at FROM source_snapshot WHERE id=?", (identifier,)).fetchone()[0], TIME)

    def test_known_snapshot_prevalidation_failure_never_invokes_write(self):
        original = transform.transform_synthetic_identity_v1

        def forged(*args, **kwargs):
            return replace(original(*args, **kwargs), canonical_normalized_bytes=0)

        with patch.object(transform, "transform_synthetic_identity_v1", side_effect=forged):
            with patch.object(database, "add_snapshot", wraps=database.add_snapshot) as add:
                result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(stage(result, S.SNAPSHOT_PERSISTENCE).commit_knowledge, C.NOT_COMMITTED)
        add.assert_not_called()

    def test_lineage_insertion_and_input_failures_are_unknown_without_reregistration(self):
        for table in ("snapshot_derivation", "derivation_input"):
            with self.subTest(table=table):
                self.new_database()

                def deny(action, first, second, schema, source):
                    return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and first == table else sqlite3.SQLITE_OK

                self.db.set_authorizer(deny)
                try:
                    with patch.object(lineage, "register_derivation", wraps=lineage.register_derivation) as register:
                        result = self.run_pipeline()
                finally:
                    self.db.set_authorizer(None)
                self.assertIs(result.status, Status.INDETERMINATE)
                self.assertIs(stage(result, S.LINEAGE_REGISTRATION).commit_knowledge, C.UNKNOWN)
                self.assertIsNotNone(result.snapshot_id)
                self.assertEqual(self.count("snapshot_derivation"), 0)
                self.assertEqual(register.call_count, 1)

    def test_final_lineage_mismatch_retains_all_confirmed_ids(self):
        original = lineage.get_derivation

        def wrong(*args, **kwargs):
            return replace(original(*args, **kwargs), transformation_version="other")

        with patch.object(lineage, "get_derivation", side_effect=wrong):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.LINEAGE_MISMATCH)
        self.assertIsNotNone(result.derivation_id)
        self.assertIsNotNone(result.snapshot_id)
        self.assertIsNotNone(result.acquisitions[0].observation_id)
        self.assertIs(stage(result, S.LINEAGE_REGISTRATION).commit_knowledge, C.CONFIRMED)

    def test_final_lineage_all_header_and_input_facts_require_exact_types_and_values(self):
        mutations = (
            lambda d: replace(d, derivation_id=d.derivation_id + 1),
            lambda d: replace(d, snapshot_id=d.snapshot_id + 1),
            lambda d: replace(d, transformation_id="other"),
            lambda d: replace(d, parameters=database.canonical({})),
            lambda d: replace(d, recorded_at="2030-10-04T00:00:00Z"),
            lambda d: replace(d, expected_input_count=True),
            lambda d: replace(d, evidence_kind="other"),
            lambda d: replace(d, sealed=1),
            lambda d: replace(d, inputs=(replace(d.inputs[0], ordinal=False),)),
            lambda d: replace(d, inputs=(replace(d.inputs[0], input_label="other"),)),
            lambda d: replace(d, inputs=(replace(d.inputs[0], observation_id=True),)),
            lambda d: replace(d, inputs=(replace(d.inputs[0], artifact_sha256="0" * 64),)),
            lambda d: replace(d, inputs=list(d.inputs)),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                self.new_database()
                original = lineage.get_derivation

                def changed(*args, **kwargs):
                    return mutate(original(*args, **kwargs))

                with patch.object(lineage, "get_derivation", side_effect=changed):
                    result = self.run_pipeline()
                self.assertIs(result.status, Status.INCOMPLETE)
                self.assertIs(result.failure.code, F.LINEAGE_MISMATCH)
                self.assertIsNotNone(result.derivation_id)

    def test_lineage_precall_validation_failure_has_known_noncommit(self):
        with patch.object(storage, "validate_derivation_for_registration", side_effect=ValueError("validation-marker")):
            with patch.object(lineage, "register_derivation", wraps=lineage.register_derivation) as register:
                result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIs(result.failure.code, F.LINEAGE_INPUT_INVALID)
        self.assertIs(stage(result, S.LINEAGE_REGISTRATION).commit_knowledge, C.NOT_COMMITTED)
        self.assertIsNotNone(result.snapshot_id)
        register.assert_not_called()

    def test_final_lineage_read_error_is_uncertain_after_confirmed_commit(self):
        with patch.object(lineage, "get_derivation", side_effect=sqlite3.OperationalError("verification-marker")):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INDETERMINATE)
        self.assertIsNotNone(result.derivation_id)
        self.assertIs(stage(result, S.LINEAGE_REGISTRATION).commit_knowledge, C.CONFIRMED)
        self.assertIs(stage(result, S.LINEAGE_VERIFICATION).outcome, O.UNRESOLVED)
        self.assertNotIn("verification-marker", repr(result))

    def test_lineage_integrity_failure_after_commit_is_conclusive(self):
        with patch.object(lineage, "get_derivation", side_effect=sqlite3.IntegrityError("integrity-marker")):
            result = self.run_pipeline()
        self.assertIs(result.status, Status.INCOMPLETE)
        self.assertIsNotNone(result.derivation_id)
        self.assertIs(stage(result, S.LINEAGE_REGISTRATION).commit_knowledge, C.CONFIRMED)

    def test_control_signals_and_unexpected_programming_errors_propagate(self):
        for signal in (KeyboardInterrupt(), SystemExit(9), GeneratorExit(), MemoryError(), AssertionError("bug"), AttributeError("bug")):
            with self.subTest(signal=type(signal).__name__):
                with patch.object(provenance, "persist_success", side_effect=signal):
                    with self.assertRaises(type(signal)) as caught:
                        self.run_pipeline()
                self.assertIs(caught.exception, signal)

    def test_runner_resource_exhaustion_is_not_a_normal_acquisition_failure(self):
        spec = specification(transport=FakeTransport(MemoryError("resource-marker")))
        with self.assertRaises(MemoryError):
            self.run_pipeline((spec,))
        self.assertEqual(self.count("acquisition_observation"), 0)

    def test_storage_control_signal_rollback_ownership(self):
        original = provenance._insert_event

        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt

        with patch.object(provenance, "_insert_event", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.run_pipeline()
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.count("raw_artifact"), 0)

    def test_failed_rollback_does_not_swallow_the_primary_control_signal(self):
        signal = KeyboardInterrupt()
        original = provenance._insert_event

        def deny_rollback(action, first, second, schema, source):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and first == "ROLLBACK" else sqlite3.SQLITE_OK

        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            self.db.set_authorizer(deny_rollback)
            raise signal

        try:
            with patch.object(provenance, "_insert_event", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.run_pipeline()
            self.assertIs(caught.exception, signal)
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.set_authorizer(None)
            self.db.rollback()  # Explicit fixture cleanup; the coordinator must not do this.

    def test_historical_research_safeguards_and_existing_state_preserved(self):
        self.db = database.connect()
        self.addCleanup(self.db.close)
        database.initialize(self.db)
        historical_run, historical_snapshots = populate_research(
            self.db, retrieved_at=TIME, publication_at="2030-10-02T00:00:00Z", publication_evidence="Synthetic assertion")
        self.namespace = self.db.execute("INSERT INTO identifier_namespace(provider,kind,name) "
                                         "VALUES('synthetic','PLAYER','pipeline-player')").lastrowid
        before = database_state(self.db)
        result = self.run_pipeline()
        self.assertIs(result.status, Status.COMPLETE)
        protected = {name: rows for name, rows in before[2] if name not in
                     ("raw_artifact", "acquisition_observation", "source_snapshot", "source_record", "snapshot_derivation", "derivation_input")}
        after = database_state(self.db)
        self.assertEqual({name: rows for name, rows in after[2] if name in protected}, protected)
        header = self.db.execute("SELECT original_file_sha256,retrieved_at,publication_at,publication_evidence "
                                 "FROM source_snapshot WHERE id=?", (result.snapshot_id,)).fetchone()
        self.assertEqual(tuple(header), (None, None, None, None))
        run = database.create_run(self.db, identity=result.snapshot_id,
                                  schedule=historical_snapshots[1], stats=historical_snapshots[2])
        self.db.execute("INSERT OR IGNORE INTO quarantine(run_id,source_record_id,reason) "
                        "SELECT ?,id,'Synthetic fixture' FROM source_record WHERE snapshot_id IN (?,?,?)",
                        (run, result.snapshot_id, historical_snapshots[1], historical_snapshots[2]))
        database.seal_run(self.db, run)
        for mode in ("OBSERVED_BY_EDGEFINDER", "VERIFIED_PUBLICATION"):
            with self.subTest(mode=mode), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                                (run, mode, "9999-12-31T23:59:59Z"))
        self.assertEqual(self.db.execute("SELECT sealed FROM validation_run WHERE id=?", (historical_run,)).fetchone()[0], 1)

    def test_pipeline_allows_only_intended_memory_database_and_bundled_schema_io(self):
        active = {"value": False}
        attempts = []
        allowed_files = {str(Path(database.__file__).with_name(name)).lower()
                         for name in ("schema.sql", "provenance_schema.sql")}

        def guard(event, args):
            if not active["value"]:
                return
            forbidden = event.startswith(("socket.", "subprocess."))
            if event == "sqlite3.connect" and args[0] != ":memory:":
                forbidden = True
            if event == "open" and (not isinstance(args[0], str) or args[0].lower() not in allowed_files):
                forbidden = True
            if forbidden:
                attempts.append(event)
                raise AssertionError("Unauthorized synthetic pipeline side effect")

        sys.addaudithook(guard)
        spec = specification()
        active["value"] = True
        try:
            result = self.run_pipeline((spec,))
        finally:
            active["value"] = False
        self.assertIs(result.status, Status.COMPLETE)
        self.assertEqual(attempts, [])


if __name__ == "__main__":
    unittest.main()
