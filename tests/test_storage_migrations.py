"""Single-extension migration tests; all databases are isolated ':memory:'."""

from contextlib import closing
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from edgefinder.storage import database
from edgefinder.storage.database import (
    add_snapshot, connect, create_run, initialize, install_provenance, seal_run,
    transaction,
)


def legacy_schema(db):
    """Use the unchanged baseline, without the new initialization path."""
    db.executescript(Path(database.__file__).with_name("schema.sql").read_text(
        encoding="utf-8"))


def populate_research(db, **times):
    """Include bindings, observations, quarantine, finding and selections."""
    for kind, name in (("PLAYER", "player"), ("TEAM", "team"), ("GAME", "game")):
        db.execute("INSERT INTO identifier_namespace(provider,kind,name) VALUES('synthetic',?,?)",
                   (kind, name))
    for kind, label in (("PLAYER", "Player"), ("TEAM", "Home"),
                        ("TEAM", "Away"), ("GAME", "Game")):
        db.execute("INSERT INTO entity(kind,label) VALUES(?,?)", (kind, label))
    rows = [
        [{"namespace_id": n, "identifier": key} for n, key in
         ((1, "p1"), (2, "home"), (2, "away"), (3, "g1"))],
        [dict(namespace_id=3, identifier="g1", home_namespace_id=2,
              home_identifier="home", away_namespace_id=2, away_identifier="away")],
        [dict(namespace_id=1, identifier=key, game_namespace_id=3,
              game_identifier="g1", team_namespace_id=2, team_identifier="home",
              payload={"yards": 0}) for key in ("p1", None)],
    ]
    snapshots = [add_snapshot(db, provider="synthetic", role=role,
                              loader_scope="fixture", rows=records, **times)
                 for role, records in zip(("IDENTITY", "SCHEDULE", "STATS"), rows)]
    run = create_run(db, identity=snapshots[0], schedule=snapshots[1], stats=snapshots[2])
    identities = db.execute("SELECT id FROM source_record WHERE snapshot_id=? ORDER BY ordinal",
                            (snapshots[0],)).fetchall()
    bindings = []
    for record, entity in zip(identities, (1, 2, 3, 4)):
        bindings.append(db.execute(
            "INSERT INTO identifier_binding(run_id,namespace_id,identifier,entity_id,source_record_id) "
            "SELECT ?,namespace_id,identifier,?,id FROM source_record WHERE id=?",
            (run, entity, record[0])).lastrowid)
    schedule = db.execute("SELECT id FROM source_record WHERE snapshot_id=?",
                          (snapshots[1],)).fetchone()[0]
    game = db.execute(
        "INSERT INTO game_observation(run_id,source_record_id,game_binding,home_binding,away_binding) "
        "VALUES(?,?,?,?,?)", (run, schedule, bindings[3], bindings[1], bindings[2])).lastrowid
    stats = db.execute("SELECT id FROM source_record WHERE snapshot_id=? AND identifier='p1'",
                       (snapshots[2],)).fetchone()[0]
    db.execute("INSERT INTO player_game_observation(run_id,source_record_id,player_binding,"
               "team_binding,game_observation_id) VALUES(?,?,?,?,?)",
               (run, stats, bindings[0], bindings[1], game))
    db.execute("INSERT INTO finding(run_id,severity,code,message) "
               "VALUES(?,'WARNING','fixture','Synthetic warning')", (run,))
    seal_run(db, run)
    db.execute("INSERT INTO research_selection(run_id,mode) VALUES(?,'RETROSPECTIVE')", (run,))
    if times:
        for mode, cutoff in (("OBSERVED_BY_EDGEFINDER", times["retrieved_at"]),
                             ("VERIFIED_PUBLICATION", times["publication_at"])):
            db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                       (run, mode, cutoff))
    return run, snapshots


def database_state(db):
    tables = db.execute("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")
    rows = []
    for (name,) in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        rows.append((name, tuple(sorted((tuple(r) for r in db.execute(f"SELECT * FROM {quoted}")), key=repr))))
    return (db.execute("PRAGMA user_version").fetchone()[0],
            database._schema_signature(db), tuple(rows))


class StorageMigrationTests(unittest.TestCase):
    def connection(self, *, legacy=False):
        db = connect()
        self.addCleanup(db.close)
        if legacy:
            legacy_schema(db)
        return db

    def assert_rejected_unchanged(self, db, operation=install_provenance):
        before = database_state(db)
        with self.assertRaises((RuntimeError, sqlite3.Error)):
            operation(db)
        self.assertEqual(database_state(db), before)
        self.assertFalse(db.in_transaction)

    def test_fresh_initialization_installs_complete_strict_schema(self):
        db = self.connection()
        initialize(db)
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
        tables = {r["name"]: r for r in db.execute("PRAGMA table_list")}
        for name in ("raw_artifact", "acquisition_observation", "snapshot_derivation", "derivation_input"):
            self.assertEqual(tables[name]["strict"], 1)
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertFalse(db.in_transaction)

    def test_populated_legacy_upgrade_preserves_every_existing_object_and_row(self):
        db = self.connection(legacy=True)
        run, snapshots = populate_research(
            db, retrieved_at="2030-10-03T00:00:00Z", publication_at="2030-10-02T00:00:00Z",
            publication_evidence="Synthetic caller assertion")
        _, (objects, structures), rows = database_state(db)
        install_provenance(db)
        after = database_state(db)
        self.assertTrue(set(objects) <= set(after[1][0]))
        self.assertTrue(set(structures) <= set(after[1][1]))
        self.assertTrue(set(rows) <= set(after[2]))
        for name in ("raw_artifact", "acquisition_observation", "snapshot_derivation", "derivation_input"):
            self.assertEqual(db.execute(f"SELECT count(*) FROM {name}").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM research_selection WHERE run_id=?", (run,)).fetchone()[0], 3)
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
        for mode, cutoff in (("OBSERVED_BY_EDGEFINDER", "2030-10-02T23:59:59Z"),
                             ("VERIFIED_PUBLICATION", "2030-10-01T23:59:59Z")):
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                           (run, mode, cutoff))
        with self.assertRaisesRegex(ValueError, "different temporal metadata"):
            add_snapshot(db, provider="synthetic", role="IDENTITY", loader_scope="fixture",
                         rows=[{"namespace_id": n, "identifier": key} for n, key in
                               ((1, "p1"), (2, "home"), (2, "away"), (3, "g1"))])
        self.assertEqual(len(snapshots), 3)

    def test_fresh_and_upgrade_have_equivalent_structure_not_rootpages(self):
        fresh = self.connection()
        initialize(fresh)
        upgraded = self.connection(legacy=True)
        populate_research(upgraded)
        install_provenance(upgraded)
        self.assertEqual(database._schema_signature(fresh), database._schema_signature(upgraded))

    def test_installed_second_call_is_validated_noop_including_populated_provenance(self):
        db = self.connection()
        initialize(db)
        db.execute("INSERT INTO raw_artifact VALUES(artifact_sha256(?),?,?)", (b"x", 1, b"x"))
        before = database_state(db)
        schema_version = db.execute("PRAGMA schema_version").fetchone()[0]
        changes = db.total_changes
        install_provenance(db)
        self.assertEqual(database_state(db), before)
        self.assertEqual(db.execute("PRAGMA schema_version").fetchone()[0], schema_version)
        self.assertEqual(db.total_changes, changes)

    def test_connect_does_not_install_or_change_version(self):
        db = self.connection()
        self.assertEqual(database_state(db), (0, ((), ()), ()))
        self.assert_rejected_unchanged(db)

    def test_initialize_rejects_legacy_and_installed_databases(self):
        for installed in (False, True):
            with self.subTest(installed=installed):
                db = self.connection(legacy=True)
                if installed:
                    install_provenance(db)
                self.assert_rejected_unchanged(db, initialize)

    def test_version_structure_combinations_fail_closed(self):
        for structure, version in (("empty", 1), ("legacy", 1), ("legacy", 2),
                                   ("installed", 0), ("installed", -1), ("installed", 99)):
            with self.subTest(structure=structure, version=version):
                db = self.connection(legacy=structure != "empty")
                if structure == "installed":
                    install_provenance(db)
                db.execute(f"PRAGMA user_version={version}")
                self.assert_rejected_unchanged(db)

    def test_partial_extension_and_unknown_prefix_objects_fail_closed(self):
        for ddl in ("CREATE TABLE raw_artifact (x TEXT) STRICT",
                    "CREATE TABLE provenance_partial (x TEXT) STRICT",
                    "CREATE TABLE provenance_unrelated (x TEXT) STRICT"):
            with self.subTest(ddl=ddl):
                db = self.connection(legacy=True)
                db.execute(ddl)
                self.assert_rejected_unchanged(db)

    def test_missing_changed_and_extra_objects_rejected_at_both_versions(self):
        alterations = (
            "DROP TABLE research_selection",
            "DROP INDEX finding_severity",
            "DROP TRIGGER selection_insert",
            "CREATE TABLE extra_table (x TEXT)",
            "CREATE INDEX extra_index ON entity(label)",
            "CREATE VIEW extra_view AS SELECT * FROM entity",
            "CREATE TRIGGER extra_trigger BEFORE UPDATE ON entity BEGIN SELECT 1; END",
            "ALTER TABLE entity ADD COLUMN extra TEXT",
            "DROP INDEX source_record_identity_keys; CREATE INDEX source_record_identity_keys ON source_record(snapshot_id)",
            "DROP TRIGGER selection_insert; CREATE TRIGGER selection_insert BEFORE INSERT ON research_selection BEGIN SELECT 1; END",
        )
        for version in (0, 1):
            for ddl in alterations:
                with self.subTest(version=version, ddl=ddl):
                    db = self.connection(legacy=True)
                    if version:
                        install_provenance(db)
                    db.executescript(ddl)
                    self.assert_rejected_unchanged(db)

    def test_changed_constraint_and_automatic_index_structure_rejected(self):
        for changed in (
                "DROP TABLE entity; CREATE TABLE entity (id INTEGER PRIMARY KEY,kind TEXT NOT NULL,label TEXT NOT NULL) STRICT",
                "DROP TABLE identifier_namespace; CREATE TABLE identifier_namespace (id INTEGER PRIMARY KEY,provider TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,UNIQUE(provider,name)) STRICT"):
            with self.subTest(changed=changed):
                db = self.connection(legacy=True)
                db.executescript(changed)
                self.assert_rejected_unchanged(db)

    def test_missing_provenance_guard_rejects_installed_noop(self):
        db = self.connection()
        initialize(db)
        db.execute("DROP TRIGGER artifact_update")
        self.assert_rejected_unchanged(db)

    def test_nested_transactions_are_left_owned_by_caller(self):
        for operation in (initialize, install_provenance):
            with self.subTest(operation=operation.__name__):
                db = self.connection()
                db.execute("BEGIN")
                with self.assertRaisesRegex(RuntimeError, "outside a transaction"):
                    operation(db)
                self.assertTrue(db.in_transaction)
                db.rollback()
                self.assertEqual(database_state(db), (0, ((), ()), ()))

    def test_missing_required_pragmas_rejected_without_mutation(self):
        for pragma in ("foreign_keys", "recursive_triggers"):
            for operation in (initialize, install_provenance):
                with self.subTest(pragma=pragma, operation=operation.__name__):
                    db = self.connection(legacy=operation is install_provenance)
                    db.execute(f"PRAGMA {pragma}=OFF")
                    self.assert_rejected_unchanged(db, operation)

    def test_unsupported_or_removed_sql_functions_are_rejected(self):
        raw = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(raw.close)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute("PRAGMA recursive_triggers=ON")
        self.assert_rejected_unchanged(raw, initialize)
        for name, arity in (("valid_canonical", 1), ("record_canonical", len(database.RECORD_FIELDS)),
                            ("artifact_sha256", 1), ("evidence_hash", 1)):
            with self.subTest(name=name):
                db = self.connection(legacy=True)
                if name == "evidence_hash":
                    db.create_aggregate(name, arity, None)
                else:
                    db.create_function(name, arity, None)
                self.assert_rejected_unchanged(db)

    def test_unsupported_sqlite_version_rejected(self):
        db = self.connection()
        with patch.object(sqlite3, "sqlite_version_info", (3, 36, 0)):
            self.assert_rejected_unchanged(db, initialize)

    def test_schema_inspection_is_inside_immediate_transaction(self):
        db = self.connection(legacy=True)
        statements = []
        db.set_trace_callback(statements.append)
        install_provenance(db)
        db.set_trace_callback(None)
        begin = statements.index("BEGIN IMMEDIATE")
        inspection = next(i for i, sql in enumerate(statements) if "main.sqlite_schema" in sql)
        self.assertLess(begin, inspection)
        self.assertEqual(statements[-1], "COMMIT")

    def test_failure_after_baseline_or_during_extension_rolls_back_all_ddl(self):
        execute = database._execute_schema
        for fresh in (False, True):
            for checkpoint in ("baseline", "first_extension_table", "complete_extension"):
                if not fresh and checkpoint == "baseline":
                    continue
                with self.subTest(fresh=fresh, checkpoint=checkpoint):
                    db = self.connection(legacy=not fresh)
                    if not fresh:
                        populate_research(db)
                    before = database_state(db)

                    def injected(target, sql):
                        if target is not db:
                            return execute(target, sql)
                        is_extension = "CREATE TABLE raw_artifact" in sql
                        if is_extension and checkpoint == "first_extension_table":
                            execute(target, sql[:sql.index("CREATE TABLE acquisition_observation")])
                            raise RuntimeError("injected after first extension table")
                        execute(target, sql)
                        if (is_extension and checkpoint == "complete_extension" or
                                not is_extension and checkpoint == "baseline"):
                            raise RuntimeError("injected after DDL")

                    with patch.object(database, "_execute_schema", side_effect=injected):
                        with self.assertRaisesRegex(RuntimeError, "injected"):
                            (initialize if fresh else install_provenance)(db)
                    self.assertEqual(database_state(db), before)
                    self.assertFalse(db.in_transaction)

    def test_failure_after_version_write_before_commit_rolls_back(self):
        for fresh in (False, True):
            with self.subTest(fresh=fresh):
                db = self.connection(legacy=not fresh)
                before = database_state(db)
                statements = []
                db.set_trace_callback(statements.append)

                def deny_commit(action, first, second, schema, source):
                    return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and first == "COMMIT" else sqlite3.SQLITE_OK

                db.set_authorizer(deny_commit)
                with self.assertRaises(sqlite3.DatabaseError):
                    (initialize if fresh else install_provenance)(db)
                db.set_authorizer(None)
                db.set_trace_callback(None)
                self.assertIn("PRAGMA main.user_version=1", statements)
                self.assertEqual(database_state(db), before)
                self.assertFalse(db.in_transaction)

    def test_existing_foreign_key_violation_is_not_repaired_or_accepted(self):
        for installed in (False, True):
            with self.subTest(installed=installed):
                db = self.connection(legacy=True)
                if installed:
                    install_provenance(db)
                # Deliberately damage only this memory fixture, then restore
                # its exact guard so structure verification cannot mask the
                # separate foreign-key integrity check under test.
                guard = db.execute("SELECT sql FROM sqlite_schema WHERE name='quarantine_insert'").fetchone()[0]
                db.execute("PRAGMA foreign_keys=OFF")
                db.execute("DROP TRIGGER quarantine_insert")
                try:
                    db.execute("INSERT INTO quarantine VALUES(999,999,'deliberate broken fixture')")
                finally:
                    db.execute(guard)
                    db.execute("PRAGMA foreign_keys=ON")
                self.assert_rejected_unchanged(db)

    def test_shadow_and_attached_schemas_rejected(self):
        for sql in ("CREATE TEMP TABLE entity (id INTEGER)", "ATTACH DATABASE ':memory:' AS other"):
            with self.subTest(sql=sql):
                db = self.connection(legacy=True)
                db.execute(sql)
                self.assert_rejected_unchanged(db)

    def test_complete_statement_execution_preserves_trigger_bodies_and_rolls_back_errors(self):
        with closing(connect()) as db:
            with self.assertRaises(sqlite3.Error):
                with transaction(db):
                    database._execute_schema(db, "CREATE TABLE probe(x TEXT) STRICT;\n"
                        "CREATE TRIGGER probe_guard BEFORE INSERT ON probe BEGIN\n"
                        " SELECT RAISE(ABORT,'literal;semicolon');\nEND;\n"
                        "INSERT INTO probe VALUES('x');\n")
            self.assertEqual(database._schema_signature(db), ((), ()))


if __name__ == "__main__":
    unittest.main()
