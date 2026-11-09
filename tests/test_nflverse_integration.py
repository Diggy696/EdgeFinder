"""Synthetic adapter -> existing storage integration, exclusively ':memory:'.

Ordinary unittest discovery is offline and does not import provider packages.
Optionally run it with extra provider-import/network/protected-file auditing:
    .venv/Scripts/python.exe -B -m tests.test_nflverse_integration --offline-discovery

No settings patches or provider imports are needed by either test path.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import date, datetime, timezone
import os
import sqlite3
import sys
import unittest

from edgefinder.nflverse_adapter import Namespaces, prepare_game_sample
from edgefinder.storage.database import (
    add_snapshot, canonical, connect, create_run, evidence_hash, initialize,
    seal_run, transaction,
)
from tests.test_nflverse_adapter import AWAY, GAME, HOME, synthetic_inputs, with_rows


class SyntheticIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        self.addCleanup(self.db.close)
        initialize(self.db)
        ids = {}
        with transaction(self.db):
            for kind, name in (("PLAYER", "gsis_id"), ("TEAM", "team_abbr"), ("GAME", "game_id")):
                ids[kind] = self.db.execute(
                    "INSERT INTO identifier_namespace(provider,kind,name) VALUES(?,?,?)",
                    ("nflverse", kind, name)).lastrowid
        self.ns = Namespaces(ids["PLAYER"], ids["TEAM"], ids["GAME"])

    def stage(self, inputs=None):
        sample = prepare_game_sample(synthetic_inputs() if inputs is None else inputs,
                                     namespaces=self.ns)
        snapshots = {s.role: add_snapshot(self.db, **s.storage_kwargs())
                     for s in (sample.identity, sample.schedule, sample.stats)}
        run = create_run(self.db, identity=snapshots["IDENTITY"],
                         schedule=snapshots["SCHEDULE"], stats=snapshots["STATS"])
        return sample, snapshots, run

    def records(self, snapshot):
        return self.db.execute(
            "SELECT * FROM source_record WHERE snapshot_id=? ORDER BY ordinal",
            (snapshot,)).fetchall()

    def promote(self, snapshots, run):
        """Exercise existing schema's explicit interpretation protocol, no adapter writes."""
        bindings = {}
        with transaction(self.db):
            for record in self.records(snapshots["IDENTITY"]):
                kind = self.db.execute("SELECT kind FROM identifier_namespace WHERE id=?",
                                       (record["namespace_id"],)).fetchone()[0]
                entity = self.db.execute("INSERT INTO entity(kind,label) VALUES(?,?)",
                                         (kind, record["identifier"])).lastrowid
                binding = self.db.execute(
                    "INSERT INTO identifier_binding(run_id,namespace_id,identifier,entity_id,source_record_id) "
                    "VALUES(?,?,?,?,?)", (run, record["namespace_id"], record["identifier"],
                                         entity, record["id"])).lastrowid
                bindings[record["namespace_id"], record["identifier"]] = binding
            record = self.records(snapshots["SCHEDULE"])[0]
            game = self.db.execute(
                "INSERT INTO game_observation(run_id,source_record_id,game_binding,home_binding,away_binding) "
                "VALUES(?,?,?,?,?)", (run, record["id"], bindings[self.ns.game, GAME],
                                     bindings[self.ns.team, "AAA"], bindings[self.ns.team, "BBB"])).lastrowid
            for record in self.records(snapshots["STATS"]):
                if self.db.execute("SELECT 1 FROM quarantine WHERE run_id=? AND source_record_id=?",
                                   (run, record["id"])).fetchone():
                    continue
                self.player_game(run, record, bindings, game)
        return bindings, game

    def player_game(self, run, record, bindings, game, team=None):
        return self.db.execute(
            "INSERT INTO player_game_observation(run_id,source_record_id,player_binding,team_binding,game_observation_id) "
            "VALUES(?,?,?,?,?)", (run, record["id"],
                                 bindings[self.ns.player, record["identifier"]],
                                 bindings[self.ns.team, record["team_identifier"] if team is None else team],
                                 game)).lastrowid

    def select(self, run, mode="RETROSPECTIVE", as_of=None):
        return self.db.execute("INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)",
                               (run, mode, as_of)).lastrowid

    def test_player_team_opponent_joins_source_values_and_successful_sealing(self):
        sample, snapshots, run = self.stage()
        self.promote(snapshots, run)
        seal_run(self.db, run)
        self.select(run)
        joined = self.db.execute(
            "SELECT pb.identifier AS player,tb.identifier AS team,gb.identifier AS game,"
            "CASE WHEN tb.id=hb.id THEN ab.identifier ELSE hb.identifier END AS opponent,"
            "r.payload FROM player_game_observation p "
            "JOIN identifier_binding pb ON pb.id=p.player_binding "
            "JOIN identifier_binding tb ON tb.id=p.team_binding "
            "JOIN game_observation g ON g.id=p.game_observation_id "
            "JOIN identifier_binding gb ON gb.id=g.game_binding "
            "JOIN identifier_binding hb ON hb.id=g.home_binding "
            "JOIN identifier_binding ab ON ab.id=g.away_binding "
            "JOIN source_record r ON r.id=p.source_record_id WHERE p.run_id=?", (run,)).fetchall()
        self.assertEqual(len(joined), 2)
        expected = {r["identifier"]: r for r in sample.stats.rows}
        for row in joined:
            payload = expected[row["player"]]["payload"]
            self.assertEqual(row["game"], GAME)
            self.assertEqual(row["team"], payload["record"]["team"])
            self.assertEqual(row["opponent"], payload["record"]["opponent_team"])
            # Exact canonical equality proves type/null/extra-field retention.
            self.assertEqual(row["payload"], canonical(payload))
        self.assertEqual(self.db.execute("SELECT sealed FROM validation_run WHERE id=?",
                                         (run,)).fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM quarantine").fetchone()[0], 0)
        self.assertEqual(self.db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_derived_snapshots_hashes_provenance_and_repeatability(self):
        sample, snapshots, _ = self.stage()
        for prepared in (sample.identity, sample.schedule, sample.stats):
            sid = snapshots[prepared.role]
            stored = self.db.execute("SELECT * FROM source_snapshot WHERE id=?", (sid,)).fetchone()
            self.assertEqual(stored["provider"], "nflverse")
            self.assertEqual(stored["role"], prepared.role)
            self.assertEqual(stored["loader_scope"], prepared.loader_scope)
            self.assertEqual(stored["retrieved_at"], prepared.retrieved_at)
            self.assertIsNone(stored["publication_at"])
            self.assertIsNone(stored["original_file_sha256"])
            self.assertEqual(stored["sealed"], 1)
            records = self.records(sid)
            self.assertEqual(stored["normalized_sha256"],
                             evidence_hash([r["normalized"] for r in records]))
            self.assertEqual([r["payload"] for r in records],
                             [canonical(r["payload"]) for r in prepared.rows])
            self.assertEqual(add_snapshot(self.db, **prepared.storage_kwargs()), sid)
        game_alias = next(r for r in sample.identity.rows if r["namespace_id"] == self.ns.game)
        self.assertEqual(game_alias["payload"]["provenance"]["loader"], "load_schedules")
        self.assertIn("synthetic", game_alias["payload"]["provenance"]["loader_scope"])

    def test_duplicate_stats_are_preserved_quarantined_and_never_promoted(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "stats", [*inputs.stats.rows, deepcopy(inputs.stats.rows[0])])
        _, snapshots, run = self.stage(inputs)
        stats = self.records(snapshots["STATS"])
        duplicates = [r for r in stats if r["identifier"] == HOME]
        self.assertEqual(len(stats), 3)
        self.assertEqual(len(duplicates), 2)
        self.assertEqual(duplicates[0]["normalized"], duplicates[1]["normalized"])
        quarantine = self.db.execute("SELECT source_record_id FROM quarantine WHERE run_id=?",
                                     (run,)).fetchall()
        self.assertEqual({r[0] for r in quarantine}, {r["id"] for r in duplicates})
        bindings, game = self.promote(snapshots, run)
        for record in duplicates:
            with self.assertRaises(sqlite3.IntegrityError):
                self.player_game(run, record, bindings, game)
        seal_run(self.db, run)
        # Sealing accounts for quarantined evidence, not a promise of completeness.
        self.assertEqual(self.db.execute("SELECT count(*) FROM player_game_observation").fetchone()[0], 1)
        self.assertEqual(len(self.records(snapshots["STATS"])), 3)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM quarantine WHERE run_id=?", (run,))

    def test_conflicting_duplicate_stats_remain_distinct_quarantined_evidence(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "stats", [*inputs.stats.rows,
                                             dict(inputs.stats.rows[0], receiving_yards=999)])
        _, snapshots, run = self.stage(inputs)
        duplicates = [r for r in self.records(snapshots["STATS"]) if r["identifier"] == HOME]
        self.assertNotEqual(duplicates[0]["payload"], duplicates[1]["payload"])
        self.assertEqual(self.db.execute("SELECT count(*) FROM quarantine WHERE run_id=?",
                                         (run,)).fetchone()[0], 2)
        self.promote(snapshots, run)
        seal_run(self.db, run)

    def test_wrong_team_cross_run_and_cross_snapshot_joins_are_rejected(self):
        _, snapshots, run = self.stage()
        bindings, game = self.promote(snapshots, run)
        other_run = create_run(self.db, identity=snapshots["IDENTITY"],
                               schedule=snapshots["SCHEDULE"], stats=snapshots["STATS"])
        record = next(r for r in self.records(snapshots["STATS"]) if r["identifier"] == HOME)
        # Remove one open observation so a uniqueness error cannot mask join errors.
        self.db.execute("DELETE FROM player_game_observation WHERE run_id=? AND source_record_id=?",
                        (run, record["id"]))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid stats join"):
            self.player_game(run, record, bindings, game, team="BBB")
        with self.assertRaises(sqlite3.IntegrityError):
            self.player_game(other_run, record, bindings, game)
        inputs = synthetic_inputs()
        changed = deepcopy(inputs.stats.rows)
        changed[0]["targets"] = 99
        other = prepare_game_sample(with_rows(inputs, "stats", changed), namespaces=self.ns)
        other_snapshot = add_snapshot(self.db, **other.stats.storage_kwargs())
        self.assertNotEqual(other_snapshot, snapshots["STATS"])
        other_record = next(r for r in self.records(other_snapshot) if r["identifier"] == HOME)
        with self.assertRaises(sqlite3.IntegrityError):
            self.player_game(run, other_record, bindings, game)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO quarantine VALUES(?,?,?)", (run, other_record["id"], "foreign"))
        self.player_game(run, record, bindings, game)
        seal_run(self.db, run)

    def test_foreign_key_namespace_failure_rolls_back_snapshot(self):
        sample = prepare_game_sample(synthetic_inputs(), namespaces=Namespaces(999, self.ns.team, self.ns.game))
        before = self.db.execute("SELECT count(*) FROM source_snapshot").fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            add_snapshot(self.db, **sample.identity.storage_kwargs())
        self.assertEqual(self.db.execute("SELECT count(*) FROM source_snapshot").fetchone()[0], before)
        self.assertEqual(self.db.execute("SELECT count(*) FROM source_record").fetchone()[0], 0)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        keys = self.db.execute("PRAGMA foreign_key_list(player_game_observation)").fetchall()
        self.assertTrue(any(row[2] == "identifier_binding" and row[3] == "run_id" for row in keys))

    def test_explicit_snapshot_selection_and_temporal_gates(self):
        inputs = synthetic_inputs()
        _, snapshots, run = self.stage(inputs)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run)
        self.promote(snapshots, run)
        seal_run(self.db, run)
        self.select(run)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, "OBSERVED_BY_EDGEFINDER", "2030-09-02T11:59:59Z")
        self.select(run, "OBSERVED_BY_EDGEFINDER", "2030-09-02T12:00:00Z")
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, "VERIFIED_PUBLICATION", "2030-09-03T00:00:00Z")
        for name in ("players", "teams", "schedules", "stats"):
            inputs = replace(inputs, **{name: replace(getattr(inputs, name), retrieved_at=None)})
        _, unknown_snapshots, unknown_run = self.stage(inputs)
        self.promote(unknown_snapshots, unknown_run)
        seal_run(self.db, unknown_run)
        self.select(unknown_run)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(unknown_run, "OBSERVED_BY_EDGEFINDER", "2030-09-03T00:00:00Z")
        selected = self.db.execute("SELECT identity_snapshot,schedule_snapshot,stats_snapshot "
                                   "FROM validation_run WHERE id=?", (run,)).fetchone()
        self.assertEqual(tuple(selected), tuple(snapshots[r] for r in ("IDENTITY", "SCHEDULE", "STATS")))

    def test_blocking_findings_and_uninterpreted_rows_prevent_sealing(self):
        _, snapshots, run = self.stage()
        with self.assertRaises(sqlite3.IntegrityError):
            seal_run(self.db, run)
        self.promote(snapshots, run)
        self.db.execute("INSERT INTO finding(run_id,severity,code,message) VALUES(?,'BLOCKING',?,?)",
                        (run, "SYNTHETIC", "Invented blocking finding"))
        with self.assertRaises(sqlite3.IntegrityError):
            seal_run(self.db, run)
        self.db.execute("DELETE FROM finding WHERE run_id=?", (run,))
        seal_run(self.db, run)

    def test_each_derived_role_respects_later_stats_retrieval(self):
        inputs = synthetic_inputs()
        _, baseline, _ = self.stage(inputs)
        inputs = replace(inputs, stats=replace(inputs.stats, retrieved_at="2030-09-02T13:00:00Z"))
        sample, later, _ = self.stage(inputs)
        for snapshot in (sample.identity, sample.schedule, sample.stats):
            self.assertEqual(snapshot.retrieved_at, "2030-09-02T13:00:00Z")
        for role in baseline:
            with self.subTest(role=role):
                selected = dict(baseline, **{role: later[role]})
                run = create_run(self.db, identity=selected["IDENTITY"],
                                 schedule=selected["SCHEDULE"], stats=selected["STATS"])
                self.promote(selected, run)
                seal_run(self.db, run)
                with self.assertRaises(sqlite3.IntegrityError):
                    self.select(run, "OBSERVED_BY_EDGEFINDER", "2030-09-02T12:59:59Z")
                self.select(run, "OBSERVED_BY_EDGEFINDER", "2030-09-02T13:00:00Z")

    def test_each_derived_role_respects_unknown_stats_retrieval(self):
        inputs = synthetic_inputs()
        _, baseline, _ = self.stage(inputs)
        inputs = replace(inputs, stats=replace(inputs.stats, retrieved_at=None))
        sample, unknown, _ = self.stage(inputs)
        for snapshot in (sample.identity, sample.schedule, sample.stats):
            self.assertIsNone(snapshot.retrieved_at)
        for role in baseline:
            with self.subTest(role=role):
                selected = dict(baseline, **{role: unknown[role]})
                run = create_run(self.db, identity=selected["IDENTITY"],
                                 schedule=selected["SCHEDULE"], stats=selected["STATS"])
                self.promote(selected, run)
                seal_run(self.db, run)
                self.select(run)
                with self.assertRaises(sqlite3.IntegrityError):
                    self.select(run, "OBSERVED_BY_EDGEFINDER", "2030-09-03T00:00:00Z")

    def test_later_or_unknown_stats_publication_controls_derived_eligibility(self):
        inputs = synthetic_inputs()
        for name in ("players", "teams", "schedules", "stats"):
            inputs = replace(inputs, **{name: replace(
                getattr(inputs, name), publication_at="2030-09-02T11:00:00Z",
                publication_evidence="Synthetic publication assertion")})
        inputs = replace(inputs, stats=replace(inputs.stats,
                         retrieved_at="2030-09-02T13:00:00Z", publication_at="2030-09-02T12:30:00Z"))
        sample, snapshots, run = self.stage(inputs)
        self.promote(snapshots, run)
        seal_run(self.db, run)
        for snapshot in (sample.identity, sample.schedule, sample.stats):
            self.assertEqual(snapshot.publication_at, "2030-09-02T12:30:00Z")
            self.assertIn("load_player_stats", snapshot.publication_evidence)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, "VERIFIED_PUBLICATION", "2030-09-02T12:29:59Z")
        self.select(run, "VERIFIED_PUBLICATION", "2030-09-02T12:30:00Z")
        inputs = replace(inputs, stats=replace(inputs.stats, publication_at=None, publication_evidence=None))
        sample, snapshots, run = self.stage(inputs)
        self.promote(snapshots, run)
        seal_run(self.db, run)
        for snapshot in (sample.identity, sample.schedule, sample.stats):
            self.assertIsNone(snapshot.publication_at)
            self.assertIsNone(snapshot.publication_evidence)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, "VERIFIED_PUBLICATION", "2030-09-03T00:00:00Z")

    def test_converted_dates_and_mapped_records_preserve_storage_evidence(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "players", [*inputs.players.rows,
                                               {"gsis_id": None, "birth_date": date(1990, 1, 1)}])
        inputs = with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0], gameday=date(2030, 9, 1))])
        stats = []
        for row in inputs.stats.rows:
            row = deepcopy(row)
            row["club"] = row.pop("team")
            row["parsed_at"] = datetime(2030, 9, 2, 10, 1, 2, 123456, tzinfo=timezone.utc)
            stats.append(row)
        inputs = with_rows(inputs, "stats", stats)
        inputs = replace(inputs, stats=replace(inputs.stats, field_mapping={"team": "club"}))
        sample, snapshots, run = self.stage(inputs)
        self.promote(snapshots, run)
        seal_run(self.db, run)
        for prepared in (sample.identity, sample.schedule, sample.stats):
            self.assertEqual([r["payload"] for r in self.records(snapshots[prepared.role])],
                             [canonical(r["payload"]) for r in prepared.rows])
        for row in sample.stats.rows:
            self.assertEqual(row["team_identifier"], row["payload"]["record"]["club"])
            self.assertEqual(row["payload"]["provenance"]["conversions"][0]["python_type"], "datetime")
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])


def run_offline_discovery():
    """Dedicated-process runner; audit hooks intentionally last until exit.

    Uses ordinary discovery without provider/settings mocks. Blocks actual
    provider imports, network events, credential reads and existing databases.
    """
    attempts = []

    def audit(event, args):
        if event.startswith("socket."):
            attempts.append(event)
            raise AssertionError("Network forbidden during offline suite")
        if event == "open" and isinstance(args[0], (str, bytes)):
            name = os.path.basename(os.fsdecode(args[0])).lower()
            if name in (".env", ".netrc", "_netrc", "edgefinder.db") or name.startswith(".env."):
                attempts.append("protected file: " + name)
                raise AssertionError("Protected file access forbidden")
        if event == "sqlite3.connect" and args[0] != ":memory:":
            if os.path.basename(os.fsdecode(args[0])) != "sample.db":
                attempts.append("unexpected database")
                raise AssertionError("Only synthetic memory/temp sample databases allowed")

    sys.addaudithook(audit)
    blocked = {"nflreadpy", "polars", "requests", "pydantic_settings", "dotenv"}

    class RejectProvider:
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in blocked:
                attempts.append("provider import")
                raise AssertionError("Provider configuration import forbidden")

    sys.meta_path.insert(0, RejectProvider())
    suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    imports = sorted(blocked.intersection(sys.modules))
    print(f"PROVIDER_MODULES_LOADED={imports}")
    print(f"NETWORK_OR_PROTECTED_FILE_ATTEMPTS={attempts}")
    return int(not result.wasSuccessful() or bool(imports) or bool(attempts))


if __name__ == "__main__":
    if sys.argv[1:] == ["--offline-discovery"]:
        raise SystemExit(run_offline_discovery())
    unittest.main()
