"""Synthetic-only adapter tests; no nflreadpy import or acquisition calls.

There is deliberately no live integration test or environment-variable shortcut.
Any future live test requires separate approval and a separate explicit opt-in;
ordinary unittest discovery must retain these synthetic-only fixtures.
"""

import ast
from copy import deepcopy
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone, time
import inspect
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from edgefinder import nflverse_adapter as adapter
from edgefinder.storage.database import canonical, evidence_hash


NS = adapter.Namespaces(player=1, team=2, game=3)
GAME = "2030_01_BBB_AAA"
HOME = "00-0000001"
AWAY = "00-0000002"


def synthetic_inputs():
    """Invented records and timestamps, never read from NFL data or disk."""
    def source(rows, scope):
        return adapter.SourceInput(
            rows, "synthetic:" + scope, retrieved_at="2030-09-02T12:00:00Z")

    return adapter.NFLInputs(
        season=2030,
        players=source([
            {"gsis_id": HOME, "display_name": "Same Name", "birth_date": None},
            {"gsis_id": AWAY, "display_name": "Same Name", "birth_date": None},
            {"gsis_id": "00-0000003", "display_name": None},
        ], "players-global"),
        teams=source([{"team_abbr": "AAA", "label": "Synthetic Home"},
                      {"team_abbr": "BBB", "label": "Synthetic Away"}], "teams-global"),
        schedules=source([
            {"game_id": GAME, "season": 2030, "week": 1, "game_type": "REG",
             "home_team": "AAA", "away_team": "BBB", "gameday": "2030-09-01",
             "gametime": "13:00", "home_score": None},
        ], "schedules-season-2030"),
        stats=source([
            {"player_id": HOME, "season": 2030, "week": 1, "season_type": "REG",
             "team": "AAA", "opponent_team": "BBB", "targets": 3,
             "receptions": 2, "receiving_yards": 12.5, "receiving_tds": None,
             "extra": {"flag": True, "values": [None, 0, 0.0, "0", False]}},
            {"player_id": AWAY, "season": 2030, "week": 1, "season_type": "REG",
             "team": "BBB", "opponent_team": "AAA", "targets": 1.0,
             "receptions": None, "receiving_yards": -2, "receiving_tds": 0},
            {"player_id": "00-0000003", "season": 2030, "week": 1,
             "season_type": "REG", "team": "AAA", "opponent_team": "BBB",
             "targets": 8, "receptions": 4, "receiving_yards": 25,
             "receiving_tds": 0},
        ], "player-stats-season-2030-summary-week"))


def with_rows(inputs, name, rows):
    return replace(inputs, **{name: replace(getattr(inputs, name), rows=rows)})


class AdapterTests(unittest.TestCase):
    def prepare(self, inputs=None, **kwargs):
        return adapter.prepare_game_sample(
            synthetic_inputs() if inputs is None else inputs, namespaces=NS, **kwargs)

    def test_default_selection_uses_ids_not_names_or_stat_totals(self):
        sample = self.prepare()
        self.assertEqual(sample.game_id, GAME)
        self.assertEqual(sample.player_ids, {"AAA": HOME, "BBB": AWAY})
        self.assertEqual(len(sample.identity.rows), 5)
        self.assertEqual(len(sample.schedule.rows), 1)
        self.assertEqual(len(sample.stats.rows), 2)

    def test_explicit_player_selection(self):
        selected = {"AAA": "00-0000003", "BBB": AWAY}
        self.assertEqual(self.prepare(game_id=GAME, player_ids=selected).player_ids, selected)
        for requested in ({"AAA": AWAY, "BBB": HOME}, {"AAA": HOME},
                          {"AAA": "Same Name", "BBB": AWAY}):
            with self.subTest(requested=requested), self.assertRaises(ValueError):
                self.prepare(player_ids=requested)

    def test_deterministic_across_source_order_and_games(self):
        inputs = synthetic_inputs()
        second = dict(inputs.schedules.rows[0], game_id="2030_02_BBB_AAA", week=2)
        inputs = with_rows(inputs, "schedules", [second, *inputs.schedules.rows])
        inputs = with_rows(inputs, "stats", [dict(r, week=2) for r in inputs.stats.rows]
                           + inputs.stats.rows)
        sample = self.prepare(inputs)
        reversed_inputs = inputs
        for name in ("players", "teams", "schedules", "stats"):
            reversed_inputs = with_rows(reversed_inputs, name,
                                       list(reversed(getattr(inputs, name).rows)))
        self.assertEqual(sample, self.prepare(reversed_inputs))
        self.assertEqual(sample.game_id, GAME)
        self.assertEqual(self.prepare(inputs, game_id=second["game_id"]).game_id,
                         second["game_id"])
        with self.assertRaises(ValueError):
            self.prepare(inputs, game_id="2030_01_AAA_BBB")

    def test_raw_values_types_nulls_and_duplicates_are_preserved(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "stats", [*inputs.stats.rows, deepcopy(inputs.stats.rows[0])])
        before = deepcopy(inputs)
        sample = self.prepare(inputs)
        rows = [r for r in sample.stats.rows if r["identifier"] == HOME]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], rows[1])
        self.assertEqual(canonical(rows[0]["payload"]["record"]), canonical(inputs.stats.rows[0]))
        self.assertIs(type(rows[0]["payload"]["record"]["targets"]), int)
        self.assertIs(type(rows[0]["payload"]["record"]["receiving_yards"]), float)
        self.assertIsNone(rows[0]["payload"]["record"]["receiving_tds"])
        away = next(r for r in sample.stats.rows if r["identifier"] == AWAY)
        self.assertIs(type(away["payload"]["record"]["targets"]), float)
        self.assertEqual(inputs, before)
        rows[0]["payload"]["record"]["extra"]["values"].append("changed")
        self.assertEqual(inputs, before)

    def test_parsed_hash_includes_unselected_rows_and_duplicate_occurrences(self):
        inputs = synthetic_inputs()
        sample = self.prepare(inputs)
        provenance = sample.stats.rows[0]["payload"]["provenance"]
        self.assertEqual(provenance["source_parsed_sha256"],
                         evidence_hash([canonical(dict(record=r, conversions=[]))
                                        for r in inputs.stats.rows]))
        self.assertEqual(provenance["hash_kind"], "parsed_rows_not_original_file")
        changed = deepcopy(inputs.stats.rows)
        changed[-1]["targets"] = 9
        other = self.prepare(with_rows(inputs, "stats", changed))
        self.assertNotEqual(provenance["source_parsed_sha256"],
                            other.stats.rows[0]["payload"]["provenance"]["source_parsed_sha256"])
        duplicate = self.prepare(with_rows(inputs, "stats", [*inputs.stats.rows, inputs.stats.rows[0]]))
        self.assertNotEqual(provenance["source_parsed_sha256"],
                            duplicate.stats.rows[0]["payload"]["provenance"]["source_parsed_sha256"])

    def test_duplicate_identity_or_schedule_is_an_error(self):
        inputs = synthetic_inputs()
        for name in ("players", "teams", "schedules"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Ambiguous"):
                self.prepare(with_rows(inputs, name,
                                       [*getattr(inputs, name).rows, getattr(inputs, name).rows[0]]))

    def test_invalid_identity_and_context_fields_fail_closed(self):
        inputs = synthetic_inputs()
        cases = [
            ("players", "gsis_id", None), ("players", "gsis_id", "Same Name"),
            ("teams", "team_abbr", "aaa"), ("teams", "team_abbr", " AAA"),
            ("schedules", "season", True), ("schedules", "week", "1"),
            ("schedules", "game_id", "2030_01_AAA_BBB"),
            ("schedules", "game_type", "POST"), ("schedules", "home_team", "BBB"),
            ("schedules", "gameday", "2030-02-30"), ("schedules", "gametime", "25:00"),
            ("stats", "player_id", "00-9999999"), ("stats", "team", "CCC"),
            ("stats", "opponent_team", "CCC"), ("stats", "week", 2),
            ("stats", "season_type", "POST"), ("stats", "game_id", "wrong"),
            ("stats", "game_id", None), ("stats", "targets", "3"),
            ("stats", "targets", True), ("stats", "targets", -1),
            ("stats", "receptions", 0.5),
            ("stats", "receiving_yards", float("inf")),
            ("stats", "extra", {"unsupported": object()}),
        ]
        for name, field, value in cases:
            rows = deepcopy(getattr(inputs, name).rows)
            rows[0][field] = value
            with self.subTest(name=name, field=field, value=value):
                with self.assertRaises((ValueError, TypeError)):
                    self.prepare(with_rows(inputs, name, rows))
        for name, field in (("players", "gsis_id"), ("stats", "opponent_team"),
                            ("stats", "targets"), ("schedules", "game_id")):
            rows = deepcopy(getattr(inputs, name).rows)
            del rows[0][field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, "Missing|no player identity"):
                self.prepare(with_rows(inputs, name, rows))

    def test_no_activity_is_not_inferred_from_nulls(self):
        inputs = synthetic_inputs()
        for inactive in (None, 0):
            rows = deepcopy(inputs.stats.rows)
            for field in ("targets", "receptions", "receiving_yards", "receiving_tds"):
                rows[1][field] = inactive
            with self.subTest(inactive=inactive), self.assertRaisesRegex(ValueError, "No game"):
                self.prepare(with_rows(inputs, "stats", rows))

    def test_one_gsis_identity_cannot_represent_both_teams_in_one_game(self):
        inputs = synthetic_inputs()
        rows = deepcopy(inputs.stats.rows)
        rows[1]["player_id"] = HOME
        with self.assertRaisesRegex(ValueError, "Ambiguous player identity"):
            self.prepare(with_rows(inputs, "stats", rows))

    def test_postseason_and_explicit_stats_game_id(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0], game_type="WC")])
        inputs = with_rows(inputs, "stats", [dict(r, season_type="POST", game_id=GAME)
                                             for r in inputs.stats.rows])
        self.assertEqual(self.prepare(inputs).game_id, GAME)

    def test_unknown_kickoff_and_temporal_claims_stay_unknown(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0], gametime=None)])
        inputs = replace(inputs, players=replace(inputs.players, retrieved_at=None))
        sample = self.prepare(inputs)
        self.assertIsNone(sample.schedule.rows[0]["kickoff_local"])
        self.assertNotIn("kickoff_utc", sample.schedule.rows[0])
        self.assertNotIn("kickoff_timezone", sample.schedule.rows[0])
        self.assertIsNone(sample.identity.retrieved_at)
        self.assertIsNone(sample.identity.publication_at)
        self.assertIsNone(sample.identity.publication_evidence)
        self.assertIsNone(sample.stats.retrieved_at)
        self.assertIsNone(sample.schedule.retrieved_at)

    def test_conservative_per_dependency_provenance(self):
        inputs = synthetic_inputs()
        for i, name in enumerate(("players", "teams", "schedules", "stats"), start=1):
            inputs = replace(inputs, **{name: replace(
                getattr(inputs, name), retrieved_at=f"2030-09-02T12:00:0{i}Z",
                publication_at=f"2030-09-02T11:00:0{i}Z",
                publication_evidence="Synthetic assertion only: " + name)})
        sample = self.prepare(inputs)
        self.assertEqual(sample.identity.retrieved_at, "2030-09-02T12:00:04Z")
        self.assertEqual(sample.identity.publication_at, "2030-09-02T11:00:04Z")
        self.assertEqual(sample.schedule.retrieved_at, "2030-09-02T12:00:04Z")
        self.assertEqual(sample.schedule.publication_at, "2030-09-02T11:00:04Z")
        self.assertEqual(sample.stats.publication_at, "2030-09-02T11:00:04Z")
        self.assertIn("Synthetic assertion only", sample.identity.publication_evidence)
        self.assertEqual(sample.stats.rows[0]["payload"]["provenance"]["loader"],
                         "load_player_stats")

    def test_unknown_stats_times_cannot_be_replaced_by_earlier_dependencies(self):
        inputs = synthetic_inputs()
        for name in ("players", "teams", "schedules"):
            inputs = replace(inputs, **{name: replace(
                getattr(inputs, name), publication_at="2030-09-01T12:00:00Z",
                publication_evidence="Invented reference publication")})
        inputs = replace(inputs, stats=replace(inputs.stats, retrieved_at=None))
        sample = self.prepare(inputs)
        for snapshot in (sample.identity, sample.schedule, sample.stats):
            self.assertIsNone(snapshot.retrieved_at)
            self.assertIsNone(snapshot.publication_at)
            self.assertIsNone(snapshot.publication_evidence)
            deps = snapshot.rows[0]["payload"]["selection_dependencies"]
            self.assertEqual({p["loader"] for p in deps},
                             {"load_players", "load_teams", "load_schedules", "load_player_stats"})
            self.assertEqual(next(p for p in deps if p["loader"] == "load_player_stats")
                             ["source_parsed_sha256"],
                             sample.stats.rows[0]["payload"]["provenance"]["source_parsed_sha256"])

    def test_nullable_unrelated_reference_rows_do_not_create_or_guess_aliases(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "players", [
            *inputs.players.rows,
            {"gsis_id": None, "display_name": "Same Name", "birth_date": date(1990, 1, 1)},
            {"display_name": "Same Name"},
        ])
        sample = self.prepare(inputs)
        self.assertEqual(sample.player_ids, {"AAA": HOME, "BBB": AWAY})
        self.assertNotEqual(sample.identity.rows[0]["payload"]["provenance"]["source_parsed_sha256"],
                            self.prepare().identity.rows[0]["payload"]["provenance"]["source_parsed_sha256"])
        for missing in (None, "absent"):
            rows = deepcopy(inputs.players.rows)
            if missing is None:
                rows[0]["gsis_id"] = None
            else:
                del rows[0]["gsis_id"]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "no player identity"):
                self.prepare(with_rows(inputs, "players", rows))

    def test_only_selected_nonnull_player_aliases_must_be_unique(self):
        inputs = synthetic_inputs()
        inputs = with_rows(inputs, "players", [*inputs.players.rows, inputs.players.rows[2]])
        self.assertEqual(self.prepare(inputs).player_ids["AAA"], HOME)
        with self.assertRaisesRegex(ValueError, "duplicate selected gsis_id"):
            self.prepare(inputs, player_ids={"AAA": "00-0000003", "BBB": AWAY})

    def test_temporal_record_conversion_preserves_type_offset_fold_and_hash_meaning(self):
        inputs = synthetic_inputs()
        day = date(2030, 9, 1)
        naive = datetime(2030, 9, 1, 13, 30, 1, 123456, fold=1)
        aware = datetime(2030, 9, 1, 13, 30, tzinfo=timezone(timedelta(hours=-4), "Synthetic Offset"))
        rows = deepcopy(inputs.stats.rows)
        rows[0]["timestamps"] = [naive, aware, datetime(2030, 9, 1, tzinfo=timezone.utc)]
        inputs = with_rows(inputs, "stats", rows)
        inputs = with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0], gameday=day)])
        before = deepcopy(inputs)
        sample = self.prepare(inputs)
        self.assertEqual(sample.schedule.rows[0]["kickoff_local"], "2030-09-01 13:00")
        home = next(r for r in sample.stats.rows if r["identifier"] == HOME)
        self.assertEqual(home["payload"]["record"]["timestamps"],
                         [x.isoformat(timespec="microseconds") for x in rows[0]["timestamps"]])
        notes = home["payload"]["provenance"]["conversions"]
        self.assertEqual(notes[0]["path"], ["timestamps", 0])
        self.assertEqual(notes[0]["fold"], 1)
        self.assertEqual(notes[0]["timezone"], {"kind": "naive"})
        self.assertEqual(notes[1]["timezone"], {"kind": "fixed_offset", "name": "Synthetic Offset"})
        self.assertEqual(sample.schedule.rows[0]["payload"]["provenance"]["conversions"],
                         [dict(path=["gameday"], python_type="date", iso8601=day.isoformat())])
        self.assertEqual(inputs, before)
        as_strings = deepcopy(rows)
        as_strings[0]["timestamps"] = home["payload"]["record"]["timestamps"]
        other = self.prepare(with_rows(inputs, "stats", as_strings))
        self.assertNotEqual(home["payload"]["provenance"]["source_parsed_sha256"],
                            other.stats.rows[0]["payload"]["provenance"]["source_parsed_sha256"])

    def test_explicit_field_and_phase_mappings_support_synthetic_preseason_week_zero(self):
        inputs = synthetic_inputs()
        game = "2030_00_BBB_AAA"
        schedule = dict(inputs.schedules.rows[0], game_id=game, week=0)
        schedule["phase_label"] = "EXHIBITION"
        schedule["calendar_date"] = date(2030, 8, 1)
        del schedule["game_type"], schedule["gameday"]
        stats = []
        for row in inputs.stats.rows:
            row = dict(row, week=0)
            row["club"] = row.pop("team")
            row["phase_label"] = "PRESEASON"
            del row["season_type"]
            stats.append(row)
        inputs = with_rows(with_rows(inputs, "schedules", [schedule]), "stats", stats)
        inputs = replace(inputs,
                         schedules=replace(inputs.schedules,
                                           field_mapping={"game_type": "phase_label", "gameday": "calendar_date"},
                                           value_mappings={"game_type": {"EXHIBITION": "PRE"}}),
                         stats=replace(inputs.stats,
                                       field_mapping={"team": "club", "season_type": "phase_label"},
                                       value_mappings={"season_type": {"PRESEASON": "PRE"}}))
        sample = self.prepare(inputs)
        self.assertEqual(sample.game_id, game)
        raw = sample.stats.rows[0]["payload"]["record"]
        self.assertIn("club", raw)
        self.assertNotIn("team", raw)
        self.assertEqual(raw["phase_label"], "PRESEASON")
        self.assertEqual(sample.stats.rows[0]["payload"]["provenance"]["field_mapping"]["team"], "club")
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.prepare(replace(inputs, stats=replace(inputs.stats, field_mapping=None, value_mappings=None)))

    def test_synthetic_postseason_weeks_and_week_zero_restrictions(self):
        inputs = synthetic_inputs()
        for phase, week in (("WC", 19), ("DIV", 20), ("CON", 21), ("SB", 22)):
            game = f"2030_{week:02d}_BBB_AAA"
            other = with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0],
                                                       game_type=phase, week=week, game_id=game)])
            other = with_rows(other, "stats", [dict(r, week=week, season_type="POST")
                                               for r in inputs.stats.rows])
            with self.subTest(phase=phase):
                self.assertEqual(self.prepare(other).game_id, game)
        with self.assertRaisesRegex(ValueError, "Week 0 requires"):
            self.prepare(with_rows(inputs, "schedules", [dict(inputs.schedules.rows[0], week=0)]))

    def test_unsupported_conversions_and_unsafe_mappings_fail_explicitly(self):
        inputs = synthetic_inputs()
        for value in (time(13, 0), {"opaque": object()}):
            rows = deepcopy(inputs.stats.rows)
            rows[0]["extra"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Unsupported source value"):
                self.prepare(with_rows(inputs, "stats", rows))
        for changes in ({"value_mappings": {"player_id": {"name": HOME}}},
                        {"field_mapping": {"team": "opponent_team"}},
                        {"field_mapping": {"imaginary": "column"}},
                        {"value_mappings": {"season_type": {"REG": "UNKNOWN"}}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.prepare(replace(inputs, stats=replace(inputs.stats, **changes)))
        schedule = dict(inputs.schedules.rows[0], gameday=datetime(2030, 9, 1, 13))
        with self.assertRaisesRegex(ValueError, "gameday"):
            self.prepare(with_rows(inputs, "schedules", [schedule]))

    def test_invalid_metadata_season_and_namespaces(self):
        inputs = synthetic_inputs()
        for changes in ({"retrieved_at": "now"}, {"publication_at": "2030-09-01T00:00:00Z"},
                        {"publication_evidence": "unsupported"},
                        {"publication_at": "2030-09-03T00:00:00Z", "publication_evidence": "late"},
                        {"loader_scope": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.prepare(replace(inputs, stats=replace(inputs.stats, **changes)))
        for season in (True, "2030", None):
            with self.subTest(season=season), self.assertRaises(ValueError):
                self.prepare(replace(inputs, season=season))
        for ns in (adapter.Namespaces(1, 1, 3), adapter.Namespaces(True, 2, 3)):
            with self.subTest(ns=ns), self.assertRaises(ValueError):
                adapter.prepare_game_sample(inputs, namespaces=ns)

    def test_prepare_has_no_file_database_or_network_io(self):
        inputs = synthetic_inputs()
        with patch("builtins.open", side_effect=AssertionError("file access")), \
                patch.object(sqlite3, "connect", side_effect=AssertionError("database access")), \
                patch.object(socket, "socket", side_effect=AssertionError("socket access")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS access")):
            sample = self.prepare(inputs)
        self.assertEqual(sample.game_id, GAME)

    def test_import_in_fresh_process_cannot_import_nflreadpy_or_acquire(self):
        script = '''
import sys
class RejectProvider:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] == 'nflreadpy':
            raise AssertionError('nflreadpy import forbidden')
sys.meta_path.insert(0, RejectProvider())
def guard(event, args):
    if event.startswith('socket.'):
        raise AssertionError('network forbidden')
    if event == 'open' and isinstance(args[0], str):
        name = args[0].replace('\\\\', '/').rsplit('/', 1)[-1].lower()
        if name == '.env' or name.startswith('.env.') or name == 'edgefinder.db':
            raise AssertionError('protected file forbidden')
sys.addaudithook(guard)
import edgefinder.nflverse_adapter
assert 'nflreadpy' not in sys.modules
'''
        result = subprocess.run([sys.executable, "-B", "-c", script],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_acquisition_boundary_is_disabled_without_invoking_it(self):
        tree = ast.parse(inspect.getsource(adapter.fetch_nflverse_inputs))
        statements = tree.body[0].body
        self.assertEqual(len(statements), 2)  # Documentation, then fail closed.
        self.assertIsInstance(statements[-1], ast.Raise)
        self.assertFalse(any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree)))


if __name__ == "__main__":
    unittest.main()
