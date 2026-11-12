"""Self-contained C2a synthetic tests; fixtures never leave a private temp tree.

Run: .venv/Scripts/python.exe -I -S -B inspection/c2a/test_runner.py
An audit hook rejects network, provider imports, SQLite, and filesystem writes
outside the test-owned temporary tree. No subprocesses or real datasets needed.
"""

import ast
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import csv
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings


HERE = Path(__file__).absolute().parent
REPOSITORY = HERE.parent.parent
spec = importlib.util.spec_from_file_location("c2a_runner", HERE / "runner.py")
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)
TEST_ROOT = None
AUDIT_ENABLED = False
AUDIT_COUNTS = dict(network_attempts=0, provider_import_attempts=0, sqlite_attempts=0, forbidden_writes=0)
FORBIDDEN_IMPORTS = {"socket", "http", "urllib", "requests", "nflreadpy", "sqlite3", "polars", "pandas"}


def _inside_test_root(path):
    try:
        return TEST_ROOT is not None and Path(os.fsdecode(path)).resolve().is_relative_to(TEST_ROOT.resolve())
    except (TypeError, ValueError, OSError):
        return False


def _audit(event, args):
    if not AUDIT_ENABLED:
        return
    if event.startswith("socket."):
        AUDIT_COUNTS["network_attempts"] += 1
        raise PermissionError("C2a tests forbid network")
    if event == "import" and args[0].split(".")[0] in FORBIDDEN_IMPORTS:
        AUDIT_COUNTS["provider_import_attempts"] += 1
        raise PermissionError("C2a tests forbid retrieval/provider/database imports")
    if event.startswith("sqlite3."):
        AUDIT_COUNTS["sqlite_attempts"] += 1
        raise PermissionError("C2a tests forbid SQLite")
    targets = ()
    if event == "open":
        path, mode, flags = args
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            targets = (path,)
    elif event in ("os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.truncate", "os.utime"):
        targets = (args[0],)
    elif event in ("os.rename", "os.link"):
        targets = args[:2]
    elif event == "os.symlink":
        targets = (args[1],)
    if any(not _inside_test_root(path) for path in targets):
        AUDIT_COUNTS["forbidden_writes"] += 1
        raise PermissionError("C2a tests forbid writes outside their private temp tree")


P1, P2, P3 = "00-0000001", "00-0000002", "00-0000003"
AS_OF = "2026-11-11T12:00:00Z"


def schedule(year=2026, week=7, home="HOM", away="AWY", **extra):
    row = dict(game_id=f"{year}_{week:02d}_{away}_{home}", season=str(year), week=str(week), game_type="REG",
               home_team=home, away_team=away, gameday="2026-10-20" if year == 2026 else "2025-10-20",
               gametime="20:00", home_score="20", away_score="0")
    row.update(extra)
    return row


def stats(year=2026, week=7, pid=P1, team="HOM", opponent="AWY", **extra):
    row = dict(player_id=pid, season=str(year), week=str(week), season_type="REG", team=team,
               opponent_team=opponent, targets="0", receptions="0", receiving_yards="0")
    row.update(extra)
    return row


def roster(year=2026, week=7, pid=P1, team="HOM", **extra):
    row = dict(gsis_id=pid, season=str(year), week=str(week), game_type="REG", team=team, position="WR", status="ACT")
    row.update(extra)
    return row


def tables():
    result = {}
    contents = dict(schedules=[schedule(2025, 1), schedule()], stats_2025=[stats(2025, 1)], stats_2026=[stats()],
                    rosters_2025=[roster(2025, 1)], rosters_2026=[roster()], players=[dict(gsis_id=P1), dict(gsis_id=P2), dict(gsis_id=P3)])
    for aid, rows in contents.items():
        result[aid] = runner.Table(aid, tuple(rows[0]), tuple(rows))
    return result


def replace_rows(data, aid, rows, columns=None):
    data[aid] = runner.Table(aid, tuple(columns or (tuple(rows[0]) if rows else data[aid].columns)), tuple(rows), data[aid].evidence)


def report(data=None, **kwargs):
    return runner.inspect_rows(data or tables(), as_of=kwargs.pop("as_of", AS_OF), **kwargs)


def candidates(result):
    return result["interpretations"]["wr_candidates"]


def codes(result):
    return [f["code"] for f in result["findings"]]


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=TEST_ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assertFalse(self.root.is_relative_to(REPOSITORY))

    def artifact(self, aid="stats_2026", *, rows=None, text=None, body=None, header=None):
        spec = runner.SPECS[aid]
        if body is None:
            if text is None:
                rows = [stats()] if rows is None else rows
                stream = io.StringIO(newline="")
                writer = csv.DictWriter(stream, fieldnames=header or list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
                text = stream.getvalue()
            body = gzip.compress(text.encode("utf-8"), mtime=0)
        (self.root / spec["filename"]).write_bytes(body)
        return dict(artifact_id=aid, release=spec["release"], filename=spec["filename"], byte_length=len(body), sha256=hashlib.sha256(body).hexdigest())

    def budget(self, **limits):
        result = dict(runner.LIMITS)
        result.update(limits)
        return runner.Budget(result)

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(runner.InspectionError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def manifest(self):
        entries = []
        for aid, table in tables().items():
            entries.append(self.artifact(aid, rows=list(table.rows)))
        path = self.root / "manifest.json"
        path.write_text(json.dumps(dict(artifacts=entries)), encoding="utf-8")
        return path


class ArtifactTests(Fixtures):
    def test_valid_gzip_csv_and_original_hash(self):
        entry = self.artifact()
        budget = self.budget()
        table = runner.validate_artifact(self.root, entry, budget=budget)
        self.assertEqual(table.rows, (stats(),))
        self.assertEqual(table.evidence["original_compressed_sha256"], entry["sha256"])
        self.assertTrue(table.evidence["expected_digest_match"])
        self.assertEqual(budget.counts["compressed_total"], entry["byte_length"])
        self.assertGreater(budget.counts["decompressed_total"], 0)
        self.assertEqual(budget.counts["rows_total"], 1)

    def test_absent_expected_hash_and_times_remain_unknown(self):
        entry = self.artifact()
        del entry["sha256"]
        evidence = runner.validate_artifact(self.root, entry).evidence
        self.assertIsNone(evidence["expected_digest_match"])
        self.assertIsNone(evidence["edgefinder_acquired_at"])
        self.assertIsNone(evidence["provider_publication_at"])
        self.assertFalse(evidence["origin_authenticated"])

    def test_invalid_gzip(self):
        self.assert_code("invalid_gzip_or_input", runner.validate_artifact, self.root, self.artifact(body=b"not gzip"))

    def test_truncated_gzip(self):
        good = gzip.compress(b"x,y\n1,2\n")
        entry = self.artifact(body=good[:-6])
        self.assert_code("missing_required_columns", runner.validate_artifact, self.root, entry)
        good_entry = self.artifact()
        payload = (self.root / good_entry["filename"]).read_bytes()[:-6]
        self.assert_code("invalid_gzip_or_input", runner.validate_artifact, self.root, self.artifact(body=payload))

    def test_crc_failure(self):
        entry = self.artifact()
        body = bytearray((self.root / entry["filename"]).read_bytes())
        body[-8] ^= 1
        self.assert_code("invalid_gzip_or_input", runner.validate_artifact, self.root, self.artifact(body=bytes(body)))

    def test_compressed_cap(self):
        entry = self.artifact()
        error = self.assert_code("limit_exceeded", runner.validate_artifact, self.root, entry, budget=self.budget(compressed_stats=entry["byte_length"]-1))
        self.assertEqual(error.details["limit"], "compressed_file")

    def test_declared_size_mismatch(self):
        entry = self.artifact()
        entry["byte_length"] += 1
        self.assert_code("compressed_length_mismatch", runner.validate_artifact, self.root, entry)

    def test_decompressed_expansion_cap(self):
        entry = self.artifact(rows=[stats(player_name="a" * 2000)])
        budget = self.budget(decompressed_file=1024)
        error = self.assert_code("limit_exceeded", runner.validate_artifact, self.root, entry, budget=budget)
        self.assertEqual(error.details["limit"], "decompressed_file")
        self.assertLessEqual(budget.counts["decompressed_total"], 1025)

    def test_aggregate_compressed_budget(self):
        first = self.artifact("stats_2025", rows=[stats(2025)])
        second = self.artifact()
        budget = self.budget(compressed_total=first["byte_length"]+second["byte_length"]-1)
        runner.validate_artifact(self.root, first, budget=budget)
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, second, budget=budget)

    def test_aggregate_decompressed_budget(self):
        first = self.artifact("stats_2025", rows=[stats(2025)])
        second = self.artifact()
        first_table = runner.validate_artifact(self.root, first)
        budget = self.budget(decompressed_total=first_table.evidence["decompressed_bytes"] + 5)
        runner.validate_artifact(self.root, first, budget=budget)
        error = self.assert_code("limit_exceeded", runner.validate_artifact, self.root, second, budget=budget)
        self.assertEqual(error.details["limit"], "decompressed_total")

    def test_aggregate_rows(self):
        first = self.artifact("stats_2025", rows=[stats(2025)])
        second = self.artifact()
        budget = self.budget(rows_total=1)
        runner.validate_artifact(self.root, first, budget=budget)
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, second, budget=budget)

    def test_retained_content_cap(self):
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, self.artifact(), budget=self.budget(retained_bytes=10))

    def test_sha256_mismatch(self):
        entry = self.artifact()
        entry["sha256"] = "0" * 64  # Synthetic mismatch, never written into the plan.
        self.assert_code("sha256_mismatch", runner.validate_artifact, self.root, entry)

    def test_unexpected_artifact_identity(self):
        entry = self.artifact()
        entry["release"] = "other"
        self.assert_code("unexpected_artifact_identity", runner.validate_artifact, self.root, entry)

    def test_invalid_utf8(self):
        valid = gzip.decompress((self.root / self.artifact()["filename"]).read_bytes())
        self.assert_code("invalid_utf8", runner.validate_artifact, self.root, self.artifact(body=gzip.compress(valid + b"\xff\n")))

    def test_duplicate_headers(self):
        self.assert_code("duplicate_headers", runner.validate_artifact, self.root, self.artifact(text="player_id,player_id\na,b\n"))

    def test_empty_header(self):
        self.assert_code("empty_header", runner.validate_artifact, self.root, self.artifact(text=",x\na,b\n"))

    def test_missing_required_columns(self):
        self.assert_code("missing_required_columns", runner.validate_artifact, self.root, self.artifact(text="player_id\n00-0000001\n"))

    def test_empty_required_cells_are_findings_not_invented_values(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(player_id="", receiving_yards="")])
        result = report(data)
        self.assertIn("missing_required_value", codes(result))
        self.assertEqual(result["raw_observations"]["stats_2026"]["missing_required_values"]["player_id"], 1)

    def test_field_limit(self):
        self.assert_code("invalid_csv", runner.validate_artifact, self.root, self.artifact(rows=[stats(extra="a" * 16385)]))

    def test_field_limit_counts_utf8_bytes(self):
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, self.artifact(rows=[stats(extra="é" * 9000)]))

    def test_logical_record_limit_including_multiline_quotes(self):
        row = stats(extra="one\ntwo\nthree")
        entry = self.artifact(rows=[row])
        header_size = len((",".join(row) + "\r\n").encode())
        budget = self.budget(record_bytes=max(header_size, 125))
        # Long fields spanning physical lines must share one logical budget.
        entry = self.artifact(rows=[stats(extra=("a" * 50 + "\n") * 3)])
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, entry, budget=budget)

    def test_column_limit(self):
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, self.artifact(rows=[stats()]), budget=self.budget(columns=3))

    def test_malformed_quoted_csv(self):
        header = ",".join(stats())
        self.assert_code("invalid_csv", runner.validate_artifact, self.root, self.artifact(text=header + '\n"unterminated\n'))

    def test_row_width(self):
        self.assert_code("csv_width_mismatch", runner.validate_artifact, self.root, self.artifact(text=",".join(stats()) + "\nx,y\n"))

    def test_row_count_cap(self):
        self.assert_code("limit_exceeded", runner.validate_artifact, self.root, self.artifact(rows=[stats(), stats()]), budget=self.budget(rows_stats=1))

    def test_multiline_unicode_bom_and_crlf(self):
        row = stats(extra="é\nquoted, cell")
        entry = self.artifact(rows=[row])
        raw = gzip.decompress((self.root / entry["filename"]).read_bytes())
        table = runner.validate_artifact(self.root, self.artifact(body=gzip.compress(b"\xef\xbb\xbf" + raw)))
        self.assertEqual(table.rows[0]["extra"], row["extra"])

    def test_duplicate_records_are_preserved(self):
        table = runner.validate_artifact(self.root, self.artifact(rows=[stats(), stats()]))
        self.assertEqual(len(table.rows), 2)

    def test_budget_cannot_exceed_approved_limits(self):
        self.assert_code("invalid_limits", self.budget, retained_bytes=runner.LIMITS["retained_bytes"]+1)

    def test_publication_requires_evidence(self):
        entry = self.artifact()
        entry["provider_publication_at"] = AS_OF
        self.assert_code("publication_evidence_required", runner.validate_artifact, self.root, entry)

    def test_publication_after_acquisition_rejected(self):
        entry = self.artifact()
        entry.update(provider_publication_at=AS_OF, provider_publication_evidence="synthetic assertion", edgefinder_acquired_at="2026-11-10T00:00:00Z")
        self.assert_code("publication_after_acquisition", runner.validate_artifact, self.root, entry)


class InterpretationTests(unittest.TestCase):
    def test_window_filtering_and_roster_population(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(week=w) for w in (6, 7, 9, 10)])
        replace_rows(data, "rosters_2025", [roster(2025, 1), roster(2025, 18), roster(2025, 19)])
        self.assertEqual([(c["season"], c["week"]) for c in candidates(report(data))], [(2025, 1), (2025, 18), (2026, 7), (2026, 9)])

    def test_schema_difference_is_explicit(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(new_field="new")])
        comparison = report(data)["schema_compatibility"]["stats"]
        self.assertEqual(comparison["only_2026"], ["new_field"])
        self.assertFalse(comparison["physical_types_verified"])

    def test_parse_failures_make_csv_compatibility_unresolved(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(targets="oops")])
        result = report(data)
        self.assertEqual(result["schema_compatibility"]["stats"]["status"], "unresolved")
        self.assertEqual(result["raw_observations"]["stats_2026"]["parse_failures"], {"targets": 1})

    def test_empty_season_cannot_claim_schema_compatibility(self):
        data = tables()
        replace_rows(data, "stats_2026", [])
        self.assertEqual(report(data)["schema_compatibility"]["stats"]["status"], "insufficient_rows")

    def test_regular_and_postseason_are_separate(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(), schedule(week=7, game_type="WC", game_id="post-game")])
        replace_rows(data, "stats_2026", [stats(), stats(season_type="POST")])
        joins = report(data)["interpretations"]["statistics_joins"]
        self.assertEqual([j["resolved_game_id"] for j in joins if j["artifact"] == "stats_2026"], [schedule()["game_id"], "post-game"])

    def test_postseason_rosters_not_regular_population(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(game_type="POST")])
        self.assertFalse([c for c in candidates(report(data)) if c["season"] == 2026])

    def test_schedule_orientation_and_missing_stat_game_id(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster(pid=P2, team="AWY")])
        replace_rows(data, "stats_2026", [stats(), stats(pid=P2, team="AWY", opponent="HOM")])
        current = [c for c in candidates(report(data)) if c["season"] == 2026]
        self.assertEqual([c["game_id"] for c in current], [schedule()["game_id"]]*2)
        self.assertTrue(all(c["statistics_match_count"] == 1 for c in current))

    def test_disagreeing_explicit_game_id(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(game_id="wrong")])
        result = report(data)
        self.assertIn("stats_game_id_disagreement", codes(result))
        self.assertIsNone(result["interpretations"]["statistics_joins"][-1]["resolved_game_id"])

    def test_missing_and_multiple_stat_game_joins(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(opponent="BAD"), stats()])
        replace_rows(data, "schedules", [schedule(), schedule(game_id="second")])
        result = report(data)
        self.assertIn("stats_game_join_zero", codes(result))
        self.assertIn("stats_game_join_multiple", codes(result))

    def test_identifiers_preserved_and_no_name_matching(self):
        result = report()
        self.assertEqual(candidates(result)[0]["player_id"], P1)
        self.assertEqual(result["interpretations"]["cross_season_identifiers"]["stats_shared"], [P1])
        data = tables()
        replace_rows(data, "stats_2026", [stats(player_id="1", player_name="Same Name")])
        self.assertIn("invalid_player_identifier", codes(report(data)))

    def test_duplicate_player_game_statistics_not_summed(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(receiving_yards="10"), stats(receiving_yards="20")])
        result = report(data)
        self.assertIn("duplicate_player_game_stats", codes(result))
        candidate = candidates(result)[-1]
        self.assertEqual(candidate["statistics_match_count"], 2)
        self.assertEqual(candidate["outcomes"]["receiving_yards"]["state"], "unresolved_relationship")

    def test_duplicate_roster_occurrences_not_deduplicated(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster()])
        current = [c for c in candidates(report(data)) if c["season"] == 2026]
        self.assertEqual(len(current), 2)
        self.assertTrue(all(c["roster_membership_ambiguous"] for c in current))

    def test_trade_across_weeks_is_reported_without_global_team_assignment(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster(week=8, team="AWY")])
        replace_rows(data, "schedules", [schedule(), schedule(week=8)])
        replace_rows(data, "stats_2026", [stats(), stats(week=8, team="AWY", opponent="HOM")])
        result = report(data)
        current = [c for c in candidates(result) if c["season"] == 2026]
        self.assertEqual([c["team"] for c in current], ["HOM", "AWY"])
        self.assertTrue(all(not c["roster_membership_ambiguous"] for c in current))
        self.assertEqual(len(result["interpretations"]["team_changes"]), 1)

    def test_same_week_changed_team_is_ambiguous(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster(team="AWY")])
        self.assertTrue(all(c["roster_membership_ambiguous"] for c in candidates(report(data)) if c["season"] == 2026))

    def test_non_wr_conflicting_roster_row_is_not_ignored(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster(position="TE")])
        result = report(data)
        self.assertIn("duplicate_roster_observation_key", codes(result))
        self.assertTrue(candidates(result)[-1]["roster_membership_ambiguous"])

    def test_statistics_for_other_team_do_not_attach_to_candidate(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(team="AWY", opponent="HOM", receiving_yards="20")])
        result = report(data)
        self.assertIn("statistics_team_disagreement", codes(result))
        self.assertEqual(candidates(result)[-1]["outcomes"]["receiving_yards"]["state"], "unresolved_relationship")
        self.assertFalse(candidates(result)[-1]["outcome_usable_retrospectively"])

    def test_stat_roster_zero_and_multiple_joins_are_reported(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(), roster()])
        replace_rows(data, "stats_2026", [stats(), stats(pid=P2)])
        result = report(data)
        self.assertIn("stats_roster_join_zero", codes(result))
        self.assertIn("stats_roster_join_multiple", codes(result))

    def test_duplicate_schedule_identifier_cannot_resolve_via_unique_orientation(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(), schedule(home="OTH", away="NEW", game_id=schedule()["game_id"])])
        result = report(data)
        self.assertIn("stats_schedule_identity_multiple", codes(result))
        self.assertIn("roster_schedule_identity_multiple", codes(result))
        self.assertIsNone(candidates(result)[-1]["game_id"])

    def test_zero_targets_does_not_force_zero_yards(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(targets="0", receiving_yards="8")])
        item = candidates(report(data))[-1]
        self.assertEqual(item["outcomes"]["targets"]["state"], "zero")
        self.assertEqual(item["outcomes"]["receiving_yards"]["parsed_integer"], 8)
        self.assertEqual(item["participation"], "unknown")

    def test_observed_zero_yards(self):
        self.assertEqual(candidates(report())[-1]["outcomes"]["receiving_yards"]["state"], "zero")

    def test_negative_yards_preserved(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(receiving_yards="-5")])
        result = report(data)
        self.assertEqual(candidates(result)[-1]["outcomes"]["receiving_yards"]["parsed_integer"], -5)
        self.assertEqual(candidates(result)[-1]["outcomes"]["receiving_yards"]["state"], "negative")

    def test_null_and_malformed_outcomes_distinct(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(targets="NA", receiving_yards="invalid")])
        outcome = candidates(report(data))[-1]["outcomes"]
        self.assertEqual(outcome["targets"]["state"], "null")
        self.assertEqual(outcome["receiving_yards"]["state"], "malformed")

    def test_missing_statistics_preserves_roster_candidate(self):
        data = tables()
        replace_rows(data, "stats_2026", [])
        candidate = candidates(report(data))[-1]
        self.assertTrue(candidate["roster_designated_wr"])
        self.assertEqual(candidate["outcomes"]["receiving_yards"]["state"], "missing_statistics_row")
        self.assertIsNone(candidate["outcomes"]["receiving_yards"]["parsed_integer"])

    def test_bye_or_missing_schedule_not_a_zero_game(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(week=8)])
        candidate = candidates(report(data))[-1]
        self.assertEqual(candidate["schedule_state"], "no_scheduled_game")
        self.assertEqual(candidate["bye_status"], "unverified")
        self.assertIsNone(candidate["player_game_key"])

    def test_roster_inactive_status_not_game_day_evidence(self):
        data = tables()
        replace_rows(data, "rosters_2026", [roster(status="INA")])
        candidate = candidates(report(data))[-1]
        self.assertEqual(candidate["roster_status_category"], "inactive_roster_status")
        self.assertEqual(candidate["participation"], "unknown")

    def test_independent_participant_and_inactive_evidence(self):
        for state in ("confirmed_participant", "known_inactive"):
            with self.subTest(state=state):
                evidence = dict(player_id=P1, game_id=schedule()["game_id"], state=state, evidence="synthetic independent game-day record")
                result = report(participation_evidence=[evidence])
                self.assertEqual(candidates(result)[-1]["participation"], state)
                if state == "known_inactive":
                    self.assertIn("inactive_statistics_conflict", codes(result))
                    self.assertFalse(candidates(result)[-1]["outcome_usable_retrospectively"])

    def test_ambiguous_roster_game_joins_do_not_multiply(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(), schedule(game_id="other", away="OTH")])
        current = [c for c in candidates(report(data)) if c["season"] == 2026]
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["game_match_count"], 2)
        self.assertIsNone(current[0]["game_id"])

    def test_duplicate_player_identity_is_unresolved(self):
        data = tables()
        replace_rows(data, "players", [dict(gsis_id=P1), dict(gsis_id=P1)])
        result = report(data)
        self.assertIn("roster_identity_join_multiple", codes(result))
        self.assertFalse(candidates(result)[-1]["outcome_usable_retrospectively"])

    def test_freshness_is_separate_from_detailed_window(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(), schedule(week=10, gameday="2026-11-08"), schedule(week=18, gameday="2027-01-03", home_score="", away_score="")])
        replace_rows(data, "stats_2026", [stats(), stats(week=10)])
        replace_rows(data, "rosters_2026", [roster(), roster(week=10)])
        result = report(data)
        freshness = result["freshness"]
        self.assertEqual(freshness["latest_observed_regular_season_week"], 18)
        self.assertEqual(freshness["latest_fully_completed_observed_week"], 10)
        self.assertEqual(freshness["latest_observed_completed_game"]["week"], 10)
        self.assertEqual(freshness["latest_receiving_statistics_week"], 10)
        self.assertEqual(freshness["latest_weekly_roster_week"], 10)
        self.assertEqual([c["week"] for c in candidates(result) if c["season"] == 2026], [7])

    def test_partially_completed_week_not_fully_completed(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(), schedule(week=10), schedule(week=10, away="OTH", game_id="unfinished", home_score="", away_score="")])
        self.assertEqual(report(data)["freshness"]["latest_fully_completed_observed_week"], 7)

    def test_future_game_with_scores_is_not_completed(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(gameday="2027-01-03")])
        result = report(data)
        self.assertIsNone(result["freshness"]["latest_observed_completed_game"])
        self.assertIn("statistics_for_unverified_completed_game", codes(result))
        self.assertFalse(candidates(result)[-1]["outcome_usable_retrospectively"])

    def test_historical_date_without_scores_not_completed(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(home_score="", away_score="")])
        self.assertIsNone(report(data)["freshness"]["latest_observed_completed_game"])

    def test_explicit_nonfinal_status_overrides_score_pair(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(game_status="IN_PROGRESS")])
        self.assertIsNone(report(data)["freshness"]["latest_observed_completed_game"])

    def test_missing_reference_time_does_not_use_clock(self):
        self.assertIsNone(report(as_of=None)["freshness"]["latest_observed_completed_game"])

    def test_unknown_timezone_boundary_remains_unknown(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(gameday="2026-11-11")])
        with patch.object(runner, "ZoneInfo", side_effect=runner.ZoneInfoNotFoundError):
            self.assertIsNone(report(data)["freshness"]["latest_observed_completed_game"])

    def test_explicit_utc_future_kickoff(self):
        data = tables()
        replace_rows(data, "schedules", [schedule(gameday="2026-11-11", kickoff_utc="2026-11-11T23:00:00Z")])
        self.assertIsNone(report(data)["freshness"]["latest_observed_completed_game"])

    def test_missing_publication_and_pregame_availability(self):
        result = report()
        self.assertEqual(result["freshness"]["publication_evidence_missing"], list(runner.SPECS))
        self.assertEqual(result["historical_availability"]["pregame_knowability"], "not_established")
        self.assertIsNone(result["historical_availability"]["local_inspection_at"])

    def test_supplied_publication_does_not_establish_historical_eligibility(self):
        data = tables()
        table = data["stats_2026"]
        data["stats_2026"] = runner.Table(table.artifact_id, table.columns, table.rows, {"provider_publication_at": AS_OF})
        result = report(data)
        self.assertNotIn("stats_2026", result["freshness"]["publication_evidence_missing"])
        self.assertEqual(result["historical_availability"]["pregame_knowability"], "not_established")

    def test_source_age_requires_actual_source_timestamp_and_explicit_reference(self):
        data = tables()
        table = data["stats_2026"]
        data["stats_2026"] = runner.Table(table.artifact_id, table.columns, table.rows,
                                         {"provider_publication_at": "2026-11-10T12:00:00Z"})
        result = report(data)
        ages = result["freshness"]["source_age_seconds_relative_to_explicit_reference"]
        self.assertEqual(ages["stats_2026"]["provider_publication_at"], 86400)
        self.assertIsNone(ages["stats_2025"]["provider_publication_at"])
        self.assertIsNone(report(data, as_of=None)["freshness"]["source_age_seconds_relative_to_explicit_reference"]["stats_2026"]["provider_publication_at"])

    def test_determinism_and_no_input_mutation(self):
        data = tables()
        before = deepcopy(data)
        self.assertEqual(runner._json(report(data)), runner._json(report(data)))
        self.assertEqual(data, before)

    def test_numeric_lexical_rules_preserve_originals(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(targets="0.0", receiving_yards="-2e0")])
        outcome = candidates(report(data))[-1]["outcomes"]
        self.assertEqual(outcome["targets"]["raw_value"], "0.0")
        self.assertEqual(outcome["receiving_yards"]["parsed_integer"], -2)

    def test_preseason_week_zero_is_not_regular(self):
        data = tables()
        replace_rows(data, "stats_2026", [stats(week=0), stats(week=0, season_type="PRE")])
        result = report(data)
        self.assertIn("invalid_period", codes(result))
        self.assertEqual(result["raw_observations"]["stats_2026"]["period_counts"], {"2026/PRE/0": 1})


class BoundaryTests(Fixtures):
    def test_plan_is_exact_and_has_no_invented_evidence(self):
        plan = runner.read_plan()
        self.assertEqual(plan["mode"], "offline_only")
        self.assertEqual(plan["limits"], runner.LIMITS)
        self.assertEqual(len(plan["artifacts"]), 6)
        for entry in plan["artifacts"]:
            self.assertNotIn("sha256", entry)
            self.assertTrue(all(t not in entry for t in runner.TIMESTAMPS))

    def test_plan_rejects_changed_sources(self):
        plan = runner.read_plan()
        plan["artifacts"][0]["filename"] = "other.csv.gz"
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan))
        self.assert_code("unapproved_plan", runner.read_plan, path)

    def test_acquire_always_fails_and_creates_nothing(self):
        before = sorted(self.root.iterdir())
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(runner.main(["acquire"]), 2)
        self.assertIn("acquisition_not_implemented_or_authorized", stderr.getvalue())
        self.assertEqual(sorted(self.root.iterdir()), before)
        self.assertFalse((HERE / "run-01").exists())

    def test_cli_preflight_does_not_create_run_directory(self):
        with redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(runner.main(["preflight"]), 0)
        self.assertFalse(json.loads(stdout.getvalue())["acquisition_enabled"])
        self.assertFalse((HERE / "run-01").exists())

    def test_cli_inspection_reads_only_and_emits_json(self):
        path = self.manifest()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(runner.main(["inspect", "--root", str(self.root), "--manifest", str(path), "--as-of", AS_OF]), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["mode"], "offline_retrospective_inspection")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_cli_failure_is_nonzero_and_not_a_success_report(self):
        path = self.manifest()
        body = json.loads(path.read_text())
        body["artifacts"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(body))
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(runner.main(["inspect", "--root", str(self.root), "--manifest", str(path)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue())["error"], "sha256_mismatch")

    def test_manifest_requires_six_distinct_artifacts(self):
        path = self.manifest()
        value = json.loads(path.read_text())
        value["artifacts"][-1] = value["artifacts"][0]
        path.write_text(json.dumps(value))
        self.assert_code("six_exact_artifacts_required", runner.inspect_manifest, self.root, path)

    def test_unapproved_and_traversal_paths(self):
        for name in ("../games.csv.gz", "..\\games.csv.gz", "C:\\games.csv.gz", "https://example.com/data", "sub/file.csv.gz"):
            with self.subTest(name=name):
                entry = self.artifact()
                entry["filename"] = name
                self.assert_code("unexpected_artifact_identity", runner.validate_artifact, self.root, entry)

    def test_manifest_cannot_supply_an_alternate_path(self):
        entry = self.artifact()
        entry["path"] = "outside.csv.gz"
        self.assert_code("unexpected_artifact_identity", runner.validate_artifact, self.root, entry)

    def test_root_parent_traversal_rejected(self):
        entry = self.artifact()
        self.assert_code("unapproved_path", runner.validate_artifact, self.root / ".." / self.root.name, entry)

    def test_unc_network_filesystem_paths_rejected_before_stat(self):
        entry = self.artifact()
        with patch.object(Path, "lstat", side_effect=AssertionError("UNC path must not be inspected")):
            self.assert_code("unapproved_path", runner.validate_artifact, "\\\\example.invalid\\share", entry)

    def test_symlink_component_rejected_with_synthetic_lstat(self):
        entry = self.artifact()
        target = self.root / entry["filename"]
        real_lstat = Path.lstat
        def fake_lstat(path):
            if path == target:
                return type("Info", (), dict(st_mode=stat.S_IFLNK, st_file_attributes=0))()
            return real_lstat(path)
        with patch.object(Path, "lstat", fake_lstat):
            self.assert_code("reparse_path_rejected", runner.validate_artifact, self.root, entry)

    def test_windows_reparse_parent_rejected_with_synthetic_lstat(self):
        entry = self.artifact()
        real_lstat = Path.lstat
        def fake_lstat(path):
            if path == self.root:
                return type("Info", (), dict(st_mode=stat.S_IFDIR, st_file_attributes=0x400))()
            return real_lstat(path)
        with patch.object(Path, "lstat", fake_lstat):
            self.assert_code("reparse_path_rejected", runner.validate_artifact, self.root, entry)

    def test_duplicate_json_keys_rejected(self):
        path = self.root / "manifest.json"
        path.write_text('{"artifacts":[],"artifacts":[]}')
        self.assert_code("duplicate_json_key", runner.inspect_manifest, self.root, path)

    def test_runner_has_no_network_database_or_provider_imports(self):
        tree = ast.parse((HERE / "runner.py").read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append((node.module or "").split(".")[0])
        self.assertTrue(FORBIDDEN_IMPORTS.isdisjoint(imports))
        self.assertNotIn("subprocess", imports)

    def test_runner_has_no_write_open_modes_or_filesystem_mutators(self):
        tree = ast.parse((HERE / "runner.py").read_text(encoding="utf-8"))
        forbidden_calls = {"write_text", "write_bytes", "mkdir", "unlink", "rmdir", "rename", "connect", "urlopen"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden_calls)
                if node.func.attr == "replace":
                    # datetime.replace sets timezone metadata; filesystem
                    # os.replace/Path.replace must still be rejected.
                    self.assertIsInstance(node.func.value, ast.Name)
                    self.assertEqual(node.func.value.id, "local")
                if node.func.attr == "open":
                    modes = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                    self.assertTrue(all(m == "rb" for m in modes))

    def test_audit_guards_reject_network_sqlite_and_project_writes(self):
        # Exercise the guard directly, without attempting those external effects.
        counts_before = dict(AUDIT_COUNTS)
        try:
            for event, args in (("socket.connect", (None, ("example.invalid", 443))),
                                ("sqlite3.connect", (":memory:",)),
                                ("import", ("nflreadpy", None)),
                                ("open", (str(REPOSITORY / "README.md"), "w", os.O_WRONLY))):
                with self.subTest(event=event), self.assertRaises(PermissionError):
                    _audit(event, args)
        finally:
            AUDIT_COUNTS.update(counts_before)

    def test_content_accounting_disclaims_rss_guarantee(self):
        accounting = report()["retained_content_accounting"]
        self.assertFalse(accounting["hard_process_memory_limit"])
        self.assertLess(accounting["bytes"], accounting["cap"])


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="edgefinder-c2a-offline-") as temp_root:
        TEST_ROOT = Path(temp_root)
        if TEST_ROOT.is_relative_to(REPOSITORY):
            raise SystemExit("Temporary fixtures must be outside the repository")
        sys.addaudithook(_audit)
        AUDIT_ENABLED = True
        try:
            with warnings.catch_warnings(record=True) as recorded_warnings:
                warnings.simplefilter("always")
                suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
                result = unittest.TextTestRunner(verbosity=2).run(suite)
            print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                                  warnings=len(recorded_warnings), skips=len(result.skipped),
                                  expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
                                  runtime_audit_attempts_excluding_four_direct_guard_self_checks=AUDIT_COUNTS,
                                  exit_status=0 if result.wasSuccessful() else 1), sort_keys=True))
        finally:
            AUDIT_ENABLED = False
    raise SystemExit(0 if result.wasSuccessful() else 1)
