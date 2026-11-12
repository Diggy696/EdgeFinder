"""C2a local-only gzip CSV inspection. No network or database functionality.

CLI preflight reads the plan; inspect reads a manifest and six approved files,
and emits JSON to stdout. acquire always fails. Nothing creates directories or
writes files. Inputs must be stable under exclusive control during inspection;
component/reparse checks are not an OS sandbox against concurrent path changes.

Manifest: {"artifacts": [{"artifact_id", "release", "filename", "byte_length",
optional "sha256", optional timestamps below}], optional "verification_evidence",
optional "participation_evidence"}. All six identities are required by inspect.
Manifest verification evidence is a caller assertion, never authenticated here.
Optional timestamps: game_event_at, provider_publication_at, hosting_release_at,
hosting_asset_at, edgefinder_acquired_at, local_inspection_at. Publication time
and provider_publication_evidence must be supplied together. No clock is read.

Retained-content accounting counts compact UTF-8 JSON bytes for column names,
source row dictionaries (including repeated keys), derived keys/records, and the
report, conservatively including repeated representations. It excludes Python
object overhead, allocator/decoder buffers and index
reference slots: 128 MiB is NOT a process-memory ceiling. Tables are retained
within this content cap; decompressed files are streamed, never materialized.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zlib
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


MIB = 1024 * 1024
ARTIFACTS = (
    ("schedules", "schedules", "games.csv.gz", "schedule", None),
    ("stats_2025", "stats_player", "stats_player_week_2025.csv.gz", "stats", 2025),
    ("stats_2026", "stats_player", "stats_player_week_2026.csv.gz", "stats", 2026),
    ("rosters_2025", "weekly_rosters", "roster_weekly_2025.csv.gz", "roster", 2025),
    ("rosters_2026", "weekly_rosters", "roster_weekly_2026.csv.gz", "roster", 2026),
    ("players", "players", "players.csv.gz", "players", None),
)
SPECS = {a[0]: dict(zip(("artifact_id", "release", "filename", "role", "season"), a)) for a in ARTIFACTS}
LIMITS = dict(compressed_schedule=2*MIB, compressed_stats=4*MIB,
              compressed_roster=4*MIB, compressed_players=8*MIB,
              compressed_total=16*MIB, decompressed_file=64*MIB,
              decompressed_total=256*MIB, columns=512, field_bytes=16384,
              record_bytes=262144, rows_schedule=25000, rows_stats=50000,
              rows_roster=100000, rows_players=100000, rows_total=425000,
              retained_bytes=128*MIB)
NULLS = ("", "NA", "NULL")
WINDOWS = {"2025": {"phase": "REG", "weeks": [1, 18]},
           "2026": {"phase": "REG", "weeks": [7, 9]}}
URL_TEMPLATE = "https://github.com/nflverse/nflverse-data/releases/download/{release}/{filename}"
REQUIRED = {
    "schedule": ("game_id", "season", "week", "game_type", "home_team", "away_team", "gameday", "gametime", "home_score", "away_score"),
    "stats": ("player_id", "season", "week", "season_type", "team", "opponent_team", "targets", "receptions", "receiving_yards"),
    "roster": ("gsis_id", "season", "week", "game_type", "team", "position", "status"),
    "players": ("gsis_id",),
}
TIMESTAMPS = ("game_event_at", "provider_publication_at", "hosting_release_at",
              "hosting_asset_at", "edgefinder_acquired_at", "local_inspection_at")
FRESHNESS_RULES = dict(season=2026,
                       scope="all_observed_regular_season_weeks_separate_from_analysis_windows",
                       reference_time="explicit_as_of_required_never_local_clock",
                       completion_rule="valid_nonnegative_home_and_away_scores_and_verified_not_future_game_time",
                       publication_evidence="unknown_unless_supplied_never_inferred_from_coverage")
CSV_RULES = dict(encoding="utf-8-sig_strict", delimiter=",", null_tokens=list(NULLS),
                 identifier_policy="original_strings_no_coercion_or_name_matching",
                 numeric_policy="season_week_decimal_digits_counts_and_yards_finite_integer_valued_decimal_absolute_max_1000000",
                 phase_policy="REG_regular_PRE_preseason_POST_WC_DIV_CON_SB_postseason")


class InspectionError(ValueError):
    """Stable code and bounded structural details, never dependency exceptions."""

    def __init__(self, code, **details):
        self.code, self.details = code, details
        super().__init__(code)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass
class Budget:
    limits: dict = field(default_factory=lambda: dict(LIMITS))
    counts: dict = field(default_factory=lambda: dict(compressed_total=0, decompressed_total=0, rows_total=0, retained_bytes=0))

    def __post_init__(self):
        if set(self.limits) != set(LIMITS) or any(type(v) is not int or v < 1 or v > LIMITS[k] for k, v in self.limits.items()):
            raise InspectionError("invalid_limits")
        if self.counts != dict(compressed_total=0, decompressed_total=0, rows_total=0, retained_bytes=0):
            raise InspectionError("invalid_initial_budget")
        self.limits = dict(self.limits)

    def add(self, name, amount):
        self.counts[name] += amount
        if self.counts[name] > self.limits[name]:
            raise InspectionError("limit_exceeded", limit=name)

    def retain(self, value):
        self.add("retained_bytes", len(_json(value).encode("utf-8")))


@dataclass(frozen=True)
class Table:
    artifact_id: str
    columns: tuple[str, ...]
    rows: tuple[dict[str, str], ...]
    evidence: dict = field(default_factory=dict)


def _safe_path(root, filename):
    """Only one exact child of an explicit existing, non-reparse directory."""
    if type(filename) is not str or filename in ("", ".", "..") or any(c in filename for c in "/\\:"):
        raise InspectionError("unapproved_path")
    root = Path(root)
    if ".." in root.parts or str(root).startswith(("\\\\", "//")):
        raise InspectionError("unapproved_path")
    root = root.absolute()
    target = root / filename
    for component in (*reversed(target.parents), target):
        try:
            info = component.lstat()
        except OSError:
            raise InspectionError("input_unavailable") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise InspectionError("reparse_path_rejected")
    if not root.is_dir() or not target.is_file() or target.resolve().parent != root.resolve():
        raise InspectionError("unapproved_path")
    return target


def _read_json(path, cap=65536):
    path = Path(path)
    checked = _safe_path(path.parent, path.name)
    try:
        with checked.open("rb") as stream:
            body = stream.read(cap + 1)
        if len(body) > cap:
            raise InspectionError("json_size_limit")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise InspectionError("duplicate_json_key")
                result[key] = value
            return result
        return json.loads(body.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InspectionError("invalid_json_number")))
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, InspectionError):
            raise
        raise InspectionError("invalid_json") from None


def read_plan(path=None):
    """Read the fixed approved design; never treat plan URLs as capabilities."""
    plan = _read_json(path or Path(__file__).with_name("plan.json"))
    if (type(plan) is not dict or type(plan.get("schema_version")) is not int or plan.get("schema_version") != 1
            or plan.get("mode") != "offline_only"
            or plan.get("artifacts") != list(SPECS.values())
            or plan.get("limits") != LIMITS
            or plan.get("analysis_windows") != WINDOWS
            or plan.get("source_url_template") != URL_TEMPLATE
            or plan.get("freshness") != FRESHNESS_RULES
            or plan.get("csv_rules") != CSV_RULES
            or plan.get("historical_policy") != "retrospective_only_pregame_knowability_not_established"):
        raise InspectionError("unapproved_plan")
    return plan


def _instant(value):
    if type(value) is not str or len(value) > 40 or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)", value):
        raise InspectionError("invalid_timestamp")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InspectionError("invalid_timestamp") from None


def _entry(entry):
    if type(entry) is not dict or type(entry.get("artifact_id")) is not str or entry["artifact_id"] not in SPECS:
        raise InspectionError("unexpected_artifact_identity")
    spec = SPECS[entry["artifact_id"]]
    allowed = {"artifact_id", "release", "filename", "byte_length", "sha256", "provider_publication_evidence", *TIMESTAMPS}
    if set(entry) - allowed or any(entry.get(k) != spec[k] for k in ("release", "filename")):
        raise InspectionError("unexpected_artifact_identity")
    if type(entry.get("byte_length")) is not int or entry["byte_length"] < 0:
        raise InspectionError("invalid_byte_length")
    digest = entry.get("sha256")
    if digest is not None and (type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise InspectionError("invalid_expected_digest")
    for name in TIMESTAMPS:
        if entry.get(name) is not None:
            _instant(entry[name])
    published, support = entry.get("provider_publication_at"), entry.get("provider_publication_evidence")
    if (published is None) != (support is None) or (support is not None and (not _text(support) or len(support.encode("utf-8")) > 4096)):
        raise InspectionError("publication_evidence_required")
    if published and entry.get("edgefinder_acquired_at") and _instant(published) > _instant(entry["edgefinder_acquired_at"]):
        raise InspectionError("publication_after_acquisition")
    return spec


class _Compressed:
    def __init__(self, stream, budget, cap):
        self.stream, self.budget, self.cap = stream, budget, cap
        self.length, self.digest = 0, hashlib.sha256()

    def read(self, size=-1):
        remaining = min(self.cap - self.length, self.budget.limits["compressed_total"] - self.budget.counts["compressed_total"])
        data = self.stream.read(min(65536, remaining + 1, size if size >= 0 else 65536))
        self.length += len(data)
        self.budget.add("compressed_total", len(data))
        if self.length > self.cap:
            raise InspectionError("limit_exceeded", limit="compressed_file")
        self.digest.update(data)
        return data


class _Decompressed(io.RawIOBase):
    def __init__(self, stream, budget):
        super().__init__()
        self.stream, self.budget, self.length = stream, budget, 0

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = min(self.budget.limits["decompressed_file"] - self.length,
                        self.budget.limits["decompressed_total"] - self.budget.counts["decompressed_total"])
        data = self.stream.read1(min(len(buffer), 65536, remaining + 1))
        self.length += len(data)
        self.budget.add("decompressed_total", len(data))
        if self.length > self.budget.limits["decompressed_file"]:
            raise InspectionError("limit_exceeded", limit="decompressed_file")
        buffer[:len(data)] = data
        return len(data)


class _RecordLines:
    def __init__(self, text, cap):
        self.text, self.cap, self.used = text, cap, 0

    def __iter__(self):
        return self

    def __next__(self):
        line = self.text.readline(self.cap - self.used + 1)
        if not line:
            raise StopIteration
        self.used += len(line.encode("utf-8"))
        if self.used > self.cap:
            raise InspectionError("limit_exceeded", limit="record_bytes")
        return line


def validate_artifact(root, entry, *, budget=None):
    """Read one exact gzip artifact; preserve all CSV cells and occurrences.

    byte_length is required. sha256 and temporal assertions are optional; a
    digest comparison never authenticates the supplied manifest or publisher.
    Resource usage includes header/decompression bytes and data-row counts.
    """
    spec = _entry(entry)
    budget = budget if budget is not None else Budget()
    path = _safe_path(root, spec["filename"])
    cap = budget.limits["compressed_" + spec["role"]]
    old_field_limit = csv.field_size_limit(budget.limits["field_bytes"])
    try:
        with path.open("rb") as source:
            info = os.fstat(source.fileno())
            if info.st_size > cap:
                raise InspectionError("limit_exceeded", limit="compressed_file")
            if info.st_size != entry["byte_length"]:
                raise InspectionError("compressed_length_mismatch")
            compressed = _Compressed(source, budget, cap)
            with gzip.GzipFile(fileobj=compressed, mode="rb") as gz:
                decoded = _Decompressed(gz, budget)
                with io.TextIOWrapper(io.BufferedReader(decoded), encoding="utf-8-sig", errors="strict", newline="") as text:
                    lines = _RecordLines(text, budget.limits["record_bytes"])
                    reader = csv.reader(lines, strict=True)
                    try:
                        header = next(reader)
                    except StopIteration:
                        raise InspectionError("missing_header") from None
                    if not header or any(not name or name in NULLS for name in header):
                        raise InspectionError("empty_header")
                    if len(header) > budget.limits["columns"]:
                        raise InspectionError("limit_exceeded", limit="columns")
                    if any(len(name.encode("utf-8")) > budget.limits["field_bytes"] for name in header):
                        raise InspectionError("limit_exceeded", limit="field_bytes")
                    if len(set(header)) != len(header):
                        raise InspectionError("duplicate_headers", positions=[i for i, name in enumerate(header) if name in header[:i]])
                    missing = sorted(set(REQUIRED[spec["role"]]) - set(header))
                    if missing:
                        raise InspectionError("missing_required_columns", columns=missing)
                    budget.retain(header)
                    rows = []
                    while True:
                        lines.used = 0
                        try:
                            cells = next(reader)
                        except StopIteration:
                            break
                        budget.add("rows_total", 1)
                        if len(rows) >= budget.limits["rows_" + spec["role"]]:
                            raise InspectionError("limit_exceeded", limit="rows_file")
                        if len(cells) != len(header):
                            raise InspectionError("csv_width_mismatch", row=len(rows) + 1)
                        if any(len(cell.encode("utf-8")) > budget.limits["field_bytes"] for cell in cells):
                            raise InspectionError("limit_exceeded", limit="field_bytes")
                        row = dict(zip(header, cells))
                        budget.retain(row)
                        rows.append(row)
            if os.fstat(source.fileno()).st_size != info.st_size:
                raise InspectionError("input_changed")
        if compressed.length != entry["byte_length"]:
            raise InspectionError("compressed_length_mismatch")
        digest = compressed.digest.hexdigest()
        if entry.get("sha256") is not None and digest != entry["sha256"]:
            raise InspectionError("sha256_mismatch")
        evidence = {name: entry.get(name) for name in (*TIMESTAMPS, "provider_publication_evidence")}
        evidence.update(original_compressed_bytes=compressed.length, original_compressed_sha256=digest,
                        expected_digest_match=True if entry.get("sha256") else None,
                        decompressed_bytes=decoded.length, source_url=URL_TEMPLATE.format(**spec),
                        source_url_is_design_input=True, local_validation_performed=True,
                        origin_authenticated=False)
        budget.retain(evidence)
        return Table(spec["artifact_id"], tuple(header), tuple(rows), evidence)
    except (OSError, EOFError, UnicodeError, csv.Error, zlib.error) as error:
        if isinstance(error, UnicodeError):
            code = "invalid_utf8"
        elif isinstance(error, csv.Error):
            code = "invalid_csv"
        else:
            code = "invalid_gzip_or_input"
        raise InspectionError(code) from None
    finally:
        csv.field_size_limit(old_field_limit)


def _phase(value):
    return {"REG": "REG", "PRE": "PRE", "POST": "POST", "WC": "POST", "DIV": "POST", "CON": "POST", "SB": "POST"}.get(value)


def _number(value, *, low=-1000000, high=1000000):
    if value in NULLS or type(value) is not str or len(value) > 64 or not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d{1,3})?", value):
        return None
    try:
        number = Decimal(value)
        return int(number) if low <= number <= high and number == number.to_integral_value() else None
    except (InvalidOperation, ValueError, OverflowError):
        return None


def _period(row, role):
    year, week = row.get("season"), row.get("week")
    phase = _phase(row.get("season_type" if role == "stats" else "game_type"))
    if (type(year) is not str or not re.fullmatch(r"\d{4}", year)
            or type(week) is not str or not re.fullmatch(r"\d{1,2}", week)
            or phase is None or (int(week) == 0 and phase != "PRE")):
        return None
    return int(year), phase, int(week)


def _identifier(value):
    """Opaque source-field text, not verification of GSIS identity or format."""
    return (_text(value) and len(value.encode("utf-8")) <= LIMITS["field_bytes"]
            and all(c.isprintable() and not c.isspace() for c in value))


def _identifier_namespaces(row):
    """Retain explicit declarations; C2a has no authority to map namespaces.

    The existing joins use only players/rosters.gsis_id and stats.player_id.
    An additional namespace assertion cannot silently join the default source
    fields, even when its text value happens to match. Report it unresolved.
    Other reference ID columns (e.g. pfr_id) are never identity crosswalks.
    """
    return {name: row[name] for name in ("gsis_id_namespace", "player_id_namespace", "identifier_namespace") if name in row}


def _text(value):
    if type(value) is not str or value in NULLS or not value.strip() or value != value.strip():
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def _lexical(value):
    if value in NULLS:
        return "empty" if value == "" else "null_token_" + value
    if re.fullmatch(r"[+-]?\d+", value):
        return "integer_lexeme"
    if re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", value):
        return "decimal_lexeme"
    return "text"


def _retrospective_result(row):
    """A result in the supplied artifact is not evidence of its historical time."""
    status = row.get("game_status")
    return (status in (None, *NULLS, "FINAL", "COMPLETED")
            and all(_number(row.get(key), low=0, high=10000) is not None for key in ("home_score", "away_score")))


def _completion(row, as_of):
    """Classify time consistency, never establish historical completion.

    Current scores and undated FINAL status cannot establish a conclusion at
    as_of. No completion/publication evidence contract is implemented here.
    The existing two-day timezone fallback ONLY bounds whether kickoff could
    be in the future; it is never a guessed duration or completion timestamp.
    """
    event = None
    if _text(row.get("kickoff_utc")):
        try:
            event = _instant(row["kickoff_utc"])
        except InspectionError:
            return "invalid_game_time", None
    try:
        day = date.fromisoformat(row.get("gameday", ""))
        local = datetime.fromisoformat(day.isoformat() + "T" + row.get("gametime", ""))
        if local.tzinfo is not None:
            return "invalid_game_time", None
        if event is None:
            try:
                event = local.replace(tzinfo=ZoneInfo("America/New_York")).astimezone(timezone.utc)
            except ZoneInfoNotFoundError:
                pass
    except (ValueError, TypeError):
        return "invalid_game_time", None
    if as_of is None:
        return "reference_time_unknown", event
    if event is not None and event > as_of:
        return "future_game", event
    if day > as_of.date():
        return "future_game", event
    if event is None:
        try:
            if datetime.combine(day + timedelta(days=2), datetime.min.time(), timezone.utc) > as_of:
                return "game_time_boundary_unknown", None
        except OverflowError:
            return "game_time_boundary_unknown", None
    status = row.get("game_status")
    if status is not None and status not in NULLS and status not in ("FINAL", "COMPLETED"):
        return "source_not_final", event
    return ("retrospective_result_only" if _retrospective_result(row) else "completion_unknown"), event


def inspect_rows(tables, *, as_of=None, participation_evidence=()):
    """Inspect six local tables. No claims of acquisition or historical access.

    Direct callers may supply synthetic Table values; those are not proof of
    artifact validation. Every raw row survives; indexes retain occurrences.
    Supplied participation evidence is explicitly caller-asserted independent
    evidence, never inferred from stats or roster status.
    """
    if set(tables) != set(SPECS) or any(type(tables[k]) is not Table or tables[k].artifact_id != k for k in tables):
        raise InspectionError("six_exact_tables_required")
    reference = _instant(as_of) if as_of is not None else None
    budget, findings, raw = Budget(), [], {}
    def issue(code, artifact, row, **details):
        item = dict(code=code, artifact=artifact, row=row, **details)
        budget.retain(item)
        findings.append(item)
    def index_add(index, key, value):
        budget.retain(key)
        index[key].append(value)
    for aid in SPECS:
        table, role = tables[aid], SPECS[aid]["role"]
        if len(table.columns) != len(set(table.columns)):
            raise InspectionError("duplicate_headers")
        if set(REQUIRED[role]) - set(table.columns):
            raise InspectionError("missing_required_columns")
        budget.retain(table.columns)
        profiles = {name: Counter() for name in table.columns}
        failures, missing, periods, duplicates = Counter(), Counter(), Counter(), defaultdict(list)
        for ordinal, row in enumerate(table.rows, 1):
            if set(row) != set(table.columns) or any(type(v) is not str for v in row.values()):
                raise InspectionError("invalid_in_memory_row")
            budget.add("rows_total", 1)
            if ordinal > LIMITS["rows_" + role]:
                raise InspectionError("limit_exceeded", limit="rows_file")
            budget.retain(row)
            encoded = _json(row)
            index_add(duplicates, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), ordinal)
            for name, value in row.items():
                profiles[name][_lexical(value)] += 1
                if name in REQUIRED[role] and (value in NULLS or not value.strip()):
                    missing[name] += 1
                    issue("missing_required_value", aid, ordinal, field=name)
                if name in ("season", "week"):
                    valid = bool(re.fullmatch(r"\d{4}" if name == "season" else r"\d{1,2}", value))
                elif name in ("targets", "receptions", "receiving_yards", "home_score", "away_score"):
                    valid = value in NULLS or _number(value, low=-1000000 if name == "receiving_yards" else 0) is not None
                elif name in ("season_type", "game_type"):
                    valid = _phase(value) is not None
                else:
                    continue
                if not valid:
                    failures[name] += 1
                    issue("parse_failure", aid, ordinal, field=name)
            if role != "players":
                period = _period(row, role)
                if period is None:
                    issue("invalid_period", aid, ordinal)
                else:
                    periods["%s/%s/%s" % period] += 1
                    if SPECS[aid]["season"] is not None and period[0] != SPECS[aid]["season"]:
                        issue("unexpected_artifact_season", aid, ordinal)
        raw[aid] = dict(columns=list(table.columns), row_count=len(table.rows),
                        lexical_forms={k: dict(sorted(v.items())) for k, v in profiles.items()},
                        parse_failures=dict(sorted(failures.items())), missing_required_values=dict(sorted(missing.items())),
                        period_counts=dict(sorted(periods.items())),
                        duplicate_record_groups=[v for _, v in sorted(duplicates.items()) if len(v) > 1],
                        artifact_evidence=table.evidence)
        budget.retain(raw[aid])

    identities = defaultdict(list)
    for i, row in enumerate(tables["players"].rows, 1):
        pid = row["gsis_id"]
        namespaces = _identifier_namespaces(row)
        if namespaces:
            issue("player_identifier_namespace_unresolved", "players", i, declarations=namespaces)
        if not _identifier(pid):
            issue("invalid_player_identifier", "players", i)
        elif not namespaces:
            index_add(identities, pid, i)

    games, orientations, team_games = defaultdict(list), defaultdict(list), defaultdict(list)
    schedule = []
    for i, row in enumerate(tables["schedules"].rows, 1):
        period, gid = _period(row, "schedule"), row["game_id"]
        home, away = row["home_team"], row["away_team"]
        if period is None or not all(_text(v) for v in (gid, home, away)) or home == away:
            issue("invalid_schedule_key", "schedules", i)
            continue
        completion, event = _completion(row, reference)
        item = dict(row=i, game_id=gid, season=period[0], phase=period[1], week=period[2],
                    home_team=home, away_team=away, completion=completion,
                    retrospective_result_observed=_retrospective_result(row),
                    historical_completion_verified=False,
                    reported_gameday=row["gameday"], reported_gametime=row["gametime"],
                    derived_kickoff_utc=event.isoformat() if event else None)
        budget.retain(item)
        schedule.append(item)
        index_add(games, gid, item)
        for team, opponent in ((home, away), (away, home)):
            index_add(orientations, (*period, team, opponent), item)
            index_add(team_games, (*period, team), item)
    for gid, rows in sorted(games.items()):
        if len(rows) > 1:
            issue("duplicate_schedule_game_id", "schedules", None, game_id=gid, rows=[r["row"] for r in rows])

    roster_occurrences = defaultdict(list)
    for aid in ("rosters_2025", "rosters_2026"):
        for i, row in enumerate(tables[aid].rows, 1):
            period = _period(row, "roster")
            if period and period[0] == SPECS[aid]["season"] and not _identifier_namespaces(row):
                index_add(roster_occurrences, (*period, row["team"], row["gsis_id"]), [aid, i])
    for key, occurrences in sorted(roster_occurrences.items()):
        if len(occurrences) > 1:
            issue("duplicate_roster_observation_key", "roster", None, key=list(key), sources=occurrences)

    stat_games, stat_joins, seen_ids = defaultdict(list), [], defaultdict(set)
    for aid in ("stats_2025", "stats_2026"):
        for i, row in enumerate(tables[aid].rows, 1):
            period, pid = _period(row, "stats"), row["player_id"]
            namespaces = _identifier_namespaces(row)
            if namespaces:
                issue("player_identifier_namespace_unresolved", aid, i, declarations=namespaces)
            matches = orientations.get((*period, row["team"], row["opponent_team"]), []) if period else []
            count = len(matches)
            resolved = matches[0]["game_id"] if count == 1 and len(games[matches[0]["game_id"]]) == 1 else None
            if count != 1:
                issue("stats_game_join_zero" if count == 0 else "stats_game_join_multiple", aid, i, match_count=count)
            if count == 1 and len(games[matches[0]["game_id"]]) != 1:
                issue("stats_schedule_identity_multiple", aid, i, match_count=len(games[matches[0]["game_id"]]))
            if resolved and row.get("game_id") not in (None, resolved):
                issue("stats_game_id_disagreement", aid, i)
                resolved = None
            id_count = len(identities.get(pid, [])) if not namespaces else 0
            if id_count != 1:
                issue("stats_identity_join_zero" if id_count == 0 else "stats_identity_join_multiple", aid, i, match_count=id_count)
            if not _identifier(pid):
                issue("invalid_player_identifier", aid, i)
            if period and period[0] == SPECS[aid]["season"] and not namespaces:
                seen_ids[str(period[0])].add(pid)
            elif period and period[0] != SPECS[aid]["season"]:
                resolved = None
            roster_count = len(roster_occurrences.get((*period, row["team"], pid), [])) if period and not namespaces else 0
            if roster_count != 1:
                issue("stats_roster_join_zero" if roster_count == 0 else "stats_roster_join_multiple", aid, i, match_count=roster_count)
            join = dict(artifact=aid, row=i, player_id=pid, game_match_count=count,
                        identity_match_count=id_count, roster_match_count=roster_count, resolved_game_id=resolved,
                        source_namespace_declarations=namespaces)
            budget.retain(join)
            stat_joins.append(join)
            if resolved and _identifier(pid) and not namespaces:
                index_add(stat_games, (pid, resolved), (aid, i, row))
                if not games[resolved][0]["historical_completion_verified"]:
                    issue("statistics_for_unverified_completed_game", aid, i, game_id=resolved)
    for (pid, gid), rows in sorted(stat_games.items()):
        if len(rows) > 1:
            issue("duplicate_player_game_stats", "stats", None, player_id=pid, game_id=gid,
                  sources=[[a, i] for a, i, _ in rows])

    participation = {}
    for evidence in participation_evidence:
        if (type(evidence) is not dict or set(evidence) != {"player_id", "game_id", "state", "evidence"}
                or not _identifier(evidence["player_id"]) or not _text(evidence["game_id"])
                or evidence["state"] not in ("confirmed_participant", "known_inactive")
                or not _text(evidence["evidence"])):
            raise InspectionError("invalid_participation_evidence")
        key = (evidence["player_id"], evidence["game_id"])
        if key in participation:
            raise InspectionError("duplicate_participation_evidence")
        budget.retain(evidence)
        participation[key] = evidence

    candidates, memberships, candidate_keys = [], defaultdict(set), defaultdict(list)
    roster_seen = defaultdict(set)
    for aid in ("rosters_2025", "rosters_2026"):
        for i, row in enumerate(tables[aid].rows, 1):
            period, pid = _period(row, "roster"), row["gsis_id"]
            namespaces = _identifier_namespaces(row)
            if namespaces:
                issue("player_identifier_namespace_unresolved", aid, i, declarations=namespaces)
            if not _identifier(pid):
                issue("invalid_player_identifier", aid, i)
            if period and period[0] == SPECS[aid]["season"] and not namespaces:
                membership_key = (*period, pid)
                budget.retain(membership_key)
                memberships[membership_key].add(row["team"])
                roster_seen[str(period[0])].add(pid)
            if row["position"] != "WR" or period is None or period[0] != SPECS[aid]["season"]:
                continue
            window = WINDOWS.get(str(period[0]))
            if not window or period[1] != "REG" or not window["weeks"][0] <= period[2] <= window["weeks"][1]:
                continue
            matches = team_games.get((*period, row["team"]), [])
            count = len(matches)
            id_count = len(identities.get(pid, [])) if not namespaces else 0
            gid = matches[0]["game_id"] if count == 1 and len(games[matches[0]["game_id"]]) == 1 else None
            if count != 1:
                issue("roster_game_join_zero" if count == 0 else "roster_game_join_multiple", aid, i, match_count=count)
            if count == 1 and len(games[matches[0]["game_id"]]) != 1:
                issue("roster_schedule_identity_multiple", aid, i, match_count=len(games[matches[0]["game_id"]]))
            if id_count != 1:
                issue("roster_identity_join_zero" if id_count == 0 else "roster_identity_join_multiple", aid, i, match_count=id_count)
            candidate = dict(artifact=aid, row=i, player_id=pid, season=period[0], phase=period[1], week=period[2],
                             team=row["team"], roster_status=row["status"], roster_designated_wr=True,
                             source_namespace_declarations=namespaces,
                             game_match_count=count, identity_match_count=id_count, game_id=gid,
                             player_game_key=[pid, gid] if gid and _identifier(pid) and not namespaces else None,
                             schedule_state="matched" if gid else ("no_scheduled_game" if count == 0 else "ambiguous"),
                             bye_status="unverified" if count == 0 else "not_applicable",
                             roster_status_category="inactive_roster_status" if row["status"] == "INA" else "other_or_unknown",
                             participation="unknown", participation_evidence=None,
                             historical_pregame_knowability="not_established")
            budget.retain(candidate)
            candidates.append(candidate)
            if gid and not namespaces:
                index_add(candidate_keys, (pid, gid), candidate)

    outcome_counts = Counter()
    for candidate in candidates:
        pid, gid = candidate["player_id"], candidate["game_id"]
        member_key = (candidate["season"], candidate["phase"], candidate["week"], pid)
        ambiguous = (bool(candidate["source_namespace_declarations"])
                     or len(memberships[member_key]) > 1
                     or len(roster_occurrences[(*member_key[:3], candidate["team"], pid)]) > 1
                     or (gid is not None and len(candidate_keys[(pid, gid)]) > 1))
        candidate["roster_membership_ambiguous"] = ambiguous
        if ambiguous:
            issue("ambiguous_roster_membership", candidate["artifact"], candidate["row"])
        supported = participation.get((pid, gid)) if not candidate["source_namespace_declarations"] else None
        if supported:
            candidate["participation"] = supported["state"]
            candidate["participation_evidence"] = dict(supported, verification="caller_asserted_independent_evidence")
        matches = stat_games.get((pid, gid), []) if gid and _identifier(pid) and not candidate["source_namespace_declarations"] else []
        candidate["statistics_match_count"] = len(matches) if gid else None
        candidate["game_completion"] = games[gid][0]["completion"] if gid else None
        candidate["historical_completion_verified"] = False
        if gid and len(matches) != 1:
            issue("candidate_stats_join_zero" if not matches else "candidate_stats_join_multiple", candidate["artifact"], candidate["row"], match_count=len(matches))
        usable = bool(gid and not ambiguous and candidate["identity_match_count"] == 1 and len(matches) == 1)
        if usable and matches[0][2]["team"] != candidate["team"]:
            issue("statistics_team_disagreement", candidate["artifact"], candidate["row"])
            usable = False
        candidate["outcomes"] = {}
        for name in ("targets", "receptions", "receiving_yards"):
            value, parsed = None, None
            if not gid:
                state = "no_unambiguous_game"
            elif not matches:
                state = "missing_statistics_row"
            elif not usable:
                state = "unresolved_relationship"
            else:
                value = matches[0][2][name]
                parsed = _number(value, low=-1000000 if name == "receiving_yards" else 0)
                state = ("null" if value in NULLS else "malformed") if parsed is None else ("zero" if parsed == 0 else "negative" if parsed < 0 else "positive")
            candidate["outcomes"][name] = dict(state=state, raw_value=value, parsed_integer=parsed)
            outcome_counts[name + ":" + state] += 1
        candidate["outcome_usable_retrospectively"] = (usable and candidate["game_completion"] == "retrospective_result_only"
                                                       and candidate["outcomes"]["receiving_yards"]["parsed_integer"] is not None)
        if supported and supported["state"] == "known_inactive" and matches:
            issue("inactive_statistics_conflict", candidate["artifact"], candidate["row"])
            candidate["outcome_usable_retrospectively"] = False
        budget.retain(candidate)

    compatibility = {}
    for role, prefix in (("stats", "stats"), ("roster", "rosters")):
        left, right = raw[prefix + "_2025"], raw[prefix + "_2026"]
        a, b = set(left["columns"]), set(right["columns"])
        compatibility[role] = dict(only_2025=sorted(a-b), only_2026=sorted(b-a), column_order_equal=left["columns"] == right["columns"],
                                   required_columns=list(REQUIRED[role]),
                                   parse_failures_2025=left["parse_failures"], parse_failures_2026=right["parse_failures"],
                                   missing_values_2025=left["missing_required_values"], missing_values_2026=right["missing_required_values"],
                                   status=("insufficient_rows" if not left["row_count"] or not right["row_count"] else
                                           "compatible_under_explicit_csv_rules" if not left["parse_failures"] and not right["parse_failures"] else "unresolved"),
                                   physical_types_verified=False)
    current = [g for g in schedule if g["season"] == 2026 and g["phase"] == "REG"]
    completed = [g for g in current if g["historical_completion_verified"] and len(games[g["game_id"]]) == 1]
    retrospective_results = [g for g in current if g["retrospective_result_observed"] and len(games[g["game_id"]]) == 1]
    weeks = defaultdict(list)
    for game in current:
        weeks[game["week"]].append(game)
    complete_weeks = [w for w, rows in weeks.items() if all(r in completed for r in rows)]
    latest_game = max(completed, key=lambda g: (g["reported_gameday"], g["reported_gametime"], g["game_id"]), default=None)
    dated_results = [g for g in retrospective_results if g["completion"] not in ("invalid_game_time", "future_game")]
    latest_result_game = max(dated_results, key=lambda g: (g["reported_gameday"], g["reported_gametime"], g["game_id"]), default=None)
    def observed_week(aid):
        observed = (_period(row, SPECS[aid]["role"]) for row in tables[aid].rows)
        return max((p[2] for p in observed if p and p[0] == 2026 and p[1] == "REG"), default=None)
    latest_week = max(complete_weeks, default=None)
    covered = set()
    for (pid, gid), rows in stat_games.items():
        for _, _, row in rows:
            key = (gid, row["team"])
            if key not in covered:
                budget.retain(key)
                covered.add(key)
    roster_coverage = set()
    for aid in ("rosters_2025", "rosters_2026"):
        for row in tables[aid].rows:
            period = _period(row, "roster")
            if period and period[0] == SPECS[aid]["season"]:
                key = (*period, row["team"])
                if key not in roster_coverage:
                    budget.retain(key)
                    roster_coverage.add(key)
    coverage = []
    for game in sorted(schedule, key=lambda g: (g["season"], g["phase"], g["week"], g["game_id"], g["row"])):
        if game["season"] not in (2025, 2026):
            continue
        for team in (game["home_team"], game["away_team"]):
            has_roster = (game["season"], game["phase"], game["week"], team) in roster_coverage
            item = dict(game_id=game["game_id"], season=game["season"], phase=game["phase"], week=game["week"], team=team,
                        completion=game["completion"], any_statistics_row=(game["game_id"], team) in covered,
                        retrospective_result_observed=game["retrospective_result_observed"],
                        historical_completion_verified=game["historical_completion_verified"],
                        any_roster_row=has_roster)
            budget.retain(item)
            coverage.append(item)
    changes = []
    affiliations = defaultdict(list)
    for (season, phase, week, pid), teams in sorted(memberships.items()):
        if phase == "REG":
            affiliations[(season, pid)].append((week, sorted(teams)))
    for (season, pid), observations in sorted(affiliations.items()):
        if len({t for _, teams in observations for t in teams}) > 1:
            changes.append(dict(season=season, player_id=pid, week_teams=[[w, teams] for w, teams in observations]))
    source_ages = {}
    for aid in SPECS:
        source_ages[aid] = {}
        for name in ("provider_publication_at", "hosting_asset_at", "edgefinder_acquired_at"):
            stamp = tables[aid].evidence.get(name)
            source_ages[aid][name] = (reference - _instant(stamp)).total_seconds() if reference and stamp else None
    result = dict(report_version=1, mode="offline_retrospective_inspection", reference_as_of=as_of,
                  player_identifier_semantics="opaque_source_field_strings_not_verified_GSIS_no_namespace_crosswalks",
                  completion_rule_interpretation="plan_rule_checks_kickoff_consistency_only_current_scores_never_verify_historical_completion",
                  explicit_csv_parse_rules=CSV_RULES,
                  raw_observations=raw,
                  interpretations=dict(analysis_windows=WINDOWS, schedule_games=schedule, statistics_joins=stat_joins,
                                       wr_candidates=candidates, outcome_counts=dict(sorted(outcome_counts.items())), team_changes=changes,
                                       game_team_coverage=coverage,
                                       cross_season_identifiers=dict(stats_shared=sorted(seen_ids["2025"] & seen_ids["2026"]),
                                                                     roster_shared=sorted(roster_seen["2025"] & roster_seen["2026"]), matching="exact_strings_only")),
                  schema_compatibility=compatibility,
                  freshness=dict(season=2026, latest_observed_regular_season_week=max(weeks, default=None),
                                 latest_observed_completed_game=latest_game, latest_fully_completed_observed_week=latest_week,
                                 historical_completion_evidence="unavailable_no_completion_evidence_contract",
                                 latest_retrospective_result_game=latest_result_game,
                                 retrospective_result_game_ids=[g["game_id"] for g in retrospective_results],
                                 retrospective_result_coverage_is_not_completion_at_reference=True,
                                 latest_receiving_statistics_week=observed_week("stats_2026"),
                                 latest_weekly_roster_week=observed_week("rosters_2026"),
                                 coverage_meaning="latest_week_means_at_least_one_source_row_not_complete_coverage",
                                 coverage_differences=[r for r in coverage if r["season"] == 2026 and r["phase"] == "REG" and r["retrospective_result_observed"] and (not r["any_statistics_row"] or not r["any_roster_row"])],
                                 coverage_differences_basis="retrospective_results_not_historical_completion",
                                 latest_completed_week_coverage=[r for r in coverage if r["season"] == 2026 and r["phase"] == "REG" and r["week"] == latest_week] if latest_week is not None else [],
                                 publication_evidence_missing=[aid for aid in SPECS if tables[aid].evidence.get("provider_publication_at") is None],
                                 publication_verification="caller_assertions_only_not_authenticated",
                                 source_age_seconds_relative_to_explicit_reference=source_ages,
                                 negative_age_means_after_reference_not_available_by_reference=True,
                                 completeness="not_established_by_latest_week_numbers"),
                  historical_availability=dict(pregame_knowability="not_established", eligibility="retrospective_only",
                                               local_inspection_at=None, current_files_do_not_prove_historical_availability=True),
                  findings=findings,
                  limitations=["CSV_only_no_Parquet_Arrow_Polars_or_nflreadpy_validation", "real_provider_completeness_not_established",
                               "roster_status_and_statistics_do_not_establish_game_day_participation", "no_hard_process_memory_limit",
                               "current_scores_and_undated_FINAL_status_do_not_establish_historical_completion",
                               "explicit_player_namespaces_are_preserved_but_unresolved_without_a_verified_mapping",
                               "no_live_acquisition_or_database_access"])
    budget.retain(result)
    result["retained_content_accounting"] = dict(bytes=budget.counts["retained_bytes"], cap=LIMITS["retained_bytes"],
                                                measure="compact_UTF8_JSON_source_columns_rows_derived_keys_records_and_report_excluding_this_field_including_repeated_representations",
                                                hard_process_memory_limit=False)
    return result


def inspect_manifest(root, manifest_path, *, plan_path=None, as_of=None):
    """Validate exactly six local files then inspect. Only stdout CLI output."""
    read_plan(plan_path)
    manifest = _read_json(manifest_path)
    if type(manifest) is not dict or set(manifest) - {"artifacts", "verification_evidence", "participation_evidence"} or type(manifest.get("artifacts")) is not list:
        raise InspectionError("invalid_manifest")
    entries = manifest["artifacts"]
    for entry in entries:
        _entry(entry)
    if len(entries) != 6 or {e["artifact_id"] for e in entries} != set(SPECS):
        raise InspectionError("six_exact_artifacts_required")
    verification = manifest.get("verification_evidence")
    if verification is not None and (not _text(verification) or len(verification.encode("utf-8")) > 4096):
        raise InspectionError("invalid_manifest_verification")
    participation = manifest.get("participation_evidence", [])
    if type(participation) is not list:
        raise InspectionError("invalid_participation_evidence")
    entries = {e["artifact_id"]: e for e in entries}
    budget = Budget()
    tables = {aid: validate_artifact(root, entries[aid], budget=budget) for aid in SPECS}
    result = inspect_rows(tables, as_of=as_of, participation_evidence=participation)
    extra = dict(validation_budget=dict(budget.counts), manifest_verification=dict(evidence=verification, authenticated_by_utility=False))
    accounted = result["retained_content_accounting"]["bytes"] + len(_json(extra).encode("utf-8"))
    if accounted > LIMITS["retained_bytes"]:
        raise InspectionError("limit_exceeded", limit="retained_bytes")
    result.update(extra)
    result["retained_content_accounting"]["bytes"] = accounted
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--plan")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--plan")
    inspect.add_argument("--root", required=True)
    inspect.add_argument("--manifest", required=True)
    inspect.add_argument("--as-of", help="Explicit timestamp with offset; never taken from local clock")
    sub.add_parser("acquire", help="Disabled: no live transport is implemented or authorized")
    args = parser.parse_args(argv)
    try:
        if args.command == "acquire":
            raise InspectionError("acquisition_not_implemented_or_authorized")
        if args.command == "preflight":
            read_plan(args.plan)
            result = dict(mode="offline_only", plan_valid=True, acquisition_enabled=False, files_created=0)
        else:
            result = inspect_manifest(args.root, args.manifest, plan_path=args.plan, as_of=args.as_of)
        print(_json(result))
        return 0
    except InspectionError as error:
        print(_json(dict(error=error.code, details=error.details)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
