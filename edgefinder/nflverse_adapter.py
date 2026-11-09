"""Offline nflverse preparation; importing this module performs no acquisition.

Acquisition audit (installed nflreadpy 0.1.5, source inspected read-only):
``__init__.py`` imports cache/config; ``config.py`` constructs BaseSettings with
env_file='.env' at import. Updating config after import is too late to prevent
that read. Cache defaults to memory; filesystem mode calls mkdir and reads/writes
Parquet in ``cache.py``. ``downloader.py`` constructs a global downloader and
Requests Session at import; Requests defaults to trust_env=True (environment
proxies and .netrc credentials may be consulted when requests are prepared).

UNENFORCED PHASE B REQUIREMENTS (no acquisition is implemented here):
Live acquisition requires separately approved isolated execution with a minimal,
credential-free environment, private temporary working/home/cache directories,
NFLREADPY_CACHE=off BEFORE provider import, and automatic dotenv loading disabled
BEFORE settings construction. An empty working directory alone is not a dotenv
opt-out. Configure every Requests session with trust_env=False before any network
activity, including the provider's import-created session; preserve TLS
certificate verification (verify=True). No automatic proxies or .netrc lookup.
Do not change the host cwd or globally patch production settings as isolation.

Before EACH request or redirect is sent, validate the resolved URL: HTTPS only,
exact approved hostnames, only approved ports (initial policy: default/443), no
URL-embedded credentials, and explicitly approved initial repository paths.
Disable automatic redirects; validate every Location/next URL before traffic,
with a bounded redirect count (proposed maximum 5, subject to Phase B approval).
GitHub release asset destination hosts are UNVERIFIED until live acquisition is
separately approved. Never wildcard-allow githubusercontent.com or automatically
trust a hostname discovered in a redirect. No downloader/URL policy is enforced
by this offline module; Phase B must implement and test these safeguards first.

Inspect actual schemas before approving field/phase mappings. In particular,
2025 field semantics, preseason week 0 and postseason numbering remain
UNVERIFIED. This module's conventions are explicit synthetic-data contracts.
Schedules downloads the entire games artifact before season filtering and can
clean roof values; players/teams are global reference tables. Loader outputs
therefore are parsed evidence, never original-file evidence.

Rows accept storage-supported Python values plus exact Python date/datetime
types. Dates become ISO calendar strings; datetimes become ISO strings retaining
microseconds and offset, with original type/fold/timezone recorded in per-row
provenance. Naive datetimes stay naive. No conversion invents UTC or discards a
time component to manufacture a gameday. Custom tzinfo/subclasses and unsupported
types fail explicitly. Parsed hashes cover records AND conversion annotations,
so date/datetime inputs cannot collide with otherwise identical source strings.
Fields default to players.gsis_id, teams.team_abbr, schedules.game_id and
stats.player_id/team/opponent_team. SourceInput mappings explicitly select source
fields and translate phase labels only; identifiers/numbers are never coerced.
The caller supplies loader scope and actual observation/publication assertions;
this module never invents historical availability or a current retrieval time.

The input envelope is independent of sample selection and can also feed future
season preparation/refresh. This module implements neither scheduling nor stale
data policy. A sample of completed receiving stats is RETROSPECTIVE research;
it is not a pregame feature set or a probability estimate.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timezone
import math
import re
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo

from edgefinder.storage.database import canonical, evidence_hash


ADAPTER_VERSION = "edgefinder.nflverse.sample.v2"
PARSED_NORMALIZATION_VERSION = "edgefinder.nflverse.parsed.v2"


@dataclass(frozen=True)
class SourceInput:
    """Parsed records and caller-asserted metadata for one loader invocation.

    loader_scope must describe the actual acquisition scope, not just selected
    rows. Null temporal metadata means unknown, including for synthetic inputs.
    """

    rows: Iterable[dict]
    loader_scope: str
    retrieved_at: str | None = None
    publication_at: str | None = None
    publication_evidence: str | None = None
    # Logical field -> exact source column, never automatic alias guessing.
    field_mapping: Mapping[str, str] | None = None
    # Only game_type/season_type translations are allowed; source stays in record.
    value_mappings: Mapping[str, Mapping[str, str]] | None = None


@dataclass(frozen=True)
class NFLInputs:
    season: int
    players: SourceInput
    teams: SourceInput
    schedules: SourceInput
    stats: SourceInput


@dataclass(frozen=True)
class Namespaces:
    """Existing nflverse PLAYER/TEAM/GAME namespace IDs; no database access."""

    player: int
    team: int
    game: int


@dataclass(frozen=True)
class PreparedSnapshot:
    role: str
    loader_scope: str
    rows: tuple[dict, ...]
    retrieved_at: str | None
    publication_at: str | None
    publication_evidence: str | None

    def storage_kwargs(self):
        """Arguments for storage.add_snapshot; original-file hash stays NULL.

        Storage computes its own normalized_sha256 over the derived records.
        source_parsed_sha256 hashes supplied parsed rows plus type conversions,
        with order ignored and duplicates retained. Neither hashes file bytes.
        """
        return dict(provider="nflverse", role=self.role,
                    loader_scope=self.loader_scope, rows=deepcopy(self.rows),
                    retrieved_at=self.retrieved_at,
                    publication_at=self.publication_at,
                    publication_evidence=self.publication_evidence)


@dataclass(frozen=True)
class PreparedGameSample:
    season: int
    game_id: str
    player_ids: dict[str, str]
    identity: PreparedSnapshot
    schedule: PreparedSnapshot
    stats: PreparedSnapshot


def fetch_nflverse_inputs(season: int) -> NFLInputs:
    """Reserved acquisition boundary, deliberately disabled for Phase A.

    Future loader plan (do not execute without separate Phase B approval):
    players = nflreadpy.load_players()
    teams = nflreadpy.load_teams()
    schedules = nflreadpy.load_schedules(seasons=[season])
    stats = nflreadpy.load_player_stats(seasons=[season], summary_level='week')
    Return NFLInputs with explicit scopes and per-call retrieval assertions.
    All unenforced Phase B isolation, trust_env=False, verified TLS, dotenv/cache
    opt-out and per-hop URL restrictions in this module's contract are required
    before enabling these loaders. They are not implemented by this stub.
    No live test exists here. A future live test needs its own explicit opt-in
    and must remain excluded from ordinary unittest discovery/network access.
    """
    raise NotImplementedError("Phase A is offline; acquisition requires Phase B approval")


def _text(value, field, pattern=None):
    if type(value) is not str or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be explicit nonempty text")
    if pattern is not None and not re.fullmatch(pattern, value):
        raise ValueError(f"Invalid {field}")
    return value


def _integer(value, field, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"Invalid {field}: expected integer in [{low}, {high}]")
    return value


def _timestamp(value):
    if value is not None:
        _text(value, "timestamp", r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
        datetime.fromisoformat(value)
    return value


class _SourceRecord(dict):
    """Working logical fields, separate from encoded original source fields."""

    def __init__(self, values, record, conversions):
        super().__init__(values)
        self.record = record
        self.conversions = conversions


def _encode_record(value, path, conversions):
    """Only narrow, reversible standard-library temporal conversions are added."""
    if type(value) is date:
        result = value.isoformat()
        conversions.append(dict(path=path, python_type="date", iso8601=result))
        return result
    if type(value) is datetime:
        zone = value.tzinfo
        if zone is not None and type(zone) not in (timezone, ZoneInfo):
            raise ValueError(f"Unsupported datetime timezone at {path!r}")
        result = value.isoformat(timespec="microseconds")
        zone_info = (dict(kind="naive") if zone is None else
                     dict(kind="zoneinfo", key=zone.key) if type(zone) is ZoneInfo else
                     dict(kind="fixed_offset", name=value.tzname()))
        conversions.append(dict(path=path, python_type="datetime", iso8601=result,
                                fold=value.fold, timezone=zone_info))
        return result
    if type(value) is dict:
        if not all(type(key) is str for key in value):
            raise ValueError(f"Source dictionary keys must be text at {path!r}")
        return {key: _encode_record(value[key], [*path, key], conversions)
                for key in sorted(value)}
    if type(value) is list:
        return [_encode_record(item, [*path, i], conversions) for i, item in enumerate(value)]
    try:
        canonical(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Unsupported source value at {path!r}: {type(value).__name__}") from error
    return value


_SOURCE_FIELDS = {
    "load_players": ("gsis_id",),
    "load_teams": ("team_abbr",),
    "load_schedules": ("season", "week", "game_type", "game_id", "home_team",
                       "away_team", "gameday", "gametime"),
    "load_player_stats": ("season", "week", "season_type", "game_id", "player_id",
                          "team", "opponent_team", "targets", "receptions",
                          "receiving_yards", "receiving_tds"),
}
_PHASE_VALUES = {
    "game_type": ("PRE", "REG", "WC", "DIV", "CON", "SB"),
    "season_type": ("PRE", "REG", "POST"),
}


def _mappings(source, loader):
    fields = dict(source.field_mapping or {})
    values = {key: dict(mapping) for key, mapping in (source.value_mappings or {}).items()}
    allowed = _SOURCE_FIELDS[loader]
    if set(fields) - set(allowed):
        raise ValueError(f"Unknown logical field mapping for {loader}")
    for logical, name in fields.items():
        _text(name, f"source field for {logical}")
    resolved = [fields.get(field, field) for field in allowed]
    if len(set(resolved)) != len(resolved):
        raise ValueError("Source field mapping must not reuse a column")
    for field, mapping in values.items():
        if field not in _PHASE_VALUES or field not in allowed:
            raise ValueError("Only schedule/stats phase value mappings are supported")
        for raw, translated in mapping.items():
            _text(raw, "source phase label")
            if type(translated) is not str or translated not in _PHASE_VALUES[field]:
                raise ValueError("Unsupported mapped phase value")
    return fields, values


def _source(source, loader):
    _text(source.loader_scope, "loader_scope")
    retrieved = _timestamp(source.retrieved_at)
    published = _timestamp(source.publication_at)
    if (published is None) != (source.publication_evidence is None):
        raise ValueError("Publication timestamp and evidence are required together")
    if published is not None:
        _text(source.publication_evidence, "publication_evidence")
        if retrieved is not None and published > retrieved:
            raise ValueError("Publication cannot follow retrieval")
    fields, values = _mappings(source, loader)
    rows, parsed = [], []
    for row in source.rows:
        if type(row) is not dict:
            raise ValueError("Supply parsed dictionary records, not a dataframe")
        conversions = []
        record = _encode_record(row, [], conversions)
        parsed.append(canonical(dict(record=record, conversions=conversions)))
        working = dict(record)
        for logical, source_field in fields.items():
            working.pop(logical, None)
            if source_field in record:
                working[logical] = record[source_field]
        for field, mapping in values.items():
            if field in working:
                raw = working[field]
                if type(raw) is not str or raw not in mapping:
                    raise ValueError(f"Unmapped source phase value for {field}")
                working[field] = mapping[raw]
        rows.append(_SourceRecord(working, record, conversions))
    provenance = dict(provider="nflverse", loader=loader,
                      loader_scope=source.loader_scope,
                      source_parsed_sha256=evidence_hash(parsed),
                      parsed_normalization_version=PARSED_NORMALIZATION_VERSION,
                      hash_kind="parsed_rows_not_original_file",
                      field_mapping=fields, value_mappings=values,
                      retrieved_at=retrieved, publication_at=published,
                      publication_evidence=source.publication_evidence)
    return rows, provenance


def _field(row, name):
    if name not in row:
        raise ValueError(f"Missing required source field: {name}")
    return row[name]


def _gsis(value):
    return _text(value, "GSIS identifier", r"[0-9]{2}-[0-9]{7}")


def _team(value):
    return _text(value, "team abbreviation", r"[A-Z]{2,4}")


def _period(row, kind):
    season = _integer(_field(row, "season"), "season", 1000, 9999)
    week = _integer(_field(row, "week"), "week", 0, 99)
    raw = _field(row, "game_type" if kind == "schedule" else "season_type")
    allowed = {"PRE": "PRE", "REG": "REG", "WC": "POST", "DIV": "POST", "CON": "POST", "SB": "POST"}
    if kind == "schedule":
        if type(raw) is not str or raw not in allowed:
            raise ValueError("Invalid schedule game_type")
        phase = allowed[raw]
    else:
        if type(raw) is not str or raw not in ("PRE", "REG", "POST"):
            raise ValueError("Invalid stats season_type")
        phase = raw
    if week == 0 and phase != "PRE":
        raise ValueError("Week 0 requires an explicit PRE phase; verify source semantics in Phase B")
    return season, week, phase


def _snapshot(role, rows, provenances, selection):
    # All dependencies must support a temporal assertion. The latest time is the
    # first instant the entire derived snapshot could have been observed/public.
    def latest(field):
        times = [p[field] for p in provenances]
        return max(times) if all(t is not None for t in times) else None

    published = latest("publication_at")
    rows = deepcopy(rows)
    for row in rows:
        row["payload"]["selection_dependencies"] = deepcopy(provenances)
    return PreparedSnapshot(
        role=role,
        loader_scope=canonical(dict(adapter=ADAPTER_VERSION, selection=selection,
                                    inputs=[{k: p[k] for k in ("loader", "loader_scope")}
                                            for p in provenances])),
        rows=tuple(sorted(rows, key=canonical)),
        retrieved_at=latest("retrieved_at"), publication_at=published,
        publication_evidence=canonical(provenances) if published is not None else None)


def prepare_game_sample(inputs: NFLInputs, *, namespaces: Namespaces,
                        game_id: str | None = None,
                        player_ids: Mapping[str, str] | None = None) -> PreparedGameSample:
    """Prepare an explicitly scoped sample with no I/O or input mutation.

    Without game_id choose the lexicographically first exact schedule game ID
    having receiving activity on both teams; without player_ids choose the
    smallest active GSIS ID per team. Activity means any supported receiving
    metric is positive (null is unknown, never zero). Selection ignores row order.
    Explicit player_ids must map each participating team to one active GSIS ID.

    Every stat row must resolve to exactly one schedule row using season, week,
    phase, team and opponent; a supplied stats.game_id must agree exactly. No
    inference from game ID substrings or player names. Identical stats duplicates
    for selected players are retained for storage quarantine, never summed or
    silently deduplicated. Selected player identities must occur exactly once.
    Unrelated reference rows with absent/null GSIS IDs are retained in parsed
    input evidence without being treated as aliases. Duplicate team identities
    and schedule IDs fail closed. Raw fields, extras, nulls and numeric types
    survive in payload.record, with explicit temporal conversion annotations.
    Every snapshot includes all four selection/validation input dependencies.
    Unknown kickoff timezone/UTC remain null.
    """
    season = _integer(inputs.season, "season", 1000, 9999)
    ns = (namespaces.player, namespaces.team, namespaces.game)
    if any(type(n) is not int or n <= 0 for n in ns) or len(set(ns)) != 3:
        raise ValueError("Supply three distinct positive namespace IDs")
    players, pp = _source(inputs.players, "load_players")
    teams, tp = _source(inputs.teams, "load_teams")
    schedules, gp = _source(inputs.schedules, "load_schedules")
    stats, sp = _source(inputs.stats, "load_player_stats")

    def unique(rows, field, validator):
        indexed = {}
        for row in rows:
            key = validator(_field(row, field))
            if key in indexed:
                raise ValueError(f"Ambiguous identity: duplicate {field} {key}")
            indexed[key] = row
        return indexed

    player_candidates = {}
    for row in players:
        key = row.get("gsis_id")
        if key is None:
            continue  # Not an alias; remains covered by the parsed-input hash.
        player_candidates.setdefault(_gsis(key), []).append(row)
    team_index = unique(teams, "team_abbr", _team)
    games, resolutions, kickoffs = {}, {}, {}
    for row in schedules:
        period = _period(row, "schedule")
        home, away = _team(_field(row, "home_team")), _team(_field(row, "away_team"))
        if home == away or home not in team_index or away not in team_index:
            raise ValueError("Invalid schedule team identities")
        gid = _text(_field(row, "game_id"), "game_id")
        if gid != f"{period[0]}_{period[1]:02d}_{away}_{home}":
            raise ValueError("Schedule game_id disagrees with source fields")
        if gid in games:
            raise ValueError("Ambiguous schedule game_id")
        games[gid] = row
        for team, opponent in ((home, away), (away, home)):
            key = (*period, team, opponent)
            resolutions.setdefault(key, []).append(gid)
        day, time = _field(row, "gameday"), _field(row, "gametime")
        if day is not None:
            _text(day, "gameday", r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
            date.fromisoformat(day)
        if time is not None:
            _text(time, "gametime", r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")
        kickoffs[gid] = f"{day} {time}" if day is not None and time is not None else None

    resolved, active, player_teams = {}, {}, {}
    for row in stats:
        period = _period(row, "stats")
        pid = _gsis(_field(row, "player_id"))
        if pid not in player_candidates:
            raise ValueError("Stats GSIS identifier has no player identity")
        team = _team(_field(row, "team"))
        opponent = _team(_field(row, "opponent_team"))
        candidates = resolutions.get((*period, team, opponent), [])
        if len(candidates) != 1:
            raise ValueError("Unresolved or ambiguous stats game resolution")
        gid = candidates[0]
        if "game_id" in row and row["game_id"] != gid:
            raise ValueError("Stats game_id disagrees with exact schedule game_id")
        prior_team = player_teams.setdefault((gid, pid), team)
        if prior_team != team:
            raise ValueError("Ambiguous player identity: multiple teams in one game")
        positive = False
        for field in ("targets", "receptions", "receiving_yards", "receiving_tds"):
            value = _field(row, field)
            if value is None:
                continue
            if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)):
                raise ValueError(f"Invalid receiving field: {field}")
            if field != "receiving_yards" and value < 0:
                raise ValueError(f"Negative receiving count: {field}")
            if field != "receiving_yards" and type(value) is float and not value.is_integer():
                raise ValueError(f"Fractional receiving count: {field}")
            positive |= value > 0
        resolved.setdefault(gid, []).append(row)
        if positive:
            active.setdefault((gid, team), set()).add(pid)

    eligible = sorted(gid for gid, row in games.items() if row["season"] == season
                      and active.get((gid, row["home_team"]))
                      and active.get((gid, row["away_team"])))
    if game_id is None:
        if not eligible:
            raise ValueError("No game has receiving-active players on both teams")
        game_id = eligible[0]
    else:
        _text(game_id, "game_id")
        if game_id not in eligible:
            raise ValueError("Requested exact game_id is not eligible for this season")
    game = games[game_id]
    participants = sorted((game["home_team"], game["away_team"]))
    if player_ids is None:
        chosen = {t: min(active[game_id, t]) for t in participants}
    else:
        if set(player_ids) != set(participants):
            raise ValueError("player_ids must specify exactly the participating teams")
        chosen = dict(player_ids)
        for team, pid in chosen.items():
            if _gsis(pid) not in active[game_id, team]:
                raise ValueError("Requested player is not receiving-active for this team/game")
    if len(set(chosen.values())) != 2:
        raise ValueError("One player cannot represent both participating teams")
    player_index = {}
    for pid in chosen.values():
        candidates = player_candidates.get(pid, [])
        if not candidates:
            raise ValueError("Selected stats GSIS identifier has no player identity")
        if len(candidates) != 1:
            raise ValueError(f"Ambiguous identity: duplicate selected gsis_id {pid}")
        player_index[pid] = candidates[0]

    def payload(row, provenance):
        provenance = dict(deepcopy(provenance), conversions=deepcopy(row.conversions))
        return dict(record=deepcopy(row.record), provenance=provenance,
                    derivation=ADAPTER_VERSION)

    identity_rows = [dict(namespace_id=namespaces.player, identifier=pid,
                          payload=payload(player_index[pid], pp)) for pid in chosen.values()]
    identity_rows += [dict(namespace_id=namespaces.team, identifier=t,
                           payload=payload(team_index[t], tp)) for t in participants]
    identity_rows.append(dict(namespace_id=namespaces.game, identifier=game_id,
                              payload=payload(game, gp)))
    schedule_rows = [dict(namespace_id=namespaces.game, identifier=game_id,
                         home_namespace_id=namespaces.team, home_identifier=game["home_team"],
                         away_namespace_id=namespaces.team, away_identifier=game["away_team"],
                         kickoff_local=kickoffs[game_id], payload=payload(game, gp))]
    stats_rows = [dict(namespace_id=namespaces.player, identifier=row["player_id"],
                       game_namespace_id=namespaces.game, game_identifier=game_id,
                       team_namespace_id=namespaces.team, team_identifier=row["team"],
                       payload=payload(row, sp)) for row in resolved[game_id]
                  if row["player_id"] == chosen[row["team"]]]
    selection = dict(season=season, game_id=game_id, player_ids=chosen)
    return PreparedGameSample(
        season, game_id, chosen,
        _snapshot("IDENTITY", identity_rows, [pp, tp, gp, sp], selection),
        _snapshot("SCHEDULE", schedule_rows, [pp, tp, gp, sp], selection),
        _snapshot("STATS", stats_rows, [pp, tp, gp, sp], selection))
