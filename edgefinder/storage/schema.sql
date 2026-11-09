-- Normalized evidence only. No original downloaded files are hashed here.
CREATE TABLE entity (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('PLAYER','TEAM','GAME')),
    label TEXT NOT NULL
) STRICT;

CREATE TABLE identifier_namespace (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL CHECK(length(provider)>0),
    kind TEXT NOT NULL CHECK(kind IN ('PLAYER','TEAM','GAME')),
    name TEXT NOT NULL CHECK(length(name)>0),
    UNIQUE(provider,kind,name)
) STRICT;

CREATE TABLE source_snapshot (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL CHECK(length(provider)>0),
    role TEXT NOT NULL CHECK(role IN ('IDENTITY','SCHEDULE','STATS')),
    loader_scope TEXT NOT NULL CHECK(length(loader_scope)>0),
    normalization_version TEXT NOT NULL CHECK(normalization_version='edgefinder.normalized.v1'),
    normalized_sha256 TEXT NOT NULL CHECK(length(normalized_sha256)=64 AND normalized_sha256 NOT GLOB '*[^0-9a-f]*'),
    original_file_sha256 TEXT CHECK(original_file_sha256 IS NULL),
    retrieved_at TEXT CHECK(retrieved_at IS NULL OR
        (strftime('%Y-%m-%dT%H:%M:%SZ',retrieved_at,'+0 days') IS NOT NULL AND
         strftime('%Y-%m-%dT%H:%M:%SZ',retrieved_at,'+0 days')=retrieved_at)),
    publication_at TEXT CHECK(publication_at IS NULL OR
        (strftime('%Y-%m-%dT%H:%M:%SZ',publication_at,'+0 days') IS NOT NULL AND
         strftime('%Y-%m-%dT%H:%M:%SZ',publication_at,'+0 days')=publication_at)),
    publication_evidence TEXT,
    sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN (0,1)),
    CHECK((publication_at IS NULL AND publication_evidence IS NULL) OR
          (publication_at IS NOT NULL AND publication_evidence IS NOT NULL AND length(trim(publication_evidence))>0)),
    CHECK(publication_at IS NULL OR retrieved_at IS NULL OR publication_at<=retrieved_at),
    UNIQUE(provider,role,loader_scope,normalization_version,normalized_sha256)
) STRICT;

CREATE TABLE source_record (
    id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshot(id),
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    namespace_id INTEGER NOT NULL REFERENCES identifier_namespace(id),
    identifier TEXT,
    game_namespace_id INTEGER REFERENCES identifier_namespace(id),
    game_identifier TEXT,
    team_namespace_id INTEGER REFERENCES identifier_namespace(id),
    team_identifier TEXT,
    home_namespace_id INTEGER REFERENCES identifier_namespace(id),
    home_identifier TEXT,
    away_namespace_id INTEGER REFERENCES identifier_namespace(id),
    away_identifier TEXT,
    kickoff_local TEXT,
    kickoff_timezone TEXT,
    kickoff_utc TEXT CHECK(kickoff_utc IS NULL OR
        (kickoff_timezone IS NOT NULL AND length(trim(kickoff_timezone))>0 AND
         strftime('%Y-%m-%dT%H:%M:%SZ',kickoff_utc,'+0 days') IS NOT NULL AND
         strftime('%Y-%m-%dT%H:%M:%SZ',kickoff_utc,'+0 days')=kickoff_utc)),
    payload TEXT NOT NULL CHECK(valid_canonical(payload)=1),
    normalized TEXT NOT NULL CHECK(normalized=record_canonical(
        namespace_id,identifier,game_namespace_id,game_identifier,team_namespace_id,
        team_identifier,home_namespace_id,home_identifier,away_namespace_id,
        away_identifier,kickoff_local,kickoff_timezone,kickoff_utc,payload)),
    UNIQUE(snapshot_id,ordinal)
) STRICT;

CREATE TABLE validation_run (
    id INTEGER PRIMARY KEY,
    identity_snapshot INTEGER NOT NULL REFERENCES source_snapshot(id),
    schedule_snapshot INTEGER NOT NULL REFERENCES source_snapshot(id),
    stats_snapshot INTEGER NOT NULL REFERENCES source_snapshot(id),
    sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN (0,1))
) STRICT;

CREATE TABLE identifier_binding (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    namespace_id INTEGER NOT NULL REFERENCES identifier_namespace(id),
    identifier TEXT NOT NULL CHECK(length(identifier)>0),
    entity_id INTEGER NOT NULL REFERENCES entity(id),
    source_record_id INTEGER NOT NULL REFERENCES source_record(id),
    UNIQUE(run_id,namespace_id,identifier),
    UNIQUE(run_id,id)
) STRICT;

CREATE TABLE quarantine (
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    source_record_id INTEGER NOT NULL REFERENCES source_record(id),
    reason TEXT NOT NULL CHECK(length(trim(reason))>0),
    PRIMARY KEY(run_id,source_record_id)
) STRICT;

CREATE TABLE finding (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    source_record_id INTEGER REFERENCES source_record(id),
    severity TEXT NOT NULL CHECK(severity IN ('BLOCKING','WARNING')),
    code TEXT NOT NULL CHECK(length(code)>0),
    message TEXT NOT NULL CHECK(length(message)>0)
) STRICT;

CREATE TABLE game_observation (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    source_record_id INTEGER NOT NULL REFERENCES source_record(id),
    game_binding INTEGER NOT NULL,
    home_binding INTEGER NOT NULL,
    away_binding INTEGER NOT NULL,
    FOREIGN KEY(run_id,game_binding) REFERENCES identifier_binding(run_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(run_id,home_binding) REFERENCES identifier_binding(run_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(run_id,away_binding) REFERENCES identifier_binding(run_id,id) ON DELETE RESTRICT,
    UNIQUE(run_id,source_record_id),
    UNIQUE(run_id,game_binding),
    UNIQUE(run_id,id)
) STRICT;

CREATE TABLE player_game_observation (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    source_record_id INTEGER NOT NULL REFERENCES source_record(id),
    player_binding INTEGER NOT NULL,
    team_binding INTEGER NOT NULL,
    game_observation_id INTEGER NOT NULL,
    FOREIGN KEY(run_id,player_binding) REFERENCES identifier_binding(run_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(run_id,team_binding) REFERENCES identifier_binding(run_id,id) ON DELETE RESTRICT,
    FOREIGN KEY(run_id,game_observation_id) REFERENCES game_observation(run_id,id) ON DELETE RESTRICT,
    UNIQUE(run_id,source_record_id),
    UNIQUE(run_id,player_binding,game_observation_id)
) STRICT;

CREATE TABLE research_selection (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES validation_run(id),
    mode TEXT NOT NULL CHECK(mode IN ('RETROSPECTIVE','OBSERVED_BY_EDGEFINDER','VERIFIED_PUBLICATION')),
    as_of TEXT CHECK(as_of IS NULL OR
        (strftime('%Y-%m-%dT%H:%M:%SZ',as_of,'+0 days') IS NOT NULL AND
         strftime('%Y-%m-%dT%H:%M:%SZ',as_of,'+0 days')=as_of)),
    CHECK(mode='RETROSPECTIVE' OR as_of IS NOT NULL)
) STRICT;

-- Cover alias and player/game duplicate checks without reading payloads. The
-- ordering also serves grouped/window counts once per selected snapshot.
CREATE INDEX source_record_identity_keys ON source_record(
    snapshot_id,namespace_id,identifier,game_namespace_id,game_identifier);
CREATE INDEX binding_source ON identifier_binding(run_id,source_record_id);
CREATE INDEX game_home ON game_observation(run_id,home_binding);
CREATE INDEX game_away ON game_observation(run_id,away_binding);
CREATE INDEX player_game_team ON player_game_observation(run_id,team_binding);
CREATE INDEX player_game_game ON player_game_observation(run_id,game_observation_id);
CREATE INDEX finding_severity ON finding(run_id,severity);

CREATE TRIGGER entity_update BEFORE UPDATE ON entity BEGIN SELECT RAISE(ABORT,'entities are immutable'); END;
CREATE TRIGGER entity_delete BEFORE DELETE ON entity BEGIN SELECT RAISE(ABORT,'entities are immutable'); END;
CREATE TRIGGER namespace_update BEFORE UPDATE ON identifier_namespace BEGIN SELECT RAISE(ABORT,'namespaces are immutable'); END;
CREATE TRIGGER namespace_delete BEFORE DELETE ON identifier_namespace BEGIN SELECT RAISE(ABORT,'namespaces are immutable'); END;
CREATE TRIGGER snapshot_insert BEFORE INSERT ON source_snapshot WHEN NEW.sealed<>0
BEGIN SELECT RAISE(ABORT,'snapshots start unsealed'); END;
CREATE TRIGGER snapshot_delete BEFORE DELETE ON source_snapshot BEGIN SELECT RAISE(ABORT,'snapshots are immutable'); END;
CREATE TRIGGER snapshot_seal BEFORE UPDATE ON source_snapshot BEGIN
    SELECT CASE WHEN OLD.sealed=1 OR NEW.sealed<>1 OR
        NEW.id IS NOT OLD.id OR NEW.provider IS NOT OLD.provider OR NEW.role IS NOT OLD.role OR
        NEW.loader_scope IS NOT OLD.loader_scope OR NEW.normalization_version IS NOT OLD.normalization_version OR
        NEW.normalized_sha256 IS NOT OLD.normalized_sha256 OR NEW.original_file_sha256 IS NOT OLD.original_file_sha256 OR
        NEW.retrieved_at IS NOT OLD.retrieved_at OR NEW.publication_at IS NOT OLD.publication_at OR
        NEW.publication_evidence IS NOT OLD.publication_evidence
        THEN RAISE(ABORT,'only initial snapshot sealing is allowed') END;
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM source_record WHERE snapshot_id=OLD.id) OR
        NEW.normalized_sha256<>(SELECT evidence_hash(normalized) FROM source_record WHERE snapshot_id=OLD.id)
        THEN RAISE(ABORT,'normalized evidence hash mismatch') END;
END;
CREATE TRIGGER record_insert BEFORE INSERT ON source_record BEGIN
    SELECT CASE WHEN (SELECT sealed FROM source_snapshot WHERE id=NEW.snapshot_id)<>0
        THEN RAISE(ABORT,'snapshot is sealed') END;
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM source_snapshot s JOIN identifier_namespace n
        ON n.id=NEW.namespace_id AND n.provider=s.provider WHERE s.id=NEW.snapshot_id AND
        (s.role='IDENTITY' OR (s.role='SCHEDULE' AND n.kind='GAME') OR (s.role='STATS' AND n.kind='PLAYER')))
        THEN RAISE(ABORT,'source namespace/provider/role mismatch') END;
    SELECT CASE WHEN
        (NEW.game_namespace_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identifier_namespace WHERE id=NEW.game_namespace_id AND kind='GAME')) OR
        (NEW.team_namespace_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identifier_namespace WHERE id=NEW.team_namespace_id AND kind='TEAM')) OR
        (NEW.home_namespace_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identifier_namespace WHERE id=NEW.home_namespace_id AND kind='TEAM')) OR
        (NEW.away_namespace_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identifier_namespace WHERE id=NEW.away_namespace_id AND kind='TEAM'))
        THEN RAISE(ABORT,'relation namespace kind mismatch') END;
END;
CREATE TRIGGER record_update BEFORE UPDATE ON source_record BEGIN SELECT RAISE(ABORT,'source records are immutable'); END;
CREATE TRIGGER record_delete BEFORE DELETE ON source_record BEGIN SELECT RAISE(ABORT,'source records are immutable'); END;

CREATE TRIGGER run_insert BEFORE INSERT ON validation_run BEGIN
    SELECT CASE WHEN NEW.sealed<>0 OR
        NOT EXISTS(SELECT 1 FROM source_snapshot WHERE id=NEW.identity_snapshot AND role='IDENTITY' AND sealed=1) OR
        NOT EXISTS(SELECT 1 FROM source_snapshot WHERE id=NEW.schedule_snapshot AND role='SCHEDULE' AND sealed=1) OR
        NOT EXISTS(SELECT 1 FROM source_snapshot WHERE id=NEW.stats_snapshot AND role='STATS' AND sealed=1)
        THEN RAISE(ABORT,'run requires three explicitly selected sealed snapshot roles') END;
END;
CREATE TRIGGER run_delete BEFORE DELETE ON validation_run BEGIN SELECT RAISE(ABORT,'runs cannot be deleted'); END;
CREATE TRIGGER run_seal BEFORE UPDATE ON validation_run BEGIN
    SELECT CASE WHEN OLD.sealed=1 OR NEW.sealed<>1 OR NEW.id IS NOT OLD.id OR
        NEW.identity_snapshot IS NOT OLD.identity_snapshot OR NEW.schedule_snapshot IS NOT OLD.schedule_snapshot OR
        NEW.stats_snapshot IS NOT OLD.stats_snapshot THEN RAISE(ABORT,'only run sealing is allowed') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM finding WHERE run_id=OLD.id AND severity='BLOCKING')
        THEN RAISE(ABORT,'blocking findings prevent sealing') END;
    SELECT CASE WHEN EXISTS(
        SELECT 1 FROM source_record r WHERE r.snapshot_id IN (OLD.identity_snapshot,OLD.schedule_snapshot,OLD.stats_snapshot)
        AND NOT EXISTS(SELECT 1 FROM quarantine q WHERE q.run_id=OLD.id AND q.source_record_id=r.id)
        AND NOT EXISTS(SELECT 1 FROM identifier_binding b WHERE b.run_id=OLD.id AND b.source_record_id=r.id)
        AND NOT EXISTS(SELECT 1 FROM game_observation g WHERE g.run_id=OLD.id AND g.source_record_id=r.id)
        AND NOT EXISTS(SELECT 1 FROM player_game_observation p WHERE p.run_id=OLD.id AND p.source_record_id=r.id))
        THEN RAISE(ABORT,'every selected record must be interpreted or quarantined') END;
END;

CREATE TRIGGER binding_insert BEFORE INSERT ON identifier_binding BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run v JOIN source_record r ON r.snapshot_id=v.identity_snapshot
        JOIN identifier_namespace n ON n.id=r.namespace_id JOIN entity e ON e.id=NEW.entity_id AND e.kind=n.kind
        WHERE v.id=NEW.run_id AND v.sealed=0 AND r.id=NEW.source_record_id AND
        r.namespace_id=NEW.namespace_id AND r.identifier=NEW.identifier)
        THEN RAISE(ABORT,'invalid identity binding evidence') END;
    SELECT CASE WHEN (SELECT count(*) FROM source_record r WHERE r.snapshot_id=(SELECT identity_snapshot FROM validation_run WHERE id=NEW.run_id)
        AND r.namespace_id=NEW.namespace_id AND r.identifier=NEW.identifier)<>1
        THEN RAISE(ABORT,'ambiguous or duplicate identity alias') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM quarantine WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id)
        THEN RAISE(ABORT,'quarantined evidence cannot be promoted') END;
END;
CREATE TRIGGER binding_update BEFORE UPDATE ON identifier_binding BEGIN SELECT RAISE(ABORT,'replace open bindings by delete/insert'); END;
CREATE TRIGGER binding_delete BEFORE DELETE ON identifier_binding BEGIN
    SELECT CASE WHEN (SELECT sealed FROM validation_run WHERE id=OLD.run_id)=1
        THEN RAISE(ABORT,'run is sealed') END;
    -- REPLACE deletes before inserting: even a same-key replacement must fail.
    SELECT CASE WHEN
        EXISTS(SELECT 1 FROM game_observation WHERE run_id=OLD.run_id AND game_binding=OLD.id) OR
        EXISTS(SELECT 1 FROM game_observation WHERE run_id=OLD.run_id AND home_binding=OLD.id) OR
        EXISTS(SELECT 1 FROM game_observation WHERE run_id=OLD.run_id AND away_binding=OLD.id) OR
        EXISTS(SELECT 1 FROM player_game_observation WHERE run_id=OLD.run_id AND player_binding=OLD.id) OR
        EXISTS(SELECT 1 FROM player_game_observation WHERE run_id=OLD.run_id AND team_binding=OLD.id)
        THEN RAISE(ABORT,'referenced bindings cannot be deleted or replaced') END;
END;

CREATE TRIGGER quarantine_insert BEFORE INSERT ON quarantine BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run v JOIN source_record r
        ON r.snapshot_id IN (v.identity_snapshot,v.schedule_snapshot,v.stats_snapshot)
        WHERE v.id=NEW.run_id AND v.sealed=0 AND r.id=NEW.source_record_id)
        THEN RAISE(ABORT,'quarantine snapshot mismatch or sealed run') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM identifier_binding WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id) OR
        EXISTS(SELECT 1 FROM game_observation WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id) OR
        EXISTS(SELECT 1 FROM player_game_observation WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id)
        THEN RAISE(ABORT,'promoted evidence cannot be quarantined') END;
END;
CREATE TRIGGER quarantine_update BEFORE UPDATE ON quarantine BEGIN SELECT RAISE(ABORT,'replace open quarantine by delete/insert'); END;
CREATE TRIGGER quarantine_delete BEFORE DELETE ON quarantine WHEN (SELECT sealed FROM validation_run WHERE id=OLD.run_id)=1
BEGIN SELECT RAISE(ABORT,'run is sealed'); END;

CREATE TRIGGER finding_insert BEFORE INSERT ON finding BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run v WHERE v.id=NEW.run_id AND v.sealed=0 AND
        (NEW.source_record_id IS NULL OR EXISTS(SELECT 1 FROM source_record r WHERE r.id=NEW.source_record_id AND
        r.snapshot_id IN (v.identity_snapshot,v.schedule_snapshot,v.stats_snapshot))))
        THEN RAISE(ABORT,'finding snapshot mismatch or sealed run') END;
END;
CREATE TRIGGER finding_update BEFORE UPDATE ON finding BEGIN SELECT RAISE(ABORT,'replace open findings by delete/insert'); END;
CREATE TRIGGER finding_delete BEFORE DELETE ON finding WHEN (SELECT sealed FROM validation_run WHERE id=OLD.run_id)=1
BEGIN SELECT RAISE(ABORT,'run is sealed'); END;

CREATE TRIGGER game_insert BEFORE INSERT ON game_observation BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run v JOIN source_record r ON r.snapshot_id=v.schedule_snapshot
        JOIN identifier_binding g ON g.id=NEW.game_binding AND g.run_id=v.id AND g.namespace_id=r.namespace_id AND g.identifier=r.identifier
        JOIN identifier_binding h ON h.id=NEW.home_binding AND h.run_id=v.id AND h.namespace_id=r.home_namespace_id AND h.identifier=r.home_identifier
        JOIN identifier_binding a ON a.id=NEW.away_binding AND a.run_id=v.id AND a.namespace_id=r.away_namespace_id AND a.identifier=r.away_identifier
        WHERE v.id=NEW.run_id AND v.sealed=0 AND r.id=NEW.source_record_id AND h.entity_id<>a.entity_id)
        THEN RAISE(ABORT,'invalid schedule join') END;
    SELECT CASE WHEN (SELECT count(*) FROM source_record r WHERE r.snapshot_id=(SELECT schedule_snapshot FROM validation_run WHERE id=NEW.run_id)
        AND r.namespace_id=(SELECT namespace_id FROM source_record WHERE id=NEW.source_record_id)
        AND r.identifier=(SELECT identifier FROM source_record WHERE id=NEW.source_record_id))<>1
        THEN RAISE(ABORT,'ambiguous or duplicate schedule') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM quarantine WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id) OR
        EXISTS(SELECT 1 FROM game_observation o JOIN identifier_binding b ON b.id=o.game_binding
        WHERE o.run_id=NEW.run_id AND b.entity_id=(SELECT entity_id FROM identifier_binding WHERE id=NEW.game_binding))
        THEN RAISE(ABORT,'quarantined or duplicate game') END;
END;
CREATE TRIGGER game_update BEFORE UPDATE ON game_observation BEGIN SELECT RAISE(ABORT,'replace open observations by delete/insert'); END;
CREATE TRIGGER game_delete BEFORE DELETE ON game_observation BEGIN
    SELECT CASE WHEN (SELECT sealed FROM validation_run WHERE id=OLD.run_id)=1
        THEN RAISE(ABORT,'run is sealed') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM player_game_observation WHERE run_id=OLD.run_id AND game_observation_id=OLD.id)
        THEN RAISE(ABORT,'referenced game observations cannot be deleted or replaced') END;
END;

CREATE TRIGGER player_game_insert BEFORE INSERT ON player_game_observation BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run v JOIN source_record r ON r.snapshot_id=v.stats_snapshot
        JOIN identifier_binding p ON p.id=NEW.player_binding AND p.run_id=v.id AND p.namespace_id=r.namespace_id AND p.identifier=r.identifier
        JOIN identifier_binding t ON t.id=NEW.team_binding AND t.run_id=v.id AND t.namespace_id=r.team_namespace_id AND t.identifier=r.team_identifier
        JOIN game_observation o ON o.id=NEW.game_observation_id AND o.run_id=v.id
        JOIN identifier_binding g ON g.id=o.game_binding AND g.namespace_id=r.game_namespace_id AND g.identifier=r.game_identifier
        JOIN identifier_binding h ON h.id=o.home_binding JOIN identifier_binding a ON a.id=o.away_binding
        WHERE v.id=NEW.run_id AND v.sealed=0 AND r.id=NEW.source_record_id AND t.entity_id IN (h.entity_id,a.entity_id))
        THEN RAISE(ABORT,'unresolved player or invalid stats join') END;
    SELECT CASE WHEN (SELECT count(*) FROM source_record r WHERE r.snapshot_id=(SELECT stats_snapshot FROM validation_run WHERE id=NEW.run_id)
        AND r.namespace_id=(SELECT namespace_id FROM source_record WHERE id=NEW.source_record_id)
        AND r.identifier=(SELECT identifier FROM source_record WHERE id=NEW.source_record_id)
        AND r.game_namespace_id=(SELECT game_namespace_id FROM source_record WHERE id=NEW.source_record_id)
        AND r.game_identifier=(SELECT game_identifier FROM source_record WHERE id=NEW.source_record_id))<>1
        THEN RAISE(ABORT,'ambiguous or duplicate player-game stats') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM quarantine WHERE run_id=NEW.run_id AND source_record_id=NEW.source_record_id) OR
        EXISTS(SELECT 1 FROM player_game_observation o JOIN identifier_binding b ON b.id=o.player_binding
        WHERE o.run_id=NEW.run_id AND o.game_observation_id=NEW.game_observation_id AND
        b.entity_id=(SELECT entity_id FROM identifier_binding WHERE id=NEW.player_binding))
        THEN RAISE(ABORT,'quarantined or duplicate player-game') END;
END;
CREATE TRIGGER player_game_update BEFORE UPDATE ON player_game_observation BEGIN SELECT RAISE(ABORT,'replace open observations by delete/insert'); END;
CREATE TRIGGER player_game_delete BEFORE DELETE ON player_game_observation WHEN (SELECT sealed FROM validation_run WHERE id=OLD.run_id)=1
BEGIN SELECT RAISE(ABORT,'run is sealed'); END;

CREATE TRIGGER selection_insert BEFORE INSERT ON research_selection BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM validation_run WHERE id=NEW.run_id AND sealed=1)
        THEN RAISE(ABORT,'research requires a sealed run') END;
    SELECT CASE WHEN NEW.mode<>'RETROSPECTIVE' AND EXISTS(
        SELECT 1 FROM source_snapshot s JOIN validation_run v ON s.id IN (v.identity_snapshot,v.schedule_snapshot,v.stats_snapshot)
        WHERE v.id=NEW.run_id AND
        ((NEW.mode='OBSERVED_BY_EDGEFINDER' AND (s.retrieved_at IS NULL OR s.retrieved_at>NEW.as_of)) OR
         (NEW.mode='VERIFIED_PUBLICATION' AND (s.publication_at IS NULL OR s.publication_evidence IS NULL OR s.publication_at>NEW.as_of))))
        THEN RAISE(ABORT,'selected evidence lacks historical time support') END;
END;
CREATE TRIGGER selection_update BEFORE UPDATE ON research_selection BEGIN SELECT RAISE(ABORT,'research selections are immutable'); END;
CREATE TRIGGER selection_delete BEFORE DELETE ON research_selection BEGIN SELECT RAISE(ABORT,'research selections are immutable'); END;
