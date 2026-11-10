-- B1.3a: synthetic evidence only. recorded_at is ledger time, not source
-- retrieval/publication time. Raw digests establish byte integrity, not origin.
-- WITHOUT ROWID prevents incremental BLOB edits that bypass SQL update guards.
CREATE TABLE raw_artifact (
    sha256 TEXT PRIMARY KEY NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*' AND instr(sha256,char(0))=0),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 0 AND 67108864),
    body BLOB NOT NULL CHECK(typeof(body)='blob' AND length(body)<=67108864 AND length(body)=byte_length),
    CHECK(sha256=artifact_sha256(body))
) STRICT, WITHOUT ROWID;

CREATE TABLE acquisition_observation (
    id INTEGER PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE CHECK(length(event_key) BETWEEN 1 AND 128 AND event_key GLOB '[A-Za-z0-9]*' AND event_key NOT GLOB '*[^A-Za-z0-9._:-]*' AND instr(event_key,char(0))=0),
    evidence_kind TEXT NOT NULL CHECK(evidence_kind='SYNTHETIC'),
    provider TEXT NOT NULL CHECK(length(provider) BETWEEN 1 AND 128 AND provider GLOB '[a-z0-9]*' AND provider NOT GLOB '*[^a-z0-9._-]*' AND instr(provider,char(0))=0),
    logical_artifact_id TEXT NOT NULL CHECK(length(logical_artifact_id) BETWEEN 1 AND 256 AND logical_artifact_id GLOB '[a-z0-9]*' AND logical_artifact_id NOT GLOB '*[^a-z0-9._-]*' AND instr(logical_artifact_id,char(0))=0),
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 1024 AND scope=trim(scope) AND scope NOT GLOB '*[^ -~]*' AND instr(scope,char(0))=0),
    declared_format TEXT NOT NULL CHECK(length(declared_format) BETWEEN 1 AND 64 AND declared_format GLOB '[a-z0-9]*' AND declared_format NOT GLOB '*[^a-z0-9._-]*' AND instr(declared_format,char(0))=0),
    recorded_at TEXT NOT NULL CHECK(length(CAST(recorded_at AS BLOB))=20 AND substr(recorded_at,1,4)>='0001' AND
        strftime('%Y-%m-%dT%H:%M:%SZ',recorded_at,'+0 days') IS NOT NULL AND
        strftime('%Y-%m-%dT%H:%M:%SZ',recorded_at,'+0 days')=recorded_at),
    outcome TEXT NOT NULL CHECK(outcome IN ('SUCCESS','FAILURE')),
    artifact_sha256 TEXT REFERENCES raw_artifact(sha256) ON DELETE RESTRICT,
    failure_code TEXT CHECK(failure_code IS NULL OR failure_code IN (
        'invalid_input','url_policy','redirect_policy','address_policy',
        'resolver_failure','transport_failure','response_protocol','status_rejected',
        'redirect_loop','redirect_limit','byte_limit','deadline_exceeded',
        'clock_failure','stream_failure','cleanup_failure')),
    cleanup_failed INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_failed IN (0,1)),
    CHECK((outcome='SUCCESS' AND artifact_sha256 IS NOT NULL AND failure_code IS NULL AND cleanup_failed=0) OR
          (outcome='FAILURE' AND artifact_sha256 IS NULL AND failure_code IS NOT NULL))
) STRICT;

CREATE TABLE snapshot_derivation (
    id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshot(id) ON DELETE RESTRICT,
    transformation_id TEXT NOT NULL CHECK(length(transformation_id) BETWEEN 1 AND 128 AND transformation_id GLOB '[a-z0-9]*' AND transformation_id NOT GLOB '*[^a-z0-9._-]*' AND instr(transformation_id,char(0))=0),
    transformation_version TEXT NOT NULL CHECK(length(transformation_version) BETWEEN 1 AND 128 AND transformation_version GLOB '[a-z0-9]*' AND transformation_version NOT GLOB '*[^a-z0-9._-]*' AND instr(transformation_version,char(0))=0),
    parameters TEXT NOT NULL CHECK(length(CAST(parameters AS BLOB))<=65536 AND valid_canonical(parameters)=1),
    recorded_at TEXT NOT NULL CHECK(length(CAST(recorded_at AS BLOB))=20 AND substr(recorded_at,1,4)>='0001' AND
        strftime('%Y-%m-%dT%H:%M:%SZ',recorded_at,'+0 days') IS NOT NULL AND
        strftime('%Y-%m-%dT%H:%M:%SZ',recorded_at,'+0 days')=recorded_at),
    expected_input_count INTEGER NOT NULL CHECK(expected_input_count BETWEEN 1 AND 4096),
    evidence_kind TEXT NOT NULL CHECK(evidence_kind='SYNTHETIC'),
    sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN (0,1))
) STRICT;

CREATE TABLE derivation_input (
    derivation_id INTEGER NOT NULL REFERENCES snapshot_derivation(id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    input_label TEXT NOT NULL CHECK(length(input_label) BETWEEN 1 AND 128 AND input_label GLOB '[a-z0-9]*' AND input_label NOT GLOB '*[^a-z0-9._-]*' AND instr(input_label,char(0))=0),
    observation_id INTEGER NOT NULL REFERENCES acquisition_observation(id) ON DELETE RESTRICT,
    PRIMARY KEY(derivation_id,ordinal)
) STRICT;

CREATE INDEX observation_artifact ON acquisition_observation(artifact_sha256);
CREATE INDEX derivation_snapshot ON snapshot_derivation(snapshot_id);
CREATE INDEX input_observation ON derivation_input(observation_id);

-- Insertion guards also reject REPLACE before its implicit deletion, including
-- unreferenced rows. No persistence/idempotency API is introduced here.
CREATE TRIGGER artifact_insert BEFORE INSERT ON raw_artifact
WHEN EXISTS(SELECT 1 FROM raw_artifact WHERE sha256=NEW.sha256)
BEGIN SELECT RAISE(ABORT,'artifacts cannot be replaced'); END;
CREATE TRIGGER artifact_update BEFORE UPDATE ON raw_artifact
BEGIN SELECT RAISE(ABORT,'artifacts are immutable'); END;
CREATE TRIGGER artifact_delete BEFORE DELETE ON raw_artifact
BEGIN SELECT RAISE(ABORT,'artifacts are immutable'); END;

CREATE TRIGGER acquisition_insert BEFORE INSERT ON acquisition_observation
WHEN EXISTS(SELECT 1 FROM acquisition_observation WHERE id=NEW.id OR event_key=NEW.event_key)
BEGIN SELECT RAISE(ABORT,'acquisition observations cannot be replaced'); END;
CREATE TRIGGER acquisition_update BEFORE UPDATE ON acquisition_observation
BEGIN SELECT RAISE(ABORT,'acquisition observations are immutable'); END;
CREATE TRIGGER acquisition_delete BEFORE DELETE ON acquisition_observation
BEGIN SELECT RAISE(ABORT,'acquisition observations are immutable'); END;

CREATE TRIGGER derivation_insert BEFORE INSERT ON snapshot_derivation BEGIN
    SELECT CASE WHEN EXISTS(SELECT 1 FROM snapshot_derivation WHERE id=NEW.id)
        THEN RAISE(ABORT,'derivations cannot be replaced') END;
    SELECT CASE WHEN NEW.sealed<>0 OR NOT EXISTS(
        SELECT 1 FROM source_snapshot WHERE id=NEW.snapshot_id AND sealed=1 AND
        retrieved_at IS NULL AND publication_at IS NULL AND publication_evidence IS NULL)
        THEN RAISE(ABORT,'synthetic derivations require a sealed snapshot without historical timestamps') END;
END;
CREATE TRIGGER derivation_delete BEFORE DELETE ON snapshot_derivation
BEGIN SELECT RAISE(ABORT,'derivations cannot be deleted'); END;
CREATE TRIGGER derivation_seal BEFORE UPDATE ON snapshot_derivation BEGIN
    SELECT CASE WHEN OLD.sealed<>0 OR NEW.sealed<>1 OR
        NEW.id IS NOT OLD.id OR NEW.snapshot_id IS NOT OLD.snapshot_id OR
        NEW.transformation_id IS NOT OLD.transformation_id OR
        NEW.transformation_version IS NOT OLD.transformation_version OR
        NEW.parameters IS NOT OLD.parameters OR NEW.recorded_at IS NOT OLD.recorded_at OR
        NEW.expected_input_count IS NOT OLD.expected_input_count OR NEW.evidence_kind IS NOT OLD.evidence_kind
        THEN RAISE(ABORT,'only initial derivation sealing is allowed') END;
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM source_snapshot WHERE id=NEW.snapshot_id AND sealed=1 AND
        retrieved_at IS NULL AND publication_at IS NULL AND publication_evidence IS NULL)
        THEN RAISE(ABORT,'synthetic output is not eligible') END;
    SELECT CASE WHEN
        (SELECT count(*) FROM derivation_input WHERE derivation_id=OLD.id)<>NEW.expected_input_count OR
        (SELECT min(ordinal) FROM derivation_input WHERE derivation_id=OLD.id) IS NOT 0 OR
        (SELECT max(ordinal) FROM derivation_input WHERE derivation_id=OLD.id) IS NOT (NEW.expected_input_count-1)
        THEN RAISE(ABORT,'derivation requires a complete contiguous input set') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM derivation_input i
        LEFT JOIN acquisition_observation o ON o.id=i.observation_id
        LEFT JOIN raw_artifact a ON a.sha256=o.artifact_sha256
        WHERE i.derivation_id=OLD.id AND (o.id IS NULL OR o.evidence_kind IS NOT NEW.evidence_kind OR
        o.outcome IS NOT 'SUCCESS' OR a.sha256 IS NULL))
        THEN RAISE(ABORT,'derivation inputs must be successful synthetic observations') END;
END;

CREATE TRIGGER input_insert BEFORE INSERT ON derivation_input BEGIN
    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM snapshot_derivation d
        JOIN acquisition_observation o ON o.id=NEW.observation_id AND o.outcome='SUCCESS' AND
        o.evidence_kind=d.evidence_kind JOIN raw_artifact a ON a.sha256=o.artifact_sha256
        WHERE d.id=NEW.derivation_id AND d.sealed=0 AND NEW.ordinal<d.expected_input_count)
        THEN RAISE(ABORT,'input requires an open derivation and a successful synthetic observation') END;
END;
CREATE TRIGGER input_update BEFORE UPDATE ON derivation_input
BEGIN SELECT RAISE(ABORT,'replace open derivation inputs by delete/insert'); END;
CREATE TRIGGER input_delete BEFORE DELETE ON derivation_input
WHEN (SELECT sealed FROM snapshot_derivation WHERE id=OLD.derivation_id)=1
BEGIN SELECT RAISE(ABORT,'derivation is sealed'); END;
