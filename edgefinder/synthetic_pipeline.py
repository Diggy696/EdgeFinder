"""Supervised synthetic A1 coordination: sequential commits, never retries.

The caller owns the connection and must provide exclusive use, no concurrent
external database writes, and trusted nonsensitive fixtures. Injected executable
objects are not sandboxed or made immutable by freezing their specification.
No durable execution journal exists. A crash returns no result. Limits bound
accepted evidence, not RSS, lock waits, callback runtime, or total elapsed time.
"""

from dataclasses import dataclass, replace
from enum import Enum
import sqlite3
from typing import Callable

from .acquisition import runner
from .acquisition.contracts import AddressRules, URLRules
from . import synthetic_transform as transform
from .storage import database, lineage, provenance, synthetic as storage
from .storage.synthetic import SyntheticObservationMetadata


class PipelineStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


class StageOutcome(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNRESOLVED = "unresolved"


class CommitKnowledge(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    CONFIRMED = "CONFIRMED"
    NOT_COMMITTED = "NOT_COMMITTED"
    UNKNOWN = "UNKNOWN"


class PipelineStage(str, Enum):
    PREFLIGHT = "preflight"
    ACQUISITION = "acquisition"
    OBSERVATION_PERSISTENCE = "observation_persistence"
    ARTIFACT_VERIFICATION = "artifact_verification"
    TRANSFORMATION = "transformation"
    SNAPSHOT_PERSISTENCE = "snapshot_persistence"
    SNAPSHOT_VERIFICATION = "snapshot_verification"
    LINEAGE_REGISTRATION = "lineage_registration"
    LINEAGE_VERIFICATION = "lineage_verification"


class PipelineFailureCode(str, Enum):
    PREFLIGHT_REJECTED = "preflight_rejected"
    ACQUISITION_ENVIRONMENT = "acquisition_environment"
    ACQUISITION_FAILED = "acquisition_failed"
    SUCCESS_INPUT_INVALID = "success_input_invalid"
    SUCCESS_PERSISTENCE_FAILED = "success_persistence_failed"
    FAILURE_PERSISTENCE_FAILED = "failure_persistence_failed"
    ARTIFACT_MISMATCH = "artifact_mismatch"
    ARTIFACT_VERIFICATION_FAILED = "artifact_verification_failed"
    TRANSFORMATION_FAILED = "transformation_failed"
    SNAPSHOT_INPUT_INVALID = "snapshot_input_invalid"
    SNAPSHOT_PERSISTENCE_FAILED = "snapshot_persistence_failed"
    SNAPSHOT_MISMATCH = "snapshot_mismatch"
    SNAPSHOT_VERIFICATION_FAILED = "snapshot_verification_failed"
    LINEAGE_INPUT_INVALID = "lineage_input_invalid"
    LINEAGE_REGISTRATION_FAILED = "lineage_registration_failed"
    LINEAGE_MISMATCH = "lineage_mismatch"
    LINEAGE_VERIFICATION_FAILED = "lineage_verification_failed"


@dataclass(frozen=True, slots=True)
class SyntheticAcquisitionSpec:
    observation: SyntheticObservationMetadata
    initial_url: str
    url_rules: URLRules
    address_rules: AddressRules
    resolver: runner.SyntheticResolver
    transport: runner.SyntheticTransport
    clock: Callable[[], float]
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class SyntheticInputOccurrence:
    acquisition_index: int
    input_label: str


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    acquisition_index: int
    outcome: StageOutcome = StageOutcome.NOT_ATTEMPTED
    effective_max_bytes: int | None = None
    byte_count: int | None = None
    sha256: str | None = None
    failure_code: runner.OfflineFailureCode | None = None
    cleanup_failed: bool | None = None
    observation_id: int | None = None
    observation_commit: CommitKnowledge = CommitKnowledge.NOT_ATTEMPTED


@dataclass(frozen=True, slots=True)
class ResolvedSyntheticInput:
    ordinal: int
    acquisition_index: int
    input_label: str
    observation_id: int | None
    artifact_sha256: str | None


@dataclass(frozen=True, slots=True)
class StageReport:
    stage: PipelineStage
    acquisition_index: int | None = None
    outcome: StageOutcome = StageOutcome.NOT_ATTEMPTED
    commit_knowledge: CommitKnowledge | None = None


@dataclass(frozen=True, slots=True)
class PipelineFailure:
    stage: PipelineStage
    code: PipelineFailureCode
    acquisition_index: int | None = None
    detail_code: str | None = None  # Only existing acquisition/transform enum values.


@dataclass(frozen=True, slots=True)
class SyntheticPipelineResult:
    status: PipelineStatus
    acquisitions: tuple[AcquisitionResult, ...]
    stages: tuple[StageReport, ...]
    inputs: tuple[ResolvedSyntheticInput, ...]
    snapshot_id: int | None
    derivation_id: int | None
    acquired_bytes: int
    occurrence_expanded_bytes: int
    output_row_count: int | None
    canonical_normalized_bytes: int | None
    failure: PipelineFailure | None = None
    secondary_failure: PipelineFailure | None = None


_STORAGE_ERRORS = (sqlite3.Error, TypeError, ValueError, RuntimeError, KeyError)
_WRITES = {PipelineStage.OBSERVATION_PERSISTENCE, PipelineStage.SNAPSHOT_PERSISTENCE,
           PipelineStage.LINEAGE_REGISTRATION}


def _propagate_interruption(error):
    # Existing transaction cleanup can mask a control signal if rollback fails.
    # Inspect only exception identities/types; never stringify or retain them.
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if not isinstance(current, Exception) or isinstance(current, (MemoryError, RecursionError)):
            raise current from None
        for nested in (current.__context__, current.__cause__):
            if nested is not None:
                pending.append(nested)


def _validate_specifications(acquisitions, occurrences):
    if (type(acquisitions) is not tuple or not 1 <= len(acquisitions) <= storage.MAX_OCCURRENCES
            or type(occurrences) is not tuple or not 1 <= len(occurrences) <= storage.MAX_OCCURRENCES
            or any(type(item) is not SyntheticAcquisitionSpec for item in acquisitions)
            or any(type(item) is not SyntheticInputOccurrence for item in occurrences)):
        raise ValueError("Invalid bounded pipeline invocation")
    for spec in acquisitions:
        if (type(spec.initial_url) is not str or len(spec.initial_url) > 4096
                or type(spec.url_rules) is not URLRules or type(spec.address_rules) is not AddressRules
                or not callable(spec.clock)):
            raise ValueError("Invalid explicit runner configuration")
        runner.OfflineLimits(spec.timeout_seconds, max_bytes=storage.MAX_BODY_BYTES)


def _matches_derivation(actual, expected):
    if type(actual) is not lineage.Derivation:
        return False
    for name in ("derivation_id", "snapshot_id", "transformation_id", "transformation_version",
                 "parameters", "recorded_at", "expected_input_count", "evidence_kind", "sealed"):
        value, wanted = getattr(actual, name), getattr(expected, name)
        if type(value) is not type(wanted) or value != wanted:
            return False
    if type(actual.inputs) is not tuple or len(actual.inputs) != len(expected.inputs):
        return False
    for item, wanted in zip(actual.inputs, expected.inputs):
        if type(item) is not lineage.DerivationInput:
            return False
        for name in ("ordinal", "input_label", "observation_id", "artifact_sha256"):
            if type(getattr(item, name)) is not type(getattr(wanted, name)) or getattr(item, name) != getattr(wanted, name):
                return False
    return True


def run_synthetic_pipeline(
    db: sqlite3.Connection, *, acquisitions: tuple[SyntheticAcquisitionSpec, ...],
    occurrences: tuple[SyntheticInputOccurrence, ...], namespace_id: int,
    loader_scope: str, derivation_recorded_at: str,
) -> SyntheticPipelineResult:
    """Execute once, stop on failure, and preserve confirmed committed IDs.

    Documented storage exceptions after invoking a write yield UNKNOWN, even
    when that particular failure likely rolled back. Known validation failures
    before a write yield NOT_COMMITTED. No reconciliation or recovery writes are
    attempted. Read mismatch and inability to finish a read are distinct outcomes.
    """
    S, O, C, F = PipelineStage, StageOutcome, CommitKnowledge, PipelineFailureCode
    reports = {(S.PREFLIGHT, None): StageReport(S.PREFLIGHT)}
    acquired = []
    safe_occurrences = ()
    snapshot_id = derivation_id = None
    acquired_bytes = expanded_bytes = 0
    row_count = normalized_bytes = None

    def mark(stage, outcome, index=None, commit=None):
        reports[stage, index] = StageReport(stage, index, outcome, commit)

    def finish(status, failure=None, secondary=None):
        inputs = tuple(ResolvedSyntheticInput(
            ordinal, occurrence.acquisition_index, occurrence.input_label,
            acquired[occurrence.acquisition_index].observation_id,
            acquired[occurrence.acquisition_index].sha256)
            for ordinal, occurrence in enumerate(safe_occurrences))
        return SyntheticPipelineResult(status, tuple(acquired), tuple(reports.values()), inputs,
                                       snapshot_id, derivation_id, acquired_bytes, expanded_bytes,
                                       row_count, normalized_bytes, failure, secondary)

    try:
        storage.check_synthetic_connection(db)
        _validate_specifications(acquisitions, occurrences)
        acquired = [AcquisitionResult(index) for index in range(len(acquisitions))]
        for stage in (S.ACQUISITION, S.OBSERVATION_PERSISTENCE, S.ARTIFACT_VERIFICATION):
            for index in range(len(acquisitions)):
                mark(stage, O.NOT_ATTEMPTED, index, C.NOT_ATTEMPTED if stage in _WRITES else None)
        for stage in (S.TRANSFORMATION, S.SNAPSHOT_PERSISTENCE, S.SNAPSHOT_VERIFICATION,
                      S.LINEAGE_REGISTRATION, S.LINEAGE_VERIFICATION):
            mark(stage, O.NOT_ATTEMPTED, commit=C.NOT_ATTEMPTED if stage in _WRITES else None)
        indices = tuple(item.acquisition_index for item in occurrences)
        storage.preflight_synthetic_pipeline(
            db, metadata=tuple(spec.observation for spec in acquisitions), occurrence_indices=indices,
            input_labels=tuple(item.input_label for item in occurrences), namespace_id=namespace_id,
            loader_scope=loader_scope, derivation_recorded_at=derivation_recorded_at)
        # Method inspection is deliberately after target/schema/ownership checks.
        for spec in acquisitions:
            if not callable(getattr(spec.resolver, "resolve", None)) or not callable(getattr(spec.transport, "open", None)):
                raise ValueError("Explicit resolver and transport methods required")
    except (*_STORAGE_ERRORS, runner.OfflineAcquisitionError) as error:
        _propagate_interruption(error)
        mark(S.PREFLIGHT, O.FAILED)
        return finish(PipelineStatus.REJECTED, PipelineFailure(S.PREFLIGHT, F.PREFLIGHT_REJECTED))
    safe_occurrences = occurrences
    mark(S.PREFLIGHT, O.SUCCEEDED)
    multiplicities = [0] * len(acquisitions)
    for index in indices:
        multiplicities[index] += 1
    successes = []
    for index, spec in enumerate(acquisitions):
        try:
            storage.check_synthetic_connection(db)
        except _STORAGE_ERRORS as error:
            _propagate_interruption(error)
            mark(S.ACQUISITION, O.UNRESOLVED, index)
            return finish(PipelineStatus.INDETERMINATE,
                          PipelineFailure(S.ACQUISITION, F.ACQUISITION_ENVIRONMENT, index))
        cap = min(storage.MAX_BODY_BYTES, storage.MAX_TOTAL_BYTES - acquired_bytes,
                  (storage.MAX_TOTAL_BYTES - expanded_bytes) // multiplicities[index])
        acquired[index] = replace(acquired[index], effective_max_bytes=cap)
        try:
            success = runner.run_offline(
                spec.initial_url, url_rules=spec.url_rules, address_rules=spec.address_rules,
                resolver=spec.resolver, transport=spec.transport, clock=spec.clock,
                limits=runner.OfflineLimits(spec.timeout_seconds, max_bytes=cap))
        except runner.OfflineAcquisitionError as error:
            _propagate_interruption(error)
            if type(error.code) is not runner.OfflineFailureCode or type(error.cleanup_failed) is not bool:
                raise TypeError("Invalid runner failure contract") from None
            acquired[index] = replace(acquired[index], outcome=O.FAILED,
                                      failure_code=error.code, cleanup_failed=error.cleanup_failed)
            mark(S.ACQUISITION, O.FAILED, index)
            failure = PipelineFailure(S.ACQUISITION, F.ACQUISITION_FAILED, index, error.code.value)
            try:
                observation_id = provenance.persist_failure(
                    db, **spec.observation.persistence_kwargs(), failure_code=error.code,
                    cleanup_failed=error.cleanup_failed)
            except _STORAGE_ERRORS as recording_error:
                _propagate_interruption(recording_error)
                acquired[index] = replace(acquired[index], observation_commit=C.UNKNOWN)
                mark(S.OBSERVATION_PERSISTENCE, O.UNRESOLVED, index, C.UNKNOWN)
                return finish(PipelineStatus.INDETERMINATE, failure,
                              PipelineFailure(S.OBSERVATION_PERSISTENCE, F.FAILURE_PERSISTENCE_FAILED, index))
            acquired[index] = replace(acquired[index], observation_id=observation_id, observation_commit=C.CONFIRMED)
            mark(S.OBSERVATION_PERSISTENCE, O.SUCCEEDED, index, C.CONFIRMED)
            return finish(PipelineStatus.INCOMPLETE, failure)
        acquired[index] = replace(acquired[index], outcome=O.SUCCEEDED, byte_count=len(success.body),
                                  sha256=success.sha256, cleanup_failed=False)
        acquired_bytes += len(success.body)
        expanded_bytes += len(success.body) * multiplicities[index]
        mark(S.ACQUISITION, O.SUCCEEDED, index)
        try:
            storage.validate_success_for_persistence(spec.observation, success, max_bytes=cap)
        except (TypeError, ValueError):
            acquired[index] = replace(acquired[index], observation_commit=C.NOT_COMMITTED)
            mark(S.OBSERVATION_PERSISTENCE, O.FAILED, index, C.NOT_COMMITTED)
            return finish(PipelineStatus.INCOMPLETE,
                          PipelineFailure(S.OBSERVATION_PERSISTENCE, F.SUCCESS_INPUT_INVALID, index))
        try:
            observation_id = provenance.persist_success(
                db, **spec.observation.persistence_kwargs(), body=success.body, sha256=success.sha256)
        except _STORAGE_ERRORS as error:
            _propagate_interruption(error)
            acquired[index] = replace(acquired[index], observation_commit=C.UNKNOWN)
            mark(S.OBSERVATION_PERSISTENCE, O.UNRESOLVED, index, C.UNKNOWN)
            return finish(PipelineStatus.INDETERMINATE,
                          PipelineFailure(S.OBSERVATION_PERSISTENCE, F.SUCCESS_PERSISTENCE_FAILED, index))
        acquired[index] = replace(acquired[index], observation_id=observation_id, observation_commit=C.CONFIRMED)
        mark(S.OBSERVATION_PERSISTENCE, O.SUCCEEDED, index, C.CONFIRMED)
        successes.append(success)

    bodies = []
    for index, (spec, success) in enumerate(zip(acquisitions, successes)):
        try:
            body = storage.read_verified_synthetic_success(
                db, observation_id=acquired[index].observation_id, metadata=spec.observation, success=success)
        except storage.SyntheticEvidenceMismatch as error:
            _propagate_interruption(error)
            mark(S.ARTIFACT_VERIFICATION, O.FAILED, index)
            return finish(PipelineStatus.INCOMPLETE,
                          PipelineFailure(S.ARTIFACT_VERIFICATION, F.ARTIFACT_MISMATCH, index))
        except _STORAGE_ERRORS as error:
            _propagate_interruption(error)
            mark(S.ARTIFACT_VERIFICATION, O.UNRESOLVED, index)
            return finish(PipelineStatus.INDETERMINATE,
                          PipelineFailure(S.ARTIFACT_VERIFICATION, F.ARTIFACT_VERIFICATION_FAILED, index))
        bodies.append(body)
        mark(S.ARTIFACT_VERIFICATION, O.SUCCEEDED, index)
    try:
        prepared = transform.transform_synthetic_identity_v1(
            tuple(bodies), occurrence_indices=indices, namespace_id=namespace_id, loader_scope=loader_scope)
    except transform.SyntheticTransformError as error:
        mark(S.TRANSFORMATION, O.FAILED)
        return finish(PipelineStatus.INCOMPLETE,
                      PipelineFailure(S.TRANSFORMATION, F.TRANSFORMATION_FAILED, detail_code=error.code.value))
    row_count, normalized_bytes = len(prepared.rows), prepared.canonical_normalized_bytes
    mark(S.TRANSFORMATION, O.SUCCEEDED)
    try:
        rows = storage.snapshot_rows(prepared)
    except (TypeError, ValueError):
        mark(S.SNAPSHOT_PERSISTENCE, O.FAILED, commit=C.NOT_COMMITTED)
        return finish(PipelineStatus.INCOMPLETE, PipelineFailure(S.SNAPSHOT_PERSISTENCE, F.SNAPSHOT_INPUT_INVALID))
    try:
        snapshot_id = database.add_snapshot(db, provider=prepared.provider, role=prepared.role,
                                            loader_scope=prepared.loader_scope, rows=rows)
    except _STORAGE_ERRORS as error:
        _propagate_interruption(error)
        mark(S.SNAPSHOT_PERSISTENCE, O.UNRESOLVED, commit=C.UNKNOWN)
        return finish(PipelineStatus.INDETERMINATE, PipelineFailure(S.SNAPSHOT_PERSISTENCE, F.SNAPSHOT_PERSISTENCE_FAILED))
    mark(S.SNAPSHOT_PERSISTENCE, O.SUCCEEDED, commit=C.CONFIRMED)
    try:
        storage.verify_synthetic_snapshot(db, snapshot_id=snapshot_id, prepared=prepared)
    except storage.SyntheticEvidenceMismatch as error:
        _propagate_interruption(error)
        mark(S.SNAPSHOT_VERIFICATION, O.FAILED)
        return finish(PipelineStatus.INCOMPLETE, PipelineFailure(S.SNAPSHOT_VERIFICATION, F.SNAPSHOT_MISMATCH))
    except _STORAGE_ERRORS as error:
        _propagate_interruption(error)
        mark(S.SNAPSHOT_VERIFICATION, O.UNRESOLVED)
        return finish(PipelineStatus.INDETERMINATE, PipelineFailure(S.SNAPSHOT_VERIFICATION, F.SNAPSHOT_VERIFICATION_FAILED))
    mark(S.SNAPSHOT_VERIFICATION, O.SUCCEEDED)
    inputs = tuple((item.input_label, acquired[item.acquisition_index].observation_id) for item in occurrences)
    parameters = dict(namespace_id=namespace_id, loader_scope=loader_scope)
    try:
        storage.validate_derivation_for_registration(
            snapshot_id=snapshot_id, prepared=prepared, parameters=parameters,
            recorded_at=derivation_recorded_at, inputs=inputs)
    except (TypeError, ValueError):
        mark(S.LINEAGE_REGISTRATION, O.FAILED, commit=C.NOT_COMMITTED)
        return finish(PipelineStatus.INCOMPLETE, PipelineFailure(S.LINEAGE_REGISTRATION, F.LINEAGE_INPUT_INVALID))
    try:
        derivation_id = lineage.register_derivation(
            db, snapshot_id=snapshot_id, transformation_id=prepared.transformation_id,
            transformation_version=prepared.transformation_version, parameters=parameters,
            recorded_at=derivation_recorded_at, inputs=inputs)
    except _STORAGE_ERRORS as error:
        _propagate_interruption(error)
        mark(S.LINEAGE_REGISTRATION, O.UNRESOLVED, commit=C.UNKNOWN)
        return finish(PipelineStatus.INDETERMINATE, PipelineFailure(S.LINEAGE_REGISTRATION, F.LINEAGE_REGISTRATION_FAILED))
    mark(S.LINEAGE_REGISTRATION, O.SUCCEEDED, commit=C.CONFIRMED)
    try:
        derivation = lineage.get_derivation(db, derivation_id=derivation_id, verify_artifacts=True)
    except (sqlite3.IntegrityError, KeyError) as error:
        _propagate_interruption(error)
        mark(S.LINEAGE_VERIFICATION, O.FAILED)
        return finish(PipelineStatus.INCOMPLETE, PipelineFailure(S.LINEAGE_VERIFICATION, F.LINEAGE_MISMATCH))
    except _STORAGE_ERRORS as error:
        _propagate_interruption(error)
        mark(S.LINEAGE_VERIFICATION, O.UNRESOLVED)
        return finish(PipelineStatus.INDETERMINATE, PipelineFailure(S.LINEAGE_VERIFICATION, F.LINEAGE_VERIFICATION_FAILED))
    expected_inputs = tuple(lineage.DerivationInput(
        ordinal, item.input_label, acquired[item.acquisition_index].observation_id,
        acquired[item.acquisition_index].sha256) for ordinal, item in enumerate(occurrences))
    expected = lineage.Derivation(derivation_id, snapshot_id, prepared.transformation_id,
                                 prepared.transformation_version, database.canonical(parameters),
                                 derivation_recorded_at, len(inputs), "SYNTHETIC", True, expected_inputs)
    if not _matches_derivation(derivation, expected):
        mark(S.LINEAGE_VERIFICATION, O.FAILED)
        return finish(PipelineStatus.INCOMPLETE, PipelineFailure(S.LINEAGE_VERIFICATION, F.LINEAGE_MISMATCH))
    mark(S.LINEAGE_VERIFICATION, O.SUCCEEDED)
    return finish(PipelineStatus.COMPLETE)
