"""Bounded synthetic acquisition only; no live transport or authorization.

Injected fixtures are trusted executable code, not an isolation boundary.
Deadlines are cooperative and cannot interrupt blocked callbacks. The byte cap
covers retained payload, not RSS: finalization temporarily copies the buffer.
SHA-256 describes synthetic bytes, not authenticity or provider provenance.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import math
from typing import Callable, Protocol

from .contracts import AddressRules, URLRules, ValidatedConnectionPlan
from .policy import resolve_redirect, validate_addresses, validate_url


class OfflineFailureCode(str, Enum):
    """Stable, input-independent failure identifiers."""

    INVALID_INPUT = "invalid_input"
    URL_POLICY = "url_policy"
    REDIRECT_POLICY = "redirect_policy"
    ADDRESS_POLICY = "address_policy"
    RESOLVER_FAILURE = "resolver_failure"
    TRANSPORT_FAILURE = "transport_failure"
    RESPONSE_PROTOCOL = "response_protocol"
    STATUS_REJECTED = "status_rejected"
    REDIRECT_LOOP = "redirect_loop"
    REDIRECT_LIMIT = "redirect_limit"
    BYTE_LIMIT = "byte_limit"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CLOCK_FAILURE = "clock_failure"
    STREAM_FAILURE = "stream_failure"
    CLEANUP_FAILURE = "cleanup_failure"


class OfflineAcquisitionError(Exception):
    """Sanitized failure; never contains partial payload or dependency text.

    Suppressed exception contexts and tracebacks are not secure memory erasure.
    """

    def __init__(self, code: OfflineFailureCode):
        self.code = code
        self.cleanup_failed = False
        super().__init__(code.value)


def _invoke(code, function, *args, **kwargs):
    # Control signals propagate unchanged. Do not attach dependency exceptions.
    try:
        return function(*args, **kwargs)
    except Exception:
        raise OfflineAcquisitionError(code) from None


@dataclass(frozen=True, slots=True)
class OfflineLimits:
    timeout_seconds: float
    max_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        if (type(self.max_bytes) is not int or self.max_bytes < 0
                or type(self.timeout_seconds) not in (int, float)):
            raise OfflineAcquisitionError(OfflineFailureCode.INVALID_INPUT)
        try:
            timeout = float(self.timeout_seconds)
        except (OverflowError, ValueError):
            raise OfflineAcquisitionError(OfflineFailureCode.INVALID_INPUT) from None
        if not math.isfinite(timeout) or timeout <= 0:
            raise OfflineAcquisitionError(OfflineFailureCode.INVALID_INPUT)
        object.__setattr__(self, "timeout_seconds", timeout)


class SyntheticResolver(Protocol):
    def resolve(
        self, hostname: str, *, port: int, deadline: float
    ) -> tuple[str, ...]: ...


class SyntheticResponseStream(Protocol):
    status: int
    locations: tuple[str, ...]

    def read(self, max_bytes: int, *, deadline: float) -> bytes: ...
    def close(self) -> None: ...


class SyntheticTransport(Protocol):
    def open(
        self, plan: ValidatedConnectionPlan, *, deadline: float
    ) -> SyntheticResponseStream: ...


@dataclass(frozen=True, slots=True)
class OfflineSuccess:
    """Synthetic evidence only; ordered plans confer no live permission."""

    request_plans: tuple[ValidatedConnectionPlan, ...]
    body: bytes
    sha256: str

    def __post_init__(self):
        if (type(self.request_plans) is not tuple
                or not 1 <= len(self.request_plans) <= 4
                or any(type(plan) is not ValidatedConnectionPlan
                       for plan in self.request_plans)
                or type(self.body) is not bytes or type(self.sha256) is not str
                or len(self.sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.sha256)):
            raise OfflineAcquisitionError(OfflineFailureCode.INVALID_INPUT)


class _Checkpoint:
    """One clock validation path, one absolute budget, including finalization."""

    def __init__(self, clock, timeout):
        self.clock = clock
        self.timeout = timeout
        self.previous = None
        self.deadline = None
        self()

    def __call__(self):
        reading = _invoke(OfflineFailureCode.CLOCK_FAILURE, self.clock)
        if type(reading) not in (int, float):
            raise OfflineAcquisitionError(OfflineFailureCode.CLOCK_FAILURE)
        try:
            now = float(reading)
        except (OverflowError, ValueError):
            raise OfflineAcquisitionError(OfflineFailureCode.CLOCK_FAILURE) from None
        if (not math.isfinite(now)
                or (self.previous is not None and now < self.previous)):
            raise OfflineAcquisitionError(OfflineFailureCode.CLOCK_FAILURE)
        self.previous = now
        if self.deadline is None:
            self.deadline = now + self.timeout
            if not math.isfinite(self.deadline):
                raise OfflineAcquisitionError(OfflineFailureCode.CLOCK_FAILURE)
        if now >= self.deadline:
            raise OfflineAcquisitionError(OfflineFailureCode.DEADLINE_EXCEEDED)


def run_offline(
    initial_url: str,
    *,
    url_rules: URLRules,
    address_rules: AddressRules,
    resolver: SyntheticResolver,
    transport: SyntheticTransport,
    clock: Callable[[], float],
    limits: OfflineLimits,
) -> OfflineSuccess:
    """Run at most four synthetic requests; return all bytes or raise.

    Fixtures must do no I/O, never follow redirects, and consume the supplied
    plan without re-resolution or destination substitution. A transport that
    raises before returning a response owns its cleanup. Every returned response
    gets one close attempt here. A broken close cannot guarantee resource release.

    read(n) returns exact bytes, at most n; empty bytes mean permanent EOF.
    No framing, decoding, expected-length verification, retries or persistence.
    """
    code = OfflineFailureCode
    if (type(initial_url) is not str or len(initial_url) > 4096
            or type(url_rules) is not URLRules
            or type(address_rules) is not AddressRules
            or type(limits) is not OfflineLimits or not callable(clock)):
        raise OfflineAcquisitionError(code.INVALID_INPUT)
    methods = _invoke(code.INVALID_INPUT, lambda: (resolver.resolve, transport.open))
    if not all(callable(method) for method in methods):
        raise OfflineAcquisitionError(code.INVALID_INPUT)
    current = _invoke(code.URL_POLICY, validate_url, initial_url, rules=url_rules)
    checkpoint = _Checkpoint(clock, limits.timeout_seconds)
    visited = {current.url}
    plans = []
    retained = bytearray()
    digest = hashlib.sha256()

    while True:
        checkpoint()
        current = _invoke(code.URL_POLICY, validate_url, current.url, rules=url_rules)
        checkpoint()
        answers = _invoke(code.RESOLVER_FAILURE, methods[0], current.hostname,
                          port=current.port, deadline=checkpoint.deadline)
        checkpoint()
        if (type(answers) is not tuple or not 1 <= len(answers) <= 64
                or any(type(answer) is not str or len(answer) > 45 for answer in answers)):
            raise OfflineAcquisitionError(code.ADDRESS_POLICY)
        plan = _invoke(code.ADDRESS_POLICY, validate_addresses, current, answers,
                       policy=address_rules)
        checkpoint()
        response = _invoke(code.TRANSPORT_FAILURE, methods[1], plan,
                           deadline=checkpoint.deadline)
        # Ownership begins before ANY post-open operation, including the clock.
        primary = None
        try:
            checkpoint()
            plans.append(plan)
            status, locations, readable, closable = _invoke(
                code.RESPONSE_PROTOCOL,
                lambda: (response.status, response.locations,
                         callable(response.read), callable(response.close)))
            if (type(status) is not int or not 100 <= status <= 599
                    or type(locations) is not tuple or len(locations) > 1
                    or any(type(location) is not str or len(location) > 4096
                           for location in locations)
                    or not readable or not closable):
                raise OfflineAcquisitionError(code.RESPONSE_PROTOCOL)
            checkpoint()
            if status in (301, 302, 303, 307, 308):
                if len(locations) != 1:
                    raise OfflineAcquisitionError(code.RESPONSE_PROTOCOL)
                destination = _invoke(code.REDIRECT_POLICY, resolve_redirect,
                                      current, locations[0], rules=url_rules)
                checkpoint()
                if destination.url in visited:
                    raise OfflineAcquisitionError(code.REDIRECT_LOOP)
                if len(plans) == 4:
                    raise OfflineAcquisitionError(code.REDIRECT_LIMIT)
                visited.add(destination.url)
                current = destination
            elif status == 200:
                if locations:
                    raise OfflineAcquisitionError(code.RESPONSE_PROTOCOL)
                while True:
                    checkpoint()
                    requested = min(64 * 1024, limits.max_bytes - len(retained) + 1)
                    chunk = _invoke(code.STREAM_FAILURE, lambda: response.read(
                        requested, deadline=checkpoint.deadline))
                    checkpoint()
                    if type(chunk) is not bytes or len(chunk) > requested:
                        raise OfflineAcquisitionError(code.RESPONSE_PROTOCOL)
                    if not chunk:
                        break
                    if len(chunk) > limits.max_bytes - len(retained):
                        raise OfflineAcquisitionError(code.BYTE_LIMIT)
                    retained.extend(chunk)
                    digest.update(chunk)
                    checkpoint()
            else:
                raise OfflineAcquisitionError(code.STATUS_REJECTED)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                _invoke(code.CLEANUP_FAILURE, lambda: response.close())
            except BaseException as cleanup_error:
                if primary is None:
                    raise
                # Preserve control signals, including one first raised by close.
                if not isinstance(cleanup_error, Exception) and isinstance(primary, Exception):
                    raise
                if isinstance(primary, OfflineAcquisitionError):
                    primary.cleanup_failed = True
        checkpoint()
        if status == 200:
            result = OfflineSuccess(tuple(plans), bytes(retained), digest.hexdigest())
            checkpoint()
            return result
