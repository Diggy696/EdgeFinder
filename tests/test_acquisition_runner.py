"""Deterministic synthetic runner tests; no provider, network or storage I/O."""

import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
import inspect
import sys
import unittest
from unittest.mock import patch

from edgefinder.acquisition import runner
from edgefinder.acquisition.contracts import (
    AddressRules, ArtifactDefinition, URLRule, URLRules, ValidatedConnectionPlan,
)
from edgefinder.acquisition.policy import validate_addresses, validate_url
from edgefinder.acquisition.runner import (
    OfflineAcquisitionError, OfflineFailureCode as Code, OfflineLimits,
    OfflineSuccess, run_offline,
)


HOST = "artifacts.example.test"
URL = "https://" + HOST + "/a"
ANSWERS = ("8.8.8.8", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111")
RULES = URLRules(tuple(URLRule(HOST, "/" + name) for name in "abcde")
                 + (URLRule("cdn.example.test", "/b"),))


def scripted(value):
    if isinstance(value, BaseException):
        raise value
    return value() if callable(value) else value


class FakeClock:
    def __init__(self, now=0.0, readings=()):
        self.now = now
        self.readings = list(readings)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return scripted(self.readings.pop(0)) if self.readings else self.now


class FakeResolver:
    def __init__(self, script=None):
        self.script = [ANSWERS] * 4 if script is None else list(script)
        self.calls = []

    def resolve(self, hostname, *, port, deadline):
        self.calls.append((hostname, port, deadline))
        return scripted(self.script.pop(0))


class FakeStream:
    def __init__(self, chunks=(), *, status=200, locations=(), on_close=None):
        self.status = status
        self.locations = locations
        self.chunks = list(chunks)
        self.reads = []
        self.closes = 0
        self.on_close = on_close

    def read(self, max_bytes, *, deadline):
        self.reads.append((max_bytes, deadline))
        return scripted(self.chunks.pop(0)) if self.chunks else b""

    def close(self):
        self.closes += 1
        scripted(self.on_close)


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.connections = []

    def open(self, plan, *, deadline):
        self.calls.append((plan, deadline))
        # Consume the validated plan; do not resolve or substitute a destination.
        self.connections.append((plan.selected_address, plan.url.port,
                                 plan.tls_hostname, plan.url.url))
        return scripted(self.responses.pop(0))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.resolver = FakeResolver()
        self.stream = FakeStream()
        self.transport = FakeTransport(self.stream)

    def acquire(self, **overrides):
        arguments = dict(initial_url=URL, url_rules=RULES, address_rules=AddressRules(),
                         resolver=self.resolver, transport=self.transport,
                         clock=self.clock, limits=OfflineLimits(10, max_bytes=16))
        arguments.update(overrides)
        return run_offline(**arguments)

    def failure(self, expected, **overrides):
        with self.assertRaises(OfflineAcquisitionError) as caught:
            self.acquire(**overrides)
        error = caught.exception
        self.assertIs(error.code, expected)
        self.assertEqual(error.args, (expected.value,))
        self.assertFalse(hasattr(error, "body"))
        self.assertFalse(hasattr(error, "sha256"))
        self.assertIsNone(error.__cause__)
        return error

    def test_default_cap_and_limit_normalization(self):
        limits = OfflineLimits(10)
        self.assertEqual(limits.max_bytes, 64 * 1024 * 1024)
        self.assertIs(type(limits.timeout_seconds), float)
        with self.assertRaises(FrozenInstanceError):
            limits.max_bytes = 1

    def test_invalid_limit_construction(self):
        for timeout in (True, None, "10", 0, -1, float("nan"), float("inf"),
                        -float("inf"), 10 ** 400):
            with self.subTest(timeout=timeout), self.assertRaises(OfflineAcquisitionError) as caught:
                OfflineLimits(timeout)
            self.assertIs(caught.exception.code, Code.INVALID_INPUT)
        for cap in (True, None, "10", -1, 1.5):
            with self.subTest(cap=cap), self.assertRaises(OfflineAcquisitionError) as caught:
                OfflineLimits(10, max_bytes=cap)
            self.assertIs(caught.exception.code, Code.INVALID_INPUT)

    def test_invalid_inputs_fail_before_callbacks(self):
        for overrides in ({"initial_url": None}, {"initial_url": b"url"},
                          {"initial_url": "x" * 4097}, {"url_rules": None},
                          {"address_rules": None}, {"limits": None}, {"clock": None},
                          {"resolver": object()}, {"transport": object()}):
            with self.subTest(overrides=overrides):
                self.failure(Code.INVALID_INPUT, **overrides)
        self.assertEqual(self.clock.calls, 0)
        self.assertEqual(self.resolver.calls, [])
        self.assertEqual(self.transport.calls, [])

    def test_noncallable_dependency_methods_rejected(self):
        class Invalid:
            resolve = None
            open = 1
        self.failure(Code.INVALID_INPUT, resolver=Invalid())
        self.failure(Code.INVALID_INPUT, transport=Invalid())
        self.assertEqual(self.clock.calls, 0)

    def test_url_policy_rejections_precede_all_callbacks(self):
        for url in ("", URL + "?", URL + "#", URL + "/", "http://" + HOST + "/a",
                    "https://user:fixture-secret@" + HOST + "/a",
                    "https://evil.example.test/a", "https://" + HOST + "/unlisted"):
            with self.subTest(url=url):
                self.failure(Code.URL_POLICY, initial_url=url)
        self.failure(Code.URL_POLICY, url_rules=URLRules())
        self.assertEqual(self.clock.calls, 0)
        self.assertEqual(self.resolver.calls, [])

    def test_candidate_metadata_does_not_supply_rules(self):
        candidate = ArtifactDefinition("fixture", "synthetic", URL, "opaque", "invented")
        self.failure(Code.INVALID_INPUT, url_rules=candidate)
        self.failure(Code.URL_POLICY, initial_url=candidate.candidate_url, url_rules=URLRules())
        self.assertEqual(self.transport.calls, [])

    def test_validated_plan_is_used_and_preserved_by_identity(self):
        result = self.acquire(initial_url="HTTPS://" + HOST.upper() + ":443/a")
        plan = result.request_plans[0]
        expected = validate_addresses(validate_url(URL, rules=RULES), ANSWERS,
                                      policy=AddressRules())
        self.assertEqual(plan, expected)
        self.assertIs(self.transport.calls[0][0], plan)
        self.assertEqual(self.transport.connections, [("1.1.1.1", 443, HOST, URL)])
        self.assertEqual(self.resolver.calls, [(HOST, 443, 10.0)])
        self.assertEqual(self.stream.closes, 1)

    def test_all_answers_checked_before_transport(self):
        for unsafe in ("127.0.0.1", "100.64.0.1", "169.254.169.254", "2001:db8::1",
                       "::ffff:8.8.8.8", "malformed"):
            for answers in (("8.8.8.8", unsafe), (unsafe, "8.8.8.8")):
                with self.subTest(answers=answers):
                    self.resolver.script = [answers]
                    self.failure(Code.ADDRESS_POLICY)
        self.assertEqual(self.transport.calls, [])

    def test_answer_shapes_and_bounds(self):
        for answers in ((), [], ["8.8.8.8"], None, "8.8.8.8", (None,), (True,),
                        (b"8.8.8.8",), ("1" * 46,), ("8.8.8.8",) * 65):
            with self.subTest(answers=answers):
                self.resolver.script = [answers]
                self.failure(Code.ADDRESS_POLICY)
        self.assertEqual(self.transport.calls, [])
        self.resolver.script = [("8.8.8.8",) * 64]
        result = self.acquire()
        self.assertEqual(result.request_plans[0].addresses, ("8.8.8.8",))

    def test_additional_address_denial_is_reused(self):
        self.failure(Code.ADDRESS_POLICY, address_rules=AddressRules(("1.1.1.0/24",)))
        self.assertEqual(self.transport.calls, [])

    def test_resolver_and_transport_exceptions_are_sanitized(self):
        self.resolver.script = [ValueError("fixture-secret")]
        self.failure(Code.RESOLVER_FAILURE)
        self.assertEqual(self.transport.calls, [])
        self.resolver.script = [ANSWERS]
        self.transport.responses = [RuntimeError("fixture-secret")]
        error = self.failure(Code.TRANSPORT_FAILURE)
        self.assertNotIn("fixture-secret", repr(error))
        self.assertTrue(error.__suppress_context__)
        self.assertEqual(self.stream.closes, 0)

    def test_every_supported_redirect_status(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                redirect = FakeStream([AssertionError("must not read")], status=status,
                                      locations=("/b",))
                final = FakeStream([b"ok"])
                transport = FakeTransport(redirect, final)
                result = self.acquire(resolver=FakeResolver(), transport=transport)
                self.assertEqual(result.body, b"ok")
                self.assertEqual([p.url.path for p in result.request_plans], ["/a", "/b"])
                self.assertEqual(redirect.reads, [])
                self.assertEqual((redirect.closes, final.closes), (1, 1))

    def test_three_redirects_and_four_requests_succeed(self):
        responses = [FakeStream(status=302, locations=("/" + name,)) for name in "bcd"]
        responses.append(FakeStream([b"done"]))
        result = self.acquire(transport=FakeTransport(*responses))
        self.assertEqual([p.url.path for p in result.request_plans], ["/a", "/b", "/c", "/d"])
        self.assertEqual(len(self.resolver.calls), 4)
        self.assertTrue(all(response.closes == 1 for response in responses))

    def test_fourth_redirect_rejected_before_fifth_request(self):
        responses = [FakeStream(status=302, locations=("/" + name,)) for name in "bcde"]
        transport = FakeTransport(*responses)
        self.failure(Code.REDIRECT_LIMIT, transport=transport)
        self.assertEqual(len(transport.calls), 4)
        self.assertEqual(len(self.resolver.calls), 4)
        self.assertTrue(all(response.closes == 1 and not response.reads for response in responses))

    def test_canonical_self_loops(self):
        for location in ("/a", "./a", "../a", URL,
                         "HTTPS://" + HOST.upper() + ":443/a", "//" + HOST + ":443/a"):
            with self.subTest(location=location):
                redirect = FakeStream(status=302, locations=(location,))
                transport = FakeTransport(redirect)
                self.failure(Code.REDIRECT_LOOP, resolver=FakeResolver(), transport=transport)
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(redirect.closes, 1)

    def test_multihop_loop_and_loop_precedence_over_count(self):
        for targets in (("b", "a"), ("b", "c", "d", "a")):
            with self.subTest(targets=targets):
                streams = [FakeStream(status=302, locations=("/" + name,)) for name in targets]
                transport = FakeTransport(*streams)
                self.failure(Code.REDIRECT_LOOP, resolver=FakeResolver(), transport=transport)
                self.assertTrue(all(stream.closes == 1 for stream in streams))

    def test_redirect_destination_is_revalidated_before_resolution(self):
        for target in ("/unlisted", "https://evil.example.test/b", "/b?", "/%62", ""):
            with self.subTest(target=target):
                stream = FakeStream(status=302, locations=(target,))
                resolver = FakeResolver()
                self.failure(Code.REDIRECT_POLICY, resolver=resolver,
                             transport=FakeTransport(stream))
                self.assertEqual(len(resolver.calls), 1)
                self.assertEqual(stream.closes, 1)

    def test_cross_host_redirect_gets_new_resolution_and_plan(self):
        redirect = FakeStream(status=302, locations=("//cdn.example.test:443/b",))
        self.transport.responses = [redirect, self.stream]
        self.resolver.script = [("8.8.8.8",), ("1.1.1.1",)]
        result = self.acquire()
        self.assertEqual([call[0] for call in self.resolver.calls], [HOST, "cdn.example.test"])
        self.assertEqual([p.selected_address for p in result.request_plans], ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(self.transport.connections[-1],
                         ("1.1.1.1", 443, "cdn.example.test", "https://cdn.example.test/b"))

    def test_redirect_same_host_does_not_reuse_answers(self):
        redirect = FakeStream(status=302, locations=("/b",))
        self.transport.responses = [redirect, self.stream]
        self.resolver.script = [ANSWERS, ("127.0.0.1",)]
        self.failure(Code.ADDRESS_POLICY)
        self.assertEqual(len(self.resolver.calls), 2)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(redirect.closes, 1)
        self.assertEqual(self.stream.closes, 0)

    def test_rejected_statuses_do_not_read(self):
        for status in (100, 201, 204, 206, 300, 304, 305, 400, 404, 500, 599):
            with self.subTest(status=status):
                stream = FakeStream(status=status)
                self.failure(Code.STATUS_REJECTED, resolver=FakeResolver(),
                             transport=FakeTransport(stream))
                self.assertEqual((stream.reads, stream.closes), ([], 1))

    def test_malformed_statuses(self):
        for status in (True, False, None, "200", 200.0, 99, 600):
            with self.subTest(status=status):
                stream = FakeStream(status=status)
                self.failure(Code.RESPONSE_PROTOCOL, resolver=FakeResolver(),
                             transport=FakeTransport(stream))
                self.assertEqual(stream.closes, 1)
                self.assertEqual(stream.reads, [])

    def test_locations_protocol_is_strict(self):
        for status, locations in ((302, ()), (302, ("/b", "/b")), (302, ["/b"]),
                                  (302, "/b"), (302, None), (302, (None,)),
                                  (302, (b"/b",)), (302, ("/" + "x" * 4096,)),
                                  (200, ("/b",)), (200, [])):
            with self.subTest(status=status, locations=locations):
                stream = FakeStream(status=status, locations=locations)
                self.failure(Code.RESPONSE_PROTOCOL, resolver=FakeResolver(),
                             transport=FakeTransport(stream))
                self.assertEqual((stream.reads, stream.closes), ([], 1))

    def test_initial_url_and_location_boundary_of_4096(self):
        path = "/" + "x" * (4096 - len("https://" + HOST) - 1)
        long_url = "https://" + HOST + path
        self.assertEqual(len(long_url), 4096)
        rules = URLRules((URLRule(HOST, "/a"), URLRule(HOST, path)))
        self.acquire(initial_url=long_url, url_rules=rules)
        redirect = FakeStream(status=302, locations=(long_url,))
        self.acquire(url_rules=rules, resolver=FakeResolver(),
                     transport=FakeTransport(redirect, FakeStream()))

    def test_metadata_access_failure_closes_response(self):
        class BrokenMetadata(FakeStream):
            @property
            def status(self):
                raise ValueError("fixture-secret")

            @status.setter
            def status(self, value):
                pass
        stream = BrokenMetadata()
        self.failure(Code.RESPONSE_PROTOCOL, transport=FakeTransport(stream))
        self.assertEqual(stream.closes, 1)

    def test_noncallable_read_is_protocol_failure(self):
        self.stream.read = None
        self.failure(Code.RESPONSE_PROTOCOL)
        self.assertEqual(self.stream.closes, 1)

    def test_empty_payload_and_permanent_eof(self):
        self.stream.chunks = [b"", AssertionError("read after EOF")]
        result = self.acquire()
        self.assertEqual(result.body, b"")
        self.assertEqual(result.sha256, hashlib.sha256(b"").hexdigest())
        self.assertEqual(len(self.stream.reads), 1)

    def test_zero_cap_uses_one_byte_probe(self):
        result = self.acquire(limits=OfflineLimits(10, max_bytes=0))
        self.assertEqual(result.body, b"")
        self.assertEqual(self.stream.reads, [(1, 10.0)])
        stream = FakeStream([b"x"])
        self.failure(Code.BYTE_LIMIT, resolver=FakeResolver(), transport=FakeTransport(stream),
                     limits=OfflineLimits(10, max_bytes=0))
        self.assertEqual(stream.closes, 1)

    def test_exact_cap_requires_eof_probe(self):
        self.stream.chunks = [b"abc", b"de", b""]
        result = self.acquire(limits=OfflineLimits(10, max_bytes=5))
        self.assertEqual(result.body, b"abcde")
        self.assertEqual([n for n, _ in self.stream.reads], [6, 3, 1])

    def test_cap_plus_one_is_failure_without_truncation(self):
        for chunks in ([b"abcdef"], [b"abcde", b"f"]):
            with self.subTest(chunks=chunks):
                stream = FakeStream(chunks)
                self.failure(Code.BYTE_LIMIT, resolver=FakeResolver(), transport=FakeTransport(stream),
                             limits=OfflineLimits(10, max_bytes=5))
                self.assertEqual(stream.closes, 1)

    def test_arbitrary_binary_chunks_have_exact_digest(self):
        payload = bytes(range(256)) * 300
        chunks = [payload[:65536], payload[65536:]]
        stream = FakeStream(chunks)
        result = self.acquire(transport=FakeTransport(stream),
                              limits=OfflineLimits(10, max_bytes=len(payload)))
        self.assertEqual(result.body, payload)
        self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual([n for n, _ in stream.reads], [65536, len(payload) - 65536 + 1, 1])

    def test_hashing_is_incremental_and_excludes_redirect_body(self):
        real_digest = hashlib.sha256()
        updates = []

        class RecordingDigest:
            def update(self, chunk):
                updates.append(chunk)
                real_digest.update(chunk)

            def hexdigest(self):
                return real_digest.hexdigest()

        redirect = FakeStream([b"ignored"], status=302, locations=("/b",))
        self.stream.chunks = [b"\x00\xff", b"abc", b"\x80"]
        self.transport.responses = [redirect, self.stream]
        with patch.object(runner.hashlib, "sha256", return_value=RecordingDigest()):
            result = self.acquire()
        self.assertEqual(updates, [b"\x00\xff", b"abc", b"\x80"])
        self.assertEqual(result.sha256, hashlib.sha256(result.body).hexdigest())
        self.assertEqual(redirect.reads, [])

    def test_rejected_chunk_is_not_hashed(self):
        digest = hashlib.sha256()
        with patch.object(runner.hashlib, "sha256", return_value=digest):
            self.stream.chunks = [b"ok", b"xx"]
            self.failure(Code.BYTE_LIMIT, limits=OfflineLimits(10, max_bytes=3))
        self.assertEqual(digest.hexdigest(), hashlib.sha256(b"ok").hexdigest())

    def test_one_byte_reads_remain_bounded(self):
        self.stream.chunks = [b"x"] * 16
        result = self.acquire()
        self.assertEqual(result.body, b"x" * 16)
        self.assertEqual(len(self.stream.reads), 17)
        self.assertEqual(self.stream.reads[-1][0], 1)

    def test_malformed_read_results(self):
        class BytesSubclass(bytes):
            pass
        for value in (None, "text", bytearray(b"x"), memoryview(b"x"), 0,
                      BytesSubclass(b"x"), b"x" * 18):
            with self.subTest(value=value):
                stream = FakeStream([value])
                self.failure(Code.RESPONSE_PROTOCOL, resolver=FakeResolver(),
                             transport=FakeTransport(stream))
                self.assertEqual(stream.closes, 1)

    def test_stream_failure_discards_partial_success(self):
        self.stream.chunks = [b"ok", ValueError("fixture-secret")]
        error = self.failure(Code.STREAM_FAILURE)
        self.assertNotIn("fixture-secret", repr(error))
        self.assertEqual(self.stream.closes, 1)

    def test_invalid_initial_clock_precedes_resolver(self):
        for value in (True, None, "0", float("nan"), float("inf"), -float("inf"),
                      10 ** 400, ValueError("fixture-secret")):
            with self.subTest(value=value):
                self.failure(Code.CLOCK_FAILURE, clock=FakeClock(readings=[value]))
        self.assertEqual(self.resolver.calls, [])

    def test_finite_deadline_required_and_rounding_cannot_disable_expiry(self):
        self.failure(Code.CLOCK_FAILURE, clock=FakeClock(1.7e308), limits=OfflineLimits(1.7e308))
        self.failure(Code.DEADLINE_EXCEEDED, clock=FakeClock(1e300), limits=OfflineLimits(1))
        self.assertEqual(self.resolver.calls, [])

    def test_clock_can_have_negative_origin(self):
        result = self.acquire(clock=FakeClock(-100))
        self.assertEqual(result.body, b"")
        self.assertEqual(self.resolver.calls[0][-1], -90)

    def test_expiry_before_resolver_callback(self):
        self.failure(Code.DEADLINE_EXCEEDED, clock=FakeClock(readings=[0, 10]))
        self.assertEqual(self.resolver.calls, [])

    def test_expiry_after_resolver_prevents_open(self):
        def late_answers():
            self.clock.now = 10
            return ANSWERS
        self.resolver.script = [late_answers]
        self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual(self.transport.calls, [])

    def test_late_open_response_is_closed_before_metadata_access(self):
        def late_response():
            self.clock.now = 10
            return self.stream
        self.transport.responses = [late_response]
        self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual((self.stream.reads, self.stream.closes), ([], 1))

    def test_expiry_before_open_after_address_policy_work(self):
        original = runner.validate_addresses

        def expire(*args, **kwargs):
            plan = original(*args, **kwargs)
            self.clock.now = 10
            return plan
        with patch.object(runner, "validate_addresses", side_effect=expire):
            self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual(self.transport.calls, [])

    def test_expiry_before_first_read(self):
        class ExpiringMetadata(FakeStream):
            @property
            def locations(stream):
                self.clock.now = 10
                return ()

            @locations.setter
            def locations(stream, value):
                pass
        stream = ExpiringMetadata()
        self.failure(Code.DEADLINE_EXCEEDED, transport=FakeTransport(stream))
        self.assertEqual((stream.reads, stream.closes), ([], 1))

    def test_expiry_after_read_even_at_eof(self):
        for chunk in (b"x", b""):
            with self.subTest(chunk=chunk):
                clock = FakeClock()

                def late_chunk():
                    clock.now = 10
                    return chunk
                stream = FakeStream([late_chunk])
                self.failure(Code.DEADLINE_EXCEEDED, resolver=FakeResolver(), clock=clock,
                             transport=FakeTransport(stream))
                self.assertEqual(stream.closes, 1)

    def test_decreasing_clock_after_open_still_closes(self):
        def backwards():
            self.clock.now = -1
            return self.stream
        self.transport.responses = [backwards]
        self.failure(Code.CLOCK_FAILURE)
        self.assertEqual(self.stream.closes, 1)

    def test_clock_failure_after_open_still_closes(self):
        for reading in (float("nan"), None, RuntimeError("fixture-secret")):
            with self.subTest(reading=reading):
                clock = FakeClock()
                stream = FakeStream()

                def response():
                    clock.readings = [reading]
                    return stream
                self.failure(Code.CLOCK_FAILURE, resolver=FakeResolver(), clock=clock,
                             transport=FakeTransport(response))
                self.assertEqual(stream.closes, 1)

    def test_single_deadline_across_redirects_and_reads(self):
        def advance():
            self.clock.now += 6
        redirect = FakeStream(status=302, locations=("/b",), on_close=advance)
        self.stream.chunks = [b"ok"]
        self.transport.responses = [redirect, self.stream]
        self.acquire()
        deadlines = [c[-1] for c in self.resolver.calls + self.transport.calls + self.stream.reads]
        self.assertEqual(set(deadlines), {10.0})

    def test_expiry_between_redirects_prevents_next_resolution(self):
        def expire():
            self.clock.now = 10
        self.stream.status = 302
        self.stream.locations = ("/b",)
        self.stream.on_close = expire
        self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual(len(self.resolver.calls), 1)
        self.assertEqual(self.stream.closes, 1)

    def test_expiry_during_close_prevents_success(self):
        def expire():
            self.clock.now = 10
        self.stream.on_close = expire
        self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual(self.stream.closes, 1)

    def test_expiry_during_finalization_prevents_success(self):
        original = OfflineSuccess

        def late_result(*args):
            result = original(*args)
            self.clock.now = 10
            return result
        with patch.object(runner, "OfflineSuccess", side_effect=late_result):
            self.failure(Code.DEADLINE_EXCEEDED)
        self.assertEqual(self.stream.closes, 1)

    def test_cleanup_failure_prevents_success_and_redirect_following(self):
        for status, locations in ((200, ()), (302, ("/b",))):
            with self.subTest(status=status):
                stream = FakeStream(status=status, locations=locations,
                                    on_close=ValueError("fixture-secret"))
                resolver = FakeResolver()
                self.failure(Code.CLEANUP_FAILURE, resolver=resolver,
                             transport=FakeTransport(stream))
                self.assertEqual(stream.closes, 1)
                self.assertEqual(len(resolver.calls), 1)

    def test_primary_failure_survives_cleanup_failure(self):
        self.stream.chunks = [ValueError("fixture-secret")]
        self.stream.on_close = RuntimeError("cleanup-secret")
        error = self.failure(Code.STREAM_FAILURE)
        self.assertTrue(error.cleanup_failed)
        self.assertNotIn("secret", str(error))
        self.assertEqual(self.stream.closes, 1)

    def test_expired_primary_survives_failed_cleanup(self):
        def late_response():
            self.clock.now = 10
            return self.stream
        self.stream.on_close = ValueError("cleanup-secret")
        self.transport.responses = [late_response]
        error = self.failure(Code.DEADLINE_EXCEEDED)
        self.assertTrue(error.cleanup_failed)
        self.assertEqual(self.stream.closes, 1)

    def test_invalid_response_cannot_produce_success(self):
        self.transport.responses = [object()]
        error = self.failure(Code.RESPONSE_PROTOCOL)
        self.assertTrue(error.cleanup_failed)

    def test_control_signals_propagate_at_all_callback_boundaries(self):
        for signal in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for boundary in ("clock", "resolver", "open", "read", "close"):
                with self.subTest(signal=signal, boundary=boundary):
                    value = signal("control")
                    stream = FakeStream()
                    resolver = FakeResolver([value] if boundary == "resolver" else None)
                    clock = FakeClock(readings=[value] if boundary == "clock" else ())
                    transport = FakeTransport(value if boundary == "open" else stream)
                    if boundary == "read":
                        stream.chunks = [value]
                    if boundary == "close":
                        stream.on_close = value
                    with self.assertRaises(signal) as caught:
                        self.acquire(resolver=resolver, clock=clock, transport=transport)
                    self.assertIs(caught.exception, value)
                    self.assertEqual(stream.closes, int(boundary in ("read", "close")))

    def test_control_signal_after_open_attempts_cleanup(self):
        value = KeyboardInterrupt()

        def response():
            self.clock.readings = [value]
            return self.stream
        self.transport.responses = [response]
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.acquire()
        self.assertIs(caught.exception, value)
        self.assertEqual(self.stream.closes, 1)

    def test_primary_control_signal_survives_all_cleanup_failures(self):
        for cleanup in (ValueError("secret"), SystemExit("cleanup")):
            with self.subTest(cleanup=cleanup):
                primary = KeyboardInterrupt("primary")
                stream = FakeStream([primary], on_close=cleanup)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.acquire(resolver=FakeResolver(), transport=FakeTransport(stream))
                self.assertIs(caught.exception, primary)
                self.assertEqual(stream.closes, 1)

    def test_cleanup_control_signal_is_not_swallowed_by_ordinary_failure(self):
        signal = SystemExit("control")
        self.stream.chunks = [ValueError("secret")]
        self.stream.on_close = signal
        with self.assertRaises(SystemExit) as caught:
            self.acquire()
        self.assertIs(caught.exception, signal)
        self.assertEqual(self.stream.closes, 1)

    def test_success_and_nested_values_are_immutable(self):
        result = self.acquire()
        self.assertIs(type(result.body), bytes)
        self.assertIs(type(result.request_plans), tuple)
        self.assertIsInstance(hash(result), int)
        for value, field in ((result, "body"), (result.request_plans[0], "addresses"),
                             (result.request_plans[0].url, "path")):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(value, field, None)
        with self.assertRaises(OfflineAcquisitionError):
            replace(result, body=bytearray())
        with self.assertRaises(OfflineAcquisitionError):
            replace(result, request_plans=list(result.request_plans))

    def test_stable_failure_codes(self):
        expected = {"invalid_input", "url_policy", "redirect_policy", "address_policy",
                    "resolver_failure", "transport_failure", "response_protocol",
                    "status_rejected", "redirect_loop", "redirect_limit", "byte_limit",
                    "deadline_exceeded", "clock_failure", "stream_failure", "cleanup_failure"}
        self.assertEqual({code.value for code in Code}, expected)

    def test_runner_has_only_explicit_standard_library_and_policy_dependencies(self):
        allowed = {"dataclasses", "enum", "hashlib", "math", "typing", "contracts", "policy"}
        tree = ast.parse(inspect.getsource(runner))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue({alias.name for alias in node.names} <= allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, allowed)
        signature = inspect.signature(run_offline)
        self.assertTrue(all(parameter.default is inspect.Parameter.empty
                            for parameter in signature.parameters.values()))

    def test_runner_paths_emit_no_io_or_import_events(self):
        state = {"active": True}
        attempts = []

        def guard(event, args):
            if state["active"] and (event in {"open", "import", "sqlite3.connect"}
                                    or event.startswith(("socket.", "subprocess.", "os."))):
                attempts.append(event)
                raise AssertionError("Unexpected runner side effect")

        sys.addaudithook(guard)
        try:
            self.acquire()
            for stream, expected in ((FakeStream(status=302, locations=("/unlisted",)), Code.REDIRECT_POLICY),
                                     (FakeStream([ValueError("secret")]), Code.STREAM_FAILURE),
                                     (FakeStream([b"x" * 17]), Code.BYTE_LIMIT),
                                     (FakeStream(on_close=ValueError("secret")), Code.CLEANUP_FAILURE)):
                self.failure(expected, resolver=FakeResolver(), transport=FakeTransport(stream))
            redirect = FakeStream(status=302, locations=("/b",))
            self.acquire(resolver=FakeResolver(), transport=FakeTransport(redirect, FakeStream()))
        finally:
            state["active"] = False
        self.assertEqual(attempts, [])


if __name__ == "__main__":
    unittest.main()
