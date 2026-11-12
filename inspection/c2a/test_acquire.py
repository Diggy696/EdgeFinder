"""Synthetic C2a acquisition tests; no network, credentials or real run paths.

Run: .venv/Scripts/python.exe -I -S -B inspection/c2a/test_acquire.py
Disposable child fixtures exercise the real supervisor without live transport.
Both parent and children forbid sockets/SQLite and writes outside owned temp.
"""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import csv
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings


HERE = Path(__file__).absolute().parent
REPOSITORY = HERE.parent.parent
TEST_ROOT = None
AUDIT_COUNTS = dict(network=0, database=0, forbidden_writes=0, forbidden_processes=0)
AUTHORIZED_CHILD_COMMAND = None


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


acquire = load("c2a_acquire", "acquire.py")
inspector = load("c2a_inspector_for_acquisition_tests", "runner.py")
STAMP = "2026-11-11T12:00:00Z"
SECRET = "SYNTHETIC_SIGNED_SECRET"
CDN_PATH = "/github-production-release-asset/452908115/01234567-89ab-cdef-0123-456789abcdef"


def audit(event, args):
    if event.startswith("socket."):
        AUDIT_COUNTS["network"] += 1
        raise PermissionError("Synthetic tests forbid sockets and DNS")
    if event.startswith("sqlite3.") or (event == "import" and args[0].split(".")[0] in
                                        {"sqlite3", "nflreadpy", "requests"}):
        AUDIT_COUNTS["database"] += 1
        raise PermissionError("Synthetic tests forbid databases/providers")
    targets = ()
    if event == "open":
        path, mode, flags = args
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            targets = (path,)
    elif event in ("os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.truncate", "os.utime"):
        targets = (args[0],)
    elif event in ("os.rename", "os.link"):
        targets = args[:2]
    elif event == "os.symlink":
        targets = (args[1],)
    for target in targets:
        if isinstance(target, int) or target == os.devnull:
            # Popen wraps its newly created anonymous pipe handles as file
            # descriptors and opens the NUL device. Neither writes a disk file.
            continue
        try:
            inside = Path(os.fsdecode(target)).absolute().is_relative_to(TEST_ROOT)
        except (TypeError, ValueError):
            inside = False
        if not inside:
            AUDIT_COUNTS["forbidden_writes"] += 1
            raise PermissionError("Writes must stay in the owned temporary tree")
    if event == "subprocess.Popen":
        command = args[1]
        # Windows audits the already serialized command line, POSIX the list.
        expected = AUTHORIZED_CHILD_COMMAND
        if expected is None or command not in (expected, acquire.subprocess.list2cmdline(expected)):
            AUDIT_COUNTS["forbidden_processes"] += 1
            raise PermissionError("Only synthetic fixture children are permitted")


def location(aid="schedules"):
    filename = acquire.SPECS[aid][1]
    return ("https://"+acquire.CDN+CDN_PATH+"?sp=r&sv=2018-11-09&sr=b&spr=https"
            +"&se=2026-12-01T00%3A00%3A00Z&sig="+SECRET
            +"&rscd=attachment%3B%20filename%3D"+filename)


class FakeResponse:
    def __init__(self, body=b"", *, status=200, headers=None, read_error=None, close_error=None):
        self.body, self.status = body, status
        self.headers = tuple(headers if headers is not None else (("Content-Length", str(len(body))),))
        self.position, self.closed, self.reads = 0, 0, []
        self.read_error, self.close_error = read_error, close_error

    def read(self, count):
        self.reads.append(count)
        if self.read_error is not None:
            raise self.read_error
        chunk = self.body[self.position:self.position+count]
        self.position += len(chunk)
        return chunk

    def close(self):
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


def fixture_rows():
    pid = "00-0000001"
    schedules = [dict(game_id=f"{year}_07_AWY_HOM", season=str(year), week="7", game_type="REG",
                      home_team="HOM", away_team="AWY", gameday=f"{year}-10-20", gametime="20:00",
                      home_score="20", away_score="0") for year in (2025, 2026)]
    rows = dict(schedules=schedules, players=[dict(gsis_id=pid)])
    for year in (2025, 2026):
        rows["stats_"+str(year)] = [dict(player_id=pid, season=str(year), week="7", season_type="REG",
                                       team="HOM", opponent_team="AWY", targets="0", receptions="0",
                                       receiving_yards="0")]
        rows["rosters_"+str(year)] = [dict(gsis_id=pid, season=str(year), week="7", game_type="REG",
                                         team="HOM", position="WR", status="ACT")]
    return rows


class Backend:
    def __init__(self, *, redirects=False):
        self.data, self.documents, self.calls, self.responses = {}, {}, [], []
        self.redirects = redirects
        for aid, rows in fixture_rows().items():
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
            self.data[aid] = gzip.compress(stream.getvalue().encode("utf-8"), mtime=0)
        for index, tag in enumerate(acquire.TAGS):
            assets = []
            for asset_id, (aid, t, filename, _) in enumerate(acquire.ARTIFACTS, 1):
                if t == tag:
                    body = self.data[aid]
                    assets.append(dict(id=asset_id, name=filename, size=len(body), state="uploaded",
                                       digest="sha256:"+hashlib.sha256(body).hexdigest(),
                                       browser_download_url=acquire.BASE+t+"/"+filename,
                                       created_at=STAMP, updated_at=STAMP))
            self.documents[tag] = dict(id=index+100, tag_name=tag, draft=False, prerelease=False,
                                       published_at=STAMP, assets=assets)

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        for tag in acquire.TAGS:
            if endpoint == acquire._metadata_endpoint(tag):
                response = FakeResponse(acquire._json_bytes(self.documents[tag]))
                break
        else:
            for aid in acquire.SPECS:
                if endpoint == acquire._artifact_endpoint(aid):
                    response = (FakeResponse(status=302, headers=(("Location", location(aid)),))
                                if self.redirects else FakeResponse(self.data[aid]))
                    break
                if endpoint == acquire._cdn_endpoint(location(aid), aid):
                    response = FakeResponse(self.data[aid])
                    break
            else:
                raise AssertionError("Unexpected synthetic endpoint")
        self.responses.append(response)
        return response


class Cases(unittest.TestCase):
    def setUp(self):
        token = acquire._ATTEMPTED_OPERATION.set(None)
        self.addCleanup(acquire._ATTEMPTED_OPERATION.reset, token)
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=TEST_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.final = self.root/"run-001"

    def failure(self, code, function, *args, **kwargs):
        with self.assertRaises(acquire.Failure) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(SECRET, str(caught.exception))
        return caught.exception

    def batch(self, backend=None):
        stage = acquire._prepare(self.final)
        acquire._batch(stage, backend or Backend(), lambda _: None, utc=lambda: STAMP)
        return stage

    def child(self, mode, *, phase=3, batch=20):
        global AUTHORIZED_CHILD_COMMAND
        command = [acquire._worker_executable(), "-I", "-S", "-B", str(Path(__file__).absolute()),
                   "--child", mode, str(self.final)]
        AUTHORIZED_CHILD_COMMAND = command
        try:
            return acquire._supervise(command, self.final, environment=acquire._worker_environment(),
                                      phase_seconds=phase, batch_seconds=batch)
        finally:
            AUTHORIZED_CHILD_COMMAND = None


class PolicyTests(Cases):
    def test_exact_artifact_and_metadata_allowlists(self):
        self.assertEqual(tuple(acquire.SPECS), tuple(inspector.SPECS))
        for aid, tag, filename, cap in acquire.ARTIFACTS:
            self.assertEqual("https://"+acquire._artifact_endpoint(aid).host
                             +acquire._artifact_endpoint(aid).target,
                             inspector.URL_TEMPLATE.format(release=tag, filename=filename))
            self.assertEqual(cap, inspector.LIMITS["compressed_"+inspector.SPECS[aid]["role"]])
        self.assertEqual(acquire.DATA_TOTAL, inspector.LIMITS["compressed_total"])
        for tag in acquire.TAGS:
            self.assertEqual("https://api.github.com"+acquire._metadata_endpoint(tag).path, acquire.API+tag)

    def test_unexpected_identities_and_direct_endpoint_rejected(self):
        for aid in ("stats_2024", "https://evil.invalid", "../players", None):
            self.failure("artifact_identity", acquire._artifact_endpoint, aid)
        self.failure("metadata_identity", acquire._metadata_endpoint, "latest")
        for endpoint in (acquire.Endpoint("evil.invalid", "/"),
                         acquire.Endpoint("github.com", "/nflverse/nflverse-data/releases/download/players/players.csv"),
                         acquire.Endpoint("api.github.com", "/repos/evil/data/releases/tags/players")):
            self.failure("endpoint_policy", acquire._approved_endpoint, endpoint)

    def test_signed_cdn_query_is_not_in_repr(self):
        endpoint = acquire._cdn_endpoint(location(), "schedules")
        self.assertIn(SECRET, endpoint.target)
        self.assertNotIn(SECRET, repr(endpoint))
        acquire._approved_endpoint(endpoint)

    def test_redirect_host_authority_and_path_rejection(self):
        valid = location()
        for bad in (valid.replace("https:", "http:"), valid.replace(acquire.CDN, acquire.CDN+".evil.invalid"),
                    valid.replace(acquire.CDN, "user@"+acquire.CDN), valid.replace(acquire.CDN, "127.0.0.1"),
                    valid.replace(acquire.CDN, acquire.CDN+":444"), valid+"#fragment",
                    valid.replace("452908115", "1"), valid.replace("/452908115/", "/452908115/../"),
                    valid.replace("/452908115/", "/452908115//"), valid.replace("/452908115/", "/452908115%2f"),
                    " "+valid, valid+"\r\n", valid.replace("https://", "https:\\\\"),
                    valid+"x"*acquire.URL_CAP):
            with self.subTest(bad=bad[:50]):
                self.failure("redirect_policy", acquire._cdn_endpoint, bad, "schedules")

    def test_redirect_query_rejection(self):
        for suffix in ("&unknown=value", "&sig=duplicate", "&jwt=%0d%0aHeader%3Ax", "&jwt=%250d",
                       "&jwt=%ZZ", "&jwt=%5C", "&jwt=%26sig%3Devil", "&jwt=", "&&jwt=x"):
            self.failure("redirect_query", acquire._cdn_endpoint, location()+suffix, "schedules")
        self.failure("redirect_query", acquire._cdn_endpoint, location().replace("spr=https", "spr=http"), "schedules")
        self.failure("redirect_query", acquire._cdn_endpoint, location(), "players")

    def test_mixed_dns_answers_reject_entire_set(self):
        endpoint = acquire._artifact_endpoint("players")
        for answers in (("8.8.8.8", "127.0.0.1"), ("8.8.8.8", "10.1.1.1"),
                        ("8.8.8.8", "::ffff:8.8.8.8"), ("8.8.8.8", "invalid"), ()):
            self.failure("dns_policy", acquire._connection_plan, endpoint, answers)

    def test_safe_dns_selection_is_deterministic(self):
        plan = acquire._connection_plan(acquire._artifact_endpoint("players"),
                                         ("8.8.8.8", "1.1.1.1", "8.8.8.8"))
        self.assertEqual(plan.selected_address, "1.1.1.1")
        self.assertEqual(plan.tls_hostname, "github.com")


class TransportTests(Cases):
    def test_tls_context_uses_standard_verification_and_no_keylogging(self):
        with patch.dict(os.environ, acquire._worker_environment(), clear=True):
            context = acquire._tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIsNone(context.keylog_filename)

    def test_tls_environment_overrides_rejected_before_context_creation(self):
        for key in ("SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            with patch.dict(os.environ, {key: SECRET}), patch.object(acquire.ssl, "SSLContext") as context:
                self.failure("tls_environment", acquire._tls_context)
                context.assert_not_called()

    def test_worker_environment_omits_secrets_proxy_and_tls_overrides(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": SECRET, "HTTPS_PROXY": SECRET,
                                     "SSLKEYLOGFILE": SECRET, "SSL_CERT_FILE": SECRET}):
            env = acquire._worker_environment()
        self.assertNotIn(SECRET, repr(env))
        self.assertTrue(set(env) <= {"SystemRoot", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA"})

    def open_fake(self, *, peer="8.8.8.8", certificate_error=False, ipv6=False):
        from unittest.mock import Mock
        address = "2606:4700:4700::1111" if ipv6 else "8.8.8.8"
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        sockaddr = (address, 443, 0, 0) if ipv6 else (address, 443)
        raw, tls, context, response = Mock(), Mock(), Mock(), Mock()
        raw.getpeername.return_value = (address if ipv6 else peer, 443)
        tls.getpeername.return_value = (address, 443)
        response.status, response.getheaders.return_value = 200, [("Content-Length", "0")]
        if certificate_error:
            context.wrap_socket.side_effect = ssl.SSLCertVerificationError(SECRET)
        else:
            context.wrap_socket.return_value = tls
        with patch.object(acquire.socket, "getaddrinfo", return_value=[
                (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]) as resolver, \
                patch.object(acquire.socket, "socket", return_value=raw) as constructor, \
                patch.object(acquire, "_tls_context", return_value=context), \
                patch.object(acquire, "_Response", return_value=response):
            if certificate_error:
                self.failure("transport_failure", acquire._open, acquire._artifact_endpoint("players"))
            elif not ipv6 and peer != address:
                self.failure("peer_mismatch", acquire._open, acquire._artifact_endpoint("players"))
            else:
                result = acquire._open(acquire._artifact_endpoint("players"))
                result.close()
                raw.connect.assert_called_once_with(sockaddr)
                context.wrap_socket.assert_called_once_with(raw, server_hostname="github.com")
                request = tls.sendall.call_args.args[0]
                self.assertIn(b"Host: github.com\r\n", request)
                self.assertNotIn(b"Authorization", request)
                self.assertNotIn(b"Cookie", request)
                self.assertIn(b"Accept-Encoding: identity", request)
                resolver.assert_called_once()
                constructor.assert_called_once_with(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                tls.close.assert_called_once()
        return raw, context

    def test_ip_pinning_and_tls_hostname(self):
        self.open_fake()

    def test_ipv6_ip_pinning(self):
        self.open_fake(ipv6=True)

    def test_peer_mismatch_prevents_tls(self):
        raw, context = self.open_fake(peer="1.1.1.1")
        context.wrap_socket.assert_not_called()
        raw.close.assert_called_once()

    def test_certificate_failure_closes_socket_and_sanitizes_error(self):
        raw, _ = self.open_fake(certificate_error=True)
        raw.close.assert_called_once()

    def test_wire_headers_are_capped_before_parsing(self):
        class Sock:
            def makefile(self, mode):
                return io.BytesIO(b"HTTP/1.1 200 OK\r\n" + (b"X-A: "+b"a"*2000+b"\r\n")*40+b"\r\n")
        response = acquire._Response(acquire._HeaderSocket(Sock()), method="GET")
        self.addCleanup(response.close)
        self.failure("header_limit", response.begin)

    def test_interim_and_folded_headers_rejected(self):
        for body in (b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nmissing-colon\r\n\r\nx",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-A: nul\x00\r\n\r\nx"):
            class Sock:
                def makefile(self, mode):
                    return io.BytesIO(body)
            response = acquire._Response(acquire._HeaderSocket(Sock()), method="GET")
            self.addCleanup(response.close)
            self.failure("response_status" if b"100" in body else "response_headers", response.begin)


class TransferTests(Cases):
    def receive(self, response, *, cap=10, expected=None):
        body = bytearray()
        result = acquire._receive(acquire._artifact_endpoint("schedules"), cap, body.extend,
                                   lambda _: response, aid="schedules", expected=expected)
        return bytes(body), result

    def test_exact_limit_and_original_byte_digest(self):
        response = FakeResponse(b"0123456789")
        body, (length, digest) = self.receive(response)
        self.assertEqual((length, digest), (10, hashlib.sha256(body).hexdigest()))
        self.assertEqual(response.closed, 1)

    def test_advertised_and_actual_size_limits(self):
        self.failure("byte_limit", self.receive, FakeResponse(b"x"*11))
        self.failure("byte_limit", self.receive,
                     FakeResponse(b"x"*11, headers=(("Content-Length", "10"),)))

    def test_remaining_aggregate_budget_applies_during_transfer(self):
        self.failure("byte_limit", self.receive, FakeResponse(b"x"*5), cap=4)

    def test_truncated_and_extra_bytes(self):
        for body, declared in ((b"123", "4"), (b"1234", "3")):
            self.failure("length_mismatch", self.receive,
                         FakeResponse(body, headers=(("Content-Length", declared),)))

    def test_metadata_length_mismatch(self):
        self.failure("length_mismatch", self.receive, FakeResponse(b"123"), expected=4)

    def test_malformed_framing_and_encoding(self):
        for headers in ((("Content-Length", "1"), ("Content-Length", "1")),
                        (("Content-Length", "-1"),), (("Content-Length", "01"),), (),
                        (("Content-Length", "1"), ("Transfer-Encoding", "chunked")),
                        (("Content-Length", "1"), ("Content-Encoding", "gzip"))):
            with self.assertRaises(acquire.Failure):
                self.receive(FakeResponse(b"x", headers=headers))

    def test_unexpected_status_and_location(self):
        for response in (FakeResponse(status=404), FakeResponse(status=206),
                         FakeResponse(b"x", headers=(("Content-Length", "1"), ("Location", location())))):
            self.failure("response_status", self.receive, response)

    def test_one_cdn_redirect_without_reading_redirect_body(self):
        redirect = FakeResponse(b"ignored", status=302, headers=(("Location", location()),))
        final = FakeResponse(b"123")
        responses = iter((redirect, final))
        endpoints = []
        def request(endpoint):
            endpoints.append(endpoint)
            return next(responses)
        used, _ = acquire._receive(acquire._artifact_endpoint("schedules"), 10, lambda _: None,
                                  request, aid="schedules")
        self.assertEqual(used, 3)
        self.assertEqual(redirect.reads, [])
        self.assertEqual((redirect.closed, final.closed), (1, 1))
        self.assertEqual(endpoints[-1], acquire._cdn_endpoint(location(), "schedules"))

    def test_loops_and_second_redirect_rejected(self):
        for second in (location(), "https://github.com"+acquire._artifact_endpoint("schedules").path):
            responses = iter((FakeResponse(status=302, headers=(("Location", location()),)),
                              FakeResponse(status=302, headers=(("Location", second),))))
            self.failure("redirect_policy", acquire._receive, acquire._artifact_endpoint("schedules"),
                         10, lambda _: None, lambda _: next(responses), aid="schedules")

    def test_metadata_redirect_rejected(self):
        self.failure("redirect_policy", acquire._receive, acquire._metadata_endpoint("players"),
                     10, lambda _: None,
                     lambda _: FakeResponse(status=302, headers=(("Location", location()),)))

    def test_close_on_stream_failure_and_cleanup_error(self):
        response = FakeResponse(b"x", read_error=acquire.Failure("test_stream"), close_error=OSError(SECRET))
        failure = self.failure("test_stream", self.receive, response)
        self.assertTrue(failure.cleanup_failed)
        self.assertEqual(response.closed, 1)
        failure = self.failure("cleanup_failure", self.receive, FakeResponse(close_error=OSError(SECRET)))
        self.assertTrue(failure.cleanup_failed)
        self.assertEqual(failure.attempted_operation, "response_close")

    def test_dependency_stream_and_close_failure_are_both_sanitized(self):
        response = FakeResponse(b"x", read_error=OSError(SECRET), close_error=OSError(SECRET))
        failure = self.failure("stream_failure", self.receive, response)
        self.assertTrue(failure.cleanup_failed)
        self.assertIsNone(failure.__cause__)

    def test_chunk_size_is_bounded(self):
        response = FakeResponse(b"x"*(acquire.CHUNK+10))
        self.receive(response, cap=2*acquire.CHUNK)
        self.assertLessEqual(max(response.reads), acquire.CHUNK)


class MetadataAndBatchTests(Cases):
    def test_metadata_exact_selection_ignores_other_formats_without_ingesting(self):
        backend = Backend()
        value = deepcopy(backend.documents["players"])
        value["assets"].append(dict(name="players.parquet"))
        self.assertEqual(set(acquire._release("players", value)), {"players"})

    def test_missing_duplicate_and_substituted_assets(self):
        backend = Backend()
        for mutate in (lambda v: v["assets"].clear(),
                       lambda v: v["assets"].append(deepcopy(v["assets"][0])),
                       lambda v: v["assets"][0].update(browser_download_url="https://evil.invalid/x"),
                       lambda v: v["assets"][0].update(state="new"),
                       lambda v: v["assets"][0].update(name="other.csv.gz")):
            value = deepcopy(backend.documents["players"])
            mutate(value)
            self.failure("asset_identity", acquire._release, "players", value)

    def test_missing_and_malformed_digest(self):
        for digest in (None, "", "md5:"+"0"*64, "sha256:"+"A"*64, "sha256:"+"a"*63):
            value = deepcopy(Backend().documents["players"])
            value["assets"][0]["digest"] = digest
            self.failure("metadata_digest", acquire._release, "players", value)

    def test_invalid_metadata_identity_size_and_timestamp(self):
        value = Backend().documents["players"]
        for key, bad in (("tag_name", "other"), ("draft", True), ("prerelease", True), ("id", True)):
            changed = deepcopy(value)
            changed[key] = bad
            self.failure("release_identity", acquire._release, "players", changed)
        for size in (-1, 0, True, 8*acquire.MIB+1):
            changed = deepcopy(value)
            changed["assets"][0]["size"] = size
            self.failure("byte_limit", acquire._release, "players", changed)
        changed = deepcopy(value)
        changed["assets"][0]["updated_at"] = "2026-02-30T00:00:00Z"
        self.failure("timestamp", acquire._release, "players", changed)

    def test_duplicate_keys_and_nonfinite_metadata_json(self):
        self.failure("duplicate_json_key", acquire._parse_json, b'{"a":1,"a":2}')
        self.failure("metadata_json", acquire._parse_json, b'{"a":NaN}')
        self.failure("metadata_json", acquire._parse_json, b"\xff")

    def test_per_response_and_total_metadata_caps(self):
        with patch.object(acquire, "METADATA_FILE", 10):
            self.failure("byte_limit", self.batch)
        other = self.root/"other"
        other.mkdir()
        self.final = other/"run-001"
        with patch.object(acquire, "METADATA_TOTAL", 100):
            self.failure("byte_limit", self.batch)

    def test_declared_aggregate_limit_rejected_before_artifact_transfer(self):
        backend = Backend()
        with patch.object(acquire, "DATA_TOTAL", sum(len(b) for b in backend.data.values())-1):
            self.failure("byte_limit", self.batch, backend)
        self.assertEqual(len(backend.calls), 4)

    def test_wrong_digest_rejects_original_compressed_bytes(self):
        backend = Backend()
        backend.documents["schedules"]["assets"][0]["digest"] = "sha256:"+"0"*64
        self.failure("integrity_mismatch", self.batch, backend)
        self.assertFalse(self.final.exists())

    def test_independent_reread_detects_same_length_file_change(self):
        original = acquire._hash_file
        def tamper(path, cap):
            body = bytearray(path.read_bytes())
            body[-1] ^= 1
            path.write_bytes(body)
            return original(path, cap)
        with patch.object(acquire, "_hash_file", side_effect=tamper):
            self.failure("integrity_mismatch", self.batch)

    def test_changed_metadata_rejects_id_digest_size_and_update_timestamp(self):
        for key, value in (("id", 99), ("digest", "sha256:"+"0"*64), ("size", 1),
                           ("updated_at", "2026-11-11T13:00:00Z")):
            with self.subTest(key=key):
                backend = Backend()
                stage = self.root/key
                stage.mkdir()
                calls = 0
                def request(endpoint):
                    nonlocal calls
                    if endpoint == acquire._metadata_endpoint("schedules"):
                        calls += 1
                        if calls == 2:
                            backend.documents["schedules"]["assets"][0][key] = value
                    return backend(endpoint)
                self.failure("metadata_changed", acquire._batch, stage, request, lambda _: None)
                self.assertFalse((stage/"manifest.json").exists())

    def test_complete_six_artifact_manifest_accepted_by_unchanged_inspector(self):
        backend = Backend(redirects=True)
        stage = self.batch(backend)
        result = inspector.inspect_manifest(stage, stage/"manifest.json", as_of=STAMP)
        self.assertEqual(result["mode"], "offline_retrospective_inspection")
        self.assertEqual(result["historical_availability"]["pregame_knowability"], "not_established")
        self.assertEqual(len(result["raw_observations"]), 6)
        self.assertTrue(all(r.closed == 1 for r in backend.responses))
        self.assertEqual(len(backend.calls), 20)
        manifest = json.loads((stage/"manifest.json").read_text())
        self.assertTrue(all("provider_publication_at" not in entry and "local_inspection_at" not in entry
                            for entry in manifest["artifacts"]))
        self.assertTrue(all(entry["edgefinder_acquired_at"] == STAMP for entry in manifest["artifacts"]))
        for name in ("receipt.json", "manifest.json"):
            body = (stage/name).read_text()
            self.assertNotIn(SECRET, body)
            self.assertNotIn(acquire.CDN, body)
        self.assertFalse(self.final.exists())  # Worker never publishes.

    def test_tampered_saved_bytes_rejected_by_inspector(self):
        stage = self.batch()
        path = stage/"games.csv.gz"
        path.write_bytes(path.read_bytes()+b"x")
        with self.assertRaises(inspector.InspectionError) as caught:
            inspector.inspect_manifest(stage, stage/"manifest.json")
        self.assertEqual(caught.exception.code, "compressed_length_mismatch")

    def test_stage_inventory_and_manifest_tampering(self):
        stage = self.batch()
        manifest = json.loads((stage/"manifest.json").read_text())
        manifest["artifacts"][0]["filename"] = "other.csv.gz"
        self.failure("manifest_identity", acquire._verify_stage, stage, manifest)
        (stage/"unexpected").write_bytes(b"preserve")
        self.failure("stage_inventory", acquire._verify_stage, stage, manifest)


class FilesystemAndSupervisorTests(Cases):
    def test_existing_final_and_interrupted_stage_never_overwritten(self):
        self.final.mkdir()
        (self.final/"keep").write_bytes(b"keep")
        self.failure("destination_exists", acquire._prepare, self.final)
        self.assertEqual((self.final/"keep").read_bytes(), b"keep")
        other = self.root/"other"
        other.mkdir()
        final = other/"run-001"
        stage = other/"run-001.incomplete"
        stage.mkdir()
        self.failure("destination_exists", acquire._prepare, final)
        self.assertTrue(stage.exists())

    def test_traversal_repository_and_unc_paths_rejected(self):
        for path in (self.root/".."/"run-001", REPOSITORY/"run-001", "\\\\server\\share\\run-001",
                     "\\\\?\\C:\\run-001", "relative/run-001"):
            self.failure("destination_policy", acquire._path, path, missing=True)

    def test_explicit_localappdata_resolution_without_creating_it(self):
        with patch.object(acquire.os, "name", "nt"), patch.dict(os.environ, {"LOCALAPPDATA": str(self.root)}):
            self.assertEqual(acquire._destination(), self.root/"EdgeFinder"/"c2a"/"run-001")
        self.assertFalse((self.root/"EdgeFinder").exists())
        for raw in ("relative", "\\\\server\\share", "C:\\base\\..\\escape", "\\\\?\\C:\\base"):
            with patch.object(acquire.os, "name", "nt"), patch.dict(os.environ, {"LOCALAPPDATA": raw}):
                self.failure("localappdata_policy", acquire._destination)

    def test_reparse_component_rejected_before_writes(self):
        original = Path.lstat
        def fake(path):
            if path == self.root:
                return type("Info", (), dict(st_mode=stat.S_IFDIR, st_file_attributes=0x400))()
            return original(path)
        with patch.object(Path, "lstat", fake):
            self.failure("reparse_path", acquire._prepare, self.final)
        self.assertFalse(self.final.exists())

    def test_cleanup_preserves_unknown_files_and_reports_failure(self):
        stage = acquire._prepare(self.final)
        (stage/"games.csv.gz").write_bytes(b"owned")
        (stage/"unrelated").write_bytes(b"preserve")
        self.assertTrue(acquire._cleanup(stage))
        self.assertEqual((stage/"unrelated").read_bytes(), b"preserve")
        self.assertFalse((stage/"games.csv.gz").exists())

    def test_supervised_success_publishes_only_verified_run(self):
        final = self.child("success")
        self.assertEqual(final, self.final)
        self.assertTrue(final.is_dir())
        self.assertFalse(final.with_name("run-001.incomplete").exists())
        inspector.inspect_manifest(final, final/"manifest.json", as_of=STAMP)

    def test_worker_crash_cleans_owned_stage(self):
        self.failure("worker_failed", self.child, "crash")
        self.assertFalse(self.final.exists())
        self.assertFalse(self.final.with_name("run-001.incomplete").exists())

    def test_cleanup_failure_reported_after_worker_crash(self):
        failure = self.failure("worker_failed", self.child, "crash_unknown")
        self.assertTrue(failure.cleanup_failed)
        self.assertEqual((self.final.with_name("run-001.incomplete")/"unknown").read_bytes(), b"preserve")

    def test_blocked_dns_is_terminated_by_external_phase_deadline(self):
        start = time.monotonic()
        self.failure("deadline_exceeded", self.child, "blocked_dns", phase=0.8)
        self.assertLess(time.monotonic()-start, 6)
        self.assertFalse(self.final.exists())
        self.assertFalse(self.final.with_name("run-001.incomplete").exists())

    def test_blocked_read_is_terminated_by_external_phase_deadline(self):
        failure = self.failure("deadline_exceeded", self.child, "blocked_read", phase=0.8)
        self.assertFalse(self.final.exists())
        stage = self.final.with_name("run-001.incomplete")
        self.assertFalse(stage.exists(), dict(cleanup_failed=failure.cleanup_failed,
                                             remaining=[p.name for p in stage.iterdir()] if stage.exists() else []))

    def test_blocked_file_verification_is_also_terminated(self):
        self.failure("deadline_exceeded", self.child, "blocked_hash", phase=0.8)
        self.assertFalse(self.final.exists())
        self.assertFalse(self.final.with_name("run-001.incomplete").exists())

    def test_worker_cleanup_failure_flag_reaches_supervisor(self):
        failure = self.failure("worker_failed", self.child, "close_failure")
        self.assertTrue(failure.cleanup_failed)
        self.assertFalse(self.final.exists())

    def test_batch_deadline_overrides_longer_phase_allowance(self):
        self.failure("deadline_exceeded", self.child, "blocked_read", phase=3, batch=0.8)
        self.assertFalse(self.final.exists())

    def test_missing_ready_and_invalid_phase_never_publish(self):
        self.failure("worker_failed", self.child, "no_ready")
        self.failure("worker_protocol", self.child, "invalid_phase")
        self.assertFalse(self.final.exists())

    def test_unverified_worker_pid_gets_no_permission_to_start(self):
        failure = self.failure("worker_pid", self.child, "wrong_pid")
        self.assertIsNone(failure.last_validated_phase)
        self.assertEqual(failure.attempted_operation, "worker_handshake")
        self.assertFalse(self.final.exists())
        self.assertFalse(self.final.with_name("run-001.incomplete").exists())

    def test_existing_final_created_during_worker_is_preserved(self):
        self.failure("destination_exists", self.child, "competing_final")
        self.assertEqual((self.final/"keep").read_bytes(), b"preserve")

    def test_expiry_during_parent_path_checks_prevents_publication(self):
        original_path, original_clock = acquire._path, time.monotonic
        offset = [0]
        def checked(path, **kwargs):
            result = original_path(path, **kwargs)
            if path == self.final:
                offset[0] = acquire.BATCH_SECONDS+1
            return result
        with patch.object(acquire, "_path", side_effect=checked), \
                patch.object(acquire.time, "monotonic", side_effect=lambda: original_clock()+offset[0]):
            self.failure("deadline_exceeded", self.child, "success")
        self.assertEqual(offset[0], acquire.BATCH_SECONDS+1)
        self.assertFalse(self.final.exists())

    def test_worker_stderr_and_exception_queries_are_never_exposed(self):
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            self.failure("worker_failed", self.child, "secret_error")
        self.assertNotIn(SECRET, stdout.getvalue()+stderr.getvalue())

    def test_cli_no_arguments_has_no_side_effects(self):
        with patch.object(acquire, "_destination") as destination, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(acquire.main([]), 2)
        destination.assert_not_called()
        self.assertIn("explicit_acquire_command_required", stderr.getvalue())

    def test_cli_sanitizes_dependency_failure(self):
        with patch.object(acquire, "_destination", side_effect=OSError(SECRET)), \
                redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(acquire.main(["acquire"]), 2)
        self.assertNotIn(SECRET, stderr.getvalue())


class DiagnosticProtocolTests(Cases):
    def test_every_allowlisted_code_round_trips_without_exception_text(self):
        acquire._attempt("metadata_validation")
        for code in sorted(acquire.FAILURE_CODES):
            with self.subTest(code=code):
                error = acquire.Failure(code)
                error.args = (SECRET,)
                wire = acquire._worker_failure(error)
                self.assertLessEqual(len(wire.encode("ascii"))+2, 128)
                record = acquire._read_worker_failure((wire+"\n").encode("ascii"))
                self.assertEqual(record["code"], code)
                self.assertEqual(record["operation"], "metadata_validation")
                self.assertEqual(record["cleanup_failed"], code == "cleanup_failure")
                self.assertNotIn(SECRET, wire)

    def test_unknown_exception_and_unknown_failure_code_use_fixed_fallback(self):
        for error in (OSError(SECRET), RuntimeError(location()), acquire.Failure(SECRET)):
            wire = acquire._worker_failure(error)
            record = acquire._read_worker_failure((wire+"\n").encode("ascii"))
            self.assertEqual(record["code"], "unexpected_exception")
            self.assertEqual(record["operation"], "unknown")
            self.assertNotIn(SECRET, wire)
            self.assertNotIn("https:", wire)

    def test_unknown_operation_is_sanitized_before_transmission(self):
        error = acquire.Failure("byte_limit")
        error.attempted_operation = SECRET
        self.assertEqual(json.loads(acquire._worker_failure(error))["operation"], "unknown")

    def test_malformed_failure_records_are_rejected(self):
        valid = json.loads(acquire._worker_failure(acquire.Failure("byte_limit")))
        cases = [b"{broken\n", b"{}\n", b"[]\n", b'{"a":NaN}\n',
                 b'{"type":"failure","type":"failure"}\n', b"\xff\n"]
        for key, value in (("type", "other"), ("code", SECRET), ("operation", SECRET),
                           ("cleanup_failed", 1), ("code", ["byte_limit"]), ("operation", None)):
            record = dict(valid)
            record[key] = value
            cases.append(acquire._json_bytes(record)+b"\n")
        extra = dict(valid, url=SECRET)
        cases.extend((acquire._json_bytes(extra)+b"\n", b"{"+b"x"*128+b"\n",
                      acquire._json_bytes(valid)))
        for body in cases:
            self.failure("worker_protocol", acquire._read_worker_failure, body)

    def test_final_json_has_no_arbitrary_exception_attributes(self):
        error = acquire.Failure(SECRET)
        error.failure_code = SECRET
        error.last_validated_phase = SECRET
        error.attempted_operation = SECRET
        error.operation_source = SECRET
        error.worker_exit_status = SECRET
        error.cleanup_failed = SECRET
        output = acquire._failure_json(error)
        self.assertEqual(output["error"], "unexpected_exception")
        self.assertEqual(output["failure_code"], "unexpected_exception")
        for key in ("last_validated_phase", "attempted_operation", "operation_source", "worker_exit_status"):
            self.assertIsNone(output[key])
        self.assertFalse(output["cleanup_failed"])
        self.assertNotIn(SECRET, acquire._json_bytes(output).decode("ascii"))

    def test_primary_failure_operation_survives_response_cleanup(self):
        error = self.failure("stream_failure", acquire._receive,
                             acquire._metadata_endpoint("schedules"), 10, lambda _: None,
                             lambda _: FakeResponse(b"x", read_error=OSError(SECRET),
                                                    close_error=OSError(SECRET)))
        record = json.loads(acquire._worker_failure(error))
        self.assertEqual(record["operation"], "response_read")
        self.assertEqual(record["code"], "stream_failure")
        self.assertTrue(record["cleanup_failed"])

    def test_nested_transport_failure_preserves_dns_operation(self):
        with patch.object(acquire.socket, "getaddrinfo", side_effect=OSError(SECRET)):
            error = self.failure("transport_failure", acquire._receive,
                                 acquire._metadata_endpoint("schedules"), 10, lambda _: None, acquire._open)
        self.assertEqual(error.attempted_operation, "dns_resolution")
        self.assertNotIn(SECRET, acquire._worker_failure(error))


class SupervisorDiagnosticTests(Cases):
    def diagnostic(self, mode, code, phase, operation, *, cleanup=False):
        failure = self.failure("worker_failed", self.child, "diagnostic:"+mode)
        output = acquire._failure_json(failure)
        self.assertEqual(output["failure_code"], code)
        self.assertEqual(output["last_validated_phase"], phase)
        self.assertEqual(output["attempted_operation"], operation)
        self.assertEqual(output["operation_source"], "worker")
        self.assertEqual(output["worker_exit_status"], 2)
        self.assertEqual(output["cleanup_failed"], cleanup)
        self.assertNotIn(SECRET, acquire._json_bytes(output).decode("ascii"))
        self.assertFalse(self.final.exists())
        self.assertFalse(self.final.with_name("run-001.incomplete").exists())
        return failure

    def test_failure_before_first_phase_has_no_validated_phase(self):
        self.diagnostic("before_phase", "unexpected_exception", None, "worker_handshake")

    def test_staging_failure_is_an_attempt_not_completed_prepare(self):
        self.diagnostic("prepare", "reparse_path", "prepare", "staging_prepare")

    def test_metadata_failure_reports_phase_and_header_operation(self):
        self.diagnostic("metadata", "response_encoding", "before:schedules", "header_validation")

    def test_artifact_failure_reports_specific_artifact_and_operation(self):
        self.diagnostic("artifact", "stream_failure", "artifact:schedules", "response_read")

    def test_final_verification_failure_does_not_report_ready(self):
        self.diagnostic("verification", "integrity_mismatch", "verify", "final_verification")

    def test_unknown_dependency_exception_is_sanitized_in_actual_worker_handler(self):
        self.diagnostic("unknown", "unexpected_exception", "prepare", "staging_prepare")

    def test_unknown_failure_code_is_sanitized_in_actual_worker_handler(self):
        self.diagnostic("unknown_code", "unexpected_exception", "prepare", "staging_prepare")

    def test_primary_response_close_failure_reaches_final_json(self):
        self.diagnostic("close_primary", "cleanup_failure", "before:schedules", "response_close", cleanup=True)

    def test_primary_read_failure_plus_close_failure_preserves_both(self):
        self.diagnostic("close_secondary", "byte_limit", "before:schedules", "response_read", cleanup=True)

    def test_malformed_oversized_duplicate_and_unexpected_messages_never_publish(self):
        for mode in ("malformed", "oversized", "unterminated", "duplicate_failure", "duplicate_phase",
                     "after_failure", "unknown_code", "extra_field", "duplicate_key", "failure_after_ready"):
            with self.subTest(mode=mode):
                with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                    failure = self.failure("worker_protocol", self.child, "protocol:"+mode)
                self.assertEqual(failure.last_validated_phase,
                                 "ready" if mode == "failure_after_ready" else "prepare")
                self.assertEqual(failure.failure_code, "worker_protocol")
                self.assertEqual(failure.operation_source, "supervisor")
                self.assertNotIn(SECRET, stdout.getvalue()+stderr.getvalue()+
                                 acquire._json_bytes(acquire._failure_json(failure)).decode("ascii"))
                self.assertFalse(self.final.exists())
                self.assertFalse(self.final.with_name("run-001.incomplete").exists())

    def test_abrupt_worker_exit_retains_real_exit_status(self):
        failure = self.failure("worker_failed", self.child, "exit_seven")
        self.assertEqual(failure.worker_exit_status, 7)
        self.assertEqual(failure.failure_code, "worker_exit")
        self.assertEqual(failure.last_validated_phase, "prepare")
        self.assertFalse(self.final.exists())

    def test_failure_record_with_zero_exit_status_still_cannot_publish(self):
        failure = self.failure("worker_failed", self.child, "failure_exit_zero")
        self.assertEqual(failure.worker_exit_status, 0)
        self.assertEqual(failure.failure_code, "byte_limit")
        self.assertFalse(self.final.exists())

    def test_failure_record_cannot_extend_existing_deadline(self):
        start = time.monotonic()
        failure = self.failure("deadline_exceeded", self.child, "failure_hang", phase=0.8)
        self.assertLess(time.monotonic()-start, 6)
        self.assertEqual(failure.failure_code, "byte_limit")
        self.assertIsNotNone(failure.worker_exit_status)
        self.assertFalse(self.final.exists())

    def test_prepublication_validation_failure_has_supervisor_operation(self):
        original = acquire._path
        def checked(path, **kwargs):
            if path == self.final:
                raise acquire.Failure("destination_policy")
            return original(path, **kwargs)
        with patch.object(acquire, "_path", side_effect=checked):
            failure = self.failure("destination_policy", self.child, "success")
        self.assertEqual(failure.last_validated_phase, "ready")
        self.assertEqual(failure.attempted_operation, "publication_validation")
        self.assertEqual(failure.operation_source, "supervisor")
        self.assertEqual(failure.worker_exit_status, 0)
        self.assertFalse(self.final.exists())

    def test_atomic_publication_failure_is_sanitized_and_cannot_publish(self):
        with patch.object(Path, "rename", side_effect=OSError(SECRET)):
            failure = self.failure("supervisor_failure", self.child, "success")
        self.assertEqual(failure.last_validated_phase, "ready")
        self.assertEqual(failure.attempted_operation, "publication")
        self.assertEqual(failure.operation_source, "supervisor")
        self.assertEqual(failure.worker_exit_status, 0)
        self.assertFalse(self.final.exists())

    def test_parent_failure_before_worker_has_no_exit_status_or_phase(self):
        with patch.object(acquire, "_destination", side_effect=OSError(SECRET)), \
                redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(acquire.main(["acquire"]), 2)
        output = json.loads(stderr.getvalue())
        self.assertIsNone(output["last_validated_phase"])
        self.assertIsNone(output["worker_exit_status"])
        self.assertEqual(output["attempted_operation"], "destination_validation")
        self.assertEqual(output["operation_source"], "supervisor")
        self.assertNotIn(SECRET, stdout.getvalue()+stderr.getvalue())

    def test_worker_start_failure_has_no_exit_status_or_validated_phase(self):
        with patch.object(acquire.subprocess, "Popen", side_effect=OSError(SECRET)):
            failure = self.failure("supervisor_failure", self.child, "success")
        self.assertIsNone(failure.worker_exit_status)
        self.assertIsNone(failure.last_validated_phase)
        self.assertEqual(failure.attempted_operation, "worker_start")
        self.assertEqual(failure.operation_source, "supervisor")
        self.assertNotIn(SECRET, acquire._json_bytes(acquire._failure_json(failure)).decode("ascii"))

    def test_final_cli_json_preserves_worker_diagnostics_without_raw_text(self):
        failure = self.diagnostic("metadata", "response_encoding", "before:schedules", "header_validation")
        with patch.object(acquire, "_destination", return_value=self.final), \
                patch.object(acquire, "_supervise", side_effect=failure), \
                redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(acquire.main(["acquire"]), 2)
        self.assertEqual(json.loads(stderr.getvalue()), acquire._failure_json(failure))
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(SECRET, stderr.getvalue())


def diagnostic_worker_fixture(mode, final):
    """Exercise production worker reporting through ONLY fake acquisition I/O."""
    from contextlib import ExitStack
    import builtins
    backend = Backend()
    original_print = builtins.print
    def safe_print(*args, **kwargs):
        if mode == "before_phase" and args == ("prepare",):
            raise OSError(SECRET)
        return original_print(*args, **kwargs)
    def request(endpoint):
        response = backend(endpoint)
        if endpoint == acquire._metadata_endpoint("schedules"):
            if mode == "metadata":
                response.headers += (("Content-Encoding", "gzip"),)
            elif mode == "close_primary":
                response.close_error = OSError(SECRET)
            elif mode == "close_secondary":
                response.read_error, response.close_error = acquire.Failure("byte_limit"), OSError(SECRET)
        if mode == "artifact" and endpoint == acquire._artifact_endpoint("schedules"):
            response.read_error = OSError(location())
        return response
    with ExitStack() as stack:
        stack.enter_context(patch.object(acquire, "_destination", return_value=final))
        stack.enter_context(patch.object(acquire, "_open", side_effect=request))
        stack.enter_context(patch.object(builtins, "print", side_effect=safe_print))
        if mode in ("prepare", "unknown", "unknown_code"):
            error = (acquire.Failure("reparse_path") if mode == "prepare" else
                     OSError(SECRET) if mode == "unknown" else acquire.Failure(SECRET))
            stack.enter_context(patch.object(acquire, "_prepare", side_effect=error))
        if mode == "verification":
            stack.enter_context(patch.object(acquire, "_verify_stage", side_effect=acquire.Failure("integrity_mismatch")))
        return acquire._worker_main()


def child_fixture(mode, final):
    """Only synthetic children: install the same no-network/write audit."""
    global TEST_ROOT
    TEST_ROOT = final.parent
    if not TEST_ROOT.is_absolute() or TEST_ROOT.is_relative_to(REPOSITORY):
        return 4
    sys.addaudithook(audit)
    if mode.startswith("diagnostic:"):
        return diagnostic_worker_fixture(mode.partition(":")[2], final)
    def progress(phase):
        print(phase, flush=True)
    progress("pid:"+str(os.getpid()+1 if mode == "wrong_pid" else os.getpid()))
    if sys.stdin.buffer.readline(4) != b"go\n":
        return 4
    progress("prepare")
    if mode == "invalid_phase":
        print("invalid", flush=True)
        return 2
    stage = acquire._prepare(final)
    progress("owned")
    if mode.startswith("protocol:"):
        kind = mode.partition(":")[2]
        acquire._attempt("metadata_collection")
        record = acquire._worker_failure(acquire.Failure("byte_limit"))
        if kind == "malformed":
            progress("{broken")
        elif kind == "oversized":
            progress("{"+SECRET*20)
        elif kind == "unterminated":
            sys.stdout.write("{"+SECRET)
            sys.stdout.flush()
        elif kind == "duplicate_phase":
            progress("prepare")
        elif kind in ("duplicate_failure", "after_failure"):
            progress(record)
            progress(record if kind == "duplicate_failure" else "before:schedules")
        elif kind in ("unknown_code", "extra_field"):
            value = json.loads(record)
            value.update(dict(code=SECRET) if kind == "unknown_code" else dict(url=SECRET))
            progress(acquire._json_bytes(value).decode("ascii"))
        elif kind == "duplicate_key":
            progress('{"type":"failure","type":"failure"}')
        elif kind == "failure_after_ready":
            acquire._batch(stage, Backend(), progress, utc=lambda: STAMP)
            progress("ready")
            progress(record)
        return 2
    if mode == "exit_seven":
        return 7
    if mode in ("failure_exit_zero", "failure_hang"):
        progress("before:schedules")
        acquire._attempt("metadata_collection")
        progress(acquire._worker_failure(acquire.Failure("byte_limit")))
        if mode == "failure_hang":
            time.sleep(3600)
        return 0
    if mode in ("crash", "crash_unknown"):
        (stage/("unknown" if mode == "crash_unknown" else "games.csv.gz")).write_bytes(b"preserve")
        return 3
    if mode == "no_ready":
        return 0
    if mode == "secret_error":
        print(location(), file=sys.stderr)
        return 2
    if mode == "close_failure":
        acquire._attempt("response_close")
        print(acquire._worker_failure(acquire.Failure("cleanup_failure")), flush=True)
        return 2
    backend = Backend()
    def blocked_dns(*args, **kwargs):
        time.sleep(3600)
        raise AssertionError("Supervisor did not terminate blocked resolver")
    def request(endpoint):
        if mode == "blocked_dns":
            with patch.object(acquire.socket, "getaddrinfo", side_effect=blocked_dns):
                return acquire._open(endpoint)
        response = backend(endpoint)
        if mode == "blocked_read" and endpoint == acquire._artifact_endpoint("schedules"):
            response.read = blocked_dns
        return response
    if mode == "blocked_hash":
        with patch.object(acquire, "_hash_file", side_effect=blocked_dns):
            acquire._batch(stage, request, progress, utc=lambda: STAMP)
    else:
        acquire._batch(stage, request, progress, utc=lambda: STAMP)
    if mode == "competing_final":
        final.mkdir()
        (final/"keep").write_bytes(b"preserve")
    progress("ready")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(child_fixture(sys.argv[2], Path(sys.argv[3])))
    with tempfile.TemporaryDirectory(prefix="edgefinder-c2a-acquire-") as temporary_root:
        TEST_ROOT = Path(temporary_root).absolute()
        if TEST_ROOT.is_relative_to(REPOSITORY):
            raise SystemExit("Synthetic fixtures must be outside the repository")
        # Load the shared pure contracts before the audit guard; no live I/O.
        acquire._load_contracts()
        sys.addaudithook(audit)
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            result = unittest.TextTestRunner(verbosity=2).run(
                unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
        print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                              warnings=len(recorded), skips=len(result.skipped),
                              expected_failures=len(result.expectedFailures),
                              unexpected_successes=len(result.unexpectedSuccesses),
                              audit_attempts=AUDIT_COUNTS, exit_code=0 if result.wasSuccessful() else 1),
                         sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
