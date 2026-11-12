r"""Fixed C2a acquisition; importing this module performs no acquisition.

Future, separately authorized use from PowerShell:
  .venv\Scripts\python.exe -I -S -B inspection/c2a/acquire.py acquire

Only the supervisor publishes run-001. A disposable child performs DNS, TLS,
HTTP, hashing and staging under externally enforced phase/batch deadlines.
The child never renames the staging directory. A killed/crashed supervisor can
leave .incomplete files, never a published run. Existing staging is not resumed.
Directories must stay under the user's exclusive control: lstat checks do not
provide an OS sandbox against concurrent malicious filesystem replacement.
Deadlines rely on normal OS scheduling/process termination, not real-time OS
guarantees. Cleanup and atomic publication are local supervisor filesystem work.

Failure JSON distinguishes the last validated phase START announcement from
the attempted operation, identifies worker/supervisor attribution, and reports
the worker exit status when available. A phase announcement is not completion.
Abrupt exits may leave the worker's exact attempted operation unknown.

HTTP bodies use one Content-Length or one chunked transfer coding, never both.
CPython 3.14's HTTPResponse reads chunk payloads; strict control-line checks
reject malformed delimiters, chunk extensions and nonempty trailers. Budgets
and SHA-256 count entity bytes (the original gzip file), not chunk framing.

HTTPS identifies the hosting service; SHA-256 binds the saved compressed bytes
to GitHub's metadata. Neither authenticates NFL facts nor proves pregame access.
This module does not decompress, inspect CSVs, use SQLite, or place wagers.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
from ipaddress import ip_address
import json
import os
from pathlib import Path, PureWindowsPath
import queue
import re
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import unquote_plus, urlsplit


HERE = Path(__file__).absolute().parent
REPOSITORY = HERE.parent.parent
MIB = 1024 * 1024
CHUNK = 65536
DATA_TOTAL = 16 * MIB
METADATA_FILE = 2 * MIB
METADATA_TOTAL = 8 * MIB
HEADER_CAP = 65536
URL_CAP = 8192
JSON_CAP = 65536
IO_SECONDS = 10
METADATA_SECONDS = 30
ARTIFACT_SECONDS = 120
BATCH_SECONDS = 600
CDN = "release-assets.githubusercontent.com"
BASE = "https://github.com/nflverse/nflverse-data/releases/download/"
API = "https://api.github.com/repos/nflverse/nflverse-data/releases/tags/"
ARTIFACTS = (
    ("schedules", "schedules", "games.csv.gz", 2*MIB),
    ("stats_2025", "stats_player", "stats_player_week_2025.csv.gz", 4*MIB),
    ("stats_2026", "stats_player", "stats_player_week_2026.csv.gz", 4*MIB),
    ("rosters_2025", "weekly_rosters", "roster_weekly_2025.csv.gz", 4*MIB),
    ("rosters_2026", "weekly_rosters", "roster_weekly_2026.csv.gz", 4*MIB),
    ("players", "players", "players.csv.gz", 8*MIB),
)
SPECS = {a: (tag, name, cap) for a, tag, name, cap in ARTIFACTS}
TAGS = ("schedules", "stats_player", "weekly_rosters", "players")
PHASES = ("prepare", *("before:"+t for t in TAGS),
          *("artifact:"+a[0] for a in ARTIFACTS),
          *("after:"+t for t in TAGS), "verify", "ready")
OWNED_NAMES = tuple(a[2] for a in ARTIFACTS) + ("manifest.json", "receipt.json")
QUERY_KEYS = frozenset(("sp", "sv", "sr", "spr", "se", "rscd", "rsct",
                        "skoid", "sktid", "skt", "ske", "sks", "skv", "sig",
                        "jwt", "response-content-disposition", "response-content-type"))
# Diagnostic values are constants, never exception text or response values.
FAILURE_CODES = frozenset((
    "acquisition_failed", "artifact_identity", "asset_identity", "asset_metadata", "byte_limit",
    "cleanup_failure", "deadline_exceeded", "deadline_policy", "destination_exists",
    "destination_policy", "destination_unavailable", "dns_policy", "duplicate_json_key",
    "endpoint_policy", "file_changed", "file_policy", "file_write", "header_limit",
    "integrity_mismatch", "json_limit", "length_mismatch", "localappdata_policy",
    "manifest_identity", "metadata_changed", "metadata_digest", "metadata_identity",
    "metadata_json", "peer_mismatch", "python_runtime", "redirect_policy", "redirect_query",
    "release_identity", "reparse_path", "response_encoding", "response_headers",
    "response_length", "response_protocol", "response_status", "stage_inventory",
    "stream_failure", "supervisor_failure", "supervisor_required", "timestamp",
    "tls_environment", "tls_policy", "transport_failure", "windows_required",
    "worker_failed", "worker_pid", "worker_protocol", "worker_exit", "unexpected_exception",
    "response_framing", "chunked_framing",
))
WORKER_OPERATIONS = frozenset((
    "worker_handshake", "destination_validation", "staging_prepare", "metadata_collection",
    "endpoint_validation", "dns_resolution", "dns_validation", "socket_connect",
    "peer_validation", "tls_context", "tls_handshake", "http_request", "http_headers",
    "header_validation", "redirect_validation", "response_validation", "response_read",
    "response_store", "response_close", "metadata_parse", "metadata_validation",
    "timestamp_recording", "artifact_download", "artifact_write", "artifact_flush",
    "artifact_verification", "metadata_comparison", "receipt_write", "manifest_write",
    "final_verification", "worker_exit", "unknown",
))
SUPERVISOR_OPERATIONS = frozenset((
    "destination_validation", "runtime_validation", "worker_start", "worker_handshake",
    "worker_wait", "worker_exit", "publication_validation", "publication", "unknown",
))
_ATTEMPTED_OPERATION = ContextVar("c2a_attempted_operation", default=None)


class Failure(Exception):
    """Only constant codes cross the CLI boundary; never dependency text/URLs."""

    def __init__(self, code):
        self.code = code
        self.cleanup_failed = False
        self.failure_code = None
        self.last_validated_phase = None
        self.attempted_operation = None
        self.operation_source = None
        self.worker_exit_status = None
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise Failure(code)


def _attempt(operation):
    _require(operation in WORKER_OPERATIONS, "worker_protocol")
    _ATTEMPTED_OPERATION.set(operation)


def _safe_code(code):
    return code if type(code) is str and code in FAILURE_CODES else "unexpected_exception"


def _worker_failure(error):
    """One bounded JSON failure record. No formatting of the exception itself."""
    known = isinstance(error, Failure)
    operation = error.attempted_operation if known else None
    if operation is None:
        operation = _ATTEMPTED_OPERATION.get()
    record = dict(type="failure", code=_safe_code(error.code if known else None),
                  operation=operation if type(operation) is str and operation in WORKER_OPERATIONS else "unknown",
                  cleanup_failed=known and (error.cleanup_failed is True or error.code == "cleanup_failure"))
    body = _json_bytes(record)
    _require(len(body)+2 <= 128, "worker_protocol")  # Includes Windows CRLF.
    return body.decode("ascii")


def _read_worker_failure(line):
    _require(type(line) is bytes and len(line) <= 128 and line.endswith(b"\n"), "worker_protocol")
    try:
        value = _parse_json(line)
    except Exception:
        raise Failure("worker_protocol") from None
    _require(type(value) is dict and set(value) == {"type", "code", "operation", "cleanup_failed"}
             and value["type"] == "failure" and type(value["code"]) is str
             and value["code"] in FAILURE_CODES and type(value["operation"]) is str
             and value["operation"] in WORKER_OPERATIONS and type(value["cleanup_failed"]) is bool,
             "worker_protocol")
    return value


def _failure_json(error):
    """Final CLI diagnostics have a closed vocabulary, even for internal callers."""
    known = isinstance(error, Failure)
    code = _safe_code(error.code if known else None)
    phase = error.last_validated_phase if known else None
    operation = error.attempted_operation if known else None
    source = error.operation_source if known else None
    status = error.worker_exit_status if known else None
    return dict(error=code, failure_code=_safe_code(error.failure_code or code) if known else code,
                last_validated_phase=phase if type(phase) is str and phase in PHASES else None,
                attempted_operation=operation if type(operation) is str and operation in
                WORKER_OPERATIONS | SUPERVISOR_OPERATIONS else None,
                operation_source=source if source in ("worker", "supervisor") else None,
                worker_exit_status=status if type(status) is int and -(2**31) <= status < 2**32 else None,
                cleanup_failed=known and error.cleanup_failed is True)


def _load_contracts():
    # Direct loading works with -I -S without adding the repo to sys.path.
    name = "_c2a_acquisition_contracts"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, REPOSITORY / "edgefinder" / "acquisition" / "contracts.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@dataclass(frozen=True)
class Endpoint:
    host: str
    path: str
    query: str = field(default="", repr=False)

    @property
    def target(self):
        return self.path + ("?"+self.query if self.query else "")


def _artifact_endpoint(aid):
    _require(type(aid) is str and aid in SPECS, "artifact_identity")
    tag, filename, _ = SPECS[aid]
    return Endpoint("github.com", "/nflverse/nflverse-data/releases/download/"+tag+"/"+filename)


def _metadata_endpoint(tag):
    _require(type(tag) is str and tag in TAGS, "metadata_identity")
    return Endpoint("api.github.com", "/repos/nflverse/nflverse-data/releases/tags/"+tag)


def _cdn_endpoint(location, aid):
    _artifact_endpoint(aid)
    _require(type(location) is str and 0 < len(location) <= URL_CAP
             and all(32 < ord(c) < 127 for c in location)
             and "\\" not in location and "#" not in location, "redirect_policy")
    try:
        parts = urlsplit(location)
    except ValueError:
        raise Failure("redirect_policy") from None
    _require(parts.scheme == "https" and parts.netloc in (CDN, CDN+":443")
             and not parts.fragment and bool(parts.query)
             and re.fullmatch(r"/github-production-release-asset/452908115/"
                              r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", parts.path),
             "redirect_policy")
    values = {}
    for pair in parts.query.split("&"):
        key, sep, raw = pair.partition("=")
        _require(sep and key in QUERY_KEYS and key not in values and raw
                 and re.fullmatch(r"(?:[A-Za-z0-9._~+:/=-]|%[0-9A-Fa-f]{2})+", raw),
                 "redirect_query")
        value = unquote_plus(raw)
        _require(all(32 <= ord(c) < 127 for c in value)
                 and not any(c in value for c in "%\\#&"), "redirect_query")
        values[key] = value
    _require({"sp", "sv", "sr", "spr", "se", "sig"} <= values.keys()
             and values["sp"] == "r" and values["sr"] == "b"
             and values["spr"] == "https", "redirect_query")
    for key in ("rscd", "response-content-disposition"):
        if key in values:
            filename = re.escape(SPECS[aid][1])
            _require(re.fullmatch(r'attachment;\s*filename=(?:'+filename+r'|"'+filename+r'")',
                                  values[key]) is not None, "redirect_query")
    return Endpoint(CDN, parts.path, parts.query)


def _approved_endpoint(endpoint):
    _require(type(endpoint) is Endpoint, "endpoint_policy")
    if endpoint.query:
        # No arbitrary Endpoint can bypass the narrow redirect validator.
        _require(any(_cdn_matches(endpoint, aid) for aid in SPECS), "endpoint_policy")
    else:
        _require(endpoint in tuple(_artifact_endpoint(a) for a in SPECS)
                 + tuple(_metadata_endpoint(t) for t in TAGS), "endpoint_policy")


def _cdn_matches(endpoint, aid):
    try:
        return _cdn_endpoint("https://"+endpoint.host+endpoint.target, aid) == endpoint
    except Failure:
        return False


def _connection_plan(endpoint, answers):
    _approved_endpoint(endpoint)
    _require(type(answers) is tuple and 0 < len(answers) <= 64
             and all(type(a) is str and len(a) <= 45 for a in answers), "dns_policy")
    contracts = _load_contracts()
    try:
        # This object carries only the host/path for address validation. The
        # query is separately governed by _cdn_endpoint, never a shared URL rule.
        return contracts.ValidatedConnectionPlan(
            contracts.ValidatedURL(endpoint.host, endpoint.path), answers, contracts.AddressRules())
    except contracts.PolicyError:
        raise Failure("dns_policy") from None


def _tls_context():
    _require(not any(k in os.environ for k in ("SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR")),
             "tls_environment")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs()
    _require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
             and context.keylog_filename is None, "tls_policy")
    return context


class _HeaderReader:
    """Bound status plus headers BEFORE http.client accumulates their contents."""

    def __init__(self, stream):
        self.stream, self.used, self.in_headers = stream, 0, True

    def readline(self, size=-1):
        if not self.in_headers:
            return self.stream.readline(size)
        is_status = self.used == 0
        remaining = HEADER_CAP - self.used
        line = self.stream.readline(min(size if size >= 0 else remaining+1, remaining+1))
        self.used += len(line)
        _require(self.used <= HEADER_CAP, "header_limit")
        _require(line.endswith(b"\r\n") and (line == b"\r\n" or line[:1] not in b" \t"),
                 "response_headers")
        if not is_status and line != b"\r\n":
            key, separator, value = line[:-2].partition(b":")
            _require(separator and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                     and all(32 <= c < 127 for c in value), "response_headers")
        if line == b"\r\n":
            self.in_headers = False
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _HeaderSocket:
    def __init__(self, sock):
        self.sock = sock

    def makefile(self, mode):
        return _HeaderReader(self.sock.makefile(mode, buffering=CHUNK))


class _Response(http.client.HTTPResponse):
    """Keep CPython's bounded payload decoder; tighten its three framing hooks.

    The inspected 3.14 decoder accepts int() spellings, discards unchecked
    delimiters and tolerates EOF in trailers. These hooks validate that syntax;
    HTTPResponse._read_chunked still owns payload reads and chunk accounting.
    Extensions and nonempty trailers deliberately fail closed. Raw-wire tests
    cover these private CPython integration points; no independent decoder.
    """

    def _read_status(self):
        result = super()._read_status()
        _require(result[1] >= 200, "response_status")  # No interim header blocks.
        self._wire_version = result[0]
        return result

    def _read_next_chunk_size(self):
        _require(self._wire_version == "HTTP/1.1", "response_framing")
        line = self.fp.readline(HEADER_CAP+1)
        _require(len(line) <= HEADER_CAP and re.fullmatch(rb"[0-9A-Fa-f]+\r\n", line),
                 "chunked_framing")
        return int(line, 16)

    def _get_chunk_left(self):
        if self.chunk_left == 0:
            _require(self._safe_read(2) == b"\r\n", "chunked_framing")
            # The delimiter is already checked/consumed; let the stdlib read
            # the next size without discarding another two bytes.
            self.chunk_left = None
        return super()._get_chunk_left()

    def _read_and_discard_trailer(self):
        # Only the mandatory empty trailer section is supported. EOF, a lone
        # LF, a partial line, or any trailer field is rejected, never ignored.
        _require(self.fp.readline(HEADER_CAP+1) == b"\r\n", "chunked_framing")


class _LiveResponse:
    def __init__(self, response, tls):
        self.response, self.tls = response, tls
        self.status = response.status
        self.headers = tuple(response.getheaders())

    def read(self, count):
        try:
            return self.response.read(count)
        except http.client.IncompleteRead:
            if self.response.chunked:
                raise Failure("chunked_framing") from None
            raise

    def close(self):
        try:
            self.response.close()
        finally:
            self.tls.close()


def _open(endpoint):
    """One request, no proxies/auth/redirects, standard-library TLS validation."""
    raw = tls = response = None
    try:
        _attempt("endpoint_validation")
        _approved_endpoint(endpoint)
        _attempt("dns_resolution")
        records = socket.getaddrinfo(endpoint.host, 443, type=socket.SOCK_STREAM,
                                     proto=socket.IPPROTO_TCP)
        _attempt("dns_validation")
        _require(0 < len(records) <= 64, "dns_policy")
        answers = []
        for family, kind, protocol, _, address in records:
            _require(family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM
                     and protocol == socket.IPPROTO_TCP and address[1] == 443
                     and (family != socket.AF_INET6 or address[2:] == (0, 0)), "dns_policy")
            answers.append(address[0])
        plan = _connection_plan(endpoint, tuple(answers))
        selected = ip_address(plan.selected_address)
        family = socket.AF_INET if selected.version == 4 else socket.AF_INET6
        _attempt("socket_connect")
        raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.settimeout(IO_SECONDS)
        address = (str(selected), 443) if selected.version == 4 else (str(selected), 443, 0, 0)
        raw.connect(address)  # Numeric sockaddr; socket.create_connection would re-resolve.
        _attempt("peer_validation")
        _require(ip_address(raw.getpeername()[0]) == selected and raw.getpeername()[1] == 443,
                 "peer_mismatch")
        _attempt("tls_context")
        context = _tls_context()
        _attempt("tls_handshake")
        tls = context.wrap_socket(raw, server_hostname=plan.tls_hostname)
        raw = None  # SSL socket now owns the descriptor.
        _attempt("peer_validation")
        _require(ip_address(tls.getpeername()[0]) == selected and tls.getpeername()[1] == 443,
                 "peer_mismatch")
        tls.settimeout(IO_SECONDS)
        accept = "application/vnd.github+json" if endpoint.host == "api.github.com" else "application/octet-stream"
        request = ("GET "+endpoint.target+" HTTP/1.1\r\nHost: "+endpoint.host
                   +"\r\nUser-Agent: EdgeFinder-C2a\r\nAccept: "+accept
                   +"\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        _attempt("http_request")
        tls.sendall(request.encode("ascii"))
        _attempt("http_headers")
        response = _Response(_HeaderSocket(tls), method="GET")
        response.begin()
        return _LiveResponse(response, tls)
    except BaseException as error:
        failed_close = False
        for resource in (response, tls, raw):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    failed_close = True
        failure = error if isinstance(error, Failure) else Failure("transport_failure")
        failure.cleanup_failed |= failed_close
        failure.attempted_operation = _ATTEMPTED_OPERATION.get()
        raise failure from None


def _headers(response):
    _require(type(response.status) is int and type(response.headers) is tuple, "response_protocol")
    headers, used = {}, 0
    for pair in response.headers:
        _require(type(pair) is tuple and len(pair) == 2 and all(type(v) is str for v in pair),
                 "response_headers")
        key, value = pair
        _require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                 and all(ord(c) >= 32 and ord(c) != 127 for c in value), "response_headers")
        used += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 4
        _require(used <= HEADER_CAP, "header_limit")
        headers.setdefault(key.lower(), []).append(value)
    for key in ("content-length", "transfer-encoding"):
        _require(len(headers.get(key, [])) <= 1, "response_framing")
    for key in ("content-encoding", "location"):
        _require(len(headers.get(key, [])) <= 1, "response_headers")
    _require(headers.get("content-encoding", ["identity"]) == ["identity"], "response_encoding")
    if "transfer-encoding" in headers:
        _require(headers["transfer-encoding"][0].lower() == "chunked"
                 and "content-length" not in headers, "response_framing")
    return headers


def _receive(endpoint, cap, sink, request, *, aid=None, expected=None):
    """Bound decoded entity bytes; never HTTP chunk sizes, CRLFs or trailers."""
    _require(type(cap) is int and cap >= 0, "byte_limit")
    current, redirected = endpoint, False
    while True:
        response = None
        primary = None
        try:
            _attempt("http_request")
            response = request(current)
            _attempt("header_validation")
            headers = _headers(response)
            if response.status == 302:
                _attempt("redirect_validation")
                _require(aid is not None and not redirected and current == _artifact_endpoint(aid)
                         and len(headers.get("location", [])) == 1, "redirect_policy")
                current = _cdn_endpoint(headers["location"][0], aid)
                redirected = True
                continue
            _attempt("response_validation")
            _require(response.status == 200 and "location" not in headers, "response_status")
            length_text = headers.get("content-length", [])
            if "transfer-encoding" in headers:
                length = None  # Exclusivity/coding were checked by _headers.
            else:
                _require(len(length_text) == 1 and re.fullmatch(r"0|[1-9][0-9]{0,9}", length_text[0]),
                         "response_framing")
                length = int(length_text[0])
                _require(length <= cap, "byte_limit")
                _require(expected is None or length == expected, "length_mismatch")
            used, digest = 0, hashlib.sha256()
            while True:
                count = min(CHUNK, cap-used+1, expected-used+1 if expected is not None else CHUNK)
                _attempt("response_read")
                chunk = response.read(count)
                _require(type(chunk) is bytes and len(chunk) <= count, "response_protocol")
                if not chunk:
                    break
                used += len(chunk)
                _require(used <= cap, "byte_limit")
                _require(length is None or used <= length, "length_mismatch")
                _require(expected is None or used <= expected, "length_mismatch")
                _attempt("response_store")
                sink(chunk)
                digest.update(chunk)
            _require(length is None or used == length, "length_mismatch")
            _require(expected is None or used == expected, "length_mismatch")
            return used, digest.hexdigest()
        except BaseException as error:
            primary = error if isinstance(error, Failure) else Failure("stream_failure")
            if primary.attempted_operation is None:
                primary.attempted_operation = _ATTEMPTED_OPERATION.get()
            raise primary from None
        finally:
            if response is not None:
                try:
                    if primary is None:
                        _attempt("response_close")
                    response.close()
                except Exception:
                    if isinstance(primary, Failure):
                        primary.cleanup_failed = True
                    elif primary is None:
                        failure = Failure("cleanup_failure")
                        failure.cleanup_failed = True
                        failure.attempted_operation = "response_close"
                        raise failure from None


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _parse_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Failure("metadata_json")))
    except (ValueError, UnicodeError, RecursionError):
        raise Failure("metadata_json") from None


def _timestamp(value):
    _require(type(value) is str and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value), "timestamp")
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise Failure("timestamp") from None
    return value


def _utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _release(tag, value):
    _metadata_endpoint(tag)
    _require(type(value) is dict and value.get("tag_name") == tag
             and value.get("draft") is False and value.get("prerelease") is False
             and type(value.get("id")) is int and value["id"] > 0
             and type(value.get("assets")) is list, "release_identity")
    published = _timestamp(value.get("published_at"))
    expected_names = {name for _, t, name, _ in ARTIFACTS if t == tag}
    matches = {name: [] for name in expected_names}
    for asset in value["assets"]:
        _require(type(asset) is dict and type(asset.get("name")) is str, "asset_metadata")
        # Releases contain other legitimate formats/seasons. Never select them.
        if asset["name"] in matches:
            matches[asset["name"]].append(asset)
    result = {}
    for aid, t, name, cap in ARTIFACTS:
        if t != tag:
            continue
        _require(len(matches[name]) == 1, "asset_identity")
        asset = matches[name][0]
        _require(type(asset.get("id")) is int and asset["id"] > 0
                 and asset.get("state") == "uploaded"
                 and asset.get("browser_download_url") == BASE+tag+"/"+name, "asset_identity")
        _require(type(asset.get("size")) is int and 0 < asset["size"] <= cap, "byte_limit")
        digest = asset.get("digest")
        _require(type(digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "metadata_digest")
        result[aid] = dict(asset_id=asset["id"], release_id=value["id"], size=asset["size"],
                           sha256=digest[7:], release_published_at=published,
                           asset_created_at=_timestamp(asset.get("created_at")),
                           asset_updated_at=_timestamp(asset.get("updated_at")))
    _require(len({a["asset_id"] for a in result.values()}) == len(result), "asset_identity")
    return result


def _path(path, *, missing=False):
    raw = os.fspath(path)
    _require(type(raw) is str and not raw.startswith(("\\\\", "//"))
             and not any(c in raw for c in ("\x00", "\r", "\n")), "destination_policy")
    target = Path(raw)
    _require(target.is_absolute() and ".." not in target.parts
             and not target.is_relative_to(REPOSITORY), "destination_policy")
    for part in target.parts[1:]:
        _require(part not in (".", "..") and ":" not in part
                 and not part.endswith((" ", ".")), "destination_policy")
    for component in (*reversed(target.parents), target):
        try:
            info = component.lstat()
        except FileNotFoundError:
            _require(missing, "destination_unavailable")
            continue
        _require(not stat.S_ISLNK(info.st_mode)
                 and not getattr(info, "st_file_attributes", 0) & 0x400, "reparse_path")
        _require(component == target or stat.S_ISDIR(info.st_mode), "destination_policy")
    return target


def _destination():
    _require(os.name == "nt", "windows_required")
    value = os.environ.get("LOCALAPPDATA")
    _require(type(value) is str and value and PureWindowsPath(value).is_absolute()
             and not value.startswith(("\\\\", "//")) and "/" not in value
             and ".." not in PureWindowsPath(value).parts, "localappdata_policy")
    return Path(value) / "EdgeFinder" / "c2a" / "run-001"


def _prepare(final):
    final = _path(final, missing=True)
    stage = final.with_name(final.name+".incomplete")
    _path(stage, missing=True)
    _require(not final.exists() and not stage.exists(), "destination_exists")
    for directory in (*reversed(final.parent.parents), final.parent):
        _path(directory, missing=True)
        if not directory.exists():
            directory.mkdir()
        _require(directory.is_dir(), "destination_policy")
    stage.mkdir()  # Exclusive; never resume another process's staging directory.
    _path(stage)
    return stage


def _hash_file(path, cap):
    _path(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap,
             "file_policy")
    used, digest = 0, hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(min(CHUNK, cap-used+1))
            if not chunk:
                break
            used += len(chunk)
            _require(used <= cap, "byte_limit")
            digest.update(chunk)
    _require(path.stat().st_size == used == info.st_size, "file_changed")
    return used, digest.hexdigest()


def _write_json(path, value):
    body = _json_bytes(value)
    _require(len(body) <= JSON_CAP, "json_limit")
    with path.open("xb") as output:
        _require(output.write(body) == len(body), "file_write")
        output.flush()
        os.fsync(output.fileno())
    with path.open("rb") as saved:
        _require(saved.read(JSON_CAP+1) == body, "file_changed")


def _verify_stage(stage, manifest):
    _path(stage)
    _require({p.name for p in stage.iterdir()} == set(OWNED_NAMES), "stage_inventory")
    _require(type(manifest) is dict and set(manifest) == {"artifacts", "verification_evidence"}
             and type(manifest["artifacts"]) is list and len(manifest["artifacts"]) == 6,
             "manifest_identity")
    entries = manifest["artifacts"]
    for (aid, tag, name, cap), entry in zip(ARTIFACTS, entries):
        _require(set(entry) == {"artifact_id", "release", "filename", "byte_length", "sha256",
                               "hosting_release_at", "hosting_asset_at", "edgefinder_acquired_at"}
                 and entry["artifact_id"] == aid and entry["release"] == tag
                 and entry["filename"] == name and type(entry["byte_length"]) is int
                 and type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                 "manifest_identity")
        for key in ("hosting_release_at", "hosting_asset_at", "edgefinder_acquired_at"):
            _timestamp(entry[key])
        _require(_hash_file(stage/name, cap) == (entry["byte_length"], entry["sha256"]), "integrity_mismatch")
    _require(sum(e["byte_length"] for e in entries) <= DATA_TOTAL, "byte_limit")
    for name, value in (("manifest.json", manifest),):
        _path(stage/name)
        with (stage/name).open("rb") as source:
            _require(source.read(JSON_CAP+1) == _json_bytes(value), "file_changed")


def _batch(stage, request, progress, *, utc=_utc):
    """Trusted fake request injection is for synthetic tests, not isolation."""
    metadata_used, before, observations = 0, {}, []

    def metadata(tag):
        nonlocal metadata_used
        _attempt("metadata_collection")
        body = bytearray()
        used, _ = _receive(_metadata_endpoint(tag), min(METADATA_FILE, METADATA_TOTAL-metadata_used),
                           body.extend, request)
        metadata_used += used
        _attempt("metadata_parse")
        value = _parse_json(body)
        _attempt("metadata_validation")
        result = _release(tag, value)
        _attempt("timestamp_recording")
        observations.append(dict(tag=tag, observed_at=_timestamp(utc())))
        return result

    for tag in TAGS:
        progress("before:"+tag)
        before.update(metadata(tag))
    _attempt("metadata_validation")
    _require(sum(a["size"] for a in before.values()) <= DATA_TOTAL, "byte_limit")
    _require(len({a["asset_id"] for a in before.values()}) == 6, "asset_identity")
    entries, total = [], 0
    for aid, tag, filename, cap in ARTIFACTS:
        progress("artifact:"+aid)
        _attempt("artifact_download")
        expected = before[aid]
        path = stage/filename
        _attempt("artifact_write")
        with path.open("xb") as output:
            def save(chunk):
                _require(output.write(chunk) == len(chunk), "file_write")
            transferred = _receive(_artifact_endpoint(aid), min(cap, DATA_TOTAL-total), save,
                                   request, aid=aid, expected=expected["size"])
            _attempt("artifact_flush")
            output.flush()
            os.fsync(output.fileno())
        _attempt("artifact_verification")
        reread = _hash_file(path, cap)
        _require(transferred == reread == (expected["size"], expected["sha256"]), "integrity_mismatch")
        total += transferred[0]
        _attempt("timestamp_recording")
        entries.append(dict(artifact_id=aid, release=tag, filename=filename,
                            byte_length=reread[0], sha256=reread[1],
                            hosting_release_at=expected["release_published_at"],
                            hosting_asset_at=expected["asset_updated_at"],
                            edgefinder_acquired_at=_timestamp(utc())))
    after = {}
    for tag in TAGS:
        progress("after:"+tag)
        after.update(metadata(tag))
    _attempt("metadata_comparison")
    _require(before == after, "metadata_changed")
    progress("verify")
    _attempt("timestamp_recording")
    manifest = dict(artifacts=entries, verification_evidence=
                    "Compressed lengths and SHA-256 matched GitHub metadata before and after acquisition; "
                    "hosting evidence only; historical pregame availability not established.")
    receipt = dict(version=1, metadata_observations=observations, assets=before,
                   canonical_sources={a: BASE+t+"/"+n for a, t, n, _ in ARTIFACTS},
                   provider_publication_evidence=None, historical_availability="not_established",
                   inspection_performed=False, completed_at=_timestamp(utc()))
    _attempt("receipt_write")
    _write_json(stage/"receipt.json", receipt)
    _attempt("manifest_write")
    _write_json(stage/"manifest.json", manifest)
    _attempt("final_verification")
    _verify_stage(stage, manifest)


def _cleanup(stage):
    """Only explicit names in this owned stage; never recursively delete."""
    failed = False
    try:
        _path(stage)
        for name in OWNED_NAMES:
            path = stage/name
            if path.exists() or path.is_symlink():
                _path(path)
                _require(path.is_file(), "cleanup_failure")
                path.unlink()
        stage.rmdir()  # Unexpected contents survive and make cleanup fail.
    except Exception:
        failed = True
    return failed


def _worker_environment():
    # Read only named non-secret OS paths; never enumerate/copy the environment.
    return {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA")
            if key in os.environ}


def _worker_executable():
    # Windows venv python.exe can be a launcher. Killing the launcher is not
    # proof that its interpreter child stopped. Use CPython's base executable
    # for this standard-library-only child, then verify its PID before ACK.
    _require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14),
             "python_runtime")
    value = getattr(sys, "_base_executable", None)
    _require(type(value) is str and Path(value).is_absolute() and Path(value).is_file(),
             "python_runtime")
    return value


def _phase_timeout(phase):
    return ARTIFACT_SECONDS if phase.startswith("artifact:") else METADATA_SECONDS


def _supervise(command, final, *, environment, batch_seconds=BATCH_SECONDS,
               phase_seconds=None):
    """Killable worker deadlines include blocked DNS, TLS, reads and file I/O.

    stdout is a tiny fixed phase protocol, not a payload channel. stderr is
    discarded to prevent dependency exceptions or signed-query leakage.
    Only exit 0 following every expected phase permits parent publication.
    """
    _require(type(batch_seconds) in (int, float) and 0 < batch_seconds <= BATCH_SECONDS,
             "deadline_policy")
    stage = final.with_name(final.name+".incomplete")
    process = None
    owned = False
    pid_verified = False
    reported_failure = None
    supervisor_operation = "worker_start"
    reader = None
    events = queue.Queue(maxsize=32)
    start = time.monotonic()
    deadline = start+batch_seconds
    phase_deadline = min(deadline, start+METADATA_SECONDS)
    phase_index, ready = 0, False

    def read_events():
        try:
            while True:
                line = process.stdout.readline(129)
                if len(line) > 128 or (line and not line.endswith(b"\n")):
                    events.put_nowait(b"invalid\n")
                    return
                if line.endswith(b"\r\n"):
                    line = line[:-2]+b"\n"  # Windows text stdout uses CRLF.
                events.put_nowait(line)
                if not line:
                    return
        except Exception:
            try:
                events.put_nowait(b"invalid\n")
            except queue.Full:
                pass

    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        supervisor_operation = "worker_handshake"
        reader = threading.Thread(target=read_events, daemon=True)
        reader.start()
        while True:
            remaining = min(deadline, phase_deadline)-time.monotonic()
            _require(remaining > 0, "deadline_exceeded")
            try:
                line = events.get(timeout=remaining)
            except queue.Empty:
                raise Failure("deadline_exceeded") from None
            _require(time.monotonic() < min(deadline, phase_deadline), "deadline_exceeded")
            if not pid_verified:
                _require(line == ("pid:"+str(process.pid)+"\n").encode("ascii"), "worker_pid")
                pid_verified = True
                process.stdin.write(b"go\n")
                process.stdin.flush()
                process.stdin.close()
                supervisor_operation = "worker_wait"
            elif reported_failure is not None:
                # Exactly one terminal failure record, then EOF. Wait within
                # the existing deadline for the real exit status; never publish.
                _require(not line, "worker_protocol")
                break
            elif line == b"owned\n":
                _require(phase_index == 1 and not owned, "worker_protocol")
                owned = True
            elif line.startswith(b"{"):
                _require(not ready, "worker_protocol")
                reported_failure = _read_worker_failure(line)
            elif not line:
                break
            else:
                expected = PHASES[phase_index] if phase_index < len(PHASES) else None
                _require(expected is not None and line == (expected+"\n").encode("ascii"), "worker_protocol")
                _require(phase_index <= 1 or owned, "worker_protocol")
                phase_index += 1
                ready = expected == "ready"
                allowance = (METADATA_SECONDS if expected == "prepare" else
                             (phase_seconds or _phase_timeout(expected)))
                phase_deadline = min(deadline, time.monotonic()+allowance)
        supervisor_operation = "worker_exit"
        returncode = process.wait(timeout=max(0.001, min(deadline, phase_deadline)-time.monotonic()))
        _require(reported_failure is None and returncode == 0 and ready and owned
                 and phase_index == len(PHASES), "worker_failed")
        _require(time.monotonic() < min(deadline, phase_deadline), "deadline_exceeded")
        supervisor_operation = "publication_validation"
        _path(stage)
        _path(final, missing=True)
        _require(not final.exists(), "destination_exists")
        _require(time.monotonic() < min(deadline, phase_deadline), "deadline_exceeded")
        # Windows rename fails if final exists, including an empty directory.
        supervisor_operation = "publication"
        stage.rename(final)
        return final
    except BaseException as error:
        failure = (error if isinstance(error, Failure) else Failure(
            "deadline_exceeded" if isinstance(error, subprocess.TimeoutExpired) else "supervisor_failure"))
        # A validated phase is an accepted START announcement, not evidence
        # that its operation completed. Only "ready" attests worker readiness.
        failure.last_validated_phase = PHASES[phase_index-1] if phase_index else None
        failure.failure_code = _safe_code(failure.code)
        failure.attempted_operation = supervisor_operation
        failure.operation_source = "supervisor"
        if reported_failure is not None:
            failure.cleanup_failed |= reported_failure["cleanup_failed"]
            if failure.code in ("worker_failed", "deadline_exceeded"):
                failure.failure_code = reported_failure["code"]
                failure.attempted_operation = reported_failure["operation"]
                failure.operation_source = "worker"
        elif failure.code == "worker_failed":
            failure.failure_code = "worker_exit"
        stopped = True
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                stopped = False
        if not stopped:
            failure.cleanup_failed = True  # Never clean while the child may still write.
        elif owned:
            failure.cleanup_failed |= _cleanup(stage)
        if process is not None:
            failure.worker_exit_status = process.poll()
        raise failure from None
    finally:
        if reader is not None:
            reader.join(timeout=1)
        if process is not None and process.poll() is not None:
            process.stdout.close()
            process.stdin.close()


def _worker_main():
    def progress(phase):
        print(phase, flush=True)
    token = _ATTEMPTED_OPERATION.set("worker_handshake")
    try:
        progress("pid:"+str(os.getpid()))
        _require(sys.stdin.buffer.readline(4) == b"go\n", "supervisor_required")
        progress("prepare")
        _attempt("destination_validation")
        final = _destination()
        _attempt("staging_prepare")
        stage = _prepare(final)
        progress("owned")
        _batch(stage, _open, progress)
        progress("ready")
        _attempt("worker_exit")
        return 0
    except BaseException as error:
        print(_worker_failure(error), flush=True)
        return 2  # Parent reports only a constant failure code; no traceback.
    finally:
        _ATTEMPTED_OPERATION.reset(token)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--worker"]:
        return _worker_main()
    if args != ["acquire"]:
        print('{"error":"explicit_acquire_command_required"}', file=sys.stderr)
        return 2
    operation = "destination_validation"
    try:
        final = _destination()
        operation = "runtime_validation"
        command = [_worker_executable(), "-I", "-S", "-B", str(HERE/"acquire.py"), "--worker"]
        operation = "worker_start"
        _supervise(command, final, environment=_worker_environment())
        print('{"status":"acquired_and_verified","historical_availability":"not_established"}')
        return 0
    except BaseException as error:
        failure = error if isinstance(error, Failure) else Failure("acquisition_failed")
        if failure.attempted_operation is None:
            failure.attempted_operation = operation
            failure.operation_source = "supervisor"
        print(_json_bytes(_failure_json(failure)).decode("ascii"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
