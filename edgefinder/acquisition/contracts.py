"""Immutable, standard-library-only contracts for offline policy evaluation.

Candidate metadata and syntax-checked values are not live authorization or
unforgeable capabilities. No class here opens a connection or reads settings.
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
import re
from urllib.parse import urlsplit


class PolicyError(ValueError):
    """A policy input or destination failed closed; messages omit input values."""


class DefinitionError(PolicyError):
    """Invalid immutable contract construction."""


class URLPolicyError(PolicyError):
    """Malformed or unlisted URL."""


class RedirectPolicyError(URLPolicyError):
    """Malformed or unlisted redirect destination."""


class AddressPolicyError(PolicyError):
    """Malformed or unsafe supplied address answers."""


def _reference(value):
    # Check BEFORE urlsplit/urljoin: they can discard whitespace/control bytes.
    if (type(value) is not str or not value
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
            or any(c in value for c in "\\%?#")):
        raise URLPolicyError("Expected an unescaped ASCII URL/reference without query or fragment")


def _hostname(value):
    if (type(value) is not str or len(value) > 253 or value != value.lower()
            or not value.isascii()):
        raise URLPolicyError("Expected a canonical ASCII hostname")
    labels = value.split(".")
    if (len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
            or any(label.startswith("xn--") or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels)):
        raise URLPolicyError("IP literals, IDNA labels, and ambiguous hostnames are forbidden")


def _path(value):
    if (type(value) is not str or not re.fullmatch(r"/[A-Za-z0-9._/-]*", value)
            or (value != "/" and any(p in ("", ".", "..") for p in value[1:].split("/")))):
        raise URLPolicyError("Expected an absolute unescaped path without empty or dot segments")


def _url_parts(value):
    """Only scheme/hostname case and an explicit :443 are normalized."""
    _reference(value)
    try:
        parts = urlsplit(value)
    except ValueError:
        raise URLPolicyError("Malformed URL") from None
    if parts.scheme != "https" or not parts.netloc:
        raise URLPolicyError("An absolute HTTPS URL is required")
    # Parsing authority ourselves excludes userinfo, empty ports, IPv6 brackets,
    # percent escapes, nondecimal/zero-padded ports, and extra delimiters.
    authority = re.fullmatch(r"([A-Za-z0-9.-]+)(?::443)?", parts.netloc)
    if authority is None:
        raise URLPolicyError("Malformed authority or forbidden credentials/port")
    host = authority[1].lower()
    _hostname(host)
    _path(parts.path)
    return host, parts.path


@dataclass(frozen=True, slots=True)
class ArtifactDefinition:
    """Source-derived candidate identity ONLY; never an approved destination."""

    artifact_id: str
    provider: str
    candidate_url: str
    media_format: str
    scope: str
    endpoint_status: str = field(default="source_derived_unverified", init=False)

    def __post_init__(self):
        for value in (self.artifact_id, self.provider, self.media_format):
            if type(value) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
                raise DefinitionError("Identity fields must be explicit lowercase ASCII identifiers")
        if (type(self.scope) is not str or not self.scope or self.scope != self.scope.strip()
                or any(ord(c) < 32 or ord(c) >= 127 for c in self.scope)):
            raise DefinitionError("Scope must be explicit printable ASCII text")
        try:
            _url_parts(self.candidate_url)
        except URLPolicyError:
            raise DefinitionError("Candidate URL must satisfy strict URL syntax") from None


@dataclass(frozen=True, slots=True)
class URLRule:
    """One exact hostname/path for offline evaluation; HTTPS/443 only.

    Rules have no live-authorization meaning. No wildcard, IDNA, query, prefix,
    or suffix matching is supported. Construction requires canonical spelling.
    """

    hostname: str
    path: str

    def __post_init__(self):
        try:
            _hostname(self.hostname)
            _path(self.path)
        except URLPolicyError:
            raise DefinitionError("Invalid exact URL rule") from None


@dataclass(frozen=True, slots=True)
class URLRules:
    """Explicit immutable destination set; empty means deny every URL."""

    destinations: tuple[URLRule, ...] = ()

    def __post_init__(self):
        if (type(self.destinations) is not tuple
                or any(type(rule) is not URLRule for rule in self.destinations)):
            raise DefinitionError("Destinations must be a tuple of URLRule values")
        if len(set(self.destinations)) != len(self.destinations):
            raise DefinitionError("Duplicate URL rules")
        object.__setattr__(self, "destinations", tuple(sorted(
            self.destinations, key=lambda rule: (rule.hostname, rule.path))))


@dataclass(frozen=True, slots=True)
class ValidatedURL:
    """Canonical syntax-checked value, not proof of live permission."""

    hostname: str
    path: str
    scheme: str = field(default="https", init=False)
    port: int = field(default=443, init=False)

    def __post_init__(self):
        try:
            _hostname(self.hostname)
            _path(self.path)
        except URLPolicyError:
            raise DefinitionError("Invalid canonical URL") from None

    @property
    def url(self):
        return f"https://{self.hostname}{self.path}"


# Conservative fixed baseline, supplemented (never weakened) by AddressRules.
# is_global alone is insufficient: multicast and special-purpose exceptions
# must not become eligible after an interpreter classification change.
_DENIED_V4 = tuple(ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))
_NATIVE_V6 = ip_network("2000::/3")
_DENIED_V6 = tuple(ip_network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20",
))


@dataclass(frozen=True, slots=True)
class AddressRules:
    """Fixed public-address baseline with optional ADDITIONAL CIDR denials.

    Conservatively excludes special assignments and IPv6 outside native
    2000::/3, including mapped/compatible IPv4, NAT64 and local-use ranges.
    Changes to the baseline require source review, not a runtime bypass.
    """

    additional_denied_networks: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.additional_denied_networks) is not tuple:
            raise DefinitionError("Additional denials must be an immutable tuple")
        canonical = []
        for value in self.additional_denied_networks:
            if type(value) is not str or "/" not in value or "%" in value:
                raise DefinitionError("Expected canonical CIDR denial")
            try:
                network = ip_network(value, strict=True)
            except ValueError:
                raise DefinitionError("Invalid CIDR denial") from None
            if str(network) != value:
                raise DefinitionError("Expected canonical CIDR denial")
            canonical.append(value)
        object.__setattr__(self, "additional_denied_networks", tuple(sorted(set(canonical))))


def _address_answers(answers, policy):
    if type(policy) is not AddressRules:
        raise AddressPolicyError("Explicit AddressRules required")
    if type(answers) is not tuple or not answers:
        raise AddressPolicyError("Supply a nonempty tuple of synthetic IP strings")
    extra = tuple(ip_network(value) for value in policy.additional_denied_networks)
    parsed = set()
    for value in answers:
        if (type(value) is not str or not value or not value.isascii()
                or "%" in value or any(c.isspace() for c in value)):
            raise AddressPolicyError("Malformed supplied IP address")
        try:
            address = ip_address(value)
        except ValueError:
            raise AddressPolicyError("Malformed supplied IP address") from None
        denied = (not address.is_global or address.is_private or address.is_loopback
                  or address.is_link_local or address.is_multicast
                  or address.is_reserved or address.is_unspecified)
        if isinstance(address, IPv4Address):
            denied = denied or any(address in network for network in _DENIED_V4)
        elif isinstance(address, IPv6Address):
            # ISATAP interface identifiers embed IPv4 even under a public prefix.
            isatap = address.packed[8:12] in (b"\x00\x00\x5e\xfe", b"\x02\x00\x5e\xfe")
            denied = (denied or address not in _NATIVE_V6 or isatap
                      or any(address in network for network in _DENIED_V6))
        denied = denied or any(address.version == network.version and address in network
                               for network in extra)
        if denied:
            raise AddressPolicyError("Unsafe answer; the entire answer set is rejected")
        parsed.add(address)
    return tuple(str(address) for address in sorted(parsed, key=lambda a: (a.version, int(a))))


@dataclass(frozen=True, slots=True)
class ValidatedConnectionPlan:
    """Deterministic offline plan; NO socket pinning or rebinding protection.

    A future transport must connect to selected_address without re-resolution,
    verify the peer, and use tls_hostname for SNI/certificate checks and Host.
    This object is not an authorization capability or OS isolation boundary.
    """

    url: ValidatedURL
    addresses: tuple[str, ...]
    address_rules: AddressRules

    def __post_init__(self):
        if type(self.url) is not ValidatedURL:
            raise AddressPolicyError("A canonical ValidatedURL is required")
        object.__setattr__(self, "addresses", _address_answers(self.addresses, self.address_rules))

    @property
    def selected_address(self):
        return self.addresses[0]

    @property
    def tls_hostname(self):
        return self.url.hostname
