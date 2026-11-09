"""Pure offline URL, redirect and supplied-address checks. No I/O or settings.

HTTPS/443, ASCII DNS names and exact unescaped paths only. URL scheme/hostname
case and explicit :443 normalize; other equivalent spellings fail closed.
Relative redirects may use RFC dot-segment resolution, but their resulting
destination must be explicitly listed. Nothing follows or sends a request.
"""

import re
from urllib.parse import urljoin, urlsplit

from .contracts import (
    AddressRules, RedirectPolicyError, URLPolicyError, URLRule, URLRules,
    ValidatedConnectionPlan, ValidatedURL, _reference, _url_parts,
)


def validate_url(url: str, *, rules: URLRules) -> ValidatedURL:
    """Evaluate an exact offline destination policy, never grant live permission."""
    if type(rules) is not URLRules:
        raise URLPolicyError("Explicit URLRules required; candidate metadata is not a rule set")
    hostname, path = _url_parts(url)
    if URLRule(hostname, path) not in rules.destinations:
        raise URLPolicyError("Destination is not explicitly listed")
    return ValidatedURL(hostname, path)


def resolve_redirect(current: ValidatedURL, location: str, *, rules: URLRules) -> ValidatedURL:
    """Resolve ONE reference and validate both endpoints; no redirect following.

    Current must still match the supplied rules. Absolute/scheme-relative
    references must already have strict URL syntax; only ordinary relative
    paths permit dot-segment normalization. Empty/query/fragment references,
    repeated slashes and scheme-without-authority forms are rejected.
    Redirect counts/loops belong to a future acquisition state machine.
    """
    try:
        if type(current) is not ValidatedURL:
            raise URLPolicyError("A canonical current URL is required")
        validate_url(current.url, rules=rules)
        _reference(location)
        parts = urlsplit(location)
        if location.startswith("///"):
            raise URLPolicyError("Ambiguous redirect authority")
        if parts.scheme:
            _url_parts(location)
        elif location.startswith("//"):
            _url_parts("https:" + location)
        else:
            # Validate reference spelling before urljoin can collapse segments.
            # A root-relative path has one permitted leading slash.
            path = parts.path[1:] if parts.path.startswith("/") else parts.path
            if (not re.fullmatch(r"[A-Za-z0-9._/-]+", path)
                    or "//" in path or path.endswith("/")):
                raise URLPolicyError("Ambiguous relative path")
        destination = urljoin(current.url, location)
        return validate_url(destination, rules=rules)
    except ValueError:
        raise RedirectPolicyError("Malformed or unlisted redirect destination") from None


def validate_addresses(
    url: ValidatedURL, answers: tuple[str, ...], *, policy: AddressRules
) -> ValidatedConnectionPlan:
    """Validate supplied synthetic answers only; never resolve a hostname.

    Reject the WHOLE set on any unsafe/malformed answer. Deduplicate and sort
    numerically (IPv4 first) so selection is independent of answer order.
    No result proves DNS authenticity, socket pinning, TLS, or live permission.
    """
    return ValidatedConnectionPlan(url, answers, policy)
