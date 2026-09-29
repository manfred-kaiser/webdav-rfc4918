"""WebDAV locking (RFC 4918 §9.10/§9.11, "Class 2" compliance).

Builds LOCK/UNLOCK request bodies and parses the ``<d:activelock>``
response, including the ``Timeout``/``Lock-Token`` header syntax
(RFC 4918 §10.5/§10.7).
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

from webdav.exceptions import MalformedResponseError
from webdav.xml_utils import dav, parse_xml, split_clark, sub_dav_element, to_xml_string

#: Characters that must never appear in a lock token that's later going to
#: be embedded in an ``If``/``Lock-Token`` request header - the transport
#: layer (``http.client``) already refuses to send a header value
#: containing these (CRLF-injection protection), but rejecting it here
#: gives a clear, library-specific error instead of a transport-level one
#: surfacing much later, from an unrelated call.
_FORBIDDEN_TOKEN_CHARS = "\r\n\x00"  # noqa: S105 -- control chars, not a password

if TYPE_CHECKING:
    from collections.abc import Iterable

    from requests import Response as HTTPResponse

#: RFC 4918 §9.10.
EXCLUSIVE = "exclusive"
SHARED = "shared"


def build_lock_body(scope: str = EXCLUSIVE, owner: "str | Element | None" = None) -> str:
    """Build a LOCK request body (RFC 4918 §9.10.3).

    Args:
        scope: :data:`EXCLUSIVE` or :data:`SHARED`.
        owner: The lock owner - plain text, or a pre-built
            :class:`~xml.etree.ElementTree.Element` for a structured
            identity (``owner``'s content model is ``ANY``; the RFC's own
            example uses ``<D:href>mailto:...</D:href>``).

    """
    root = Element(dav("lockinfo"))
    scope_el = sub_dav_element(root, "lockscope")
    sub_dav_element(scope_el, scope)
    type_el = sub_dav_element(root, "locktype")
    sub_dav_element(type_el, "write")
    if owner is not None:
        owner_el = sub_dav_element(root, "owner")
        if isinstance(owner, Element):
            owner_el.append(owner)
        else:
            owner_el.text = owner
    return to_xml_string(root)


def format_timeout(seconds: "int | Iterable[int | None] | None") -> str:
    """Build a ``Timeout`` request header value (RFC 4918 §10.7).

    Args:
        seconds: A single value, or an ordered preference list the server
            picks from (most preferred first) - e.g.
            ``format_timeout([3600, None])`` for
            ``"Second-3600, Infinite"``. ``None`` (either as the whole
            argument, or as one entry of a list) requests an infinite
            timeout - the server is free to grant a shorter one
            regardless, see :attr:`ActiveLock.timeout`.

    """
    values: Iterable[int | None] = (
        (seconds,) if seconds is None or isinstance(seconds, int) else seconds
    )
    return ", ".join("Infinite" if s is None else f"Second-{s}" for s in values)


def parse_timeout(value: str | None) -> "int | None":
    """Parse a ``Timeout`` response header value.

    Returns ``None`` for ``Infinite`` (or an unparseable/absent value -
    treated the same as "no known expiry").
    """
    if not value:
        return None
    first = value.split(",")[0].strip()
    if first.startswith("Second-"):
        digits = first[len("Second-") :]
        if digits.isdigit():
            return int(digits)
    return None


@dataclass(frozen=True)
class LockEntry:
    """One ``<d:lockentry>``: a (scope, type) pair a resource's ``supportedlock`` advertises.

    RFC 4918 §15.10: ``supportedlock`` is a sequence of these, describing
    which scope/type combinations LOCK will accept on this resource - not
    to be confused with :class:`ActiveLock`, which describes a lock that
    already exists.
    """

    scope: str
    lock_type: str

    @classmethod
    def from_element(cls, element: Element) -> "LockEntry":
        """Parse a single ``<d:lockentry>`` element."""
        scope = (
            SHARED
            if element.find(f"{dav('lockscope')}/{dav('shared')}") is not None
            else EXCLUSIVE
        )
        type_el = element.find(dav("locktype"))
        lock_type = "write"
        if type_el is not None and len(type_el):
            lock_type = split_clark(type_el[0].tag)[1]
        return cls(scope=scope, lock_type=lock_type)


@dataclass
class ActiveLock:
    """A parsed ``<d:activelock>`` element: the state of a granted lock."""

    token: str
    scope: str
    depth: str
    owner: str | None
    timeout: "int | None"
    lock_root: str | None

    @classmethod
    def from_element(
        cls, element: Element, *, timeout_header: str | None = None
    ) -> "ActiveLock":
        """Parse a single ``<d:activelock>`` element.

        Raises:
            MalformedResponseError: The element has no
                ``<d:locktoken><d:href>``, or that token contains a control
                character that could never be a legitimate lock token.

        """
        token = element.findtext(f"{dav('locktoken')}/{dav('href')}")
        if not token:
            msg = "<d:activelock> is missing a required <d:locktoken><d:href>"
            raise MalformedResponseError(msg)
        if any(c in token for c in _FORBIDDEN_TOKEN_CHARS):
            msg = f"server returned a lock token with a control character: {token!r}"
            raise MalformedResponseError(msg)

        scope = (
            SHARED
            if element.find(f"{dav('lockscope')}/{dav('shared')}") is not None
            else EXCLUSIVE
        )
        depth = element.findtext(dav("depth")) or "0"
        owner = element.findtext(dav("owner"))
        lock_root = element.findtext(f"{dav('lockroot')}/{dav('href')}")

        timeout_text = element.findtext(dav("timeout")) or timeout_header
        timeout = parse_timeout(timeout_text)

        return cls(
            token=token,
            scope=scope,
            depth=depth,
            owner=owner,
            timeout=timeout,
            lock_root=lock_root,
        )


def parse_lock_response(http_response: "HTTPResponse") -> ActiveLock:
    """Parse a successful LOCK response into an :class:`ActiveLock`.

    Works for both a new lock (``Lock-Token`` response header present)
    and a lock refresh (RFC 4918 §9.10.2 - no ``Lock-Token`` header is
    sent back, the token is only in the body).

    Raises:
        MalformedResponseError: The response body has no usable
            ``<d:activelock>``.

    """
    tree = parse_xml(http_response.content)
    activelock_el = tree.find(f".//{dav('activelock')}")
    if activelock_el is None:
        msg = "LOCK response body has no <d:activelock>"
        raise MalformedResponseError(msg)

    header_token = http_response.headers.get("Lock-Token", "").strip("<>")
    timeout_header = http_response.headers.get("Timeout")
    lock = ActiveLock.from_element(activelock_el, timeout_header=timeout_header)
    if header_token and header_token != lock.token:
        # RFC 4918 doesn't actually allow these to disagree - if a server
        # does it anyway, the header is authoritative (it's what UNLOCK
        # needs verbatim), but this is worth surfacing rather than
        # silently picking one.
        lock.token = header_token
    return lock
