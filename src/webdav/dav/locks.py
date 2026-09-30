"""WebDAV locking (RFC 4918 §9.10/§9.11, "Class 2" compliance).

Builds LOCK/UNLOCK request bodies and parses the ``<d:activelock>``
response, including the ``Timeout``/``Lock-Token`` header syntax
(RFC 4918 §10.5/§10.7).
"""

import posixpath
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

from webdav.dav.conditional import (
    Condition,
    build_if_header_single,
    merge_if_headers,
    token_condition,
)
from webdav.dav.urls import URL, path_key
from webdav.dav.xml_utils import (
    dav,
    parse_xml,
    split_clark,
    sub_dav_element,
    to_xml_string,
)
from webdav.exceptions import ClientError, MalformedResponseError
from webdav.methods import WRITE_METHODS, Method
from webdav.transport.parse_utils import parse_uint
from webdav.url_safety import effective_origin

#: What a lock token may look like. A token is a Coded-URL (RFC 4918 sec.
#: 10.4): an absolute URI, in ASCII, that this library puts between ``<`` and
#: ``>`` in an ``If`` or ``Lock-Token`` header. The server chose it, so it is
#: checked against the URI character set - a token containing ``>``, a space
#: or a quote could otherwise close the brackets and add conditions of its
#: own to the header, and one with characters outside Latin-1 would make
#: every later request under that path fail to encode.
_TOKEN_RE = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{1,1024}")


def check_token(token: str) -> str:
    """Return ``token``, a lock token the *server* sent, if it is usable.

    Raises:
        MalformedResponseError: It is not (see ``_TOKEN_RE``).

    """
    if not _TOKEN_RE.fullmatch(token):
        msg = f"server returned an unusable lock token: {token[:60]!r}"
        raise MalformedResponseError(msg)
    return token


def validate_token(token: str) -> str:
    """Return ``token``, a lock token the *caller* gave, if it is usable.

    The same test as :func:`check_token`, but a bad token here is the caller's
    mistake, not a malformed answer from the server.

    Raises:
        ValueError: It is not a usable lock token (see ``_TOKEN_RE``).

    """
    if not _TOKEN_RE.fullmatch(token):
        msg = f"not a usable lock token: {token[:60]!r}"
        raise ValueError(msg)
    return token


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from requests import Response as HTTPResponse

    from webdav.url_safety import Origin

#: How long a lock is requested for when the caller says nothing, in seconds.
#: Deliberately finite: a client that crashes or loses the network never
#: sends its UNLOCK, and an "Infinite" lock would then block everyone else
#: until an administrator steps in. Pass ``lock_timeout=None`` for infinite.
DEFAULT_LOCK_TIMEOUT = 600

#: RFC 4918 §9.10.
EXCLUSIVE = "exclusive"
SHARED = "shared"


def build_lock_body(
    scope: str = EXCLUSIVE, owner: "str | Element | None" = None
) -> str:
    """Build a LOCK request body (RFC 4918 §9.10.3).

    Args:
        scope: :data:`EXCLUSIVE` or :data:`SHARED`.
        owner: The lock owner - plain text, or a pre-built
            :class:`~xml.etree.ElementTree.Element` for a structured
            identity (``owner``'s content model is ``ANY``; the RFC's own
            example uses ``<D:href>mailto:...</D:href>``).

    """
    if scope not in (EXCLUSIVE, SHARED):
        msg = f"lock scope must be {EXCLUSIVE!r} or {SHARED!r}, got {scope!r}"
        raise ValueError(msg)
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
    values: list[int | None] = (
        [seconds] if seconds is None or isinstance(seconds, int) else list(seconds)
    )
    if not values:
        msg = "a Timeout preference list cannot be empty"
        raise ValueError(msg)
    for value in values:
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < 2**32
        ):
            msg = f"a lock timeout is a number of seconds (0 to 2**32-1) or None, got {value!r}"
            raise ValueError(msg)
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
        return parse_uint(first[len("Second-") :])
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
        token = (element.findtext(f"{dav('locktoken')}/{dav('href')}") or "").strip()
        if not token:
            msg = "<d:activelock> is missing a required <d:locktoken><d:href>"
            raise MalformedResponseError(msg)
        check_token(token)

        scope = (
            SHARED
            if element.find(f"{dav('lockscope')}/{dav('shared')}") is not None
            else EXCLUSIVE
        )
        depth = element.findtext(dav("depth")) or "0"
        # ``owner`` may hold anything (sec. 14.17; the RFC's own example is an
        # ``<href>``): its text, including that of its children.
        owner_el = element.find(dav("owner"))
        owner = (
            "".join(owner_el.itertext()).strip() or None
            if owner_el is not None
            else None
        )
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


def parse_lock_response(
    http_response: "HTTPResponse", expected_token: "str | None" = None
) -> ActiveLock:
    """Parse a successful LOCK response into an :class:`ActiveLock`.

    Works for both a new lock (``Lock-Token`` response header present)
    and a lock refresh (RFC 4918 sec. 9.10.2 - no ``Lock-Token`` header is
    sent back, the token is only in the body; pass the refreshed lock's
    token as ``expected_token``).

    A ``lockdiscovery`` may list several locks (shared locks): the one
    described is the one whose token is the ``Lock-Token`` header (or
    ``expected_token``) - never simply the first, which could be another
    holder's lock.

    Raises:
        MalformedResponseError: The response body has no usable
            ``<d:activelock>``, or none of them is the lock asked about.

    """
    tree = parse_xml(http_response.content)
    elements = tree.findall(f".//{dav('activelock')}")
    if not elements:
        msg = "LOCK response body has no <d:activelock>"
        raise MalformedResponseError(msg)

    header_token = http_response.headers.get("Lock-Token", "").strip().strip("<>")
    timeout_header = http_response.headers.get("Timeout")
    wanted = check_token(header_token) if header_token else expected_token
    locks = [
        ActiveLock.from_element(el, timeout_header=timeout_header) for el in elements
    ]
    if wanted:
        for lock in locks:
            if lock.token == wanted:
                return lock
        if header_token and len(locks) == 1:
            # RFC 4918 doesn't actually allow these to disagree - if a server
            # does it anyway, the header is authoritative (it's what UNLOCK
            # needs verbatim) and there is no other lock it could be about.
            locks[0].token = header_token
            return locks[0]
        msg = "LOCK response lists no lock with the token that was asked about"
        raise MalformedResponseError(msg)
    if len(locks) == 1:
        return locks[0]
    msg = "LOCK response lists several locks and names none of them"
    raise MalformedResponseError(msg)


@dataclass(frozen=True)
class HeldLock:
    """A lock this session took: where, which token, how deep."""

    url: str
    token: str
    depth: str


def _tag_url(url: str) -> str:
    """``url`` as it is written into an ``If`` header: a valid URI, without query or fragment.

    The resource tag is a Coded-URL, so a space, a ``>`` or a non-ASCII character
    in it has to be percent-encoded (it could otherwise close the bracket early
    or fail to encode), and a fragment is not part of what a lock is on.
    """
    parsed = URL(url)
    parsed.query = ""
    parsed.fragment = ""
    return str(parsed)


class LockRegistry:
    """The locks a session currently holds, so its writes can carry their tokens.

    Keyed by *origin and path* of the URL that was locked (never a bare
    path): a lock token is a capability for one resource on one server,
    and must not be attached to a request for the same path on a
    different host. Lookups are on the requested URL only - never on a
    server-supplied ``lockroot``, which a malicious server could point at
    an unrelated resource to make this client attach a token somewhere
    the caller never asked for.

    Thread-safe: a session (and so its registry) may be shared.
    """

    def __init__(self) -> None:
        """Create an empty registry."""
        # (origin, comparison key of the path) -> the locks held there; a
        # list since RFC 4918 sec. 6.2 lets several (shared) locks coexist
        # on one resource.
        self._held: dict[tuple[Origin, str], list[HeldLock]] = {}
        self._mutex = threading.RLock()

    def __bool__(self) -> bool:
        """Whether any lock is held."""
        return bool(self._held)

    @staticmethod
    def _key(url: str) -> "tuple[Origin, str]":
        origin = effective_origin(url)
        if origin is None:
            msg = f"cannot track a lock for {url!r}: not a plain http(s) URL"
            raise ClientError(msg)
        return origin, path_key(URL(url).path)

    def add(self, url: str, token: str, depth: str) -> None:
        """Record that ``token`` (with ``depth``) is held on ``url``."""
        key = self._key(url)
        check_token(token)
        with self._mutex:
            self._held.setdefault(key, []).append(HeldLock(_tag_url(url), token, depth))

    def discard(self, url: str, token: str, depth: str) -> None:
        """Forget a held lock; a no-op if it isn't recorded."""
        key = self._key(url)
        with self._mutex:
            entries = self._held.get(key)
            if not entries:
                return
            entries[:] = [e for e in entries if (e.token, e.depth) != (token, depth)]
            if not entries:
                del self._held[key]

    def discard_token(self, token: str, *, url: "str | None" = None) -> None:
        """Forget every held lock with this ``token``; a no-op if there is none.

        Wherever it was recorded - or, with ``url``, only there.
        """
        only = self._key(url) if url is not None else None
        with self._mutex:
            for key in list(self._held):
                if only is not None and key != only:
                    continue
                entries = self._held[key]
                entries[:] = [e for e in entries if e.token != token]
                if not entries:
                    del self._held[key]

    def replace_token(self, old: str, new: str) -> None:
        """Swap a token after a refresh (RFC 4918 sec. 9.10.2)."""
        check_token(new)
        with self._mutex:
            for entries in self._held.values():
                for i, held in enumerate(entries):
                    if held.token == old:
                        entries[i] = HeldLock(held.url, new, held.depth)

    def covering(self, url: str) -> list[HeldLock]:
        """The locks a write to ``url`` has to present a token for.

        - a lock on ``url`` itself;
        - a ``Depth: infinity`` lock on an ancestor (it covers everything
          below it, including not-yet-existing members);
        - a lock - of *either* depth - on ``url``'s parent collection: RFC
          4918 sec. 7.4 has a write lock on a collection prevent members
          being added to or removed from it, whether it was taken with
          ``Depth: 0`` or ``infinity``.

        Matched purely on the path string, never on whether anything
        exists there.
        """
        if not self._held:
            return []
        try:
            origin, path = self._key(url)
        except ClientError:
            return []
        parent = posixpath.dirname(path.rstrip("/")) or "/"
        found: list[HeldLock] = []
        with self._mutex:
            for (held_origin, held_path), entries in self._held.items():
                if held_origin != origin:
                    continue
                # The root ("/") needs no extra separator before its
                # children; every other path does, so "/a" doesn't also
                # match "/ab".
                prefix = held_path if held_path == "/" else held_path + "/"
                for held in entries:
                    exact = path == held_path
                    below = held.depth == "infinity" and path.startswith(prefix)
                    if exact or below or (path != "/" and held_path == parent):
                        found.append(held)
        return found

    def below(self, url: str) -> list[HeldLock]:
        """The locks held strictly *inside* ``url`` (on members of the collection it names).

        A ``DELETE`` or ``MOVE`` of a collection takes everything under it along,
        and RFC 4918 sec. 7.4/10.4 wants the token of every locked resource within
        that scope submitted.
        """
        if not self._held:
            return []
        try:
            origin, path = self._key(url)
        except ClientError:
            return []
        prefix = path if path == "/" else path + "/"
        with self._mutex:
            return [
                held
                for (held_origin, held_path), entries in self._held.items()
                if held_origin == origin
                and held_path != path
                and held_path.startswith(prefix)
                for held in entries
            ]

    def token_for(self, url: str) -> str | None:
        """The token of a held lock that covers ``url`` itself, if any.

        (The lock itself, or a ``Depth: infinity`` lock above it - not a
        lock that merely protects the membership of its parent
        collection, see :meth:`covering`.)
        """
        try:
            _origin, path = self._key(url)
        except ClientError:
            return None
        for held in self.covering(url):
            held_path = self._key(held.url)[1]
            if path == held_path or held.depth == "infinity":
                return held.token
        return None

    def if_header(self, *urls: str, include_below: "Iterable[str]" = ()) -> str | None:
        """The ``If`` header a write touching ``urls`` needs, or ``None``.

        ``include_below`` names the ones whose *members* the write takes along (a
        ``DELETE``/``MOVE`` of a collection): the locks held inside those are
        presented too.

        A write to one resource that is itself locked gets the plain
        (untagged) form ``(<token>)``. Anything else - a request touching
        several resources (COPY/MOVE), or one that needs the lock of a
        *parent* collection or of members below - gets a tagged list per lock, each
        scoped to the resource the lock is on (sec. 10.4: an untagged token only
        speaks about the request's own resource, and the lock on a parent
        is not one on it). The two forms cannot be mixed in one header.
        """
        held_locks: list[HeldLock] = []
        for url in urls:
            for held in self.covering(url):
                if held not in held_locks:
                    held_locks.append(held)
        for url in include_below:
            for held in self.below(url):
                if held not in held_locks:
                    held_locks.append(held)
        if not held_locks:
            return None
        if (
            len(urls) == 1
            and not tuple(include_below)
            and all(self._key(h.url) == self._key(urls[0]) for h in held_locks)
        ):
            return token_condition(held_locks[0].token)
        return merge_if_headers(
            *(
                build_if_header_single([Condition(token=h.token)], resource=h.url)
                for h in held_locks
            )
        )

    def headers_for(
        self, method: str, url: str, headers: "Mapping[str, str]"
    ) -> dict[str, str]:
        """``headers`` plus the ``If`` header of any held lock a ``method`` request to ``url`` needs.

        Only a write carries one - a read has no use for a lock token, and
        sending one anyway would put a capability on the wire for nothing -
        and never on top of an ``If`` header the caller wrote themselves.
        """
        if method not in WRITE_METHODS or any(k.lower() == "if" for k in headers):
            return dict(headers)
        below = (url,) if method == Method.DELETE else ()
        header = self.if_header(url, include_below=below)
        return {**headers, "If": header} if header else dict(headers)

    def if_header_for_transfer(
        self, source: str, destination: str, *, moves: bool
    ) -> str | None:
        """The ``If`` header a COPY/MOVE from ``source`` to ``destination`` needs, or ``None``.

        RFC 4918 sec. 10.2: "If a source or destination resource within
        the scope of the Depth header is locked in such a way as to
        prevent the successful execution of the method, then the lock
        token for that resource MUST be submitted with the request in the
        If request header." That includes a lock on the *parent* of either
        (sec. 7.4: a lock on a collection covers its membership: the
        source's parent loses a member on a MOVE, the destination's gains
        one), and - for a MOVE, which takes the source and all it holds away -
        locks on members of the source. Every lock touched is presented as a
        tagged list of its own resource - a plain token would only speak about
        the request's.
        """
        return self.if_header(
            source, destination, include_below=(source,) if moves else ()
        )
