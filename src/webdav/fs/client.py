"""``FileSystem``: treats a WebDAV server like a local filesystem.

Its methods (``ls``, ``info``, ``exists``, ``mkdir``, ``remove``, ``copy``,
``move``, ``open``, ``walk``, ``upload_file``, ``download_file``, ``locked``,
...) return plain Python values and raise a
:class:`~webdav.exceptions.WebDAVError` on failure - never a raw
:class:`~webdav.response.Response`, never silence. This is the counterpart to
:class:`~webdav.session.Session`, which speaks HTTP/WebDAV verbs directly
(one request, a ``Response``, no exception unless asked for): the two are
peers, like :mod:`os` and :class:`pathlib.Path` are for the local
filesystem - neither lives inside the other.

A :class:`FileSystem` either owns a private :class:`~webdav.session.Session`
(``FileSystem(base_url, ...)``, the same arguments ``Session`` takes) or
shares an existing one (:meth:`FileSystem.from_session`) - sharing is what
makes a lock taken through the ``FileSystem`` attach to a write made directly
through the shared ``Session``, and vice versa, since both go through the
same :attr:`~webdav.session.Session.locks`.

For the module-level functions that mirror this class one-to-one
(``webdav.ls(url)``, ``webdav.mkdir(url)``, ...) see :mod:`webdav.fs.api`.
"""

# FileSystem reaches into Session's own private helpers (a FileSystem *is*
# the internal API a Session composes its file-system layer from).
# pylint: disable=redefined-builtin,protected-access
import codecs
import errno
import logging
import os
import pathlib
import secrets
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from io import TextIOWrapper
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    Literal,
    TextIO,
    Unpack,
    cast,
    overload,
)

import requests

from webdav.dav.conditional import token_condition
from webdav.dav.features import FeatureDetection
from webdav.dav.fs_utils import peek_filelike_length
from webdav.dav.headers import depth_header
from webdav.dav.locks import (
    _TOKEN_RE,
    DEFAULT_LOCK_TIMEOUT,
    EXCLUSIVE,
    ActiveLock,
    build_lock_body,
    format_timeout,
    parse_lock_response,
    validate_token,
)
from webdav.dav.properties import (
    build_mkcol_body,
    build_propfind_body,
    build_proppatch_body,
)
from webdav.dav.urls import URL, path_key
from webdav.exceptions import (
    ClientError,
    HTTPStatusError,
    IsACollectionError,
    IsAResourceError,
    MalformedResponseError,
    PreconditionFailedError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
)
from webdav.fs._remote import Remote
from webdav.fs.streams import IterStream, SizedIterator
from webdav.methods import Method
from webdav.resource import Resource
from webdav.session import Session, SessionOptions
from webdav.transport.limits import check_chunk_size
from webdav.url_safety import display_url, redact_url

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from datetime import datetime
    from os import PathLike
    from typing import Any, Self
    from xml.etree.ElementTree import Element

    from webdav.dav.multistatus import ResourceResponse
    from webdav.dav.properties import DAVProperties, PropName
    from webdav.response import Response

_LOGGER = logging.getLogger("webdav")

#: The modes :meth:`FileSystem.open` understands.
_OPEN_MODES = frozenset({"r", "rt", "rb", "w", "wt", "wb", "x", "xt", "xb"})

#: ``walk`` refuses to go deeper / visit more collections than this, however
#: the caller set ``max_depth`` - see ``FileSystem.walk``.
_WALK_MAX_DEPTH = 256
_WALK_MAX_DIRS = 100_000

#: A write-mode ``open`` keeps this many bytes in memory before spilling to disk.
_SPOOL_SIZE = 8 * 1024 * 1024

#: The character sets a server's ``Content-Type`` may select for text reads.
_TEXT_CHARSETS = frozenset(
    {
        "utf-8",
        "utf_8",
        "ascii",
        "iso8859-1",
        "latin-1",
        "cp1252",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "utf-32",
    }
)


def _text_charset(name: "str | None") -> "str | None":
    """``name`` if it is a text encoding worth trusting from a server, else ``None``."""
    if not name:
        return None
    try:
        canonical = codecs.lookup(name).name
    except LookupError:
        return None
    return canonical if canonical in _TEXT_CHARSETS else None


def _direct_members(
    responses: "list[ResourceResponse]", own: "ResourceResponse | None", own_key: str
) -> "list[ResourceResponse]":
    """The entries of a ``Depth: 1`` listing that are direct members of the collection asked for.

    An entry outside the collection is a lie or a bug - refused, never
    followed (``walk`` and anything built on ``ls`` would walk out of the
    subtree); one deeper down means the server ignored ``Depth: 1``, and is
    left out.
    """
    prefix = own_key.rstrip("/") + "/"
    members = []
    for resp in responses:
        if resp is own:
            continue
        key = path_key(resp.path)
        if not key.startswith(prefix):
            msg = f"server response href {resp.href!r} is outside the listed collection"
            raise MalformedResponseError(msg)
        if "/" not in key[len(prefix) :]:
            members.append(resp)
    return members


def _resource(response: "ResourceResponse", base_url: URL) -> Resource:
    """The :class:`~webdav.resource.Resource` a multistatus entry describes."""
    props = response.properties
    return Resource(
        response.path_relative_to(base_url),
        href=response.href,
        is_dir=props.resource_type == "directory",
        size=props.content_length,
        created=props.created,
        modified=props.modified,
        etag=props.etag,
        content_type=props.content_type,
        content_language=props.content_language,
        display_name=props.display_name,
    )


def _bounded_chunks(
    fileobj: BinaryIO,
    size: "int | None",
    chunk_size: int,
    callback: "Callable[[int], Any] | None",
    problem: list[str],
) -> "Iterator[bytes]":
    """The chunks of ``fileobj``, exactly ``size`` bytes of them (any length if ``size`` is ``None``).

    A file that is longer or shorter than declared ends the upload with a
    :class:`~webdav.exceptions.ClientError` (its message is also put in ``problem``,
    for the caller to raise when the request itself breaks in consequence).
    """
    sent = 0
    while True:
        want = chunk_size if size is None else min(chunk_size, size - sent)
        if want <= 0:
            if fileobj.read(1):
                problem.append(
                    f"the file is longer than the {size} bytes it was declared to be"
                )
                raise ClientError(problem[0])
            return
        data = fileobj.read(want)
        if not data:
            if size is not None and sent != size:
                problem.append(
                    f"the file ended after {sent} of the {size} bytes it was declared to be"
                )
                raise ClientError(problem[0])
            return
        sent += len(data)
        yield data
        if callback is not None:
            callback(len(data))


class FileSystem:
    """A WebDAV server, treated like a local filesystem - see the module docstring."""

    _session: Session
    _owns_session: bool
    _remote: Remote

    def __init__(
        self, base_url: "str | None" = None, **options: Unpack[SessionOptions]
    ) -> None:
        """Open a private :class:`~webdav.session.Session` for this ``FileSystem`` alone.

        Takes exactly the arguments :class:`~webdav.session.Session` does.
        Use :meth:`from_session` instead to share an existing session (and
        its locks, cookies and connection pool) with code that also sends
        verbs directly.
        """
        self._bind(Session(base_url, **options), owns=True)

    @classmethod
    def from_session(cls, session: Session) -> "FileSystem":
        """Wrap ``session``: shares its connection, cookies and locks.

        A lock taken via :meth:`locked` on the result attaches to a write
        made directly through ``session`` (and vice versa), since both share
        the same :attr:`~webdav.session.Session.locks`. Closing the result
        does *not* close ``session`` - the caller still owns it.
        """
        self = cls.__new__(cls)
        self._bind(session, owns=False)
        return self

    def _bind(self, session: Session, *, owns: bool) -> None:
        self._session = session
        self._remote = Remote(session)
        self._owns_session = owns

    @property
    def session(self) -> Session:
        """The session this ``FileSystem`` sends its requests through.

        Its verbs, settings and ``locks`` are the ones :meth:`locked` and every
        other operation use; for a ``FileSystem`` built with
        :meth:`from_session` it is the session that was given.
        """
        return self._session

    def close(self) -> None:
        """Close the underlying session - only if this ``FileSystem`` created it itself."""
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> "Self":
        """Return ``self`` - see :meth:`close`."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Call :meth:`close`."""
        self.close()

    # -- properties/compliance -------------------------------------------

    def dav_compliance(self, path: str = "") -> set[str]:
        """Return the ``DAV:`` compliance classes the server advertises.

        Asks the server every time (an ``OPTIONS`` request) and raises if it
        cannot be reached; :meth:`Session.features_for
        <webdav.session.Session.features_for>` is the cached variant, for
        which a server that does not answer is "nothing known".
        """
        response = self._session.request(
            Method.OPTIONS, self._remote.locate(path).url, raise_on_error=False
        )
        return set(FeatureDetection.from_response(response).dav_compliances)

    def get_props(
        self,
        path: str,
        *,
        props: "Iterable[str | PropName] | None" = None,
        all_prop: bool = False,
        include: "Iterable[str | PropName] | None" = None,
    ) -> "DAVProperties":
        """Return properties of a resource via PROPFIND.

        Args:
            path: Resource path.
            props: Specific property names to request - see
                :func:`~webdav.dav.properties.build_propfind_body`. Requests
                all properties when omitted (and ``all_prop`` is falsy).
            all_prop: Explicitly request ``<d:allprop/>``.
            include: Additional named properties to request alongside
                ``all_prop`` - see
                :func:`~webdav.dav.properties.build_propfind_body`.

        """
        _url, base, rel = self._remote.locate(path)
        data = build_propfind_body(
            props, all_prop=all_prop or not props, include=include
        )
        # Depth: 0 - this is a single-resource lookup, not a traversal.
        # No explicit Content-Type: prepare_body() sets it for any
        # XML_BODY_METHODS call with a body - PROPFIND is one.
        headers = {"Depth": "0"}
        result = self._remote.propfind(path, headers=headers, data=data)
        return result.get_response_for_path(base.path, rel).properties

    def set_props(
        self,
        path: str,
        *,
        set_props: "dict[str | PropName, Any] | None" = None,
        remove_props: "Iterable[str | PropName] | None" = None,
    ) -> None:
        """Set and/or remove properties via PROPPATCH (RFC 4918 sec. 9.2)."""
        data = build_proppatch_body(set_props, remove_props)
        self._remote.send(Method.PROPPATCH, path, data=data)

    def content_length(self, path: str) -> "int | None":
        """Return the ``getcontentlength`` property."""
        return self.get_props(path, props=["content_length"]).content_length

    def created(self, path: str) -> "datetime | None":
        """Return the ``creationdate`` property."""
        return self.get_props(path, props=["created"]).created

    def modified(self, path: str) -> "datetime | None":
        """Return the ``getlastmodified`` property."""
        return self.get_props(path, props=["modified"]).modified

    def etag(self, path: str) -> "str | None":
        """Return the ``getetag`` property."""
        return self.get_props(path, props=["etag"]).etag

    def content_type(self, path: str) -> "str | None":
        """Return the ``getcontenttype`` property."""
        return self.get_props(path, props=["content_type"]).content_type

    def content_language(self, path: str) -> "str | None":
        """Return the ``getcontentlanguage`` property."""
        return self.get_props(path, props=["content_language"]).content_language

    # -- locking ----------------------------------------------------------

    @contextmanager
    def locked(
        self,
        path: str,
        *,
        scope: str = EXCLUSIVE,
        depth: str = "infinity",
        lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
        owner: "str | Element | None" = None,
    ) -> "Iterator[ActiveLock]":
        """Hold a WebDAV lock on ``path`` for the duration of the ``with`` block.

        Writes made through the shared session to ``path`` (or, with
        ``depth="infinity"``, anything under it) automatically carry the
        held lock's token in an ``If`` header. The lock is released on
        exit, even if the block raised.

        Locking a ``path`` that does not exist yet creates an empty resource
        there (RFC 4918 sec. 9.10.4). The RFC only says it "SHOULD NOT
        disappear" once the lock is gone - a SHOULD, not a MUST - and real
        servers differ: it outlives the lock on wsgidav, but Apache's
        mod_dav deletes it again once the lock is released (confirmed
        against a real instance, see tests/test_apache_compliance.py). The
        lock times out (see ``lock_timeout`` and the granted
        :attr:`~webdav.dav.locks.ActiveLock.timeout`) and is not refreshed for
        you - use :meth:`refresh_lock`; writes made after it timed out fail with
        ``412``.

        Args:
            path: Resource to lock.
            scope: :data:`~webdav.dav.locks.EXCLUSIVE` or
                :data:`~webdav.dav.locks.SHARED`.
            depth: ``"0"`` or ``"infinity"`` - no other value is legal on
                a LOCK request (RFC 4918 sec. 9.10.4).
            lock_timeout: A single seconds value, ``None`` for infinite, or
                an ordered preference list - see
                :func:`~webdav.dav.locks.format_timeout`.
            owner: Plain text, or a pre-built
                :class:`~xml.etree.ElementTree.Element` for a structured
                owner identity - see :func:`~webdav.dav.locks.build_lock_body`.

        Raises:
            ValueError: ``depth`` is neither ``"0"`` nor ``"infinity"``.
            ResourceLockedError: A conflicting lock is held (423).
            MultiStatusError: A ``Depth: infinity`` lock could not cover every
                member (207 - it names the member that stopped it).
            ClientError: The server did not grant the lock.
            MalformedResponseError: The server sent an unusable lock answer.

        """
        depth = depth_header(depth, Method.LOCK)
        # No explicit Content-Type: prepare_body() sets it for any
        # XML_BODY_METHODS call with a body - LOCK is one.
        headers = {
            "Depth": depth,
            "Timeout": format_timeout(lock_timeout),
        }
        # The URL that is locked - fixed now, so the UNLOCK on cleanup
        # always goes to the exact resource that was locked.
        url = self._remote.locate(path).url
        # A 207 is not a granted lock: for ``Depth: infinity`` it names the member
        # that could not be locked (RFC 4918 sec. 9.10.6) and raises here.
        response = self._remote.send(
            Method.LOCK,
            path,
            data=build_lock_body(scope, owner),
            headers=headers,
        )
        try:
            active_lock = parse_lock_response(response)
            # Always keyed by the *requested* URL, never by the server-supplied
            # <lockroot>: a malicious server could name an unrelated resource
            # there and make this session attach the token somewhere the
            # caller never asked to lock (see LockRegistry).
            self._session.locks.add(url, active_lock.token, depth)
        except (MalformedResponseError, ClientError):
            # The server granted a lock this side cannot use: release it (with
            # the token of the Lock-Token header, if that is a usable one)
            # instead of leaving it there until it times out.
            header_token = response.headers.get("Lock-Token", "").strip().strip("<>")
            if _TOKEN_RE.fullmatch(header_token):
                self._unlock_quietly(url, header_token)
            raise
        try:
            yield active_lock
        finally:
            self._session.locks.discard(url, active_lock.token, depth)
            self._unlock_quietly(url, active_lock.token)

    def _unlock_quietly(self, url: str, token: str) -> None:
        """Release the lock ``token`` on ``url``, never raising (and never hiding that it failed).

        A failed UNLOCK (a dropped connection, a refusal, a status other
        than success) must not replace whatever the ``with`` body raised -
        nor hide that the lock is still there: say so, and go on.
        """
        try:
            response = self._session.unlock(url, token, raise_on_error=False)
        except requests.RequestException as exc:
            _LOGGER.warning(
                "could not release the lock on %s: %s - it stays on the server "
                "until it times out",
                redact_url(url),
                exc,
            )
            return
        status = response.status_code
        if HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES:
            return
        if status in (HTTPStatus.NOT_FOUND, HTTPStatus.CONFLICT):
            # RFC 4918 sec. 9.11.1: 409 - the resource was not locked (the URL is
            # the one that was locked, so: it may have timed out) - or it is gone.
            # Nothing to release any more, but writes since may have lost the lock.
            message = "the lock on %s was already gone when it was released (the server answered %s %s) - it may have timed out"
        else:
            # 403: not permitted to remove it; anything else: the server did not release it.
            message = "could not release the lock on %s: the server answered %s %s"
        _LOGGER.warning(message, redact_url(url), status, response.reason or "")

    def refresh_lock(
        self,
        path: str,
        token: str,
        *,
        lock_timeout: "int | Iterable[int | None] | None" = DEFAULT_LOCK_TIMEOUT,
    ) -> ActiveLock:
        """Refresh a held lock's timeout (RFC 4918 sec. 9.10.2).

        Sends a bodyless LOCK request carrying the lock's token in the
        ``If`` header - the RFC's mechanism for extending a lock's
        timeout without releasing and re-acquiring it, which would risk
        another client taking the lock in the gap between the two. No
        ``Depth`` header is sent, since the lock's depth was already
        fixed when it was created and can't change on refresh.

        Updates the shared session's own bookkeeping so a still-open
        :meth:`locked` block for the same lock keeps attaching the right
        token; the returned :class:`~webdav.dav.locks.ActiveLock` reflects the
        refreshed timeout (the one an open block is already holding does
        not update itself - use this method's return value instead).
        """
        validate_token(token)
        headers = {
            "If": token_condition(token),
            "Timeout": format_timeout(lock_timeout),
        }
        response = self._remote.send(Method.LOCK, path, headers=headers)
        active_lock = parse_lock_response(response, expected_token=token)
        self._session.locks.replace_token(token, active_lock.token)
        return active_lock

    # -- collections/entries -----------------------------------------------

    def mkdir(
        self,
        path: str,
        *,
        data: "str | None" = None,
        set_props: "dict[str | PropName, Any] | None" = None,
    ) -> None:
        """Create a collection.

        Args:
            path: Collection path.
            data: Optional, pre-built Extended MKCOL request body (RFC 5689)
                to set a non-default resourcetype and/or properties at
                creation time. Sent with ``Content-Type: application/xml``
                when given.
            set_props: Properties to set at creation time - builds the
                Extended MKCOL body instead of passing one directly (see
                :func:`~webdav.dav.properties.build_mkcol_body`). Pass
                either this or ``data``, not both.

        Raises:
            ValueError: Both ``data`` and ``set_props`` were given.
            ResourceAlreadyExistsError: ``path`` already exists.
            WebDAVError: A server supporting Extended MKCOL refused one or
                more of ``set_props`` - :func:`~webdav.dav.properties.parse_mkcol_response`
                on ``exc.response`` names which one and why.

        """
        if set_props is not None:
            if data is not None:
                msg = "pass either data or set_props, not both"
                raise ValueError(msg)
            data = build_mkcol_body(set_props)
        try:
            response = self._remote.send(
                Method.MKCOL, path, add_trailing_slash=True, data=data
            )
        except HTTPStatusError as exc:
            if exc.status_code == HTTPStatus.METHOD_NOT_ALLOWED:
                raise ResourceAlreadyExistsError(exc.response, path) from exc
            # Apache's mod_dav answers 400, not 405, for this same conflict
            # when the trailing slash this method always adds (RFC 4918 sec.
            # 5.2) lands on an existing *plain* resource - confirmed against
            # a real instance, see tests/test_apache_compliance.py. Only
            # trusted bodyless (``data is None``): a 400 for a request that
            # did carry a body is more likely a genuinely malformed one.
            if exc.status_code == HTTPStatus.BAD_REQUEST and data is None:
                raise ResourceAlreadyExistsError(exc.response, path) from exc
            raise

        if response.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED):
            msg = f"unexpected status {response.status_code} from MKCOL"
            raise MalformedResponseError(msg)

    def remove(self, path: str) -> None:
        """Remove a resource (or a collection, with everything in it).

        Raises:
            ClientError: ``path`` is the root of the session (its ``base_url``, or
                the server's root) - deleting that is not something a slip of an
                empty string should be able to do.

        """
        url, base, _rel = self._remote.locate(path)
        if path_key(URL(url).path) == path_key(base.path):
            msg = "refusing to remove the root of the session (its base_url): name what to remove"
            raise ClientError(msg)
        self._remote.send(Method.DELETE, path)

    def copy(
        self,
        path: str,
        destination: str,
        *,
        overwrite: "bool | None" = False,
        depth: "int | str | None" = None,
    ) -> None:
        """Copy a resource (or a collection, with everything in it) server-side.

        See :meth:`~webdav.session.Session.copy` for the arguments; unlike
        it, this raises a :class:`~webdav.exceptions.WebDAVError` on failure
        instead of returning the raw response.

        Raises:
            ResourceAlreadyExistsError: ``overwrite`` is false and ``destination`` exists.

        """
        self._raise_for_overwrite_conflict(
            self._session.copy(path, destination, overwrite=overwrite, depth=depth),
            overwrite=overwrite,
            destination=destination,
        )

    def move(
        self, path: str, destination: str, *, overwrite: "bool | None" = False
    ) -> None:
        """Move (rename) a resource server-side.

        See :meth:`~webdav.session.Session.move` for the arguments; unlike
        it, this raises a :class:`~webdav.exceptions.WebDAVError` on failure
        instead of returning the raw response.

        Raises:
            ResourceAlreadyExistsError: ``overwrite`` is false and ``destination`` exists.

        """
        self._raise_for_overwrite_conflict(
            self._session.move(path, destination, overwrite=overwrite),
            overwrite=overwrite,
            destination=destination,
        )

    @staticmethod
    def _raise_for_overwrite_conflict(
        response: "Response", *, overwrite: "bool | None", destination: str
    ) -> None:
        """``response.raise_for_status()``, translating a 412 into the more specific error.

        RFC 4918 sec. 9.8.4/9.9.3: with ``Overwrite: F``, a COPY/MOVE onto an
        existing destination fails with 412 - the same condition
        :meth:`upload_fileobj`/:meth:`mkdir` already report as
        :class:`~webdav.exceptions.ResourceAlreadyExistsError`, for the same
        caller-facing reason.
        """
        try:
            response.raise_for_status()
        except PreconditionFailedError as exc:
            if not overwrite:
                raise ResourceAlreadyExistsError(
                    exc.response, display_url(destination)
                ) from exc
            raise

    def ls(self, path: str) -> "list[Resource]":
        """List the members of a collection.

        Always a list of :class:`~webdav.resource.Resource` - each is its own name
        (relative to ``base_url``, or to the server root without one) and carries
        what the server reported (``.size``, ``.is_dir``, ``.modified``, ...).

        Raises:
            IsAResourceError: ``path`` is not a collection (:meth:`info` describes one resource).
            ResourceNotFoundError: There is nothing at ``path``.

        """
        url, base, _rel = self._remote.locate(path)
        result = self._remote.propfind(path, headers={"Depth": "1"})
        responses = result.responses

        own_key = path_key(URL(url).path)
        own = responses.get(own_key)
        if own is None:
            # A case-insensitive server (IIS, SharePoint) may spell the
            # collection's own href differently from the request.
            folded = own_key.casefold()
            own = next(
                (r for k, r in responses.items() if k.casefold() == folded), None
            )
            if own is not None:
                own_key = path_key(own.path)
        if own is not None and own.properties.resource_type == "file":
            raise IsAResourceError(display_url(path), "not a collection: use info()")
        members = _direct_members(result.entries, own, own_key)
        return [_resource(resp, base) for resp in members]

    def info(self, path: str) -> Resource:
        """Describe one resource (a file or a collection - not its members).

        The same :class:`~webdav.resource.Resource` :meth:`ls` returns for each member.
        """
        _url, base, rel = self._remote.locate(path)
        result = self._remote.propfind(path, headers={"Depth": "0"})
        return _resource(result.get_response_for_path(base.path, rel), base)

    def exists(self, path: str) -> bool:
        """Check whether a resource exists."""
        try:
            self._remote.propfind(path, headers={"Depth": "0"})
        except ResourceNotFoundError:
            return False
        return True

    def _is_collection(self, path: str) -> "bool | None":
        """``True`` for a collection, ``False`` for anything else, ``None`` if there is nothing."""
        try:
            return bool(self.get_props(path, props=["resourcetype"]).collection)
        except ResourceNotFoundError:
            return None

    def isdir(self, path: str) -> bool:
        """Check whether a resource is a collection (``False`` if it does not exist)."""
        return self._is_collection(path) is True

    def isfile(self, path: str) -> bool:
        """Check whether a resource exists and is not a collection."""
        return self._is_collection(path) is False

    # -- reading/writing ----------------------------------------------------

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["rb", "wb", "xb"],
        *,
        encoding: "str | None" = ...,
        chunk_size: "int | None" = ...,
    ) -> Iterator[BinaryIO]: ...

    @overload
    @contextmanager
    def open(
        self,
        path: str,
        mode: Literal["r", "rt", "w", "wt", "x", "xt"] = ...,
        *,
        encoding: "str | None" = ...,
        chunk_size: "int | None" = ...,
    ) -> Iterator[TextIO]: ...

    @contextmanager
    def open(
        self,
        path: str,
        mode: str = "r",
        *,
        encoding: "str | None" = None,
        chunk_size: "int | None" = None,
    ) -> "Iterator[TextIO | BinaryIO]":
        """Open a resource for reading or writing, like the builtin ``open``.

        Modes ``r``/``rt``/``rb`` stream the resource down (resuming after
        a dropped connection). Modes ``w``/``wb`` collect what is written -
        in memory up to a threshold, on disk beyond it - and ``PUT`` it,
        replacing the resource, when the ``with`` block ends *without* an
        exception; ``x``/``xb`` do the same but fail if the resource
        already exists (``If-None-Match: *``, atomic on the server).
        Add ``t`` (or nothing) for text, ``b`` for bytes.
        """
        if mode not in _OPEN_MODES:
            msg = f"unsupported mode {mode!r}"
            raise ValueError(msg)
        if chunk_size is not None:
            check_chunk_size(chunk_size)
        if mode[0] == "r":
            yield from self._open_read(path, mode, encoding, chunk_size)
        else:
            yield from self._open_write(path, mode, encoding, chunk_size)

    def _open_read(
        self, path: str, mode: str, encoding: "str | None", chunk_size: "int | None"
    ) -> "Iterator[TextIO | BinaryIO]":
        if self.isdir(path):
            raise IsACollectionError(path, "cannot open a collection")

        with IterStream(
            self._session,
            self._remote.locate(path).url,
            chunk_size=chunk_size or self._session.chunk_size,
        ) as buffer:
            buff = cast("BinaryIO", buffer)
            if mode == "rb":
                yield buff
            else:
                # The server does not get to pick the codec: only well-known text
                # encodings are taken from its Content-Type, anything else is UTF-8.
                enc = encoding or _text_charset(buffer.encoding) or "utf-8"
                yield TextIOWrapper(buff, encoding=enc)

    def _open_write(
        self, path: str, mode: str, encoding: "str | None", chunk_size: "int | None"
    ) -> "Iterator[TextIO | BinaryIO]":
        with tempfile.SpooledTemporaryFile(max_size=_SPOOL_SIZE, mode="w+b") as spool:
            if "b" in mode:
                yield cast("BinaryIO", spool)
            else:
                text = TextIOWrapper(spool, encoding=encoding or "utf-8")
                yield text
                text.flush()
                text.detach()  # leave ``spool`` open for the upload below
            # Reached only if the block raised nothing: a failed write must
            # never replace the remote resource with a half-written one.
            size = spool.seek(0, os.SEEK_END)
            spool.seek(0)
            self.upload_fileobj(
                cast("BinaryIO", spool),
                path,
                overwrite=mode[0] == "w",
                chunk_size=chunk_size,
                size=size,
            )

    def walk(
        self, path: str, *, max_depth: "int | None" = None
    ) -> "Iterator[tuple[str, list[Resource], list[Resource]]]":
        """Walk a collection tree top-down, like :func:`os.walk`.

        Yields ``(path, directories, files)`` for ``path`` and every collection
        below it. The members are the same :class:`~webdav.resource.Resource`
        objects :meth:`ls` returns - full names, usable as they are - not bare
        basenames as in :func:`os.walk`. Each collection costs one ``Depth: 1``
        PROPFIND - never ``Depth: infinity``, which servers commonly
        refuse and which would make one request return a whole tree.
        Remove a directory from the list to skip that subtree. A
        collection reachable a second time (RFC 5842 bindings can make a
        tree cyclic) is visited only once.

        Args:
            path: The collection to start at.
            max_depth: How many levels below ``path`` to descend; ``None``
                for no limit.

        """
        seen: set[str] = set()
        stack: list[tuple[str, int]] = [(path, 0)]
        while stack:
            current, depth = stack.pop()
            key = path_key(URL(self._remote.locate(current).url).path)
            if key in seen:
                continue
            if depth > _WALK_MAX_DEPTH or len(seen) >= _WALK_MAX_DIRS:
                msg = (
                    f"walk gave up at {display_url(current)!r}: more than {_WALK_MAX_DEPTH} levels "
                    f"deep or {_WALK_MAX_DIRS} collections - a server that invents directories "
                    "as you go never ends. Pass max_depth to bound it deliberately."
                )
                raise ClientError(msg)
            seen.add(key)
            entries = self.ls(current)
            dirnames = [e for e in entries if e.is_dir]
            files = [e for e in entries if not e.is_dir]
            subdirs = {e.name for e in dirnames}
            yield current, dirnames, files
            if max_depth is not None and depth >= max_depth:
                continue
            # Honours names the caller removed from ``dirnames``.
            stack.extend(
                (self._from_name(current, name.name), depth + 1)
                for name in reversed(dirnames)
                if name.name in subdirs
            )
            if len(seen) + len(stack) > _WALK_MAX_DIRS:
                # The queue counts too: one listing can announce a hundred
                # thousand subdirectories, and each waits in memory.
                msg = f"walk gave up: more than {_WALK_MAX_DIRS} collections found or queued"
                raise ClientError(msg)

    def _from_name(self, current: str, name: str) -> str:
        """The path (or, without a ``base_url``, URL) an ``ls`` entry ``name`` stands for."""
        if self._session.base_url is not None:
            return name
        return str(URL(current).copy_with(path="/" + name.lstrip("/"), query=""))

    def download_fileobj(
        self,
        path: str,
        fileobj: BinaryIO,
        *,
        chunk_size: "int | None" = None,
        callback: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Write a resource's contents to an open, writable file object.

        Raises if the transfer does not complete - whatever was written to
        ``fileobj`` before then is a partial file, not a download.
        """
        if chunk_size is not None:
            check_chunk_size(chunk_size)
        with self.open(path, mode="rb", chunk_size=chunk_size) as remote_obj:
            size = chunk_size or self._session.chunk_size
            # (pylint takes the @contextmanager result for a generator)
            while data := remote_obj.read(size):
                fileobj.write(data)
                if callback:
                    callback(len(data))

    def download_file(
        self,
        path: str,
        local_path: "str | PathLike[str]",
        *,
        overwrite: bool = False,
        chunk_size: "int | None" = None,
        callback: "Callable[[int], Any] | None" = None,
    ) -> None:
        """Download a resource to a local file.

        The data goes to a temporary file next to ``local_path`` first, and only
        a complete download is moved into place: a failed or interrupted one
        leaves neither a partial file nor - with ``overwrite=True`` - a
        destroyed old one behind. Without ``overwrite`` an existing
        ``local_path`` is an error (``FileExistsError``), checked again
        atomically at the moment of the move, like ``upload_file``'s
        ``overwrite=False``.

        Never writes through a symlink: one at ``local_path`` is refused
        (``OSError``, or ``FileExistsError`` without ``overwrite``), so a
        pre-planted link can't redirect the write to an unintended local file
        (the same class of attack OpenSSH's ``sftp`` client hardened against).
        """
        if chunk_size is not None:
            check_chunk_size(chunk_size)
        target = pathlib.Path(local_path)
        directory = target.absolute().parent
        if not directory.is_dir():
            raise FileNotFoundError(errno.ENOENT, "no such directory", str(directory))
        if (target.is_symlink() or target.exists()) and not overwrite:
            raise FileExistsError(
                errno.EEXIST,
                "file exists (pass overwrite=True to replace it)",
                str(target),
            )
        if target.is_symlink():
            raise OSError(
                errno.ELOOP, "refusing to write through a symlink", str(target)
            )
        # The kernel applies the umask when it creates the file, exclusively
        # (O_EXCL) and without following a link; nothing here reads or changes
        # the process-wide umask, which another thread may be relying on.
        temp = directory / f".webdav-{secrets.token_hex(8)}.part"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp, flags, 0o666)
        claimed = False
        try:
            with os.fdopen(fd, mode="wb") as fobj:
                self.download_fileobj(
                    path, fobj, callback=callback, chunk_size=chunk_size
                )
            if overwrite:
                if target.exists():
                    shutil.copymode(
                        target, temp
                    )  # keep the permissions of what is replaced
            else:
                # Claim the name first: O_EXCL is atomic on every file system
                # (a hard link is not available on some), and only a complete
                # download gets this far, so no half-written file is ever visible.
                os.close(os.open(target, flags, 0o666))
                claimed = True
            temp.replace(target)
        except BaseException:
            temp.unlink(missing_ok=True)
            if claimed and target.exists() and target.stat().st_size == 0:
                target.unlink(missing_ok=True)  # our own, still empty claim
            raise

    def upload_file(
        self,
        local_path: "str | PathLike[str]",
        path: str,
        *,
        overwrite: bool = False,
        chunk_size: "int | None" = None,
        callback: "Callable[[int], Any] | None" = None,
        headers: "dict[str, str] | None" = None,
    ) -> None:
        """Upload a local file to a remote path."""
        with pathlib.Path(local_path).open(mode="rb") as fobj:
            self.upload_fileobj(
                fobj,
                path,
                overwrite=overwrite,
                chunk_size=chunk_size,
                callback=callback,
                headers=headers,
            )

    def upload_fileobj(
        self,
        fileobj: BinaryIO,
        path: str,
        *,
        overwrite: bool = False,
        chunk_size: "int | None" = None,
        callback: "Callable[[int], Any] | None" = None,
        size: "int | None" = None,
        headers: "dict[str, str] | None" = None,
    ) -> None:
        """Upload an open, readable file object to a remote path.

        The body is exactly ``size`` bytes (measured from the file object unless
        given): a file that turns out longer or shorter while it is read is an
        error - never sent as a silently truncated copy, and never allowed to
        leave surplus bytes on the connection for the server to read as the
        start of another request.

        Raises:
            ClientError: The file object did not hold as many bytes as ``size``.
            IsACollectionError: ``path`` is a collection, which takes no PUT (405).
            ResourceAlreadyExistsError: ``overwrite`` is false and ``path`` exists.
            PreconditionFailedError: A precondition of the upload failed.
            requests.RequestException: The transport failed.

        """
        if chunk_size is not None:
            check_chunk_size(chunk_size)
        headers = dict(headers or {})

        # We try to avoid chunked transfer as much as possible, so we try
        # to use size as a hint if provided, else find it out from the
        # file object, else gracefully fall back to chunked encoding.
        if size is None:
            size = peek_filelike_length(fileobj)

        if not overwrite:
            # An `exists()` pre-check followed by a separate PUT would be a
            # TOCTOU race (another client could create the resource in
            # between); `If-None-Match: *` (RFC 7232 §3.2) makes the
            # not-already-there check atomic on the server, which maps a
            # conflicting PUT to 412 Precondition Failed.
            headers.setdefault("If-None-Match", "*")

        problem: list[str] = []
        chunks = _bounded_chunks(
            fileobj, size, chunk_size or self._session.chunk_size, callback, problem
        )

        # SizedIterator lets `requests` learn the real length itself and
        # keep the upload streamed with a plain Content-Length - passing
        # size via our own header instead doesn't work, see its docstring.
        body: Iterator[bytes] | SizedIterator = (
            SizedIterator(chunks, size) if size is not None else chunks
        )
        try:
            self._remote.send(
                Method.PUT, path, data=body, headers=headers, error_path=path
            )
        except PreconditionFailedError as exc:
            if not overwrite and not isinstance(exc, ResourceAlreadyExistsError):
                # We set ``If-None-Match: *``: a 412 here means "it exists".
                raise ResourceAlreadyExistsError(
                    exc.response, display_url(path)
                ) from exc
            raise
        except HTTPStatusError as exc:
            # A 405 is also what a resource answers that takes no PUT at all (a read-only
            # one): it only says "is a collection" if there is one.
            if exc.status_code == HTTPStatus.METHOD_NOT_ALLOWED and self.isdir(path):
                raise IsACollectionError(display_url(path)) from exc
            raise
        except requests.RequestException as exc:
            if problem:  # the request broke because the body could not be completed
                raise ClientError(problem[0]) from exc
            raise
