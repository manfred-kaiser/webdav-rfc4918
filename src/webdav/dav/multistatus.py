"""Parsing of 207 Multi-Status responses (RFC 4918 §13).

A Multi-Status response can carry results for many resources at once -
PROPFIND/PROPPATCH enumerate one ``<d:response>`` per resource, while
COPY/MOVE/DELETE/LOCK use it to report partial failure across a
collection. Both shapes are parsed here.
"""

import logging
import re
from http.client import responses as _reason_phrases
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

import requests

from webdav.dav.properties import DAVProperties, PropStat
from webdav.dav.urls import (
    URL,
    join_url_path,
    path_key,
    relative_url_to,
    strip_trailing_slash,
)
from webdav.dav.xml_utils import dav, parse_xml, split_clark
from webdav.exceptions import MalformedResponseError, MultiStatusError

if TYPE_CHECKING:
    from requests import Response as HTTPResponse

logger = logging.getLogger(__name__)


#: A multistatus with more ``<d:response>`` elements than this is refused: each
#: costs real work to build, and a server that wants a client to spend
#: gigabytes of memory needs only a few dozen megabytes of tiny elements to do it.
MAX_RESPONSES = 200_000

#: Longest ``<d:href>`` accepted, in characters.
MAX_HREF_LENGTH = 8192

#: An encoded ``/`` in an href would turn into a path separator once decoded -
#: the client would then request a different resource than the one the server
#: listed. (A backslash is an ordinary character in a POSIX file name; where it
#: separates paths, ``relative_url_to`` refuses it.)
_ENCODED_SEPARATOR = re.compile(r"%2f", re.IGNORECASE)


def _parse_status_code(status_line: str | None) -> int | None:
    if not status_line:
        return None
    parts = status_line.split()
    if len(parts) < 2 or not (parts[1].isascii() and parts[1].isdigit()):
        return None
    return int(parts[1])


def _check_href(href: str) -> None:
    """Refuse an href that cannot be trusted to name one resource.

    Raises:
        ValueError: The href is too long, or hides a path separator in
            percent-encoding.

    """
    if len(href) > MAX_HREF_LENGTH:
        msg = f"<d:href> longer than {MAX_HREF_LENGTH} characters"
        raise ValueError(msg)
    if _ENCODED_SEPARATOR.search(href):
        msg = f"<d:href> {href[:80]!r} contains an encoded path separator"
        raise ValueError(msg)


class Response:
    """One ``<d:response>`` element: the result for a single resource."""

    def __init__(self, response_xml: Element) -> None:
        """Parse a ``<d:response>`` element.

        Raises:
            ValueError: The element is missing its required ``<d:href>``.

        """
        self.response_xml = response_xml
        # §14.24: response = href, ((href*, status) | propstat+), ... - a
        # status-bearing (non-propstat) response can carry *several*
        # <href> elements sharing one <status> (e.g. one collection
        # member's DELETE/COPY/MOVE failure reported once for multiple
        # equivalent paths). `self.href`/`.path`/`.path_norm` below stay
        # the first one (the common single-href case, and what property
        # lookups always use), `self.hrefs` carries all of them.
        hrefs = [el.text for el in response_xml.findall(dav("href")) if el.text]
        if not hrefs:
            msg = "<d:response> is missing a required <d:href>"
            raise ValueError(msg)
        for href in hrefs:
            _check_href(href)
        self.hrefs = hrefs

        parsed = URL(hrefs[0])
        self.href = hrefs[0]
        self.is_href_absolute = parsed.is_absolute_url
        self.path = parsed.path
        # Absolute path without a trailing slash - used as the responses
        # dict key, so collections and their trailing-slash-free lookups
        # both resolve to the same entry.
        self.path_norm = strip_trailing_slash(self.path)

        # A member <d:response> either carries its own top-level <d:status>
        # (COPY/MOVE/DELETE/LOCK reporting failure for one member of a
        # collection operation), or one <d:status> per <d:propstat> block
        # (PROPFIND/PROPPATCH enumerating properties) - both are parsed;
        # ``status_code``/``reason_phrase`` reflect the former when present.
        status_text = response_xml.findtext(dav("status"))
        self.status_code = _parse_status_code(status_text)
        if status_text and status_text.strip() and self.status_code is None:
            msg = f"unparseable <d:status> {status_text.strip()[:60]!r}"
            raise ValueError(msg)
        self.reason_phrase = (
            _reason_phrases.get(self.status_code) if self.status_code else None
        )

        self.response_description = response_xml.findtext(dav("responsedescription"))
        self.error = response_xml.find(dav("error"))
        # §14.11: <location> wraps an <href> child - it carries no text of
        # its own, so a bare findtext(dav("location")) always returns None.
        self.location = response_xml.findtext(f"{dav('location')}/{dav('href')}")

        self.propstats: list[PropStat] = [
            PropStat(el) for el in response_xml.findall(dav("propstat"))
        ]
        self.has_propstat = bool(self.propstats)
        self.properties = DAVProperties.from_propstats(self.propstats)

    def __str__(self) -> str:
        """User-facing representation."""
        return f"Response: {self.path_norm}"

    def __repr__(self) -> str:
        """Debug representation."""
        return f"Response({self.path!r})"

    def path_relative_to(self, base_url: URL) -> str:
        """Path of this response's resource, relative to ``base_url``.

        Raises:
            MalformedResponseError: This response's ``href`` does not
                resolve to a path under ``base_url`` - a server response
                should never point outside of what was requested.

        """
        try:
            return relative_url_to(base_url, self.path_norm)
        except ValueError as exc:
            msg = f"server response href {self.href!r} is outside the requested subtree"
            raise MalformedResponseError(msg) from exc


class MultiStatusResponse:
    """A parsed 207 Multi-Status response body.

    Note that a PROPFIND/PROPPATCH response can be partial - properties
    not requested, or not supported by a resource, simply won't appear;
    see :attr:`~webdav.dav.properties.DAVProperties.failed` for properties the
    server explicitly rejected.
    """

    def __init__(self, content: str | bytes) -> None:
        """Parse ``content``, the body of a 207 response."""
        self.content = content
        self.tree = tree = parse_xml(content)

        self.response_description: str | None = tree.findtext(
            dav("responsedescription")
        )

        self.responses: dict[str, Response] = {}
        #: Every ``<d:response>``, in document order. ``responses`` is a lookup
        #: by path - two entries for one path (or for the NFC and NFD spelling
        #: of one name) share a key there, so anything that has to see them
        #: all (a failure hiding behind a later success, a listing) uses this.
        self.entries: list[Response] = []
        for count, resp_el in enumerate(tree.findall(f".//{dav('response')}"), start=1):
            if count > MAX_RESPONSES:
                msg = f"multistatus has too many <d:response> elements (over {MAX_RESPONSES})"
                raise MalformedResponseError(msg)
            try:
                response = Response(resp_el)
            except ValueError as exc:
                # Never skipped quietly: in a DELETE/COPY/MOVE reply the entry
                # that does not parse may be the one reporting the failure, and
                # dropping it would turn that failure into a success.
                msg = f"unusable <d:response> entry in the multistatus: {exc}"
                raise MalformedResponseError(msg) from exc
            self.entries.append(response)
            # Register under every href this response covers (usually just
            # one - see Response.__init__ for the multi-href case). Keyed by
            # ``path_key``: NFC, so either spelling of a name finds it.
            for href in response.hrefs:
                self.responses[path_key(URL(href).path)] = response

    def get_response_for_path(self, hostname: str, path: str) -> Response:
        """Return the response for the resource at ``path``.

        Args:
            hostname: The base URL's path component (WebDAV root), used to
                reconstruct the absolute path a server's ``href`` would use.
            path: Resource path relative to ``hostname``.

        Raises:
            MalformedResponseError: The server's multistatus reply has no
                ``<d:response>`` entry for ``path`` - e.g. because its
                ``href`` used a different (but equally valid) form of the
                path than this client expected.

        """
        key = path_key(join_url_path(hostname, path))
        try:
            return self.responses[key]
        except KeyError:
            msg = f"server's multistatus reply has no <d:response> for {path!r}"
            raise MalformedResponseError(msg) from None

    def raise_for_status(self) -> None:
        """Raise :class:`~webdav.exceptions.MultiStatusError` on any failure.

        Covers both shapes a ``<d:response>`` can report failure in: its
        own top-level ``<d:status>`` (COPY/MOVE/DELETE/LOCK reporting a
        failed collection member), and a per-property status inside a
        ``<d:propstat>`` (PROPFIND/PROPPATCH) - the latter matters most
        for PROPPATCH, where the overall HTTP exchange is a plain 207
        even when the server rejected setting/removing a specific
        property (e.g. 403/409/507 on that one ``<d:prop>`` entry).
        """
        statuses: dict[str, str] = {}
        error_codes: dict[str, frozenset[str]] = {}

        def record(key: str, reason: str, error_el: Element | None) -> None:
            statuses[key] = reason
            codes = _error_codes(error_el)
            if codes:
                error_codes[key] = codes

        for resp in self.entries:
            # RFC 4918 sec. 13: anything but a 2xx is a failure - not just the
            # 4xx/5xx a phrase exists for (a 3xx or an unknown code is no success).
            if resp.status_code is not None and not 200 <= resp.status_code < 300:
                record(
                    resp.href,
                    _reason_phrases.get(resp.status_code, str(resp.status_code)),
                    resp.error,
                )
            for propstat in resp.propstats:
                if propstat.status_code == 0:
                    msg = f"unparseable <d:status> in a <d:propstat> for {resp.href!r}"
                    raise MalformedResponseError(msg)
                if 200 <= propstat.status_code < 300:
                    continue
                reason = _reason_phrases.get(
                    propstat.status_code, str(propstat.status_code)
                )
                for tag in propstat.properties:
                    _, local_name = split_clark(tag)
                    record(f"{resp.href} ({local_name})", reason, propstat.error)

        statuses = dict(sorted(statuses.items()))
        if statuses:
            raise MultiStatusError(statuses, error_codes=error_codes)


def _error_codes(error_el: Element | None) -> frozenset[str]:
    """RFC 4918 §16: the local names of every precondition/postcondition child.

    ``<error>``'s content model is intentionally open-ended (extensible
    precondition/postcondition XML elements, e.g. ``<d:no-conflicting-lock/>``)
    - this exposes just their local names rather than trying to parse each
    one's own (extension-defined) structure.
    """
    if error_el is None:
        return frozenset()
    return frozenset(split_clark(child.tag)[1] for child in error_el)


def parse_multistatus_response(http_response: "HTTPResponse") -> MultiStatusResponse:
    """Parse a 207 Multi-Status response.

    Raises:
        MalformedResponseError: ``http_response`` isn't a 207 response (a
            plain web server, a proxy or a captive portal answering the
            PROPFIND) or its body is not a well-formed multistatus.

    """
    if http_response.status_code != requests.codes.multi_status:
        msg = f"the server answered {http_response.status_code}, not a 207 Multi-Status - is this a WebDAV server?"
        raise MalformedResponseError(msg)
    return MultiStatusResponse(http_response.content)
