"""Parsing of 207 Multi-Status responses (RFC 4918 §13).

A Multi-Status response can carry results for many resources at once -
PROPFIND/PROPPATCH enumerate one ``<d:response>`` per resource, while
COPY/MOVE/DELETE/LOCK use it to report partial failure across a
collection. Both shapes are parsed here.
"""

import logging
from http.client import responses as _reason_phrases
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

from webdav.exceptions import MalformedResponseError, MultiStatusError
from webdav.properties import DAVProperties, PropStat
from webdav.urls import URL, join_url_path, relative_url_to, strip_trailing_slash
from webdav.xml_utils import dav, parse_xml, split_clark

if TYPE_CHECKING:
    from requests import Response as HTTPResponse

logger = logging.getLogger(__name__)


def _parse_status_code(status_line: str | None) -> int | None:
    if not status_line:
        return None
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])


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
        self.status_code = _parse_status_code(response_xml.findtext(dav("status")))
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
    see :attr:`~webdav.properties.DAVProperties.failed` for properties the
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
        for resp_el in tree.findall(f".//{dav('response')}"):
            try:
                response = Response(resp_el)
            except ValueError:
                # One malformed <d:response> entry must not discard every
                # other, otherwise valid, entry in the same reply.
                logger.warning("skipping unparseable <d:response> entry", exc_info=True)
                continue
            # Register under every href this response covers (usually just
            # one - see Response.__init__ for the multi-href case).
            for href in response.hrefs:
                key = strip_trailing_slash(URL(href).path)
                self.responses[key] = response

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
        key = join_url_path(hostname, path)
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

        for resp in self.responses.values():
            if (
                resp.reason_phrase
                and resp.status_code
                and 400 <= resp.status_code <= 599
            ):
                record(resp.href, resp.reason_phrase, resp.error)
            for propstat in resp.propstats:
                if propstat.ok or not (400 <= propstat.status_code <= 599):
                    continue
                reason = _reason_phrases.get(propstat.status_code, str(propstat.status_code))
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
        ValueError: ``http_response`` isn't actually a 207 response.

    """
    if http_response.status_code != 207:
        msg = "http response is not a multistatus response"
        raise ValueError(msg)
    return MultiStatusResponse(http_response.content)
