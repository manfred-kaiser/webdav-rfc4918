"""Safe, namespace-aware XML helpers shared across the WebDAV client.

Centralizes the XML-security invariant every parser in this codebase
relies on: stdlib :mod:`xml.etree.ElementTree` never resolves external
entities, and modern expat (>=2.4.0) rejects the worst entity amplification
by default - but only past 8 MiB of output, and it counts bytes, not the
objects a tree of tiny elements costs. A document that declares an entity is
therefore refused outright (a WebDAV server sends none), and a document with
absurdly many elements is refused before it is parsed (:data:`MAX_MARKUP`).
"""

import re
from xml.etree.ElementTree import Element, ParseError, SubElement
from xml.etree.ElementTree import fromstring as _fromstring
from xml.etree.ElementTree import tostring as _tostring

from webdav._xml_guard import UnsafeXMLError, check_xml
from webdav.exceptions import MalformedResponseError

DAV_NAMESPACE = "DAV:"

#: The most ``<`` a document may carry (two per element, so about half as many
#: elements), counted before it is parsed. Far above what a real answer holds -
#: 200 000 ``<d:response>`` (``multistatus.MAX_RESPONSES``) of a Nextcloud
#: ``allprop`` listing, the richest seen, are 13.6 million; of Apache's, 8.4
#: million - and well beyond what the default ``max_response_size`` (64 MiB:
#: at most 16.8 million of ``<a/>``) can carry, so it only ever matters to a
#: session that raised or lifted that limit. Not a size limit: a listing of
#: any number of ordinary entries stays far below. ``None`` turns it off.
MAX_MARKUP: "int | None" = 64_000_000


def clark(namespace: str, local_name: str) -> str:
    """Build a Clark-notation qualified name: ``{namespace}local_name`` (just ``local_name`` with no namespace)."""
    return f"{{{namespace}}}{local_name}" if namespace else local_name


def dav(local_name: str) -> str:
    """Build a Clark-notation qualified name in the ``DAV:`` namespace."""
    return clark(DAV_NAMESPACE, local_name)


def split_clark(tag: str) -> tuple[str, str]:
    """Split a Clark-notation tag into ``(namespace, local_name)``.

    ``namespace`` is ``""`` for a tag with no namespace.
    """
    if tag.startswith("{"):
        namespace, _, local_name = tag[1:].partition("}")
        return namespace, local_name
    return "", tag


def parse_xml(content: str | bytes) -> Element:
    """Parse XML content into an :class:`~xml.etree.ElementTree.Element`.

    See the module docstring for why this is safe against XXE/entity
    expansion attacks.

    Raises:
        MalformedResponseError: ``content`` is not well-formed XML, declares
            an entity, or has more than :data:`MAX_MARKUP` ``<`` - wraps
            the stdlib's bare :class:`~xml.etree.ElementTree.ParseError` so
            every exception this library raises stays a
            :class:`~webdav.exceptions.WebDAVError`, per the promise in
            :mod:`webdav.exceptions`.

    """
    try:
        check_xml(content, MAX_MARKUP)
    except UnsafeXMLError as exc:
        msg = f"refusing the server's XML: {exc}"
        raise MalformedResponseError(msg) from exc
    try:
        # Safe against XXE/entity expansion: see the module docstring. (bandit reads every
        # word after "nosec" as a test id, so the reason cannot sit on that line.)
        return _fromstring(content)  # noqa: S314 # nosec B314
    except (ParseError, LookupError, ValueError, UnicodeError) as exc:
        # LookupError: an unknown ``encoding=`` declaration; ValueError/
        # UnicodeError: one expat cannot honour (e.g. ``utf-16`` on an ASCII
        # body). The server picked them - none may escape as a bare error.
        msg = f"could not parse server response as XML: {exc}"
        raise MalformedResponseError(msg) from exc


#: What XML 1.0 cannot carry at all (its ``Char`` production): control characters
#: other than tab/newline/carriage return, lone surrogates, U+FFFE and U+FFFF.
_ILLEGAL_XML_CHARS = re.compile(
    "[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]"
)


def _check_xml_text(value: "str | None", what: str) -> None:
    if value and (bad := _ILLEGAL_XML_CHARS.search(value)):
        msg = f"{what} contains a character XML cannot carry (U+{ord(bad.group()):04X})"
        raise ValueError(msg)


def to_xml_string(element: Element) -> str:
    """Serialize an element tree to a unicode XML string.

    Refuses text XML cannot carry (a NUL, a lone surrogate, ...) rather than
    sending an ill-formed document, and writes a carriage return as ``&#13;``:
    a bare one is read back as a newline, which would change stored data.

    Raises:
        ValueError: A tag, attribute or text of the tree holds a character
            XML 1.0 cannot represent.

    """
    for node in element.iter():
        _check_xml_text(
            node.tag if isinstance(node.tag, str) else "", "an element name"
        )
        _check_xml_text(node.text, "a text value")
        _check_xml_text(node.tail, "a text value")
        for key, value in node.attrib.items():
            _check_xml_text(key, "an attribute name")
            _check_xml_text(value, "an attribute value")
    return _tostring(element, encoding="unicode").replace("\r", "&#13;")


def sub_dav_element(parent: Element, local_name: str) -> Element:
    """Add a ``DAV:``-namespaced child element to ``parent``."""
    return SubElement(parent, dav(local_name))
