"""Safe, namespace-aware XML helpers shared across the WebDAV client.

Centralizes the XML-security invariant every parser in this codebase
relies on: stdlib :mod:`xml.etree.ElementTree` never resolves external
entities, and modern expat (>=2.4.0) rejects billion-laughs-style entity
amplification by default - verified empirically against the versions this
project supports, not just assumed.
"""

import re
from xml.etree.ElementTree import Element, ParseError, SubElement
from xml.etree.ElementTree import fromstring as _fromstring
from xml.etree.ElementTree import tostring as _tostring

from webdav.exceptions import MalformedResponseError

DAV_NAMESPACE = "DAV:"


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
    expansion attacks without any extra hardening.

    Raises:
        MalformedResponseError: ``content`` is not well-formed XML - wraps
            the stdlib's bare :class:`~xml.etree.ElementTree.ParseError` so
            every exception this library raises stays a
            :class:`~webdav.exceptions.WebDAVError`, per the promise in
            :mod:`webdav.exceptions`.

    """
    try:
        return _fromstring(content)  # noqa: S314 # nosec B314 -- see module docstring
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
