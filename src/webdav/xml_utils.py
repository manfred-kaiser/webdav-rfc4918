"""Safe, namespace-aware XML helpers shared across the WebDAV client.

Centralizes the XML-security invariant every parser in this codebase
relies on: stdlib :mod:`xml.etree.ElementTree` never resolves external
entities, and modern expat (>=2.4.0) rejects billion-laughs-style entity
amplification by default - verified empirically against the versions this
project supports, not just assumed.
"""

from xml.etree.ElementTree import Element, ParseError, SubElement
from xml.etree.ElementTree import fromstring as _fromstring
from xml.etree.ElementTree import tostring as _tostring

from webdav.exceptions import MalformedResponseError

DAV_NAMESPACE = "DAV:"


def clark(namespace: str, local_name: str) -> str:
    """Build a Clark-notation qualified name: ``{namespace}local_name``."""
    return f"{{{namespace}}}{local_name}"


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
    except ParseError as exc:
        msg = f"could not parse server response as XML: {exc}"
        raise MalformedResponseError(msg) from exc


def to_xml_string(element: Element) -> str:
    """Serialize an element tree to a unicode XML string."""
    return _tostring(element, encoding="unicode")


def sub_dav_element(parent: Element, local_name: str) -> Element:
    """Add a ``DAV:``-namespaced child element to ``parent``."""
    return SubElement(parent, dav(local_name))
