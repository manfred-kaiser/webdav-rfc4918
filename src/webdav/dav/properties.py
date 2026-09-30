"""WebDAV property model (RFC 4918 §14) and PROPFIND/PROPPATCH request bodies.

Properties are generic and namespace-aware: every property a server
returns is kept, keyed by its Clark-notation qualified name
(``{namespace}local-name``), not just a fixed subset of well-known
``DAV:`` properties. A thin, typed convenience layer sits on top for the
common live properties (``getetag``, ``getcontentlength``, ...).
"""

import logging
import re
from typing import TYPE_CHECKING, Any
from xml.etree.ElementTree import Element

from webdav.dav.date_utils import from_rfc1123, fromisoformat
from webdav.dav.locks import ActiveLock, LockEntry
from webdav.dav.xml_utils import (
    DAV_NAMESPACE,
    clark,
    dav,
    split_clark,
    sub_dav_element,
    to_xml_string,
)
from webdav.exceptions import MalformedResponseError
from webdav.transport.parse_utils import parse_uint

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

logger = logging.getLogger(__name__)

#: Convenience-name -> DAV: live property local name, RFC 4918 §15.
CONVENIENCE_PROPS: dict[str, str] = {
    "content_length": "getcontentlength",
    "etag": "getetag",
    "created": "creationdate",
    "modified": "getlastmodified",
    "content_language": "getcontentlanguage",
    "content_type": "getcontenttype",
    "display_name": "displayname",
}

PropName = tuple[str, str]  # (namespace, local_name)


def _parse_active_locks(lockdiscovery_el: Element | None) -> "list[ActiveLock]":
    """RFC 4918 §15.8: ``lockdiscovery`` is zero or more ``<d:activelock>``."""
    if lockdiscovery_el is None:
        return []
    locks: list[ActiveLock] = []
    for el in lockdiscovery_el.findall(dav("activelock")):
        try:
            locks.append(ActiveLock.from_element(el))
        except MalformedResponseError:
            # One malformed <d:activelock> must not discard the whole
            # property lookup, same rationale as multistatus.py's
            # per-<d:response> handling.
            logger.warning("skipping unparseable <d:activelock> entry", exc_info=True)
    return locks


def _parse_lock_entries(supportedlock_el: Element | None) -> "list[LockEntry]":
    """RFC 4918 §15.10: ``supportedlock`` is zero or more ``<d:lockentry>``."""
    if supportedlock_el is None:
        return []
    return [
        LockEntry.from_element(el) for el in supportedlock_el.findall(dav("lockentry"))
    ]


class PropStat:
    """One ``<d:propstat>`` block: a status shared by a group of properties."""

    def __init__(self, element: Element) -> None:
        """Parse a ``<d:propstat>`` element."""
        status_line = element.findtext(dav("status")) or ""
        parts = status_line.split()
        self.status_code = (parse_uint(parts[1]) or 0) if len(parts) >= 2 else 0
        self.response_description = element.findtext(dav("responsedescription"))
        self.error = element.find(dav("error"))

        self.properties: dict[str, Element] = {}
        prop_el = element.find(dav("prop"))
        if prop_el is not None:
            for child in prop_el:
                self.properties[child.tag] = child

    @property
    def ok(self) -> bool:
        """Whether this propstat's properties were successfully returned."""
        return 200 <= self.status_code < 300


class DAVProperties:
    """Generic, namespace-aware view over a resource's WebDAV properties.

    ``elements`` holds every successfully-returned property, keyed by
    Clark-notation tag. ``failed`` holds the HTTP status a property was
    rejected with (e.g. from a PROPPATCH that partially failed, or a
    PROPFIND for a named property the resource doesn't have).
    """

    def __init__(
        self,
        elements: dict[str, Element] | None = None,
        failed: dict[str, int] | None = None,
    ) -> None:
        """Build from Clark-tag-keyed elements, as parsed from propstats."""
        self.elements: dict[str, Element] = elements or {}
        self.failed: dict[str, int] = failed or {}

        def leaf_text(local_name: str) -> str | None:
            el = self.elements.get(dav(local_name))
            return el.text if el is not None and len(el) == 0 else None

        created = leaf_text("creationdate")
        self.created: datetime | None = fromisoformat(created) if created else None

        modified = leaf_text("getlastmodified")
        self.modified: datetime | None = from_rfc1123(modified) if modified else None

        self.etag: str | None = leaf_text("getetag") or None
        self.content_type: str | None = leaf_text("getcontenttype")

        self.content_length: int | None = parse_uint(leaf_text("getcontentlength"))
        self.content_language: str | None = leaf_text("getcontentlanguage")
        self.display_name: str | None = leaf_text("displayname")

        resourcetype_el = self.elements.get(dav("resourcetype"))
        self.collection: bool | None = None
        self.resource_type: str | None = None
        # §15.9: resourcetype is explicitly extensible - a resource can
        # carry resource types this library doesn't have a dedicated,
        # typed view for (e.g. an RFC 4437 redirect reference, or a
        # CalDAV/CardDAV-style extension type). `resource_type`/
        # `collection` stay the simple file-or-directory convenience view
        # (every other resource type collapses to "file" there, same as
        # before); `resource_types` exposes every child's local name so
        # that distinction isn't silently lost for a caller who cares.
        self.resource_types: frozenset[str] = frozenset()
        if resourcetype_el is not None:
            self.resource_types = frozenset(
                split_clark(child.tag)[1] for child in resourcetype_el
            )
            self.collection = "collection" in self.resource_types
            self.resource_type = "directory" if self.collection else "file"

        lockdiscovery_el = self.elements.get(dav("lockdiscovery"))
        self.lock_discovery: Element | None = lockdiscovery_el
        self.active_locks: list[ActiveLock] = _parse_active_locks(lockdiscovery_el)

        supportedlock_el = self.elements.get(dav("supportedlock"))
        self.supported_lock: Element | None = supportedlock_el
        self.supported_locks: list[LockEntry] = _parse_lock_entries(supportedlock_el)

    @classmethod
    def from_propstats(cls, propstats: "Iterable[PropStat]") -> "DAVProperties":
        """Merge a ``<d:response>``'s propstat blocks into one properties view."""
        elements: dict[str, Element] = {}
        failed: dict[str, int] = {}
        for propstat in propstats:
            for tag, el in propstat.properties.items():
                if propstat.ok:
                    elements[tag] = el
                else:
                    failed[tag] = propstat.status_code
        return cls(elements, failed)

    def element(self, namespace: str, local_name: str) -> "Element | None":
        """The XML element of a property, or ``None`` if the server did not return it."""
        return self.elements.get(clark(namespace, local_name))

    def text(self, namespace: str, local_name: str) -> "str | None":
        """The text of a property, or ``None`` if it is absent or has no text (use :meth:`element`)."""
        el = self.element(namespace, local_name)
        return el.text if el is not None and len(el) == 0 else None

    def as_dict(self) -> dict[str, Any]:
        """The well-known live properties as a plain dict (``None`` for one the server did not return)."""
        return {
            "content_length": self.content_length,
            "created": self.created,
            "modified": self.modified,
            "content_language": self.content_language,
            "content_type": self.content_type,
            "etag": self.etag,
            "type": self.resource_type,
            "display_name": self.display_name,
        }


def build_propfind_body(
    props: "Iterable[str | PropName] | None" = None,
    *,
    all_prop: bool = False,
    prop_name: bool = False,
    include: "Iterable[str | PropName] | None" = None,
) -> str:
    """Build a PROPFIND request body (RFC 4918 §9.1).

    Args:
        props: Property names to request. Each is either a convenience
            name (``"etag"``), a bare ``DAV:`` local name
            (``"getetag"``), or a ``(namespace, local_name)`` tuple for a
            property outside the ``DAV:`` namespace.
        all_prop: Request ``<d:allprop/>`` - all properties the server
            knows about.
        prop_name: Request ``<d:propname/>`` - names only, no values.
        include: Additional named properties to request alongside
            ``all_prop`` (``<d:allprop/><d:include>...</d:include>``,
            §9.1/§14.8) - a server isn't required to return every property
            it has for a bare ``allprop``, ``include`` names specific ones
            it should add. Only meaningful together with ``all_prop``;
            ignored otherwise (the grammar doesn't allow it alongside a
            named-``prop``/``propname`` request).

    Exactly one of ``props``, ``all_prop``, ``prop_name`` should be given;
    with none of them, an empty ``<d:prop/>`` is sent (equivalent to
    requesting no properties at all - callers typically want ``all_prop``
    instead).

    """
    root = Element("{DAV:}propfind")
    if prop_name:
        sub_dav_element(root, "propname")
    elif all_prop:
        sub_dav_element(root, "allprop")
        if include:
            include_el = sub_dav_element(root, "include")
            for namespace, local_name in _names(include, "include"):
                include_el.append(Element(clark(namespace, local_name)))
    else:
        prop_el = sub_dav_element(root, "prop")
        for namespace, local_name in _names(props, "props"):
            prop_el.append(Element(clark(namespace, local_name)))
    return to_xml_string(root)


def build_proppatch_body(
    set_props: "dict[str | PropName, str | Element] | None" = None,
    remove_props: "Iterable[str | PropName] | None" = None,
) -> str:
    """Build a PROPPATCH request body (RFC 4918 §9.2).

    Args:
        set_props: Properties to set, mapping a name (see
            :func:`build_propfind_body` for the accepted name forms) to
            either a plain text value or a pre-built
            :class:`~xml.etree.ElementTree.Element` for a complex/typed
            value.
        remove_props: Properties to remove.

    """
    if not set_props and not remove_props:
        msg = "a PROPPATCH needs at least one property to set or remove (RFC 4918 sec. 14.19)"
        raise ValueError(msg)
    root = Element("{DAV:}propertyupdate")

    if set_props:
        set_el = sub_dav_element(root, "set")
        prop_el = sub_dav_element(set_el, "prop")
        for name, value in set_props.items():
            namespace, local_name = _resolve_name(name)
            tag = clark(namespace, local_name)
            if isinstance(value, Element):
                wrapper = Element(tag)
                wrapper.append(value)
                prop_el.append(wrapper)
            else:
                el = Element(tag)
                if not isinstance(value, str):
                    msg = f"property value for {name!r} must be str or Element, got {type(value).__name__}"
                    raise TypeError(msg)
                el.text = value
                prop_el.append(el)

    if remove_props:
        remove_el = sub_dav_element(root, "remove")
        prop_el = sub_dav_element(remove_el, "prop")
        for namespace, local_name in _names(remove_props, "remove_props"):
            prop_el.append(Element(clark(namespace, local_name)))

    return to_xml_string(root)


#: The local part of an XML name (NCName): a letter or underscore, then letters,
#: digits, dots, hyphens, underscores - no colon, no space, nothing that could end
#: the name and start something else.
_NCNAME = re.compile(r"[^\W\d][\w.\-]*")


def _resolve_name(name: "str | PropName") -> PropName:
    """Turn a property name into ``(namespace, local_name)``, refusing anything that is not one.

    Accepted: a convenience name (``"etag"``), a bare ``DAV:`` local name
    (``"getetag"``), Clark notation (``"{urn:x}y"`` - the form ``DAVProperties``
    reports names in) and a ``(namespace, local_name)`` tuple; an empty
    namespace means no namespace.

    Raises:
        ValueError: Not a valid property name (the name could otherwise alter the XML around it).
        TypeError: Not a ``str`` or a pair of ``str``.

    """
    if isinstance(name, tuple):
        if len(name) != 2 or not all(isinstance(part, str) for part in name):
            msg = f"a property name is a str or a (namespace, local name) pair of str, got {name!r}"
            raise TypeError(msg)
        namespace, local_name = name
    elif isinstance(name, str):
        if name.startswith("{"):
            namespace, brace, local_name = name[1:].partition("}")
            if not brace:
                msg = f"invalid property name {name!r}: unclosed namespace"
                raise ValueError(msg)
        else:
            namespace, local_name = DAV_NAMESPACE, CONVENIENCE_PROPS.get(name, name)
    else:
        msg = f"a property name is a str or a (namespace, local name) pair of str, got {type(name).__name__}"
        raise TypeError(msg)
    if not _NCNAME.fullmatch(local_name):
        msg = f"invalid property name {local_name!r}"
        raise ValueError(msg)
    if any(c in namespace for c in "{}<>&\"'") or not namespace.isprintable():
        msg = f"invalid property namespace {namespace!r}"
        raise ValueError(msg)
    return namespace, local_name


def _names(names: "Iterable[str | PropName] | None", what: str) -> "list[PropName]":
    """The names in ``names`` resolved - and a single ``str`` refused (it would be read as its characters)."""
    if names is None:
        return []
    if isinstance(names, str | bytes):
        msg = f"{what} is a list of names, not a single {type(names).__name__}: pass [{names!r}]"
        raise TypeError(msg)
    return [_resolve_name(name) for name in names]
