"""What a document from a server must not contain, checked before it is parsed.

A leaf (it imports only :mod:`pyexpat`), so both :mod:`webdav.dav.xml_utils`
and :mod:`webdav.exceptions` - which cannot import each other - can parse
server XML through the same checks.
"""

from pyexpat import ExpatError, ParserCreate


class UnsafeXMLError(ValueError):
    """The document is one this library refuses to parse (see :func:`check_xml`)."""


class _Stop(Exception):  # noqa: N818
    """Internal: the prolog has been read - the root element starts here."""


def _entity_declared(*_args: object) -> None:
    msg = (
        "the document declares an entity (<!ENTITY ...>): a WebDAV server sends none, "
        "and entity expansion is how a small document is made to cost gigabytes"
    )
    raise UnsafeXMLError(msg)


def _root_reached(*_args: object) -> None:
    raise _Stop


def check_xml(content: "str | bytes") -> None:
    """Refuse ``content`` if it declares an entity.

    The check reads only up to the root element - where every declaration has to be - so
    it costs nothing on a document of any size.

    Raises:
        UnsafeXMLError: It does (the message names the way out).

    """
    parser = ParserCreate()
    parser.EntityDeclHandler = _entity_declared
    parser.StartElementHandler = _root_reached
    try:
        parser.Parse(content, True)
    except UnsafeXMLError:
        raise
    except (_Stop, ExpatError, LookupError, ValueError, UnicodeError):
        # The root element, or a document that is not well-formed (an encoding
        # expat does not know, ...): the real parse - which comes next - reports
        # what is wrong with it.
        pass
