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


def check_xml(content: "str | bytes", max_markup: "int | None" = None) -> None:
    """Refuse ``content`` if it declares an entity, or has more than ``max_markup`` ``<``.

    The entity check reads only up to the root element - where every
    declaration has to be - so it costs nothing on a document of any size. The
    ``<`` count is an upper bound for the work parsing will do (two per element,
    plus comments and processing instructions), taken before anything is built:
    a few megabytes of ``<a/>`` become gigabytes of objects, and ``expat`` only
    counts bytes.

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
    if max_markup is not None:
        found = content.count("<") if isinstance(content, str) else content.count(b"<")
        if found > max_markup:
            msg = (
                f"the document has {found} '<', more than the {max_markup} allowed "
                "(set webdav.dav.xml_utils.MAX_MARKUP to a larger number, or to None, "
                "if this server really sends documents this large)"
            )
            raise UnsafeXMLError(msg)
