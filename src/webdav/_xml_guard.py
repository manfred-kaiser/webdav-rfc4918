"""What a document from a server must not contain, checked before it is parsed.

A leaf (it imports only :mod:`pyexpat` and the standard library), so both :mod:`webdav.dav.xml_utils`
and :mod:`webdav.exceptions` - which cannot import each other - can parse
server XML through the same checks.
"""

import logging
import pyexpat
import threading
from pyexpat import ExpatError, ParserCreate

_LOGGER = logging.getLogger("webdav")

#: The first ``expat`` the Python documentation (xml.html, "XML security") does not list as
#: possibly open to billion laughs, quadratic blowup and large tokens.
MIN_EXPAT_VERSION = (2, 7, 2)

_warned = threading.Event()


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


def warn_if_expat_is_old() -> None:
    """Log once that the ``expat`` in use is older than :data:`MIN_EXPAT_VERSION`.

    Its protection against entity expansion and large tokens is the parser's own;
    :func:`check_xml` refuses entity declarations whatever the version, but not
    the rest. The version is that of the Python in use (a distribution's Python links
    the system's ``expat``): ``pyexpat.EXPAT_VERSION``.
    """
    if _warned.is_set() or tuple(pyexpat.version_info) >= MIN_EXPAT_VERSION:
        return
    _warned.set()
    _LOGGER.warning(
        "this Python uses %s, older than expat %s: it may be open to XML entity "
        "expansion and large-token attacks from a hostile server; update Python or the "
        "system's expat",
        pyexpat.EXPAT_VERSION,
        ".".join(map(str, MIN_EXPAT_VERSION)),
    )


def check_xml(content: "str | bytes", encoding: "str | None" = None) -> None:
    """Refuse ``content`` if it declares an entity.

    ``encoding`` is the one the document is going to be parsed with, when that is
    not the one it declares: the check has to read the same document the parse will.

    The check reads only up to the root element - where every declaration has to be - so
    it costs nothing on a document of any size.

    Raises:
        UnsafeXMLError: It does (the message names the way out).

    """
    warn_if_expat_is_old()
    parser = ParserCreate(encoding)
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
